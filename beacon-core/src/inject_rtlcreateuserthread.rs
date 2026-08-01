//! Port of src/inject_rtlcreateuserthread.cpp — remote thread creation via
//! the native RtlCreateUserThread.

use std::ffi::c_void;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

/// CLIENT_ID { PVOID UniqueProcess; PVOID UniqueThread; }.
#[repr(C)]
#[derive(Clone, Copy)]
struct ClientId {
    unique_process: *mut c_void,
    unique_thread: *mut c_void,
}

/// NTSTATUS RtlCreateUserThread(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN,
/// ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, CLIENT_ID*).
type RtlCreateUserThread = unsafe extern "system" fn(
    HANDLE,
    *mut c_void,
    u8,
    u32,
    *mut u32,
    *mut u32,
    *mut c_void,
    *mut c_void,
    *mut HANDLE,
    *mut ClientId,
) -> i32;

/// Create a remote thread via RtlCreateUserThread
/// (inject_via_createuserthread).
pub fn inject_via_createuserthread(h_process: isize, lp_start_address: *mut c_void, lp_parameter: *mut c_void) -> bool {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            return false;
        }
        let Some(func_addr) = GetProcAddress(ntdll, b"RtlCreateUserThread\0".as_ptr()) else {
            return false;
        };
        let func: RtlCreateUserThread = std::mem::transmute(func_addr);

        let mut h_remote_thread: HANDLE = std::ptr::null_mut();
        let mut cid: ClientId = std::mem::zeroed();
        func(
            h_process as HANDLE,
            std::ptr::null_mut(),
            0, /* CreateSuspended = FALSE */
            0, /* StackZeroBits */
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            lp_start_address,
            lp_parameter,
            &mut h_remote_thread,
            &mut cid,
        );

        !h_remote_thread.is_null()
    }
}
