//! Port of src/inject_createthread.cpp — CreateRemoteThread / CreateThread
//! injection techniques.

use std::ffi::c_void;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, CreateThread, LPTHREAD_START_ROUTINE,
};

/// Create a remote thread in the target process (inject_via_remotethread).
pub fn inject_via_remotethread(h_process: isize, lp_start_address: *mut c_void, lp_parameter: *mut c_void) -> bool {
    unsafe {
        /* kick it off */
        let routine: LPTHREAD_START_ROUTINE = std::mem::transmute(lp_start_address);
        let h_thread = CreateRemoteThread(
            h_process as HANDLE,
            std::ptr::null(),
            0,
            routine,
            lp_parameter,
            0,
            std::ptr::null_mut(),
        );
        !h_thread.is_null()
    }
}

/// Create a thread in the current process (inject_via_createthread; only
/// works for same-PID injection). `h_process`/`pid` are unused, exactly as
/// in the C++.
pub fn inject_via_createthread(_h_process: isize, _pid: u32, lp_start_address: *mut c_void, lp_parameter: *mut c_void) -> bool {
    unsafe {
        let routine: LPTHREAD_START_ROUTINE = std::mem::transmute(lp_start_address);
        let h_thread = CreateThread(
            std::ptr::null(),
            0,
            routine,
            lp_parameter,
            0,
            std::ptr::null_mut(),
        );
        !h_thread.is_null()
    }
}
