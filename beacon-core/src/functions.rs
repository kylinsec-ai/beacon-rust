//! Wow64 文件系统重定向辅助函数（functions.cpp）。
//! Wow64 fs redirection helpers (functions.cpp).

use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

/// Wow64DisableWow64FsRedirection（禁用 Wow64 文件系统重定向）。
/// Wow64DisableWow64FsRedirection.
pub fn disable_wow64(old_value: &mut *mut core::ffi::c_void) {
    unsafe {
        let kernel32 = GetModuleHandleA(c"kernel32".as_ptr().cast());
        if kernel32.is_null() {
            return;
        }
        let function = GetProcAddress(kernel32, c"Wow64DisableWow64FsRedirection".as_ptr().cast());
        if let Some(function) = function {
            let f: unsafe extern "system" fn(*mut *mut core::ffi::c_void) -> i32 =
                std::mem::transmute(function);
            f(old_value);
        }
    }
}

/// Wow64RevertWow64FsRedirection（恢复 Wow64 文件系统重定向）。
/// Wow64RevertWow64FsRedirection.
pub fn revert_wow64(old_value: *mut core::ffi::c_void) {
    unsafe {
        let kernel32 = GetModuleHandleA(c"kernel32".as_ptr().cast());
        if kernel32.is_null() {
            return;
        }
        let function = GetProcAddress(kernel32, c"Wow64RevertWow64FsRedirection".as_ptr().cast());
        if let Some(function) = function {
            let f: unsafe extern "system" fn(*mut core::ffi::c_void) -> i32 =
                std::mem::transmute(function);
            f(old_value);
        }
    }
}
