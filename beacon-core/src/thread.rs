//! 安全的线程派生 + 退出例程（thread.cpp）。
//! Safe thread spawning + exit routines (thread.cpp).

use crate::beacon::{EXIT_FUNK_THREAD, SETTING_CFG_CAUTION, SETTING_EXIT_FUNK};
use crate::settings::setting_short;
use crate::state::THREAD_COUNT;
use crate::track_memory::track_memory_cleanup;
use std::sync::atomic::Ordering;
use windows_sys::Win32::System::Threading::*;

/// 在新线程上运行一个函数（C++ 原版支持 CFG；安全 Rust 中不需要
/// trampoline 机制，因此直接派生线程）。
/// Run a function on a new thread (CFG-aware in the C++ original; the
/// trampoline mechanics are not needed in safe Rust, so we spawn directly).
pub fn run_thread_start<F>(function: F)
where
    F: FnOnce() + Send + 'static,
{
    THREAD_COUNT.fetch_add(1, Ordering::SeqCst);
    std::thread::spawn(function);
}

/// 一种安全退出当前进程的方式。
/// A safe way to exit this process.
pub fn safe_exit() {
    let exit_funk = setting_short(SETTING_EXIT_FUNK);
    let cfg_caution = setting_short(SETTING_CFG_CAUTION);

    // 清理所有被跟踪的内存
    track_memory_cleanup(); // clean up all the tracked memory

    if exit_funk == EXIT_FUNK_THREAD {
        if cfg_caution == 1 {
            // 永远休眠
            // sleep forever
            loop {
                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
        } else {
            unsafe {
                ExitThread(0);
            }
        }
    } else {
        if cfg_caution == 1 {
            unsafe {
                // 等待一个退出进程的线程
                // wait on a thread that exits the process
                let _ = CreateThread(
                    std::ptr::null(),
                    0,
                    Some(exit_process_wrapper),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                );
            }
            loop {
                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
        } else {
            unsafe {
                ExitProcess(0);
            }
        }
    }
}

#[allow(unreachable_code)]
unsafe extern "system" fn exit_process_wrapper(_param: *mut core::ffi::c_void) -> u32 {
    ExitProcess(0);
    0
}
