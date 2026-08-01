//! 移植自 src/inject_setthreadcontext.cpp —— SetThreadContext / ResumeThread
//! 注入。Rust 移植版面向 x64，因此这是 C++ 的 `_M_X64` 分支：它提供原生
//! x64 变体、WOW64（x64 中的 x86）变体，以及按目标架构选择的分发器。
//! Port of src/inject_setthreadcontext.cpp — SetThreadContext / ResumeThread
//! injection. The Rust port targets x64, so this is the `_M_X64` branch of
//! the C++: it provides the native x64 variant, the WOW64 (x86-in-x64)
//! variant, and the dispatcher that picks by target architecture.

use crate::inject::{InjectContext, INJECT_ARCH_X86};
use std::ffi::c_void;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, Wow64GetThreadContext, Wow64SetThreadContext, CONTEXT,
    CONTEXT_INTEGER_AMD64, CONTEXT_INTEGER_X86, WOW64_CONTEXT,
};
use windows_sys::Win32::System::Threading::ResumeThread;

/// 针对原生 x64 线程的 SetThreadContext / ResumeThread
/// （inject_via_resumethread_x64）：Rcx = 起始地址，Rdx = 参数。
/// SetThreadContext / ResumeThread for a native x64 thread
/// (inject_via_resumethread_x64): Rcx = start address, Rdx = parameter.
pub fn inject_via_resumethread_x64(h_thread: isize, lp_start_address: *mut c_void, lp_parameter: *mut c_void) -> bool {
    unsafe {
        // 尝试查询一些关于我们线程的信息。
        /* try to query some information about our thread */
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_INTEGER_AMD64;
        if GetThreadContext(h_thread as HANDLE, &mut ctx) == 0 {
            return false;
        }

        // 把 Rcx 更新为我们的新起始地址，用 Rdx 传递参数。
        /* update the Rcx value to our new start address, use Rdx to pass a parameter */
        ctx.Rcx = lp_start_address as u64;
        ctx.Rdx = lp_parameter as u64;
        if SetThreadContext(h_thread as HANDLE, &ctx) == 0 {
            return false;
        }

        // 启动线程，拜托了。
        /* kick off the thread, please */
        ResumeThread(h_thread as HANDLE) != u32::MAX
    }
}

/// 针对 x64 进程中 WOW64（x86）线程的 SetThreadContext / ResumeThread
/// （inject_via_resumethread_x86）：Eax = 起始地址；这种方式无法传递参数。
/// SetThreadContext / ResumeThread for a WOW64 (x86) thread in an x64
/// process (inject_via_resumethread_x86): Eax = start address; no parameter
/// can be passed this way.
pub fn inject_via_resumethread_x86(h_thread: isize, lp_start_address: *mut c_void, lp_parameter: *mut c_void) -> bool {
    unsafe {
        // 这种方式无法传递参数；所以现在直接失败……
        /* we can't pass a parameter this way; so fail now... */
        if !lp_parameter.is_null() {
            return false;
        }

        // 尝试查询一些关于我们线程的信息。
        /* try to query some information about our thread */
        let mut ctx: WOW64_CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_INTEGER_X86;
        if Wow64GetThreadContext(h_thread as HANDLE, &mut ctx) == 0 {
            return false;
        }

        // 把 Eax 更新为我们的新起始地址。
        /* update the Eax value to our new start address */
        ctx.Eax = lp_start_address as u32;
        if Wow64SetThreadContext(h_thread as HANDLE, &ctx) == 0 {
            return false;
        }

        // 启动线程，拜托了。
        /* kick off the thread, please */
        ResumeThread(h_thread as HANDLE) != u32::MAX
    }
}

/// 按目标进程架构分发（inject_via_resumethread）。
/// Dispatch by the target process architecture (inject_via_resumethread).
pub fn inject_via_resumethread(injctx: &mut InjectContext, lp_start_address: *mut c_void, lp_parameter: *mut c_void) -> bool {
    if injctx.target_arch == INJECT_ARCH_X86 {
        inject_via_resumethread_x86(injctx.h_thread, lp_start_address, lp_parameter)
    } else {
        inject_via_resumethread_x64(injctx.h_thread, lp_start_address, lp_parameter)
    }
}
