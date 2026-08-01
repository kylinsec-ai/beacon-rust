//! Memory tracking (track_memory.cpp).
//!
//! The C++ version tracks allocations so Gargle can mask them during sleep
//! and so `safe_exit` can run cleanup callbacks. In Rust, allocations are
//! managed by the language; we keep the registry for allocations that need
//! masking during `GargleSleep` and for cleanup callbacks.

use parking_lot::Mutex;

pub const TRACK_MEMORY_MALLOC: i32 = 1;
pub const TRACK_MEMORY_VALLOC: i32 = 2;
pub const TRACK_MEMORY_CLEANUP_FUNC: i32 = 3;

#[derive(Clone)]
pub struct HeapRecord {
    pub ptr: usize,
    pub size: usize,
}

#[allow(dead_code)] // mirrors the C++ MEMORY_RECORD
struct MemoryRecord {
    ptr: usize,
    size: usize,
    rtype: i32,
    mask: bool,
    cleanup: Option<Box<dyn FnOnce() + Send>>,
}

static MEMORY_TRACKER: Mutex<Vec<MemoryRecord>> = Mutex::new(Vec::new());
static HEAP_RECORDS: Mutex<Vec<HeapRecord>> = Mutex::new(Vec::new());

/// Track a memory allocation. When `mask` is set the record is registered
/// for masking by Gargle.
pub fn track_memory_add(
    ptr: usize,
    size: usize,
    rtype: i32,
    mask: bool,
    cleanup: Option<Box<dyn FnOnce() + Send>>,
) {
    let mut tracker = MEMORY_TRACKER.lock();
    tracker.push(MemoryRecord {
        ptr,
        size,
        rtype,
        mask,
        cleanup,
    });
    if mask {
        HEAP_RECORDS.lock().push(HeapRecord { ptr, size });
    }
}

/// Run all cleanup callbacks and reset the tracker.
pub fn track_memory_cleanup() {
    let mut tracker = MEMORY_TRACKER.lock();
    for rec in tracker.drain(..) {
        if let Some(cleanup) = rec.cleanup {
            cleanup();
        }
    }
    HEAP_RECORDS.lock().clear();
}

/// Get the heap records to mask.
pub fn track_memory_get_heap_records_to_mask() -> Vec<HeapRecord> {
    HEAP_RECORDS.lock().clone()
}
