//! 设置表的内部辅助（myargs 存储）。
//! Internal helpers for the settings table (myargs storage).
//!
//! C++ 的 `myargs` 数组是一个在构建时打入 DLL 映像的可变 4096 字节块。我们保留一份进程全局副本；初始化路径取副本、解析，然后丢弃它（对应 C++ 的 `memset`）。
//! The C++ `myargs` array is a mutable 4096-byte blob patched into the DLL
//! image at build time. We keep a process-global copy; the init path takes
//! a copy, parses it, then discards it (mirroring the C++ `memset`).

use crate::settings::PATCH_SIZE;
use parking_lot::Mutex;

/// 打入配置块的进程全局副本（受锁保护；只在单线程的设置初始化路径中触碰）。
/// Process-global copy of the patched config blob (guarded; only touched
/// during the single-threaded settings init path).
static MYARGS: Mutex<[u8; PATCH_SIZE]> = Mutex::new([0u8; PATCH_SIZE]);

pub fn set_myargs(blob: &[u8]) {
    let mut myargs = MYARGS.lock();
    let n = blob.len().min(PATCH_SIZE);
    myargs[..n].copy_from_slice(&blob[..n]);
}

/// 取当前 myargs 块的副本供解析。
/// Take a copy of the current myargs blob for parsing.
pub fn take_myargs() -> Box<[u8; PATCH_SIZE]> {
    Box::new(*MYARGS.lock())
}

#[cfg(test)]
pub fn reset_for_test() {
    MYARGS.lock().fill(0);
}
