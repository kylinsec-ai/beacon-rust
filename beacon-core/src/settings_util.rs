//! Internal helpers for the settings table (myargs storage).
//!
//! The C++ `myargs` array is a mutable 4096-byte blob patched into the DLL
//! image at build time. We keep a process-global copy; the init path takes
//! a copy, parses it, then discards it (mirroring the C++ `memset`).

use crate::settings::PATCH_SIZE;
use parking_lot::Mutex;

/// Process-global copy of the patched config blob (guarded; only touched
/// during the single-threaded settings init path).
static MYARGS: Mutex<[u8; PATCH_SIZE]> = Mutex::new([0u8; PATCH_SIZE]);

pub fn set_myargs(blob: &[u8]) {
    let mut myargs = MYARGS.lock();
    let n = blob.len().min(PATCH_SIZE);
    myargs[..n].copy_from_slice(&blob[..n]);
}

/// Take a copy of the current myargs blob for parsing.
pub fn take_myargs() -> Box<[u8; PATCH_SIZE]> {
    Box::new(*MYARGS.lock())
}

#[cfg(test)]
pub fn reset_for_test() {
    MYARGS.lock().fill(0);
}
