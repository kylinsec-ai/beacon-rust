//! File recursion (recurse.cpp).

use windows_sys::Win32::Storage::FileSystem::{
    FindClose, FindFirstFileA, FindNextFileA, WIN32_FIND_DATAA, FILE_ATTRIBUTE_DIRECTORY,
};

/// File recursion callback (RCALLBACK).
pub type RCallback = fn(&[u8], &[u8], bool);

fn walk_parent(parent: &[u8], callback: RCallback) {
    unsafe {
        let mut pattern = parent.to_vec();
        if pattern.last() != Some(&b'\\') {
            pattern.push(b'\\');
        }
        pattern.extend_from_slice(b"*");
        pattern.push(0);

        let mut ffd: WIN32_FIND_DATAA = std::mem::zeroed();
        let h = FindFirstFileA(pattern.as_ptr() as *const _, &mut ffd);
        if h == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return;
        }

        loop {
            let name_bytes = ffd.cFileName;
            let mut name_len = 0usize;
            while name_len < name_bytes.len() && name_bytes[name_len] != 0 {
                name_len += 1;
            }
            let name: &[u8] = std::slice::from_raw_parts(name_bytes.as_ptr() as *const u8, name_len);

            // skip . and ..
            if name == b"." || name == b".." {
                // continue
            } else {
                let is_dir = (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                    == FILE_ATTRIBUTE_DIRECTORY;
                callback(parent, name, is_dir);
            }

            if FindNextFileA(h, &mut ffd) == 0 {
                break;
            }
        }

        FindClose(h);
    }
}

/// Recurse through a directory (recurse).
pub fn recurse(start: &[u8], callback: RCallback) {
    walk_parent(start, callback);
}
