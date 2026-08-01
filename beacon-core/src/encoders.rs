//! Encoders (encoders.cpp) — netbios, base64url, xor.
//!
//! Compatible with LibTomCrypt's base64 signatures: the base64 transforms
//! here use the same wire encoding.

use crate::beacon::bigger_rand;
use base64::Engine;

/// NetBIOS-encode `src` into `dst` with a base offset (`'a'` or `'A'`).
/// Returns the number of bytes written.
pub fn netbios_encode(base: u8, src: &[u8], dst: &mut [u8], maxlength: usize) -> usize {
    let mut y = 0usize;
    let mut x = 0usize;
    while x < src.len() && y < maxlength {
        let hi = (src[x] & 0x0000_00F0) >> 4;
        let low = src[x] & 0x0000_000F;
        dst[y] = hi + base;
        dst[y + 1] = low + base;
        x += 1;
        y += 2;
    }
    y
}

/// NetBIOS-decode `src` into `dst`. Returns the number of bytes written.
pub fn netbios_decode(base: u8, src: &[u8], dst: &mut [u8], maxlength: usize) -> usize {
    // NetBIOS encoded text should *always* be even length
    if (src.len() % 2) == 1 {
        return 0;
    }
    let mut i = 0usize;
    while i < src.len() && (i / 2) < maxlength {
        let hi = src[i] as i8;
        let low = src[i + 1] as i8;
        let me = ((hi - base as i8) << 4) as u8;
        let me = me.wrapping_add((low - base as i8) as u8);
        dst[i / 2] = me;
        i += 2;
    }
    src.len() / 2
}

/// Base64url-encode (RFC 4648 URL-safe, no padding).
pub fn base64url_encode(inp: &[u8], out: &mut [u8]) -> usize {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let encoded = engine.encode(inp);
    let n = encoded.len().min(out.len());
    out[..n].copy_from_slice(&encoded.as_bytes()[..n]);
    n
}

/// Base64url-decode. `max` bounds the decoded length. Returns the decoded
/// length or 0 on failure.
pub fn base64url_decode(inp: &[u8], max: usize, out: &mut [u8]) -> usize {
    // transform URL-safe back to standard base64
    let mut work = inp.to_vec();
    for b in work.iter_mut() {
        if *b == b'_' {
            *b = b'/';
        } else if *b == b'-' {
            *b = b'+';
        }
    }
    // restore padding
    while (work.len() % 4) != 0 {
        if work.len() > max {
            return 0;
        }
        work.push(b'=');
    }

    let engine = base64::engine::general_purpose::STANDARD;
    match engine.decode(&work) {
        Ok(decoded) => {
            let n = decoded.len().min(out.len());
            out[..n].copy_from_slice(&decoded[..n]);
            n
        }
        Err(_) => 0,
    }
}

/// XOR-encode: prepend a 4-byte random nonce (the key), then XOR the data
/// with the nonce bytes cyclically. Returns the encoded length.
pub fn xor_encode(src: &[u8], dst: &mut [u8], maxlength: usize) -> usize {
    // check if maxlength is safe
    if (src.len() + 4) > maxlength {
        return 0;
    }
    let nonce = bigger_rand();
    let key = nonce.to_le_bytes();
    dst[..4].copy_from_slice(&key);

    for (x, b) in src.iter().enumerate() {
        dst[4 + x] = *b ^ key[x % 4];
    }
    src.len() + 4
}

/// XOR-decode: read the 4-byte key from the front, then undo the XOR.
pub fn xor_decode(src: &[u8], dst: &mut [u8], maxlength: usize) -> usize {
    if src.len() < 4 {
        return 0;
    }
    // sanity check on the length
    if (src.len() - 4) > maxlength {
        return 0;
    }
    let key = &src[..4];
    let length = src.len() - 4;
    for x in 0..length {
        dst[x] = src[4 + x] ^ key[x % 4];
    }
    length
}
