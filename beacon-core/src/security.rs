//! 加密（security.cpp）——用 RustCrypto 取代 LibTomCrypt。
//! Crypto (security.cpp) — replaces LibTomCrypt with RustCrypto.
//!
//! 线格式（必须与 Cobalt Strike 保持字节兼容）：
//! Wire format (must stay byte-compatible with Cobalt Strike):
//!   * 会话密钥：16 个随机字节
//!   * session key: 16 random bytes
//!   * 派生密钥材料：SHA256(session_key) -> 32 字节
//!   * derived key material: SHA256(session_key) -> 32 bytes
//!       key[0..16]     = AES-128 密钥
//!       key[0..16]     = AES-128 key
//!       key[16..32]    = HMAC 密钥
//!       key[16..32]    = HMAC key
//!   * IV："abcdefghijklmnop"
//!   * IV: "abcdefghijklmnop"
//!   * 加密：AES-128-CBC，零填充到 16 字节倍数，然后追加密文的截断 HMAC-SHA256（16 字节）
//!   * encrypt: AES-128-CBC, zero-pad to 16-byte multiple, then append
//!     truncated HMAC-SHA256 (16 bytes) of the ciphertext
//!   * 解密：验证 HMAC、CBC 解密、检查计数器重放、提取 [counter:4][len:4][payload]
//!   * decrypt: verify HMAC, CBC decrypt, check counter replay, extract
//!     [counter:4][len:4][payload]
//!   * 元数据：RSA-1024 PKCS#1 v1.5 加密（sprng），密钥 = 162 字节 DER
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

/// 从 16 字节会话密钥初始化加密（security_init）。
/// Initialize crypto from a 16-byte session key (security_init).
pub fn security_init(k: &[u8]) {
    let mut hasher = Sha256::new();
    hasher.update(&k[..KEY_SIZE]);
    let key_bucket = hasher.finalize(); // 32 字节 / 32 bytes

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

/// 计算 `data` 的截断 HMAC-SHA256（16 字节）。
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

/// 就地解密 `ciphertext`；返回明文长度（不含 HMAC 与 8 字节加密头），失败时返回 0。
/// Decrypt `ciphertext` in place; returns the plaintext length (excluding the
/// HMAC and 8-byte crypto header) or 0 on failure.
pub fn security_decrypt(ciphertext: &mut [u8], length: usize) -> i32 {
    // 健全性检查
    // sanity check
    if length <= HMAC_SIZE {
        return 0;
    }
    // 另一项健全性检查
    // another sanity check
    if (length % 16) != 0 {
        return 0;
    }

    let mut st = crypto();

    // 针对密文计算 hmac
    // calculate hmac against ciphertext
    let hmac_calc = hmac_sha256_truncated(&st.hmac_key, &ciphertext[..length - HMAC_SIZE]);
    let hmac_sent = &ciphertext[length - HMAC_SIZE..length];
    if hmac_calc.as_slice() != hmac_sent {
        // 不是硬性失败
        // not a hard failure
        return 0;
    }

    // 截断以在无 HMAC 的情况下处理密文
    // truncate to work w/o the HMAC in the ciphertext
    let length = length - HMAC_SIZE;

    // 用 CBC 解密（手动链式，以便就地解密）
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
        // 手动 CBC：与上一个密文块异或
        // manual CBC: xor with previous ciphertext block
        for j in 0..16 {
            plaintext[i * 16 + j] = dec[j] ^ prev[j];
        }
        prev = block_in;
    }

    // 解析 [counter:4][len:4][payload]
    // parse [counter:4][len:4][payload]
    if length < 8 {
        return 0;
    }
    let counter = u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
    let len = u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);

    // 重放检查
    // replay check
    if (counter + TOLERANCE) <= st.lastcounter {
        crate::callback::post_crypt_replay_error(st.lastcounter - (counter + TOLERANCE));
        return 0;
    }

    if len <= 0 || len as usize > length {
        return 0;
    }

    let dptr = &plaintext[8..8 + len as usize];
    // 把载荷复制回 ciphertext 的前部
    // copy the payload back to the front of ciphertext
    ciphertext[..len as usize].copy_from_slice(dptr);

    // 为防止重放攻击，存储我们最后接收到的 counter 值
    // to prevent replay attacks, store our last recv'd counter value
    st.lastcounter = counter;

    len as i32
}

/// 就地加密 `ciphertext`；返回新长度（填充 + HMAC）。
/// Encrypt `ciphertext` in place; returns the new length (padded + HMAC).
pub fn security_encrypt(ciphertext: &mut [u8], length: usize) -> i32 {
    let st = crypto();

    let mut pad = length % 16;
    let mut length = length;
    while pad != 0 && pad < 16 {
        pad += 1;
        length += 1;
    }

    // 用 CBC 就地加密（手动链式，以便就地加密）
    // encrypt in place with CBC (manual chain so we encrypt in place)
    let blocks = length / 16;
    let mut prev = st.iv;
    for i in 0..blocks {
        let src = &ciphertext[i * 16..(i + 1) * 16];
        let mut block = [0u8; 16];
        block.copy_from_slice(src);
        // 与 prev 异或
        // xor with prev
        for j in 0..16 {
            block[j] ^= prev[j];
        }
        let mut mode = Aes128CbcEnc::new_from_slices(&st.key, &st.iv).expect("aes");
        mode.encrypt_block_mut((&mut block).into());
        ciphertext[i * 16..(i + 1) * 16].copy_from_slice(&block);
        prev = block;
    }

    // 为缓冲区计算 hmac
    // calculate hmac for the buffer
    let hmac = hmac_sha256_truncated(&st.hmac_key, &ciphertext[..length]);
    ciphertext[length..length + HMAC_SIZE].copy_from_slice(&hmac);

    // 将长度加上 HMAC_SIZE 以体现附加数据
    // add HMAC_SIZE to length to reflect additional data
    (length + HMAC_SIZE) as i32
}

/// 用 162 字节 DER 公钥 RSA 加密 `indata`（最大 117 字节）。`outdata` 必须是 128 字节。成功返回 CRYPT_OK (0)。
/// RSA-encrypt `indata` (max 117 bytes) with the 162-byte DER public key.
/// `outdata` must be 128 bytes. Returns CRYPT_OK (0) on success.
pub fn rsa_encrypt_once(
    kbuffer: &[u8],
    indata: &[u8],
    outdata: &mut [u8],
    outlen: &mut usize,
) -> i32 {
    // 导入我们的 RSA-1024 密钥（PKCS#1 DER）
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

/// (x^y) % p —— 模幂运算。
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

/// watermark 的紧凑表示。
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

/// 解码/验证 watermark 哈希。成功返回 0，失败返回 1。
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

    // base64 解码
    // base64 decode
    let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded_text) {
        Ok(d) if d.len() == 16 => d,
        _ => return 1,
    };

    // 用 key=wmKeyBytes、iv="abcdefghijklmnop" 进行 AES-128-CBC 解密
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
