//! Beacon main definitions (beacon.h constants) and shared utilities that
//! lived in commands.cpp (bigger_rand, genagentid).

/// Protocol flags.
pub const BEACON_PROTO_HTTP: u16 = 0x00;
pub const BEACON_PROTO_DNS: u16 = 0x01;
pub const BEACON_PROTO_SMB: u16 = 0x02;
pub const BEACON_PROTO_TCP_REVERSE: u16 = 0x04;
pub const BEACON_PROTO_HTTPS: u16 = 0x08;
pub const BEACON_PROTO_TCP_BIND: u16 = 0x10;

/// Setting constants.
pub const SETTING_PROTOCOL: usize = 1;
pub const SETTING_PORT: usize = 2;
pub const SETTING_SLEEPTIME: usize = 3;
pub const SETTING_MAXGET: usize = 4;
pub const SETTING_JITTER: usize = 5;
pub const SETTING_MAXDNS: usize = 6;
pub const SETTING_PUBKEY: usize = 7;
pub const SETTING_DOMAINS: usize = 8;
pub const SETTING_USERAGENT: usize = 9;
pub const SETTING_SUBMITURI: usize = 10;
pub const SETTING_C2_RECOVER: usize = 11;
pub const SETTING_C2_REQUEST: usize = 12;
pub const SETTING_C2_POSTREQ: usize = 13;
pub const DEPRECATED_SETTING_SPAWNTO: usize = 14;
pub const SETTING_PIPENAME: usize = 15;
pub const DEPRECATED_SETTING_KILLDATE_YEAR: usize = 16;
pub const DEPRECATED_SETTING_KILLDATE_MONTH: usize = 17;
pub const DEPRECATED_SETTING_KILLDATE_DAY: usize = 18;
pub const SETTING_DNS_IDLE: usize = 19;
pub const SETTING_DNS_SLEEP: usize = 20;
pub const SETTING_C2_VERB_GET: usize = 26;
pub const SETTING_C2_VERB_POST: usize = 27;
pub const SETTING_C2_CHUNK_POST: usize = 28;
pub const SETTING_SPAWNTO_X86: usize = 29;
pub const SETTING_SPAWNTO_X64: usize = 30;
pub const SETTING_CRYPTO_SCHEME: usize = 31;
pub const SETTING_PROXY_CONFIG: usize = 32;
pub const SETTING_PROXY_USER: usize = 33;
pub const SETTING_PROXY_PASSWORD: usize = 34;
pub const SETTING_PROXY_BEHAVIOR: usize = 35;
pub const SETTING_WATERMARK_HASH: usize = 36;
pub const SETTING_WATERMARK: usize = 37;
pub const SETTING_CLEANUP: usize = 38;
pub const SETTING_CFG_CAUTION: usize = 39;
pub const SETTING_KILLDATE: usize = 40;
pub const SETTING_GARGLE_NOOK: usize = 41;
pub const SETTING_GARGLE_SECTIONS: usize = 42;
pub const SETTING_PROCINJ_PERMS_I: usize = 43;
pub const SETTING_PROCINJ_PERMS: usize = 44;
pub const SETTING_PROCINJ_MINALLOC: usize = 45;
pub const SETTING_PROCINJ_TRANSFORM_X86: usize = 46;
pub const SETTING_PROCINJ_TRANSFORM_X64: usize = 47;
pub const DEPRECATED_SETTING_PROCINJ_ALLOWED: usize = 48;
pub const SETTING_BINDHOST: usize = 49;
pub const SETTING_HTTP_NO_COOKIES: usize = 50;
pub const SETTING_PROCINJ_EXECUTE: usize = 51;
pub const SETTING_PROCINJ_ALLOCATOR: usize = 52;
pub const SETTING_PROCINJ_STUB: usize = 53;
pub const SETTING_HOST_HEADER: usize = 54;
pub const SETTING_EXIT_FUNK: usize = 55;
pub const SETTING_SSH_BANNER: usize = 56;
pub const SETTING_SMB_FRAME_HEADER: usize = 57;
pub const SETTING_TCP_FRAME_HEADER: usize = 58;
pub const SETTING_HEADERS_REMOVE: usize = 59;
pub const SETTING_DNS_BEACON_BEACON: usize = 60;
pub const SETTING_DNS_BEACON_GET_A: usize = 61;
pub const SETTING_DNS_BEACON_GET_AAAA: usize = 62;
pub const SETTING_DNS_BEACON_GET_TXT: usize = 63;
pub const SETTING_DNS_BEACON_PUT_METADATA: usize = 64;
pub const SETTING_DNS_BEACON_PUT_OUTPUT: usize = 65;
pub const SETTING_DNSRESOLVER: usize = 66;
pub const SETTING_DOMAIN_STRATEGY: usize = 67;
pub const SETTING_DOMAIN_STRATEGY_SECONDS: usize = 68;
pub const SETTING_DOMAIN_STRATEGY_FAIL_X: usize = 69;
pub const SETTING_DOMAIN_STRATEGY_FAIL_SECONDS: usize = 70;
pub const SETTING_MAX_RETRY_STRATEGY_ATTEMPTS: usize = 71;
pub const SETTING_MAX_RETRY_STRATEGY_INCREASE: usize = 72;
pub const SETTING_MAX_RETRY_STRATEGY_DURATION: usize = 73;

/// Exit funks.
pub const EXIT_FUNK_PROCESS: u16 = 0;
pub const EXIT_FUNK_THREAD: u16 = 1;

/// Host strategies.
pub const HOST_STRATEGY_ROUND_ROBIN: i32 = 0;
pub const HOST_STRATEGY_RANDOM: i32 = 1;
pub const HOST_STRATEGY_EVENT: i32 = 2;

/// Generate an agent id (`genagentid` in the C++ entries; DNS beacon ORs
/// 1202 into the value).
pub fn genagentid() -> u32 {
    let result = bigger_rand() & 0x7FFF_FFFF & !1;
    if crate::state::DNS_BEACON.load(std::sync::atomic::Ordering::SeqCst) {
        result | 1202
    } else {
        result
    }
}

/// Secure random (bigger_rand, from tomcrypt rng_get_bytes).
pub fn bigger_rand() -> u32 {
    let mut buf = [0u8; 4];
    let _ = getrandom::fill(&mut buf);
    u32::from_le_bytes(buf)
}
