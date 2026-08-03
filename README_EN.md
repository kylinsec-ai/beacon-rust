# Cobalt Strike Beacon — Rust Implementation

> A Rust reimplementation of the Cobalt Strike Beacon, ported
> module-for-module from the C++ reference source.
>
> [中文版](README.md) | [Chinese Version](README.md)

## Introduction

A complete, module-for-module Rust port of the Cobalt Strike Beacon. It
keeps the original C2 wire protocols (HTTP/S, DNS, SMB, TCP pivot), the
crypto formats, and the command set, while rewriting the whole
implementation in memory-safe Rust and compiling to reflectively loadable
DLLs.

**Credits**: the C++ reference source comes from
[kyxiaxiang](https://github.com/kyxiaxiang) — thanks for making it
public. This port is faithful to the original protocols and structure;
all code is rewritten in Rust.

## Features

- **Full command surface**: injection (9 techniques), process/token
  manipulation, file & download, BOF/COFF loading, PowerShell, lateral
  movement (SMB/TCP links), pivot sessions, web server, argument
  spoofing, elevate/getsystem, etc.
- **Byte-compatible wire protocols**:
  - AES-128-CBC + truncated HMAC-SHA256 (IV `"abcdefghijklmnop"`, keys
    derived from SHA256(session_key) split 16/16)
  - RSA-1024 PKCS#1 v1.5 metadata encryption
  - Full Malleable C2 transform support (apply/recover)
  - DNS beacon (A/AAAA/TXT) and SMB/TCP frame formats byte-for-byte
- **Memory-safe implementation**: Win32 via `windows-sys` FFI, no hand
  written assembly; global state is consolidated in `state.rs`
  (atomics + locks).
- **Four-in-one artifacts**: same as `beacon.sln`, produces `beacon` /
  `dnsb` / `pivot` / `extc2` DLLs, each exporting `DllMain` and
  `ReflectiveLoader`.

## Workspace layout

```
rust/
├── Cargo.toml          # workspace manifest
├── CONTRACT.md         # cross-module API contracts (maintained during the port)
├── beacon-core/        # shared library: 56 modules, mirroring src/*.cpp
├── beacon/             # cdylib: standard HTTP beacon (beacon.cpp + DllMain)
├── dnsb/               # cdylib: DNS beacon (dnsb.cpp + DllMain)
├── pivot/              # cdylib: pivot beacon (beacon_pivot.cpp + DllMain)
└── extc2/              # cdylib: external C2 beacon (beacon_extc2.cpp + DllMain)
```

## Build

Requires a Windows toolchain with the MSVC linker and the Windows SDK
(verified on: MSVC 14.51 + Windows SDK 10.0.26100).

```sh
cd rust

# make the MSVC tools visible and point LIB at the SDK import libs
# (adjust paths to your installation)
export PATH="/d/Program Files/Microsoft Visual Studio/18/Community/VC/Tools/MSVC/<ver>/bin/Hostx64/x64:$PATH"
export LIB="D:/Program Files/Microsoft Visual Studio/18/Community/VC/Tools/MSVC/<ver>/lib/x64;D:/Windows Kits/10/Lib/<sdk>/um/x64;D:/Windows Kits/10/Lib/<sdk>/ucrt/x64"

cargo check --workspace   # type-check (no linker needed)
cargo build --workspace   # debug DLLs -> target/debug/{beacon,dnsb,pivot,extc2}.dll
cargo build --release     # optimized DLLs -> target/release/*.dll
```

## Verification

- `cargo check --workspace`: 0 errors, 0 warnings.
- All four DLLs link with MSVC and export `DllMain` + `ReflectiveLoader`
  (confirmed via `link.exe /dump /exports`).
- Crypto round-trips, encoder round-trips (netbios/xor/base64url),
  builder frame layout, and DNS wire format (htonl/ntohl byte order)
  verified with isolated test binaries.
- Coverage check: every `.cpp` in the four vcxproj ClCompile lists has a
  corresponding ported module.
- CI (GitHub Actions, windows-latest): `cargo check` / `cargo build` /
  `cargo test` all pass.

## Porting notes

- `datap` → `parse::DataP`; `formatp` → `bformat::FormatP`;
  `builder` → `build::Builder`
- callbacks `void(*)(char*, int, int)` → `Callback = fn(&[u8], i32, i32)`
- `HANDLE` is represented as `isize` at module boundaries (cast at FFI
  call sites)
- `src/*.c` (tcp.c, registry.c, kerberos.c, interfaces.c) is dead code —
  not compiled by any vcxproj, so not ported
- LibTomCrypt replaced by RustCrypto with identical wire format

## Roadmap

- [x] **LLVM/OLLVM integration** (done): `lld-link` linking verified; the
      OLLVM toolchain (Obfuscator-Rust, LLVM 21 + Rust 1.92) built via
      Docker, `tools/ollvm_build.sh` produces obfuscated DLLs in one
      shot (string encryption + instruction substitution + bogus control
      flow).
- [ ] **Out-of-the-box evasion**: package the built-in memory masking
      (gargle sleep mask), reflective loading, direct syscalls, and
      argument spoofing into toggleable feature sets, usable as-is
      without manual configuration.
- [ ] Test suite: regression tests for wire protocols, crypto, and
      command parsing.
- [ ] Non-Windows development verification (cross-compile + Wine
      integration tests).

## Disclaimer

This code is for educational and research purposes only, for
understanding C2 beacon internals and improving detection/defense
capabilities. The author assumes no responsibility for any misuse.

---

[中文版](README.md)
