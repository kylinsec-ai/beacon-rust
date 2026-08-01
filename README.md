# Beacon Rust Port

Rust port of the Cobalt Strike Beacon C++ source in this repository.
The C++ sources in `../src/` are the reference implementation; this
workspace ports them module-for-module into idiomatic Rust.

## Workspace layout

```
rust/
├── Cargo.toml          # workspace manifest
├── CONTRACT.md         # cross-module API contracts (for the port)
├── beacon-core/        # shared library: every module ported from src/*.cpp
├── beacon/             # cdylib: standard HTTP beacon (beacon.cpp + DllMain)
├── dnsb/               # cdylib: DNS beacon (dnsb.cpp + DllMain)
├── pivot/              # cdylib: pivot beacon (beacon_pivot.cpp + DllMain)
└── extc2/              # cdylib: external C2 beacon (beacon_extc2.cpp + DllMain)
```

The four DLL projects from `beacon.sln` share ~85 source files; the port
mirrors that: `beacon-core` holds the shared implementation, each entry
crate provides the `DllMain` + `beacon()` loop + `ReflectiveLoader` sled.

## Dependencies / decisions

- **Crypto**: LibTomCrypt is replaced by RustCrypto (`aes`, `cbc`, `sha2`,
  `hmac`, `rsa`, `base64`, `getrandom`, `rand`). The wire format is
  byte-identical: AES-128-CBC with IV `"abcdefghijklmnop"`, keys derived as
  SHA256(session_key) split 16/16, truncated HMAC-SHA256 (16 bytes),
  RSA-1024 PKCS#1 v1.5 for metadata, zero-pad to 16-byte blocks.
- **Win32**: `windows-sys` FFI (raw bindings, no runtime).
- **State**: C++ process globals (`sleep_time`, `jitter`, `agentid`,
  `bigsession`, `post_type`, `http_post_len`, `atoken`, ...) live in
  `beacon-core::state` guarded by atomics/`parking_lot::Mutex`.
- **Settings**: `settings_init` parses the patched `myargs` config blob
  exactly like the C++ (XOR 0x2E unmask, `[index][type][length][value]*`).
  A real deployment patches the blob into the DLL image; `seed_myargs`
  exists for tooling/tests.
- **Reflective loader**: `ReflectiveLoader.5k` is a compiler-generated
  INT3/NOP sled (`__debugbreak(); __nop()*7;` per line, 5120 bytes) that the
  UDRL overwrites; each entry crate reproduces it as a static byte array.

## Build

Requires a Windows toolchain with the MSVC linker and the Windows SDK
(the machine this port was verified on: MSVC 14.51 + Windows SDK
10.0.26100).

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

Each DLL exports `DllMain` and `ReflectiveLoader` (verified with
`link.exe /dump /exports`).

## Verification status

- `cargo check --workspace`: **passes with 0 errors, 0 warnings**.
- `cargo build --workspace` / `--release` with the MSVC linker: all four
  DLLs link successfully and export `DllMain` + `ReflectiveLoader`.
- Crypto round-trip (AES-128-CBC + truncated HMAC-SHA256) verified in an
  isolated test binary: encrypt→decrypt recovers the payload, tampered
  ciphertext fails the HMAC check, padding layout matches the C++
  (16-byte blocks + 16-byte HMAC).
- Encoder round trips (netbios, xor, base64url) verified.
- Builder frame layout verified against `build.cpp`
  (`[nonce:4][len:4][type][data]`, `build_length = b->len + 4`).
- DNS wire format verified byte-for-byte: `dns_put` uses
  `htonl(dataz[i])` semantics (BE-read of raw bytes), `dns_get` uses
  `ntohl`/host-memory copy parity, `dnsb` signal decode matches.
- Module coverage: every `.cpp` in the four vcxproj ClCompile lists is
  ported. `execute/spawn/process_block/process_ppid/ppidfriends` merge
  into `process.rs`; `ReflectiveDll`/`ReflectiveLoader` live in the entry
  crates; the four entries are separate crates. The `.c` files are dead
  code (not compiled by any project) and not ported.

## Porting notes

- `datap` → `beacon_core::parse::DataP` (cursor over `&mut [u8]`)
- `formatp` → `beacon_core::bformat::FormatP`
- `builder` → `beacon_core::build::Builder` (nonce/len header)
- callbacks `void(*)(char*, int, int)` → `Callback = fn(&[u8], i32, i32)`
- `HANDLE` → `isize` at module boundaries (cast at FFI call sites)
- `track_memory_add` mirrors the C++ tracker (masked heap records are
  consumed by `GargleSleep`)
- The `.c` files in `../src` (`tcp.c`, `registry.c`, `kerberos.c`,
  `interfaces.c`) are not compiled by any vcxproj (dead code) and are not
  ported.
