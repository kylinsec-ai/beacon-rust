# Cobalt Strike Beacon — Rust 实现

> 用 Rust 重新实现 Cobalt Strike Beacon，逐模块移植自 C++ 参考源码。

本仓库是一份完整的、模块对模块的 Rust 移植：保留原 Beacon 的 C2
通信协议（HTTP/S、DNS、SMB、TCP pivot）、加密格式与命令体系，同时
以内存安全的 Rust 重写全部实现，可编译为反射加载的 DLL。

**鸣谢**：C++ 参考源码来自 [kyxiaxiang](https://github.com/kyxiaxiang)，
感谢其公开分享。本移植在协议与结构上忠实于原作，代码全部为 Rust 重写。

---

## 目录

- [特性](#特性)
- [Workspace 结构](#workspace-结构)
- [构建](#构建)
- [验证](#验证)
- [移植说明](#移植说明)
- [路线图](#路线图)
- [免责声明](#免责声明)

---

## 特性

- **完整命令面**：注入（9 种技术）、进程/令牌操作、文件与下载、
  BOF/COFF 加载、PowerShell、横向移动（SMB/TCP link）、pivot
  会话、web server、argue（参数欺骗）、elevate/getsystem 等。
- **字节级兼容的线协议**：
  - AES-128-CBC + 截断 HMAC-SHA256（IV `"abcdefghijklmnop"`，
    密钥由 SHA256(session_key) 分 16/16 派生）
  - RSA-1024 PKCS#1 v1.5 元数据加密
  - Malleable C2 transform（apply/recover）完整实现
  - DNS beacon（A/AAAA/TXT 记录）与 SMB/TCP 帧格式逐字节一致
- **内存安全实现**：以 `windows-sys` FFI 调用 Win32，无手写汇编；
  全局状态收敛于 `state.rs`（原子量 + 锁）。
- **四合一产物**：与 `beacon.sln` 相同，产出 `beacon` / `dnsb` /
  `pivot` / `extc2` 四个 DLL，均导出 `DllMain` 与 `ReflectiveLoader`。

## Workspace 结构

```
rust/
├── Cargo.toml          # workspace 清单
├── CONTRACT.md         # 跨模块 API 契约（移植期间维护）
├── beacon-core/        # 共享库：56 个模块，对应 src/*.cpp
├── beacon/             # cdylib：标准 HTTP beacon（beacon.cpp + DllMain）
├── dnsb/               # cdylib：DNS beacon（dnsb.cpp + DllMain）
├── pivot/              # cdylib：pivot beacon（beacon_pivot.cpp + DllMain）
└── extc2/              # cdylib：外部 C2 beacon（beacon_extc2.cpp + DllMain）
```

## 构建

需要带 MSVC 链接器与 Windows SDK 的 Windows 工具链
（验证环境：MSVC 14.51 + Windows SDK 10.0.26100）。

```sh
cd rust

# 让 MSVC 工具可见，并将 LIB 指向 SDK 导入库（按实际路径调整）
export PATH="/d/Program Files/Microsoft Visual Studio/18/Community/VC/Tools/MSVC/<ver>/bin/Hostx64/x64:$PATH"
export LIB="D:/Program Files/Microsoft Visual Studio/18/Community/VC/Tools/MSVC/<ver>/lib/x64;D:/Windows Kits/10/Lib/<sdk>/um/x64;D:/Windows Kits/10/Lib/<sdk>/ucrt/x64"

cargo check --workspace   # 类型检查（无需链接器）
cargo build --workspace   # debug DLL -> target/debug/{beacon,dnsb,pivot,extc2}.dll
cargo build --release     # 优化 DLL -> target/release/*.dll
```

## 验证

- `cargo check --workspace`：0 错误 0 警告。
- 四个 DLL 均以 MSVC 链接成功，导出 `DllMain` + `ReflectiveLoader`
  （`link.exe /dump /exports` 确认）。
- 加密往返、编码器（netbios/xor/base64url）往返、builder 帧布局、
  DNS 线格式（`htonl`/`ntohl` 字节序）均经独立测试验证。
- 覆盖核对：四个 vcxproj 的每个 `.cpp` 均有对应移植模块。

## 移植说明

- `datap` → `parse::DataP`；`formatp` → `bformat::FormatP`；
  `builder` → `build::Builder`
- 回调 `void(*)(char*, int, int)` → `Callback = fn(&[u8], i32, i32)`
- `HANDLE` 在模块边界以 `isize` 表示（FFI 调用处强转）
- `src/*.c`（tcp.c、registry.c、kerberos.c、interfaces.c）为死代码，
  未被任何 vcxproj 编译，故未移植
- 加密库由 LibTomCrypt 替换为 RustCrypto，线格式保持一致

## 路线图

- [ ] **LLVM 集成**：引入基于 LLVM 的工具链/变换（如控制流平坦化、
      指令替换、字符串/常量加密等），为生成物提供更强的静态规避
      能力；同时评估以 `lld-link` 替代 MSVC 链接的可行性。
- [ ] **开箱即用的规避能力**：将目前内建的内存掩码（gargle sleep
      mask）、反射加载、syscall 直调、参数欺骗等能力整理为可开关的
      特性组合，开箱即得，无需手工配置。
- [ ] 测试套件：为线协议、加密与命令解析建立可回归的单元测试。
- [ ] 支持在非 Windows 环境（交叉编译 + Wine 集成测试）下开发验证。

## 免责声明

本代码仅用于教育和研究目的，用于理解 C2 信标的工作原理与提升
检测/防御能力。作者对任何滥用行为不承担责任。
