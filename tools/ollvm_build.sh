#!/bin/sh
# =============================================================================
# OLLVM 混淆构建脚本 / OLLVM obfuscated build script
#
# 使用 Obfuscator-Rust（LLVM 21 + Rust 1.92 OLLVM fork）对 Beacon 进行
# 混淆编译，产出 x86_64-pc-windows-gnu 目标 DLL。
# Uses the Obfuscator-Rust (LLVM 21 + Rust 1.92 OLLVM fork) toolchain to
# build obfuscated x86_64-pc-windows-gnu DLLs.
#
# 前置条件 / Prerequisites:
#   - WSL 内 Docker + 已构建 ollvm-rustc 镜像
#     Docker in WSL with the ollvm-rustc image built (see Dockerfile in
#     the Obfuscator-Rust repo; build via `docker build -t ollvm-rustc .`)
#   - 本机 Windows SDK 无需 —— 交叉目标由 mingw-w64 提供
#     No local Windows SDK needed — mingw-w64 provides the cross target.
#
# 用法 / Usage:
#   wsl -e bash tools/ollvm_build.sh
# =============================================================================
set -e

# 项目根（脚本所在目录的上一级）/ Project root (parent of script dir)
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${OLLVM_IMAGE:-ollvm-rustc:latest}"
ARTIFACTS="${OLLVM_ARTIFACTS:-/tmp/ollvm-artifacts}"
# 混淆 pass / Obfuscation passes (逐个启用，避免 -enable-allobf 的 OOM)
PASSES="${OLLVM_PASSES:--enable-strcry -enable-subobf -enable-bcfobf}"
JOBS="${OLLVM_JOBS:-2}"
CRATES="${OLLVM_CRATES:-beacon dnsb pivot extc2}"

mkdir -p "$ARTIFACTS"

cat > /tmp/ollvm_build_inner.sh <<INNER
#!/bin/sh
set -e
export PATH=/opt/rust/bin:\$PATH
export CARGO_HOME=/tmp/ch CARGO_TARGET_DIR=/out/target
mkdir -p /tmp/cfg && cat > /tmp/cfg/config.toml <<CFGEOF
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
CFGEOF
cd /project

echo "[ollvm] un-obfuscated baseline (workspace) / 未混淆基线"
cargo build --target x86_64-pc-windows-gnu --release --config /tmp/cfg/config.toml --jobs $JOBS

for crate in $CRATES; do
  echo "[ollvm] obfuscating \$crate / 混淆编译 \$crate"
  cargo rustc --target x86_64-pc-windows-gnu --release --config /tmp/cfg/config.toml -p \$crate --jobs 1 -- \
    -Ccodegen-units=1 -Cdebuginfo=0 -Copt-level=3 -Cllvm-args=$PASSES
done
echo "[ollvm] done / 完成"
INNER
chmod +x /tmp/ollvm_build_inner.sh

echo "[ollvm] mounting $PROJECT_ROOT -> /project"
docker run --rm \
  -v "$PROJECT_ROOT:/project" \
  -v "$ARTIFACTS:/out" \
  -v /tmp/ollvm_build_inner.sh:/build.sh \
  "$IMAGE" /build.sh

echo "[ollvm] artifacts / 产物: $ARTIFACTS/target/x86_64-pc-windows-gnu/release/*.dll"
ls -la "$ARTIFACTS/target/x86_64-pc-windows-gnu/release/"*.dll 2>/dev/null || true
