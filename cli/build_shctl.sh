#!/usr/bin/env bash
# Build the shctl KPM-control CLI as an Android arm64 executable using NDK clang.
set -euo pipefail
NDK="${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/26.1.10909125}"
HOSTTAG="$(ls -d "$NDK"/toolchains/llvm/prebuilt/*/ 2>/dev/null | head -1)"
CLANG="${HOSTTAG%/}/bin/clang"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[*] building shctl (android arm64) ..."
"$CLANG" --target=aarch64-linux-android33 -O2 -Wall -Wno-unused-function "$HERE/shctl.c" -o "$HERE/shctl"
echo "[+] built: $HERE/shctl"
