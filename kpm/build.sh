#!/usr/bin/env bash
# Build a KernelPatch module (.kpm) on macOS/Linux using the NDK clang toolchain.
# KPMs are freestanding, position-dependent relocatable ELFs (ET_REL); KernelPatch
# resolves their relocations at load time. We target aarch64-none-elf (bare metal)
# and link with -r, mirroring the upstream gcc-based Makefile but using clang.
#
# Usage: build.sh [-s shpoc.c] [-l]   (default: shpoc.c, product build)
#   -l  define SHPTE_POC_LADDER to re-include the P2..P5 regression ladder for the
#       tools/run_*.sh harnesses. The DEFAULT (product) build OMITS the ladder.
set -euo pipefail
SRC="shpoc.c"; LADDER=0
while getopts "s:l" o; do case "$o" in s) SRC="$OPTARG";; l) LADDER=1;; esac; done

# NDK: honour ANDROID_NDK_HOME (set by CI) and fall back to the local dev default.
NDK="${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/26.1.10909125}"
HOSTTAG="$(ls -d "$NDK"/toolchains/llvm/prebuilt/*/ 2>/dev/null | head -1)"
BIN="${HOSTTAG%/}/bin"
CLANG="$BIN/clang"; READELF="$BIN/llvm-readelf"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KP="$(cd "$HERE/../vendor/KernelPatch/kernel" && pwd)"

# Same include set as the upstream kpm Makefile.
INC=(. include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include)
INCFLAGS=(); for d in "${INC[@]}"; do INCFLAGS+=("-I$KP/$d"); done

CFLAGS=(
  --target=aarch64-none-elf -nostdinc -ffreestanding -fno-stack-protector
  -fno-pic -mgeneral-regs-only -mbranch-protection=bti
  -fno-asynchronous-unwind-tables -fno-unwind-tables
  # NOTE: clang -O2 miscompiles for the KP module loader (runtime SP/PC fault).
  # -O0 is verified-good; do not raise without re-testing on device.
  -O0 -Wall -Wno-unused-parameter -Wno-unused-function
)
[ "$LADDER" = 1 ] && CFLAGS+=(-DSHPTE_POC_LADDER)

STEM="${SRC%.c}"; OBJ="$HERE/$STEM.o"; KPM="$HERE/$STEM.kpm"
echo "[*] clang: $CLANG"
echo "[*] KP kernel headers: $KP"
echo "[*] compiling $SRC ..."
"$CLANG" "${CFLAGS[@]}" "${INCFLAGS[@]}" -c "$HERE/$SRC" -o "$OBJ"
echo "[*] relocatable link -> $STEM.kpm ..."
"$CLANG" --target=aarch64-none-elf -nostdlib -r "$OBJ" -o "$KPM"
echo "[+] built: $KPM"
if [ -x "$READELF" ]; then "$READELF" -h "$KPM" | grep -E "Type:|Machine:"; "$READELF" -S "$KPM" | grep "\.kpm" || true; fi
