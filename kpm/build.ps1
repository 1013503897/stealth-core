# Build a KernelPatch module (.kpm) on Windows using the NDK clang toolchain.
# KPMs are freestanding, position-dependent relocatable ELFs (ET_REL); KernelPatch
# resolves their relocations at load time. We target aarch64-none-elf (bare metal)
# and link with -r, mirroring the upstream gcc-based Makefile but using clang.
#
# Usage: build.ps1 [-Src shpoc.c]   (default: shpoc.c)
param([string]$Src = "shpoc.c")
$ErrorActionPreference = "Stop"

$ndk   = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.1.10909125"
$bin   = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin"
$clang = Join-Path $bin "clang.exe"
$readelf = Join-Path $bin "llvm-readelf.exe"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$kp   = (Resolve-Path (Join-Path $here "..\vendor\KernelPatch\kernel")).Path

# Same include set as the upstream kpm Makefile.
$incDirs = @(".", "include", "patch/include", "linux/include",
             "linux/arch/arm64/include", "linux/tools/arch/arm64/include")
$incFlags = $incDirs | ForEach-Object { "-I" + (Join-Path $kp ($_ -replace '/', '\')) }

$cflags = @(
    "--target=aarch64-none-elf",
    "-nostdinc",
    "-ffreestanding",
    "-fno-stack-protector",
    "-fno-pic",
    "-mgeneral-regs-only",
    "-mbranch-protection=bti",          # BTI landing pads: bp handler is called indirectly by kernel perf
    "-fno-asynchronous-unwind-tables",
    "-fno-unwind-tables",
    # NOTE: clang -O2 miscompiles for the KP module loader (runtime SP/PC fault).
    # -O0 is verified-good; do not raise without re-testing on device.
    "-O0", "-Wall", "-Wno-unused-parameter", "-Wno-unused-function"
)

$stem = [System.IO.Path]::GetFileNameWithoutExtension($Src)
$src = Join-Path $here $Src
$obj = Join-Path $here "$stem.o"
$kpm = Join-Path $here "$stem.kpm"

Write-Host "[*] clang: $clang"
Write-Host "[*] KP kernel headers: $kp"
Write-Host "[*] compiling shpoc.c ..."
& $clang @cflags @incFlags -c $src -o $obj
if ($LASTEXITCODE -ne 0) { throw "compile failed ($LASTEXITCODE)" }

Write-Host "[*] relocatable link -> shpoc.kpm ..."
& $clang "--target=aarch64-none-elf" "-nostdlib" "-r" $obj -o $kpm
if ($LASTEXITCODE -ne 0) { throw "link failed ($LASTEXITCODE)" }

Write-Host "[+] built: $kpm"
if (Test-Path $readelf) {
    Write-Host "[*] ELF type + kpm sections:"
    & $readelf -h $kpm | Select-String -Pattern "Type:|Machine:"
    & $readelf -S $kpm | Select-String -Pattern "\.kpm"
}
