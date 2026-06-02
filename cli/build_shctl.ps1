# Build the shctl KPM-control CLI as an Android arm64 executable using NDK clang.
$ErrorActionPreference = "Stop"

$ndk   = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.1.10909125"
$bin   = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin"
$clang = Join-Path $bin "clang.exe"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# shctl.c is self-contained (only bionic libc); no KernelPatch headers needed.
$src = Join-Path $here "shctl.c"
$out = Join-Path $here "shctl"

Write-Host "[*] building shctl (android arm64) ..."
& $clang "--target=aarch64-linux-android33" "-O2" "-Wall" "-Wno-unused-function" $src -o $out
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }
Write-Host "[+] built: $out"
