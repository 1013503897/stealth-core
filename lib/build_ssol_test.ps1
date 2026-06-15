# Build the libssol unit test as an Android arm64 binary (NDK clang).
# Run it on the device:  adb push lib/ssol_test /data/local/tmp/ ;
#   adb shell chmod 755 /data/local/tmp/ssol_test ; adb shell /data/local/tmp/ssol_test
# -DSSOL_TEST makes ssol.c use the pt_regs shim (instead of <asm/ptrace.h>).
$ErrorActionPreference = "Stop"
$ndk = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.1.10909125"
$clang = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = Join-Path $here "ssol_test"
& $clang "--target=aarch64-linux-android33" "-O2" "-Wall" "-DSSOL_TEST" `
    (Join-Path $here "ssol.c") (Join-Path $here "ssol_test.c") -o $out
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }
Write-Host "[+] built: $out"
