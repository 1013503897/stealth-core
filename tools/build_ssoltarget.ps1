# Build the SSOL P1 self-test target as an Android arm64 binary (NDK clang).
# Run on device:  adb push tools/ssoltarget /data/local/tmp/ ;
#   adb shell chmod 755 /data/local/tmp/ssoltarget ; adb shell /data/local/tmp/ssoltarget
$ErrorActionPreference = "Stop"
$ndk = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.1.10909125"
$clang = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = Join-Path $here "ssoltarget"
& $clang "--target=aarch64-linux-android33" "-O2" "-Wall" (Join-Path $here "ssoltarget.c") -o $out
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }
Write-Host "[+] built: $out"
