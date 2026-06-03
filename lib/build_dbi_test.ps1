# Build the libdbi unit test as an Android arm64 binary (NDK clang).
# Run it on the device:  adb push lib/dbi_test /data/local/tmp/ ;
#   adb shell chmod 755 /data/local/tmp/dbi_test ; adb shell /data/local/tmp/dbi_test
$ErrorActionPreference = "Stop"
$ndk = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.1.10909125"
$clang = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = Join-Path $here "dbi_test"
& $clang "--target=aarch64-linux-android33" "-O2" "-Wall" (Join-Path $here "dbi.c") (Join-Path $here "dbi_test.c") -o $out
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }
Write-Host "[+] built: $out"
