# Build kpmhooktool (Android arm64) -- the in-process agent that drives the KPM
# multi-page pghook table via lib/kpmhook over the syscall bridge.
# Links lib/dbi.c + lib/kpmhook.c + tools/kpmhooktool.c.
# -fno-stack-protector keeps the victim functions clean for the DBI recompiler
# (matches the device-verified pgtool/hwhooktool build).
$ErrorActionPreference = "Stop"
$ndk = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.1.10909125"
$clang = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$out = Join-Path $here "kpmhooktool"

& $clang "--target=aarch64-linux-android33" "-O2" "-Wall" "-fno-stack-protector" `
    (Join-Path $root "lib\dbi.c") (Join-Path $root "lib\kpmhook.c") (Join-Path $here "kpmhooktool.c") `
    "-llog" -o $out
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }
Write-Host "[+] built: $out"
