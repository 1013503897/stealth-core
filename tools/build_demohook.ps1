# Build demohook (Android arm64) -- the smallest end-to-end example of the
# traceless inline-hook API (lib/kpmhook over the no-superkey bridge).
# Links lib/dbi.c + lib/kpmhook.c + tools/demohook.c.
# -fno-stack-protector keeps the target function clean for the DBI recompiler
# (matches the device-verified kpmhooktool/pgtool build).
$ErrorActionPreference = "Stop"
$ndk = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.1.10909125"
$clang = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$out = Join-Path $here "demohook"

& $clang "--target=aarch64-linux-android33" "-O2" "-Wall" "-fno-stack-protector" `
    (Join-Path $root "lib\dbi.c") (Join-Path $root "lib\kpmhook.c") (Join-Path $here "demohook.c") `
    "-llog" -o $out
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }
Write-Host "[+] built: $out"
