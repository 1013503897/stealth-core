# Build s0probe (Android arm64) -- the S0 read-only exposure probe. Self-hooks one
# victim via lib/kpmhook over the no-superkey bridge, then proves the DBI clone is
# hidden-from-maps but readable+executable+present. Links lib/dbi.c + lib/kpmhook.c.
# -fno-stack-protector keeps the victim clean for the DBI recompiler (matches
# build_kpmhooktool.ps1, the device-verified build).
$ErrorActionPreference = "Stop"
$ndk = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.1.10909125"
$clang = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$out = Join-Path $here "s0probe"

& $clang "--target=aarch64-linux-android33" "-O2" "-Wall" "-fno-stack-protector" `
    (Join-Path $root "lib\dbi.c") (Join-Path $root "lib\kpmhook.c") (Join-Path $here "s0probe.c") `
    "-llog" -o $out
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }
Write-Host "[+] built: $out"
