# stealth-poc

**English** | [中文](#中文说明)

Clean-room PoC for kernel-level **traceless hooking** on Android (ARM64), built on
APatch / KernelPatch (KPM). Goal: intercept a target's execution **without modifying
any of its memory** (no `.text` patch, no injected SO, no anonymous executable maps),
so it survives CRC / maps-scan style anti-tamper checks.

**Related project:** this repo is the kernel + userspace-glue **source** of the KPM traceless-hook
backend used by [**Vector**](https://github.com/1013503897/Vector) — our fork of JingMatrix's Zygisk
ART-hook framework. Vector vendors `lib/kpmhook` + `lib/dbi` from here and routes its `HookInline`
through `kpm_inline_hooker` (KPM traceless) first, falling back to Dobby when the KPM bridge is
unarmed. See the **L1b/L1d/L1e** status rows and the *Productization* section below.

Reference (concepts only): the kanxue article *Android 内核无痕 Hook 理解和感悟* and
the public `xiaojianbang-stealth-hook` repo. **No third-party code is copied** — this
is implemented against the KernelPatch kpm SDK API and the stable Linux/ARM ABIs.

## Status

| Phase | What | State |
|---|---|---|
| **P0** | KPM toolchain + syscall-hook smoke test (`shpoc`) | ✅ verified on device |
| **P1** | ARM64 hardware breakpoint hook + register capture (`shhwbp`) | ✅ verified |
| **P1.5** | Single-breakpoint **entry↔return state machine** (kills the re-trigger livelock; captures args + return value; target runs transparently) | ✅ verified |
| **P1.6** | Multi-thread following — per-thread bp table, all **existing** threads (each runs its own state machine, captures its own args) | ✅ verified |
| **P1.6b** | Follow threads created **after** the hook (`wake_up_new_task`) + slot **GC on thread exit** (`do_exit`); table stays bounded under create/exit churn | ✅ verified |
| **P2.0** | Page-table walk: read + decode any process's leaf PTE (`get_task_mm` + `apply_to_existing_page_range`) — read-only foundation for UXN (`shpte`) | ✅ verified |
| **P2.1** | UXN flip on the target code page + `do_page_fault` interception with **self-healing** resume (validates the page-table-write + fault-hook + safe-EL0-resume machinery) | ✅ verified |
| **P2.2** | **Single-function no-trace redirect**: keep UXN set, reroute the faulting PC to a verbatim **clone** of a page-isolated, PC-relative-free function (`.text` untouched, no new exec VMA at the func) | ✅ verified |
| **P3.1** | `offset_map` routing in `do_page_fault` (clone insn idx per orig insn); map read cross-process via `access_process_vm` | ✅ verified |
| **P3.2** | Userspace DBI recompiler: `ADR`/`ADRP`/`B`/`BL` → absolute (LDR-literal / `BR`/`BLR` x16), builds the offset_map; clone of a PC-relative `hook_me()` runs correctly | ✅ verified |
| **P3.3** | DBI: conditional + internal branches (`B.cond`/`CBZ`/`TBZ`, clone-relative re-encode) → functions with loops/branches | ✅ verified |
| **P3.4** | DBI: `LDR`-literal (re-point the load to a clone-local copy of the value) | ✅ verified |
| **P3.5** | DBI: `BLRAAZ`/`BRAAZ` PAC-call demote (article §5.7); stock NDK doesn't emit it, PAC-ret `paciasp`/`retaa` are PC-independent and pass through verbatim | ⬜ todo |
| **P4.1** | `/proc/*/maps` hide: hook `show_map`, drop the clone's entry from the `seq_file` output (article §5.8) — beats CRC scan **and** maps scan together | ✅ verified |
| **P4.2** | VMA-less **ghost memory**: inject a PTE for the clone with **no VMA** (`vmalloc`+`vmalloc_to_pfn`+`apply_to_page_range`); step A = inject+read (invisible to `maps`/`mincore`), step B = execute the DBI clone from the ghost page (`sync_icache`) — complete no-trace hook, no maps-hide hook needed | ✅ verified |
| **P5** | Productization groundwork for LSPlant/Vector (and a future Frida-Gum stealth backend): `lib/libdbi` (reusable recompiler) · **HWBP-redirect `inline_hooker`** for real non-page-isolated funcs (`hwhookto`) + UXN variant (`hookto`) with ghost `backup` · no-superkey **syscall bridge** · **TracerPid spoof** (anti-debug) | ✅ verified |
| **L1a** | LSPlant `inline_hooker` carrier: `pghook` scaled to **many overrides per page** (`MAX_OV`, barrier-safe sentinel table) across **`MAX_PG=24`** pages + `pgunhook` (per-fn `inline_unhooker`); **`lib/kpmhook`** userspace glue maps LSPlant's `InitInfo` callbacks onto the bridge (whole-page DBI clone per page, mmap RX). ~20 simultaneous libart-style hooks, several sharing a page, all from one no-superkey agent | ✅ verified |
| **L1b** | **Vector wiring** (`../Vector`): `native_api.h` `HookInline`/`UnhookInline` (the funnel for both `lsplant::InitInfo` sites + the `NativeAPIEntries` ABI) try `kpm_inline_hooker`/`unhooker` first, **fall back to Dobby** when the bridge is unarmed; `lib/kpmhook`+`lib/dbi` vendored into `native/src/kpm`; `:zygisk:assembleDebug` → `libzygisk.so` | ✅ built (not yet runtime-verified) |
| **L1c** | **Page-span census** (`tools/libartcensus.c`, zero-risk on-disk ELF scan): real libart `.text` has **12.2% of functions spanning page boundaries (lower bound), 46.5% of code bytes in spanning runs, max fn ~27 pages** → the single-page whole-page clone is **unusable for real libart**; **multi-page clones are mandatory** (scopes RV-2) | ✅ measured |
| **RV-2** | **Clean-bounded multi-page region clones**: a `pghook` slot now traps a contiguous page **region** whose `R_hi` falls in an inter-function gap, cloned in one piece — so a function spanning a page boundary (or a page-neighbor that does) is wholly in the clone and `RET`s normally. Region-relative routing + `fn_vmalloc`'d offmap in the KPM; clean-`R_hi` scan + region clone in `lib/kpmhook`. Verified by `tools/rgntool.c`: a ~1100-insn page-spanning fn runs its FULL body via a 2-page clone (backup returns `n+1100`), its 2nd-page neighbor runs normally; single-page (`npages=1`) regressions stay green | ✅ verified |
| **L1d** | **LIVE in-app traceless hook of real libart**: the custom Vector routes the **LSPosed manager**'s libart hooks through our KPM — `dump` shows **6-page and 11-page region clones** of real ART code (`redirects=39823`), manager UI fully functional, `.text` untouched. Required: bridge carrier moved `personality`→**`sysinfo`** (Android app seccomp arg-filters `personality`); gate moved cmdline→**UID** (cmdline is still `zygote64` at `LSPlant::Init` time); deploy via `apd module install` (device anti-tamper blocks direct module writes) | ✅ verified |
| **L1e** | **100% inline-hook coverage**: the manager installs **6** simultaneous libart inline hooks; at `MAX_RGN=16` only **2/6** found a clean region boundary (clean ends — a function RET landing exactly on a page boundary — are sparse in dense libart). Raising **`MAX_RGN` 16→64** brings **all 6** through as region clones (6/39/19/11/25/39 pages; the 4 ex-Dobby ones needed 19/25/39/39), `dump npg=6`, manager fully functional, zero crash, zero Dobby fallback | ✅ verified |
| **SSOL** | **Traceless Java hooking via single-step-out-of-line** (Layer 2 for dense framework JIT). Keeps the original code at its original address and executes it one instruction at a time out-of-line (XOL), *simulating* PC-relative insns and fixing mid-step faults — so ART's PC→method map / stack unwind / GC / deopt all work unchanged (region-clone can't: literal pools → SIGILL, clone return addresses → SIGSEGV). It is "traceless uprobes": uprobes' XOL machinery triggered by our **UXN execute-fault** instead of a code-writing `BRK`. KPM side done — entry-override + call-original bypass, multi-target SSOL region (N overrides/page), snapshot-staleness guard + drift refresh, dead-process GC, auto-hidden xol scratch page; `hookdemo` all 5 surfaces CLEAN | ✅ verified (KPM side) |
| **fs-hide** | **Kernel-side filesystem anti-detection** (`fshide`): `vfs_statfs` spoofs the gated process's overlay `f_type` back to the underlying fs (erofs), and `show_mountinfo` SKIPs the overlay/magisk mount lines — a **reader-gate** (tgid/uid hide-set), so only the target process is fooled while root's own `mount`/`df` stay honest. Kills Duck Detector's Mount / hidden-overlayfs "Danger" verdict without any userspace hook | ✅ M1+M2 verified |
| **Rev1/Rev2** | **Ghost main-path** (Rev1 ①): the `pghook` host clone itself now lives in VMA-less ghost memory. **Fork safety** (Rev2 ②): forked children are un-trapped so their own-`.text` execute faults never false-hit | ✅ verified |

## Requirements

- **Device**: ARM64, bootloader unlocked, **APatch + KernelPatch** installed. Verified on
  Pixel 6 (oriole), Android 16, kernel `6.1.145-android14` GKI, **KernelPatch 0.13.3** (verified
  live via the unauthenticated `SUPERCALL_KERNELPATCH_VER`; `kver` reported `6.1.145` to match).
  ⚠️ Cloud phones can't run this (no custom kernel / KPM). Use a physical, expendable test device.
- **Host (Windows)**: Android NDK (uses `26.1.10909125`, clang 17) — no WSL/gcc needed.
  `adb` + the device's APatch **superkey**. ⚠️ On the lab Pixel 6 the superkey was
  **removed/migrated (2026-07-24)**, so `shctl` auth changed — confirm with the user before use.
  `shpte` now **auto-arms the sysinfo bridge at init**, so an injected agent can drive it
  **without the superkey** (that is the path Vector uses).
- KernelPatch SDK headers (`vendor/KernelPatch`, tag `0.13.1`) — ABI-compatible with the device's
  0.13.3 (the loaded `shpte` KPM is verified working). `shctl`'s `KP_VER_CODE` packs a version into
  each supercall's `vcmd`, but the 0.13.x dispatcher **ignores those bits** (`cmd = arg1 & 0xFFFF`),
  so it is cosmetic; only the SDK-header ABI actually has to match.

## Layout

```
kpm/        shpoc.c     P0 syscall-hook smoke test
            shhwbp.c    P1.5/P1.6 HWBP hook: per-thread bp table + state machine
            shpte.c     P2/P4/P5/L1/SSOL/fs-hide main module. cmds: pte | arm | redirect |
                        redirectmap | pagehook (whole-page UXN hook) | pghook/pgunhook/pgdisarm
                        (multi-page, multi-override-per-page RV-2 region table) | hookto/hwhookto/
                        hwunhook (inline_hooker+ghost backup) | ghosttest/ghostredirect/ghostfree |
                        ssolhook/ssolunhook/ssolguard/ssolgc/ssoldisarm (single-step-out-of-line,
                        Java) | hidemaps/unhidemaps/hidergn | hidetracer | fshide (statfs/mountinfo
                        anti-detect) | bridge/unbridge | disarm | dump
            shmin.c     minimal ctl0 isolation test
            build.ps1   build a .kpm with NDK clang  (build.ps1 -Src shhwbp.c)
cli/        shctl.c     KPM control CLI (supercall: load/unload/list/info/control)
            build_shctl.ps1
tools/      hbtarget.c  self-contained single-thread HWBP test target (pid + &tick, loops)
            mttarget.c  multi-thread target; spawns workers gradually (grow) or churns them (churn)
            dbitarget.c        P2.2 target: page-isolated, PC-relative-free tick() + self-clone
            dbitarget2.c       P3.2 target + DBI recompiler: PC-relative hook_me() (ADR+B) → clone
            dbitarget3.c       P3.3 target: work() with a loop (internal B.cond/B) → clone
            dbitarget4.c       P3.4 target: lwork() with an LDR-literal → clone
            run_mt_test.sh     P1.6 harness (hook every existing thread → dump → unhook → unload)
            run_grow_test.sh   P1.6b harness (hook t0 threads, watch new threads auto-followed)
            run_churn_test.sh  P1.6b harness (churn threads, watch slot GC keep the table bounded)
            run_uxn_test.sh    P2.1 harness (UXN + do_page_fault self-heal)
            run_redirect_test.sh    P2.2 harness (UXN net + reroute tick into its verbatim clone)
            run_redirectmap_test.sh P3.1 harness (offset_map routing, identity map)
            run_dbi_test.sh         P3.2 harness (DBI-recompiled hook_me runs from the clone)
            run_dbi3_test.sh        P3.3 harness (recompiled work() loop runs correctly)
            run_dbi4_test.sh        P3.4 harness (recompiled lwork() LDR-literal runs correctly)
            run_hidemaps_test.sh    P4.1 harness (clone vanishes from /proc/<pid>/maps)
            ghosttool.c             P4.2-A target: probes a no-VMA VA (read magic vs mincore/maps)
            ghostexec.c             P4.2-B target: hook_me clone executes from a ghost page
            hooktool.c              inline_hooker test: funcA -> funcB (replace) + ghost backup
            run_ghost_test.sh       P4.2-A harness (inject + read; invisible to maps/mincore)
            run_ghostexec_test.sh   P4.2-B harness (clone runs from VMA-less ghost memory)
            hooktool.c / hwhooktool.c   P5 inline_hooker tests (UXN isolated / HWBP non-isolated)
            bridgetool.c            P5 syscall-bridge test (drive KPM with no superkey)
            tracertest.c            P5 TracerPid spoof test (ptrace a child, read its status)
            pagetool.c              P5 whole-page UXN hook: funcA/B/C share a page (single `pagehook`)
            pgtool.c                P5 MULTI-page table: funcA/funcB on different pages, both
                                    hooked at once (`pghook` x2 + `pgdisarm`)
            run_hookto_test.sh / run_hwhook_test.sh / run_bridge_test.sh / run_tracer_test.sh
            run_pagehook_test.sh    P5 harness (single page-shared func hooked, neighbors normal)
            run_pghook_test.sh      P5 harness (two pages hooked simultaneously, neighbors normal)
            kpmhooktool.c           L1a: in-process agent mimicking LSPlant's call pattern --
                                    inline-hooks vx1/vx2/vx3 (3 overrides on ONE page) + vy1 (a
                                    second page) via lib/kpmhook over the no-superkey bridge
            run_kpmhook_test.sh     L1a harness (arm bridge, run kpmhooktool, observe multi-
                                    override + partial/full unhook + page disarm)
            libartcensus.c          L1c: zero-risk page-span census of a system lib's .text
                                    (on-disk ELF scan; quantifies how many functions span page
                                    boundaries -> whether multi-page clones are needed)
            rgntool.c               RV-2: multi-page region clone test (a ~1100-insn page-spanning
                                    fn + a 2nd-page neighbor, via lib/kpmhook over the bridge)
            run_rgn_test.sh         RV-2 harness (spanning fn full body via the region clone)
            s0probe.c   S0: measure clone-readable residual exposure (upgraded probe)
            fsprobe.c   fs-hide probe (statfs f_type / mountinfo, as a target sees them)
            ssoltarget.c            SSOL target
            run_ssoltest.sh / run_ssolguard_test.sh / run_ssolretire_test.sh   SSOL harnesses
lib/        dbi.c/.h    libdbi: reusable AArch64 position-independent function recompiler
            dbi_test.c  host/device-runnable unit test (build_dbi_test.ps1)
            kpmhook.c/.h L1a: LSPlant InitInfo inline_hooker/unhooker glue -> KPM multi-page
                        pghook table over the syscall bridge (region DBI clone; Vector links this).
                        Also carries kpm_hook_fshide_enable (arm fs-hide + register self tgid)
            ssol.c/.h   SSOL userspace glue
vendor/     KernelPatch  (SDK headers + docs; tag 0.13.1)

The DBI recompiler is being consolidated into `lib/libdbi` for reuse by the userspace agent
(it's what the Vector/LSPlant integration links against). `tools/ghostexec.c` already uses it;
`tools/dbitarget2..4.c` still carry their own (now-superseded) copies.
```

## Quick self-test (pure userspace — no KPM load, no superkey)

The two core algorithms ship **pure-userspace unit tests** — they don't load the KPM, don't touch the
kernel, and need no superkey, so they run on any arm64 Android device (cloud phones included). Fastest
way to confirm the toolchain + recompiler/simulator are correct:

```powershell
powershell lib/build_dbi_test.ps1       # libdbi: AArch64 position-independent recompiler
powershell lib/build_ssol_test.ps1      # libssol: SSOL instruction simulator (+ on-silicon cross-check)
```
```bash
adb push lib/dbi_test lib/ssol_test /data/local/tmp/
adb shell chmod 755 /data/local/tmp/dbi_test /data/local/tmp/ssol_test
adb shell /data/local/tmp/dbi_test      # expect: libdbi: ALL TESTS PASSED
adb shell /data/local/tmp/ssol_test     # expect: [native cross-check enabled] / ssol: ALL TESTS PASSED
```

Last run on Pixel 6 (`1C091FDF6008DN`): both exit 0, `ALL TESTS PASSED`.

## End-to-end over the bridge (no superkey — verified)

Once `shpte` is loaded and the bridge is armed (auto-armed at init, or `control shpte bridge`), **any
process drives the whole KPM without the superkey** — that is exactly what `bridgetool` does:
`syscall(179 /*sysinfo*/, "SHPTBRDG", cmd, len, out, outlen)`; a real `sysinfo(&info)` call (arg0 ≠
magic) passes straight through. Every `shctl KEY control shpte "<cmd>"` in `tools/run_*.sh` has an
equivalent `bridgetool "<cmd>"`.

```bash
# probe device state first (pure syscall; empty reply if the KPM isn't loaded — safe)
adb push tools/bridgetool /data/local/tmp/ ; adb shell chmod 755 /data/local/tmp/bridgetool
adb shell /data/local/tmp/bridgetool probe   # armed bridge -> all resolved kernel symbols; rc=0
adb shell /data/local/tmp/bridgetool dump    # current armed slots / npg / redirects / maps_hidden

# flagship RV-2 end-to-end: rgntool self-hooks a page-spanning fn over the bridge (no shctl/superkey)
adb push tools/rgntool /data/local/tmp/ ; adb shell chmod 755 /data/local/tmp/rgntool
adb shell /data/local/tmp/rgntool            # self-hook -> verify -> self-unhook (cleans up its slot)
```

`rgntool` expects: `[R span] n=k -> backup=1100+k` (the whole page-spanning function ran from the
region clone), the page-neighbor `nbfn(n)=n*2` normal, `unhook: 1`. `kpmhooktool` (L1a, many overrides
per page, mimics LSPlant) likewise self-hooks via `lib/kpmhook`.

> Verified on Pixel 6 (`1C091FDF6008DN`, superkey removed): `shpte` already running in-kernel, bridge
> armed; `bridgetool probe` returned all symbols; `rgntool` all-green + clean self-teardown. `dump` also
> showed a **live production session** — 7 region clones (one 63 pages) on a real process, `.text`
> untouched, `maps_hidden=388` (i.e. L1d/L1e live in-app traceless-hook of real libart). ⚠️ If `dump`
> shows existing slots, the device is in production use — self-hooking tests (rgntool/kpmhooktool) are
> safe (own slot + self-cleanup), but never run `pgdisarm`/`unbridge`/`unload` against live slots.

## Build & run (P1.5 demo)

```powershell
# build
powershell kpm/build.ps1 -Src shhwbp.c          # -> kpm/shhwbp.kpm
powershell cli/build_shctl.ps1                  # -> cli/shctl   (android arm64)

# push (shctl/hbtarget persist across reboot; re-push the .kpm after changes)
adb push kpm/shhwbp.kpm /data/local/tmp/ ; adb push cli/shctl /data/local/tmp/
adb push tools/hbtarget /data/local/tmp/ ; adb shell su -c 'chmod 755 /data/local/tmp/shctl /data/local/tmp/hbtarget'

# load + drive (KEY = APatch superkey)
adb shell su -c '/data/local/tmp/shctl KEY load /data/local/tmp/shhwbp.kpm'
adb shell su -c '/data/local/tmp/shctl KEY control shhwbp probe'        # resolve symbols
adb shell su -c 'setsid /data/local/tmp/hbtarget >/data/local/tmp/hbt.out 2>&1 </dev/null &'
adb shell cat /data/local/tmp/hbt.out                                   # -> pid=.. tick=0x..
# hook syntax: hook <hexaddr> <pid> <tid> [tid ...]; <pid> is the tgid to follow new
# threads of; single-thread target => tid == pid, so pass pid twice
adb shell su -c '/data/local/tmp/shctl KEY control shhwbp "hook <tickaddr> <pid> <pid>"'
adb shell su -c '/data/local/tmp/shctl KEY control shhwbp dump'         # hits low, x0=arg, return captured
adb shell su -c '/data/local/tmp/shctl KEY control shhwbp unhook'
adb shell su -c '/data/local/tmp/shctl KEY unload shhwbp'
```

Always wrap device supercalls in `timeout N` during development, and **unhook before unload**.

### P1.6 multi-thread demo (one shot)

`mttarget` spawns main + 4 worker threads all calling `tick`; the harness enumerates
`/proc/<pid>/task`, installs a per-thread HWBP on every thread, and dumps per-thread hits:

```powershell
powershell cli/build_shctl.ps1                                          # also builds nothing extra
# build mttarget (no script): NDK clang, same target as shctl
& "$ndk\...\clang.exe" --target=aarch64-linux-android33 -O2 tools/mttarget.c -o tools/mttarget
adb push tools/mttarget tools/run_mt_test.sh /data/local/tmp/
adb shell su -c 'chmod 755 /data/local/tmp/mttarget /data/local/tmp/run_mt_test.sh'
adb shell su -c 'sh /data/local/tmp/run_mt_test.sh KEY'                  # full load→hook all→dump→unhook→unload
```

Expected: `slots=5`, and every TID shows `e=N r=N` with `x0` = its own `who` (0..4) — proof each
thread is followed independently. (If two devices are attached, add `-s <serial>` to every `adb`.)

## Hard-won lessons (don't relearn these the hard way)

1. **clang `-O2` miscompiles for the KP module loader** → runtime SP/PC-alignment panic & reboot.
   KP's own demos use gcc; with clang you must build KPMs at **`-O0`** (locked in `build.ps1`,
   plus `-mbranch-protection=bti` because the bp handler is called indirectly by kernel perf).
2. **Never call blocking/perf kernel APIs from the KP supercall/control context or from the
   breakpoint-exception handler.** Calling `register/unregister/modify_user_hw_breakpoint` on a
   remote task there wedges the thread in uninterruptible D-state **while holding a KernelPatch
   lock** → every subsequent supercall (incl. APatch `su`) hangs → only a *physical* reboot
   recovers it. Fix: defer all perf calls to the **target task's own context via `task_work_add`**
   (sleepable, local install, runs before the faulting instruction re-executes).
3. arm64 only auto-single-steps over an execute breakpoint when the perf event uses the
   **default** overflow handler. With a custom handler (needed to capture regs) it does **not**,
   so a plain execute bp re-triggers forever. Solution: the **entry↔return state machine** —
   move the bp to LR on entry, back to entry on return.
4. `pgrep -f <path>` matches its **own** command line — use `ps -A` / `pgrep -x <comm>` to count.

## Next

The full traceless-hook pipeline is implemented and device-verified: HWBP multi-thread following
(P1.6) → UXN net + `do_page_fault` routing (P2) → DBI recompiler (P3) → VMA-less ghost-memory
execution (P4.2). The original `.text` is never modified (CRC-clean) and the recompiled clone runs
from memory invisible to both `/proc/*/maps` and `mincore`. P5 adds the productization primitives
(reusable `libdbi`, HWBP/UXN `inline_hooker` with ghost `backup`, no-superkey syscall bridge,
TracerPid spoof). Anti-detection coverage: CRC + maps scan + ptrace/TracerPid + fs/mount
(`fshide`: overlay `statfs`/`mountinfo` spoof, reader-gated).

### Productization: LSPlant/Vector (and a future Frida-Gum stealth backend)
The intended end-product is a modified **Vector** (JingMatrix's Zygisk ART-hook framework; cloned at
`../Vector`) whose hook backend is our KPM. Findings (see memory `lsplant-vector-integration`):
- Vector's `inline_hooker(target, hooker) → backup` maps **exactly** onto `hwhookto` (HWBP, since
  real libart funcs share pages) + ghost backup; `inline_unhooker` → `hwunhook` + `ghostfree`.
- JingMatrix's LSPlant `InitInfo` has **no `mem_map`** → the article's `alloc_ghost` is unnecessary.
- **Layer 1** (native libart hooks at LSPlant init): swap Vector's `inline_hooker`/`unhooker` to call
  our KPM via the syscall bridge. LSPlant installs **~20 simultaneous** libart inline hooks (more than
  6 HWBPs, more than the old `MAX_PG=8`), so the carrier is **multi-page UXN `pghook`** scaled to many
  overrides per page across 24 pages. **L1a done + device-verified** (`kpmhooktool`). **L1b done +
  built**: `native_api.h` `HookInline`/`UnhookInline` route through `lib/kpmhook` with a Dobby fallback;
  `:zygisk:assembleDebug` links it. **L1c census** (`tools/libartcensus.c`) shows **46.5% of libart
  code bytes live in page-spanning functions** → the single-page whole-page clone is unusable for real
  libart. **RV-2 done + device-verified**: a `pghook` slot now traps a clean-bounded multi-page **region**
  (`R_hi` in an inter-function gap) cloned in one piece, so page-spanning functions/neighbors run wholly
  from the clone (`tools/rgntool.c`). **L1d/L1e done + LIVE-verified in-app**: the custom Vector routes the
  LSPosed manager's libart hooks through the KPM; raising `MAX_RGN` 16→64 brings **all 6** of the manager's
  inline hooks through as region clones (none on Dobby), manager fully functional, `.text` untouched.
  **Remaining:** multi-slot `hwhookto` (HWBP, entry-only) as a fallback for functions still too large for a
  clean region past 64 pages, or hosts needing more than `MAX_PG` regions; and a Vector-passed package-name
  gate to replace the UID gate.
- **Layer 2** (Java methods): **SSOL** (single-step-out-of-line) is the correct + scalable path for
  dense framework JIT — keep the original code in place and step it one instruction at a time
  (triggered by our UXN fault, not a code-writing `BRK`), so ART's PC→method map / unwind / GC / deopt
  stay intact where a region clone would SIGILL (literal pools) or SIGSEGV (clone return addresses).
  **KPM side done + device-verified** (`hookdemo` all 5 surfaces CLEAN); region-clone stays for L1
  native and simple-app Java hooks. Remaining: Vector/LSPlant `DoHook` wiring. See `docs/SSOL-design.md`.
- **Frida-Gum** (optional, larger): re-back Gum's `Interceptor` with `hwhookto` and Stalker's code
  cache with ghost memory; plus process/port/thread hiding hooks. Same KPM, different frontend.

Remaining / future:
- **P3.5**: `BLRAAZ`/`BRAAZ` PAC-call demotion (article §5.7); stock NDK doesn't emit PAC'd calls.
- **More hiding hooks**: process (`/proc` readdir), port (`/proc/net/tcp`), thread (`/proc/pid/task`).
- **Hardening**: multi-page clones (currently one ghost page); pin the ghost VA against allocator
  reuse; per-process gating for the maps-hide / tracer hooks; RCU for the slot table (article §5.1).

---

## 中文说明

**中文** | [English](#stealth-poc)

Android（ARM64）上**内核级无痕 Hook** 的 clean-room PoC，基于 **APatch / KernelPatch（KPM）**。

> 深入的工程约定与硬核教训见 [`CLAUDE.md`](./CLAUDE.md)。

**关联项目**：本仓是 [**Vector**](https://github.com/1013503897/Vector)（我们 fork 的 JingMatrix Zygisk ART-hook 框架）所用 **KPM 无痕后端的内核 + 用户态胶水源头**。Vector 从这里 vendored `lib/kpmhook` + `lib/dbi`，其 `HookInline` **先走 `kpm_inline_hooker`**（KPM 无痕）、桥未开时退 Dobby。见下方状态表 **L1b/L1d/L1e** 与《产品化》一节。

## 这是什么

一句话：**在不改动目标任何一个字节内存的前提下，拦截并接管它的执行**。

- 不 patch 目标 `.text`（过得了 CRC / 自校验）；
- 不注入 SO、不建匿名可执行映射（过得了 `/proc/*/maps` 扫描）；
- 重编译后的克隆代码跑在 **连 `/proc/*/maps` 和 `mincore` 都看不见** 的内存里。

它是 Vector（`../Vector`，JingMatrix 的 Zygisk ART-hook 框架）**KPM 无痕后端的内核源头**——Vector 通过 vendored 的 `lib/kpmhook` + `lib/dbi` 经无 superkey 的 sysinfo bridge 驱动本仓的 KPM。本仓保持独立 git（remote `github.com/1013503897/stealth-poc`）。

参考（仅概念）：看雪文章《Android 内核无痕 Hook 理解和感悟》与公开的 `xiaojianbang-stealth-hook`。**未拷贝任何第三方代码**——全部对着 KernelPatch kpm SDK API 和稳定的 Linux/ARM ABI 自研实现。

## 无痕的三重保证

| 反检测面 | 常规 hook 的破绽 | 本方案 |
|---|---|---|
| **CRC / 自校验** | inline patch 改了 `.text` 字节 | `.text` 一字不改，靠 PTE 的 UXN 位或硬件断点触发陷阱 |
| **`/proc/*/maps` 扫描** | 注入 SO / 匿名 RX 段留下映射行 | 克隆跑在 **VMA-less ghost 内存**（无 VMA，maps/mincore 均不可见）；另有 maps-hide 兜底 |
| **ptrace / 反调试** | 附加调试器改 TracerPid | 无需 ptrace；并提供 `hidetracer` 把 `/proc/*/status` 的 TracerPid 伪造为 0 |

## 三层架构

Hook 逻辑横跨内核态与用户态，靠一条字符串命令控制通道桥接：

1. **KPM 模块**（`kpm/*.c`）——被 KernelPatch **加载进内核** 的内核侧代码。freestanding ELF `ET_REL`（无 libc / 无 stdlib），加载期由 KernelPatch 解重定位；通过 `kallsyms_lookup_name` 在运行时解析内核函数（不与内核链接）。生命周期钩子用 SDK 的 section-attribute 宏导出（`KPM_INIT`/`KPM_CTL0`/`KPM_EXIT`）。
2. **`shctl`**（`cli/shctl.c`）——用户态 ARM64 CLI，通过 **supercall**（`syscall(45, superkey, vcmd, ...)`）驱动已加载的 KPM。`control <name> <args>` 把字符串路由到 KPM 的 `KPM_CTL0` handler，并打印回拷的应答。
3. **测试目标**（`tools/*.c`）——一批自包含的靶子进程，各自验证一个阶段能力（打印 pid + 目标函数地址，循环调用以便断点/陷阱命中）。

### `KPM_CTL0` 命令桥
KPM 只有一个 `KPM_CTL0` 入口，内部用手写的 freestanding 字符串解析（内核态无 libc）分发一套文本协议。新能力以**新命令动词**的形式加入，而非新增 supercall。`shpte` 当前支持的动词：

```
probe        解析内核符号
pte          读+解码某进程的叶子 PTE（只读）
arm/disarm   给目标代码页置/清 PTE_UXN，挂 do_page_fault（自愈式）
redirect     UXN 陷阱 + 把 PC 重定向到用户态克隆页
redirectmap  经 offset_map 路由（DBI 克隆指令位移后仍正确落点）
pagehook     整页 UXN hook（页内多函数共享，单次）
pghook/pgunhook/pgdisarm/pghookg/pggc   多页 region 克隆 + 每页多 override 表（RV-2）
hookto/hwhookto/hwunhook   inline_hooker 原语（UXN / 硬件断点 + ghost backup）
ghosttest/ghostredirect/ghostfree       VMA-less ghost 内存
ssolhook/ssolunhook/ssolguard/ssolgc/ssoldisarm/ssolstat/ssoltest/ssolpoison   SSOL（单步出线）Java 无痕 hook
hidemaps/unhidemaps/hidergn   从 /proc/*/maps 抹掉克隆的 VMA
hidetracer/unhidetracer       伪造 TracerPid=0（反调试）
fshide       fs 反检测（statfs f_type 伪装 + mountinfo 行过滤）
bridge/unbridge  开/关无 superkey 的 sysinfo 桥
selfstep/dump    自测/诊断
```

## 阶段进度

| 阶段 | 内容 | 状态 |
|---|---|---|
| **P0** | KPM 工具链 + syscall-hook 冒烟测试（`shpoc`） | ✅ 设备实测 |
| **P1 / P1.5** | ARM64 硬件断点 hook + 寄存器捕获；单断点 **entry↔return 状态机**（消除重触发 livelock，捕获入参+返回值，目标透明运行） | ✅ |
| **P1.6 / P1.6b** | 多线程跟随——每线程断点表；跟随 hook 后新建线程（`wake_up_new_task`）+ 线程退出 GC（`do_exit`），线程 churn 下表保持有界 | ✅ |
| **P2.0 / P2.1** | 页表遍历读+解码任意进程叶子 PTE；目标代码页翻 UXN + `do_page_fault` 拦截 + **自愈式**恢复 | ✅ |
| **P2.2** | **单函数无痕重定向**：保持 UXN，把 faulting PC 改到函数的逐字**克隆**（`.text` 不动，函数处无新可执行 VMA） | ✅ |
| **P3.1–P3.4** | 用户态 **DBI 重编译器**：`ADR/ADRP/B/BL` 转绝对、条件+内部分支（`B.cond/CBZ/TBZ`）clone-relative 重编码、`LDR`-literal 重指向——带循环/分支/字面量池的函数都能从克隆正确运行；`offset_map` 跨进程路由 | ✅ |
| **P3.5** | `BLRAAZ`/`BRAAZ` PAC-call 降级（需 pauth 构建的目标；stock NDK 不产出） | ⬜ todo |
| **P4.1** | `/proc/*/maps` 隐藏：hook `show_map`，从 seq_file 输出里抹掉克隆行（CRC + maps 扫描一起过） | ✅ |
| **P4.2** | **VMA-less ghost 内存**：`vmalloc`+`vmalloc_to_pfn`+`apply_to_page_range` 给克隆注入一个**无 VMA** 的 PTE——maps/mincore 均不可见，且直接从 ghost 页执行 DBI 克隆（`sync_icache`）；无需 maps-hide 兜底 | ✅ |
| **P5** | 产品化原语：可复用 `lib/dbi`、HWBP/UXN `inline_hooker`（`hwhookto`/`hookto` + ghost backup）、无 superkey syscall bridge、TracerPid 伪造 | ✅ |
| **L1a–L1e** | LSPlant `inline_hooker` 载体：`pghook` 扩到每页多 override（barrier-safe sentinel 表）× 多页；`lib/kpmhook` 把 LSPlant `InitInfo` 回调映射到桥；**RV-2 干净边界多页 region 克隆**（页跨越函数整体在克隆里、正常 `RET`）；把 `MAX_RGN` 提到 64 后，LSPosed 管理器 **6 个** libart inline hook 全部走 region 克隆（零 Dobby 回退），**真机应用内实测无痕 hook 真实 libart**、`.text` 不动 | ✅ 真机实测 |
| **SSOL** | **单步出线（single-step out of line）Java 无痕 hook**：把原始代码留在原地、逐指令 XOL 执行——PC 始终在原始地址，ART 的 PC→method 映射/栈回溯/GC/deopt 全部照常工作，解决稠密框架 JIT 上 region 克隆的「代码/数据交织」「克隆返回地址」两大结构性脆弱点。相当于「用 UXN 陷阱触发的 uprobes」。KPM 侧核心 + 多目标 region + 抗漂移 guard + 死进程 GC 已实现，hookdemo 五个面全 CLEAN | ✅ 真机实测（KPM 侧） |
| **fs-hide** | 内核态文件系统反检测：`vfs_statfs` 把 gated 进程看到的 overlay `f_type` 伪装成底层 fs、`show_mountinfo` SKIP 掉 overlay/magisk 挂载行（reader-gate，只骗要骗的进程）。触发场景：Duck Detector 把 Mount/hidden-overlayfs 判 Danger | ✅ M1+M2 |

## 目录结构

```
kpm/        KPM 内核模块 + 构建脚本
  shpoc.c       P0 syscall-hook 冒烟
  shhwbp.c      P1.5/P1.6 HWBP hook：每线程断点表 + 状态机
  shpte.c       P2/P3/P4/P5/L1/SSOL/fs-hide 主模块（~4100 行，命令集见上）
  shmin.c       最小 ctl0 隔离测试
  build.ps1     用 NDK clang 编 .kpm（build.ps1 -Src shhwbp.c）
  *.py          elf_syms / scope_db / btf_off / oat_census 等符号解析脚本
  libart*.so    census / 离线分析用的 ART 样本

cli/        shctl.c + build_shctl.ps1   KPM 控制 CLI（supercall：load/unload/list/info/control）

lib/        可复用用户态库（Vector 链接的就是这里）
  dbi.c/.h      libdbi：可复用的 AArch64 位置无关函数重编译器
  kpmhook.c/.h  LSPlant InitInfo inline_hooker/unhooker → KPM 多页 pghook 表（经 syscall bridge）
  ssol.c/.h     SSOL 用户态胶水
  *_test.c      host/device 可跑的单元测试

tools/      测试靶子 + 端到端 harness（各 .c 与 shctl 同法编译）
  hbtarget/mttarget          单线程 / 多线程 HWBP 靶
  dbitarget..dbitarget4      P2.2→P3.4 逐级 DBI 靶（逐字→ADR/ADRP/B/BL→分支→LDR-literal）
  ghosttool/ghostexec        P4.2 ghost 内存靶（注入读 / 从 ghost 页执行）
  hooktool/hwhooktool        inline_hooker 靶（UXN 隔离 / HWBP 非隔离）
  pagetool/pgtool/rgntool    整页 / 多页 / region 克隆靶
  kpmhooktool                L1a：模拟 LSPlant 调用模式的进程内 agent
  ssoltarget                 SSOL 靶
  libartcensus               L1c：ELF 页跨越普查（零风险，量化是否需要多页克隆）
  s0probe/fsprobe            残余暴露 / fs 反检测 探针
  bridgetool/tracertest      桥 / TracerPid 探针
  run_*.sh                   各阶段设备侧 harness

docs/       设计文档（SSOL、L2 Java 无痕、fs 隐藏、ghost VA 钉死、脱壳器等）
vendor/     KernelPatch（SDK 头 + 文档；tag 0.13.1）
```

## 关键机制（无痕怎么实现的）

- **UXN「高压网」**：给目标代码页的 PTE 置 `PTE_UXN`，EL0 执行即触发 `do_page_fault`。fault handler **硬门控**（armed + 精确目标页 + faulting `tgid` 匹配），PTE 指针在 arm 期缓存，热路径不做页表遍历。
- **DBI 重编译器**（在用户态靶/`lib/dbi`，不在 KPM——内核只路由入口 fault）：把 PC 相关指令（`ADR/ADRP/B/BL/B.cond/CBZ/TBZ/LDR-literal`）重编码成位置无关，产出 `offset_map`（原指令 idx → 克隆指令 idx）供内核路由。
- **RV-2 干净边界多页 region 克隆**：L1c 普查发现真实 libart **46.5% 的代码字节** 落在跨页函数里，单页克隆会截断函数。解决：一个 `pghook` 槽陷阱一段**连续页 region**，其 `R_hi` 落在函数间空隙——每个函数整体在克隆里、正常 `RET`，无需 trampoline。
- **VMA-less ghost 内存**：`vmalloc` 一页 → `vmalloc_to_pfn` 拿 PFN（**不用** `virt_to_phys`，其 `linear_voffset` 未导出给 KPM）→ 从模板可执行页拷属性 → `apply_to_page_range` 在一个无 VMA 的 VA 注入 PTE → `sync_icache` 后把 UXN 重定向指到这里。ghost 主路径（Rev1 ①）已让 `pghook` 的宿主克隆本身也搬进 ghost 内存。
- **SSOL 单步出线**：稠密框架 JIT 上，region 克隆有两个结构性坑（① 代码/数据交织，字面量池被当指令执行 → SIGILL；② 克隆返回地址上栈，ART unwinder/GC 认不出 → SIGSEGV）。SSOL 把原码留在原地，只逐指令 XOL、对 PC 相关指令做 simulate、mid-step fault 修正——PC 之间永远在原始地址，ART 全套机制照常。触发用已有的 UXN 执行 fault（不写 BRK，故无痕）。
- **fork 安全**（Rev2 ②）：给 fork 出的子进程**解陷阱**，子进程在自己 `.text` 上的执行 fault 不再误命中。

### 最重要的不变量：deferred-work 安全模型

perf/断点内核 API（`register/unregister/modify_user_hw_breakpoint`）和其它阻塞调用，**绝不能在 supercall/`KPM_CTL0` 上下文或断点异常 handler 里跑**——那会让线程卡在不可中断 D-state **同时持有 KernelPatch 锁**，之后每一次 supercall（含 APatch `su`）都挂，只能**物理重启**。全仓强制的模式：

- 断点/fault handler 只**快照寄存器**，然后 `task_work_add(target_task, ..., TWA_RESUME)` 入队；
- 真正的 perf 调用推迟到**目标任务自己的上下文**（可睡眠、返回用户态前）执行。

任何新碰 perf/调度/可能阻塞内核 API 的代码，必须遵守同样的 defer-to-`task_work` 纪律。

## 构建

Windows + NDK clang（无需 WSL/gcc）。构建脚本是 PowerShell。NDK 在脚本里**硬编码为 `26.1.10909125`（clang 17）**，机器不同就改脚本里的 `$ndk`。

```powershell
# KPM 内核模块（传任意 kpm/*.c，产出同名 .kpm + .o）
powershell kpm/build.ps1 -Src shpte.c        # -> kpm/shpte.kpm（默认 Src 是 shpoc.c）

# shctl 用户态 CLI -> cli/shctl（aarch64-linux-android33）
powershell cli/build_shctl.ps1
```

**KPM 构建 flag 是 load-bearing 的，未在真机重测前不要改**：

- **只能 `-O0`**。clang `-O2` 对 KP 模块加载器会 miscompile → 运行期 SP/PC 对齐 panic + 设备重启。（上游 demo 用 gcc `-O2`，不迁移到 clang。）
- **`-mbranch-protection=bti`**——断点 handler 被内核 perf 间接调用，需要 BTI landing pad。
- `--target=aarch64-none-elf -nostdinc -ffreestanding -mgeneral-regs-only`，再做可重定位链接（`-r -nostdlib`）；`-I` 集镜像上游 kpm Makefile。

`tools/*.c` 靶子没有构建脚本，与 `shctl` 同法编译（`--target=aarch64-linux-android33`）。

## 快速自检（纯用户态，无需内核加载 / superkey）

两个核心算法有**纯用户态单元测试**——不 load KPM、不碰内核、不需要 superkey，任意 arm64 Android 设备（含云手机）都能跑，是验证工具链 + 重编译器/模拟器是否正确的最快 smoke test：

```powershell
# 1) libdbi —— AArch64 位置无关重编译器（重编译一个函数、原件 vs 克隆逐一比对）
powershell lib/build_dbi_test.ps1
# 2) libssol —— SSOL 指令模拟器（golden 向量 + 在真芯片上交叉校验 simulate 结果）
powershell lib/build_ssol_test.ps1
```

```bash
adb push lib/dbi_test lib/ssol_test /data/local/tmp/
adb shell chmod 755 /data/local/tmp/dbi_test /data/local/tmp/ssol_test
adb shell /data/local/tmp/dbi_test     # 期望: libdbi: ALL TESTS PASSED
adb shell /data/local/tmp/ssol_test    # 期望: [native cross-check enabled] / ssol: ALL TESTS PASSED
```

> 最近一次在 Pixel 6（`1C091FDF6008DN`）实测：两者 exit 0、`ALL TESTS PASSED`。

## 部署与运行（真机）

需要**物理 ARM64 设备** + APatch/KernelPatch。云手机跑不了（无自定义内核 / KPM）。已实测：Pixel 6（oriole），Android 16，kernel `6.1.145-android14` GKI，**KernelPatch 0.13.3**（经免鉴权的 `SUPERCALL_KERNELPATCH_VER` 现场查得；`kver` 同时回报 `6.1.145` 对得上）。

> ⚠️ 本机 Pixel 6 的 **superkey 已于 2026-07-24 移除/迁移**，`shctl` 认证方式已变——用前先与用户确认。`shpte` 现支持 init 时自动开桥，用户态 agent 经 sysinfo bridge 无 superkey 驱动。
>
> ⚠️ 无开机自动加载（`/data/adb/kpms` 空），每次开机手动从 `/data/local/tmp/shpte.kpm` 加载。开发期把设备 supercall 都包在 `timeout N` 里，且 **`unload` 前务必先 `unhook`/`disarm`**（需要目标存活）。`shctl`/靶子重启后仍在，改完 `.kpm` 要重推。

```powershell
adb push kpm/shpte.kpm /data/local/tmp/ ; adb push cli/shctl /data/local/tmp/
adb shell su -c 'chmod 755 /data/local/tmp/shctl'

# KEY = APatch superkey（若已迁移，见上）
adb shell su -c '/data/local/tmp/shctl KEY load /data/local/tmp/shpte.kpm'
adb shell su -c '/data/local/tmp/shctl KEY control shpte probe'    # 解析内核符号
adb shell su -c '/data/local/tmp/shctl KEY control shpte bridge'   # 开无 superkey 桥
adb shell su -c '/data/local/tmp/shctl KEY control shpte dump'     # 诊断
```

内核侧 `logki`/`logke` 输出进内核日志（`adb shell su -c 'dmesg'`），不到 `shctl` stdout——`shctl` 只打印 `KPM_CTL0` 应答缓冲。各阶段端到端 harness 见 `tools/run_*.sh`（它们用 `shctl KEY control` 驱动，需 superkey）。

### 经桥端到端（无 superkey，已实测）

一旦 `shpte` 已加载且桥已开（init 自动开，或 `control shpte bridge`），**任意进程都能不用 superkey 驱动整个 KPM**——`bridgetool` 就是这么做的：`syscall(179 /*sysinfo*/, "SHPTBRDG", cmd, len, out, outlen)`，真 `sysinfo(&info)` 调用（arg0≠magic）原样放行。`tools/run_*.sh` 里凡是 `shctl KEY control shpte "<cmd>"` 都可等价替换成 `bridgetool "<cmd>"`。

```bash
# 先探测：KPM 是否已加载 + 桥是否已开（纯 syscall，未加载则空返回，安全）
adb push tools/bridgetool /data/local/tmp/ ; adb shell chmod 755 /data/local/tmp/bridgetool
adb shell /data/local/tmp/bridgetool probe   # 已开则回全部已解析内核符号；rc=0
adb shell /data/local/tmp/bridgetool dump    # 看当前 armed slot / npg / redirects / maps_hidden

# 旗舰 RV-2 端到端：rgntool 经桥「自 hook」一个跨页函数（不需 shctl/superkey）
adb push tools/rgntool /data/local/tmp/ ; adb shell chmod 755 /data/local/tmp/rgntool
adb shell /data/local/tmp/rgntool            # 自 hook -> 验证 -> 自 unhook（自清理）
```

`rgntool` 期望：`[R span] n=k -> backup=1100+k`（跨页函数**整体**从 region 克隆跑通）、页邻居 `nbfn(n)=n*2` 正常、`unhook: 1`。同理 `kpmhooktool`（L1a 每页多 override，仿 LSPlant 调用模式）也经 `lib/kpmhook` 自 hook。

> 实测（Pixel 6 `1C091FDF6008DN`，superkey 已移除）：`shpte` 已在内核运行、桥已开；`bridgetool probe` 回全部符号；`rgntool` 全项 OK、自清理干净。`dump` 还显示该机正跑着生产级会话——7 个 region（含 63 页的）挂在一个真实进程上、`.text` 不动、`maps_hidden=388`（即 L1d/L1e 真机应用内无痕 hook）。⚠️ 若 `dump` 显示已有存量 slot，说明设备在生产使用中——自 hook 类测试（rgntool/kpmhooktool）用自己的 slot 且自清理是安全的，但别对存量 slot 跑 `pgdisarm`/`unbridge`/`unload`。

## 版本耦合（必须与设备一致）

两个独立的版本 pin 必须与设备匹配，否则 load/supercall 会**静默失败**：

- `vendor/KernelPatch` checkout 在 tag **0.13.1**，提供 kpm SDK 头。设备实际是 **0.13.3**（现场查得），两者 **ABI 兼容**——当前加载的 `shpte` KPM 实测正常工作，故 SDK 头无需强行对齐到 0.13.3。真正必须匹配的是 SDK 头的 ABI，不是那个数字。
- `cli/shctl.c` 的 `KP_VER_CODE`（现为 `0.13.3`）会打进每次 supercall 的 `vcmd` 高位，**但 0.13.x 的 supercall 分发器只取 `cmd = arg1 & 0xFFFF`、忽略版本高位**（`vendor/KernelPatch/.../supercall.c` 里 `// todo: from 0.10.5` 那段被注释掉了），所以它是**运行时无效的装饰值**——查询版本时我压根没传高位，supercall 照样生效即为铁证。升级 KP 时按需对齐 SDK 头 tag 即可，`KP_VER_CODE` 改不改都不影响运行。

## 硬核教训（别再用血踩一遍）

1. **clang `-O2` 对 KP 加载器 miscompile** → 运行期 SP/PC 对齐 panic + 重启。KPM 必须 `-O0`（`build.ps1` 已锁），外加 `-mbranch-protection=bti`。
2. **绝不在 supercall/control 上下文或断点异常 handler 里调阻塞/perf 内核 API**。对远端 task 调 `register/unregister/modify_user_hw_breakpoint` 会卡 D-state + 持 KernelPatch 锁 → 后续 supercall 全挂 → 只能物理重启。修法：一切 perf 调用经 `task_work_add` 推迟到目标任务自己的上下文。
3. arm64 只有在 perf event 用**默认** overflow handler 时才会对执行断点自动单步；用了自定义 handler（为捕获寄存器）就不会 → 裸执行断点无限重触发。解法：**entry↔return 状态机**（入口把断点移到 LR，返回时移回入口）。
4. `pgrep -f <path>` 会匹配到它自己的命令行——用 `ps -A` / `pgrep -x <comm>` 计数。

## 产品化：LSPlant / Vector（及未来的 Frida-Gum 无痕后端）

目标成品是一个改造版 **Vector**（`../Vector`），其 hook 后端换成本仓 KPM。要点（另见 memory `lsplant-vector-integration`）：

- Vector 的 `inline_hooker(target, hooker) → backup` **精确对应** `hwhookto`（HWBP，因真实 libart 函数共享页）+ ghost backup；`inline_unhooker` → `hwunhook` + `ghostfree`。
- **Layer 1**（LSPlant init 时的 native libart hook）：把 Vector 的 `inline_hooker`/`unhooker` 换成经 syscall bridge 调 KPM。载体是扩到每页多 override、跨多页的 **UXN `pghook`**（RV-2 region 克隆）。L1a–L1e 已完成并**真机应用内实测**：LSPosed 管理器 6 个 libart inline hook 全走 region 克隆、零 Dobby 回退、`.text` 不动。
- **Layer 2**（Java 方法）：**SSOL** 是稠密框架 JIT 的正确+可扩展路径（region 克隆保留给 L1 native 与简单 app 的 Java hook）。
- **Frida-Gum**（可选、更大）：用 `hwhookto` 重做 Gum 的 `Interceptor`、用 ghost 内存重做 Stalker 代码缓存；同一 KPM、不同前端。

**剩余 / 未来**：P3.5（`BLRAAZ`/`BRAAZ` PAC 降级）；更多隐藏 hook（进程 `/proc` readdir、端口 `/proc/net/tcp`、线程 `/proc/pid/task`）；ghost VA 钉死防分配器复用、slot 表 RCU 等加固。
