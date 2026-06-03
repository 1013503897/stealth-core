# stealth-poc

Clean-room PoC for kernel-level **traceless hooking** on Android (ARM64), built on
APatch / KernelPatch (KPM). Goal: intercept a target's execution **without modifying
any of its memory** (no `.text` patch, no injected SO, no anonymous executable maps),
so it survives CRC / maps-scan style anti-tamper checks.

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
| **P4.2** | VMA-less **ghost memory**: inject a PTE for the clone with no VMA (article §5.9) so it's invisible to `maps`/`mincore` even via API probing | ⬜ todo (highest brick risk) |

## Requirements

- **Device**: ARM64, bootloader unlocked, **APatch + KernelPatch** installed. Verified on
  Pixel 6 (oriole), Android 16, kernel `6.1.145-android14` GKI, KernelPatch kpimg `d01` (= 0.13.1).
  ⚠️ Cloud phones can't run this (no custom kernel / KPM). Use a physical, expendable test device.
- **Host (Windows)**: Android NDK (uses `26.1.10909125`, clang 17) — no WSL/gcc needed.
  `adb` + the device's APatch **superkey**.
- KernelPatch source checked out at the **matching tag** for the kpm SDK headers
  (`vendor/KernelPatch`, tag `0.13.1`).

## Layout

```
kpm/        shpoc.c     P0 syscall-hook smoke test
            shhwbp.c    P1.5/P1.6 HWBP hook: per-thread bp table + state machine
            shpte.c     P2 PTE/UXN: pte read | arm (self-heal) | redirect (clone) | disarm
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
vendor/     KernelPatch  (SDK headers + docs; tag 0.13.1)
```

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

- **P3.5**: `BLRAAZ`/`BRAAZ` PAC-call demotion (article §5.7) — clear bit 21 to demote the PAC'd
  indirect call to a branch (keeps target-pointer auth, stops LR clobber) and set LR to the clone's
  next insn. Stock NDK doesn't emit PAC'd calls, so this needs a pauth-built target to exercise.
- **P4**: the clone is still **visible in `/proc/*/maps`** (an ordinary RX anon mapping) — the one
  remaining trace. **P4.1** hides it by filtering the `seq_file`/`show_map` path (§5.8); **P4.2** goes
  further with VMA-less ghost memory — inject a PTE for the clone with no VMA (§5.9) so it can't be
  found by `maps` or `mincore`. P4.2 is page-table surgery; expect reboots during bring-up.
