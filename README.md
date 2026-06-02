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
| **P1.6** | Multi-thread following (per-thread bp table + hook new threads) | ⬜ todo |
| **P2** | PTE/UXN + `do_page_fault` routing + userspace DBI recompile + ghost memory (breaks the 6-breakpoint limit → article's "ultimate" architecture) | ⬜ todo |

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
            shhwbp.c    P1/P1.5 HWBP hook (state machine)
            shmin.c     minimal ctl0 isolation test
            build.ps1   build a .kpm with NDK clang  (build.ps1 -Src shhwbp.c)
cli/        shctl.c     KPM control CLI (supercall: load/unload/list/info/control)
            build_shctl.ps1
tools/      hbtarget.c  self-contained HWBP test target (prints pid + &tick, loops)
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
adb shell su -c '/data/local/tmp/shctl KEY control shhwbp "hook <pid> <tickaddr>"'
adb shell su -c '/data/local/tmp/shctl KEY control shhwbp dump'         # hits low, x0=arg, return captured
adb shell su -c '/data/local/tmp/shctl KEY control shhwbp unhook'
adb shell su -c '/data/local/tmp/shctl KEY unload shhwbp'
```

Always wrap device supercalls in `timeout N` during development, and **unhook before unload**.

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

- **P1.6**: per-thread bp table (HWBP is per-thread) + hook thread creation, with RCU + deferred GC
  so a thread exiting mid-fire doesn't UAF (article §5.1).
- **P2**: PTE/UXN + `do_page_fault` interception + userspace DBI recompiler + VMA-less ghost memory.
  This is the high-risk phase (page-table surgery); expect device reboots during bring-up.
