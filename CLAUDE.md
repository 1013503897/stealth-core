# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`stealth-poc` is one subproject of the `at-xx-hook` mono-repo (see `../CLAUDE.md`). It is a
clean-room PoC for **kernel-level traceless hooking** on Android ARM64: intercept a target's
execution *without modifying any of its memory* (no `.text` patch, no injected SO, no anonymous
executable maps), so it survives CRC / maps-scan anti-tamper. It is built on **APatch /
KernelPatch (KPM)**. Read `README.md` first — it tracks phase status (P0/P1/P1.5 done, P1.6/P2 todo)
and the canonical run sequence.

## Three-tier architecture

Hooking spans kernel and userspace, bridged by a string-command control channel:

1. **KPM modules** (`kpm/*.c`) — kernel-side code loaded *into the kernel* by KernelPatch. They
   are freestanding ELF `ET_REL` objects (no libc, no stdlib); KernelPatch resolves their
   relocations at load time. Each exports lifecycle hooks via section-attribute macros from the
   SDK (`KPM_INIT`/`KPM_CTL0`/`KPM_EXIT`, see `vendor/KernelPatch/kernel/include/kpmodule.h`).
   They call kernel functions resolved at runtime via `kallsyms_lookup_name` — there is no link
   against the kernel.
2. **`shctl`** (`cli/shctl.c`) — userspace ARM64 CLI that drives a loaded KPM. It talks to
   KernelPatch through the **supercall** (`syscall(45, superkey, vcmd, ...)`), reimplementing the
   ABI constants directly (it deliberately does *not* include KernelPatch's `supercall.h`, which
   doesn't compile under clang at 0.13.1). `control <name> <args>` routes a string to the KPM's
   `KPM_CTL0` handler and prints the reply copied back via `compat_copy_to_user`.
3. **`hbtarget`** (`tools/hbtarget.c`) — a self-contained test victim that prints its pid and the
   runtime address of `tick()`, then loops calling `tick(i)` so an execute breakpoint on `&tick`
   fires with `x0 = i`.

### The KPM_CTL0 command bridge
`shhwbp` exposes a tiny text protocol through its single `KPM_CTL0` entrypoint
(`shhwbp_control0`): `probe | hook <hexaddr> <pid> <tid> [tid…] | dump | unhook`. Commands are parsed
with hand-rolled freestanding string helpers (`apps`/`apphex`/`appdec`/`parse_ull`) because there is
no libc in kernel context. New module capabilities are added as new verbs here, not as new supercalls.

### Per-thread breakpoint table (P1.6)
HWBP is a *per-thread* CPU debug-register state — a breakpoint on one TID does not fire for sibling
threads. So `shhwbp` keeps a fixed `struct bp_slot g_slots[MAX_SLOTS]`, one `perf_event` per thread,
each with its own attr copy, entry↔return state, and **its own `task_work` heads** (sharing one head
across threads would corrupt the task_work list). The `tw_install`/`tw_move`/`tw_remove` callbacks
recover their slot via `container_of(head, struct bp_slot, <member>)`; the breakpoint handler maps the
firing `perf_event` back to its slot by pointer match (`slot_by_bp`). Userspace enumerates
`/proc/<pid>/task` and passes the `<pid>` (tgid) + initial TID list (the kernel-side thread-group walk
is deliberately avoided).

**New-thread following + GC (P1.6b):** while hooked, `shhwbp` inline-hooks (`hook_wrap1`)
`wake_up_new_task` to catch threads created after the hook — if the new task's tgid matches the
target (read via `__task_pid_nr_ns`), it arms a slot and defers the perf install to the new thread's
own context via `task_work` (never registering from the `wake_up_new_task` entry). It also hooks
`do_exit` to GC the exiting thread's slot (clear `active`/`bp`, **no** `unregister` — the kernel reaps
the perf_event itself), keeping the table bounded under thread churn. Both wraps are removed on
`unhook`/module exit. Safety net: a task ref is leaked per slot, `dump` never derefs `task`/`bp`, and
`unhook` drops a slot without `unregister` if `task_work_add` fails on a dead thread — so even a missed
GC cannot UAF. Full RCU on the slot table (article §5.1) is judged overkill for this static array.

### The deferred-work safety model (most important invariant)
Perf/breakpoint kernel APIs (`register/unregister/modify_user_hw_breakpoint`) and other
blocking calls **must never run in the supercall/`KPM_CTL0` context or the breakpoint-exception
handler** — doing so wedges the thread in uninterruptible D-state *while holding a KernelPatch
lock*, which hangs every later supercall (including APatch `su`) and requires a **physical
reboot**. The pattern enforced throughout `shhwbp.c`:
- The breakpoint handler (`hwbp_handler`) only **snapshots registers** and queues a
  `task_work_add(target_task, ..., TWA_RESUME)`.
- The real perf calls run later in **the target task's own context** (sleepable, on
  return-to-user) via `tw_install` / `tw_move` / `tw_remove`.

Any new code that touches perf, scheduling, or potentially-blocking kernel APIs must follow the
same defer-to-`task_work` discipline.

### The entry↔return state machine (`shhwbp` P1.5)
arm64 only auto-single-steps over an execute breakpoint when the perf event uses the *default*
overflow handler. A custom handler (needed to capture regs) means a plain execute bp re-triggers
forever (livelock). Fix: on an ENTRY hit, move the bp to the return address (`LR`/x30, PAC-stripped
via `STRIP_PAC`); on the RETURN hit, move it back to ENTRY. This uncovers the entry instruction
before it re-executes — the target runs transparently — and captures both args (X0..X7 at entry)
and return value (X0 at return). State is `g_state` (`ST_ENTRY`/`ST_RETURN`) with `g_move_pending`
guarding against re-queuing.

## Build

Windows + NDK clang (no WSL/gcc). Build scripts are PowerShell. NDK is hardcoded to
`26.1.10909125` (clang 17) inside both scripts — edit the `$ndk` var if yours differs.

```powershell
# KPM (kernel module). Pass any kpm/*.c; output is the matching .kpm + .o next to it.
powershell kpm/build.ps1 -Src shhwbp.c       # -> kpm/shhwbp.kpm   (default Src is shpoc.c)

# shctl userspace CLI -> cli/shctl  (aarch64-linux-android33)
powershell cli/build_shctl.ps1
```

KPM build flags are load-bearing — do not change without re-testing on device:
- **`-O0` only.** clang `-O2` miscompiles for the KP module loader → runtime SP/PC-alignment
  panic and device reboot. (Upstream demos use gcc `-O2`; that does not transfer to clang.)
- **`-mbranch-protection=bti`** — the bp handler is called indirectly by kernel perf and needs BTI
  landing pads.
- `--target=aarch64-none-elf -nostdinc -ffreestanding -mgeneral-regs-only`, then a relocatable
  link (`-r -nostdlib`). Include set mirrors the upstream kpm Makefile
  (`kpm/build.ps1` derives `-I` flags from `vendor/KernelPatch/kernel/{.,include,patch/include,linux/...}`).

`hbtarget` has no build script; compile it the same way as `shctl` (`--target=aarch64-linux-android33`).

## Deploy & run (on device)

Requires a **physical ARM64 device** with APatch + KernelPatch and its **superkey**. Cloud phones
can't run this (no custom kernel / KPM). Always wrap device supercalls in `timeout N` during
development, and **always `unhook` before `unload`** (unhook needs the target alive). `shctl` and
`hbtarget` persist across reboot once pushed; re-push the `.kpm` after every rebuild.

```powershell
adb push kpm/shhwbp.kpm /data/local/tmp/ ; adb push cli/shctl /data/local/tmp/
adb push tools/hbtarget /data/local/tmp/ ; adb shell su -c 'chmod 755 /data/local/tmp/shctl /data/local/tmp/hbtarget'

# KEY = APatch superkey
adb shell su -c '/data/local/tmp/shctl KEY load /data/local/tmp/shhwbp.kpm'
adb shell su -c '/data/local/tmp/shctl KEY control shhwbp probe'                  # resolve kernel symbols
adb shell su -c 'setsid /data/local/tmp/hbtarget >/data/local/tmp/hbt.out 2>&1 </dev/null &'
adb shell cat /data/local/tmp/hbt.out                                            # -> pid=.. tick=0x..
adb shell su -c '/data/local/tmp/shctl KEY control shhwbp "hook <pid> <tickaddr>"'
adb shell su -c '/data/local/tmp/shctl KEY control shhwbp dump'                  # captured args + return
adb shell su -c '/data/local/tmp/shctl KEY control shhwbp unhook'
adb shell su -c '/data/local/tmp/shctl KEY unload shhwbp'
```

Kernel-side `logki`/`logke` output goes to the kernel log (`adb shell su -c 'dmesg'`), not to
`shctl` stdout — `shctl` only prints the `KPM_CTL0` reply buffer.

## Version coupling (must stay in sync)

Two independent version pins must match the device, or load/supercall silently fails:
- `vendor/KernelPatch` is checked out at tag **0.13.1**; the kpm SDK headers it provides must match
  the kpimg version on the device (verified: kpimg `d01` = 0.13.1).
- `KP_VER_CODE` in `cli/shctl.c` (`(0<<16)|(13<<8)|1`) encodes the KernelPatch version into every
  supercall's `vcmd`. Bump it to match the device's KernelPatch if you upgrade.

## Module map (`kpm/`)

- `shpoc.c` — P0 smoke test: hooks `__NR_execve` via the SDK `hook_syscalln` API. Proves the
  toolchain + KPM load path works. No control channel.
- `shmin.c` — minimal `KPM_CTL0` isolation test (init + fixed-string ctl0 + exit).
- `shhwbp.c` — P1.5/P1.6 HWBP hook: per-thread breakpoint table + entry↔return state machine with
  `task_work` deferral (the real PoC; everything above describes it).
- `shpte.c` — P2 PTE/UXN "high-voltage net". Commands: `pte` (read+decode a leaf PTE, read-only),
  `arm` (set `PTE_UXN` on the target code page + `hook_wrap3(do_page_fault)`, **self-heal** the
  fault — P2.1), `redirect` (same but keep UXN set and set `regs->pc = clone + (far & 0xfff)` to
  reroute into a userspace clone page — P2.2), `disarm`/`dump`. PTE resolved via `get_task_mm` +
  `apply_to_existing_page_range` (callback hands the `pte_t*`, no mm/pgd offsets); bits from KP's
  `pgtable.h`. The `do_page_fault` callback is hard-gated (armed + exact target page + faulting
  `tgid` via `__task_pid_nr_ns`/`get_current`) and the PTE pointer is cached at arm time so the hot
  path does no page walk. `redirectmap` (P3.1) routes via an `offset_map` (orig-insn-idx → clone-insn-idx) read from the
  target with `access_process_vm` and cached in `g_offmap[1024]`, so a DBI clone whose instructions
  shifted still routes correctly. The userspace **DBI recompiler** lives in the targets, not the KPM
  (the kernel only routes the entry fault): `tools/dbitarget.c` (P2.2, verbatim clone of a
  PC-relative-free `tick()`), `tools/dbitarget2.c` (P3.2, fixes ADR/ADRP/B/BL), `tools/dbitarget3.c`
  (P3.3, 3-pass engine: also re-encodes internal B/B.cond/CBZ/TBZ clone-relative for loops/branches).
  `pagehook <pid> <page> <clone> <map> <ninsn> <target_off> <replace>` UXN-traps a **whole page** and
  routes every faulting instruction into a whole-page DBI clone (per-page `offset_map`), overriding
  **one** function's entry (`page+target_off`) to `replace` while the clone's faithful copy of that
  function serves as the `backup` — the process-wide, page-neighbor-safe inline hook for real
  (page-shared) functions (target `tools/pagetool.c`). `pghook`/`pgdisarm` are the **multi-page** form:
  a fixed `g_pg[MAX_PG]` table so several such pages can be trapped at once (what an LSPlant frontend
  needs — many libart funcs on distinct code pages, all hooked simultaneously); the shared `before_pf`
  routes each fault by `(page, tgid)` to its slot, and the single `do_page_fault` hook is **ref-counted**
  across the single-page and multi-page paths (`ensure_pf_hooked`/`maybe_unhook_pf`).
  `hidemaps`/`unhidemaps` (P4.1) hook `show_map` and drop the clone's VMA from `/proc/*/maps` output
  (rewind `seq_file->count` + `SEQ_SKIP`; struct offsets taken from the device's kernel BTF).
  `hookto`/`hwhookto <pid> <target> <replace> <clonebytes> <nclone> <template> <ghost_va>` are the
  **inline_hooker primitive** (for LSPlant): route the target's entry to a `replace` function (LR
  untouched → replace returns to the original caller), with a DBI ghost clone of the target as the
  `backup`. `hookto` uses UXN (whole-page → only for page-isolated targets); **`hwhookto` uses a
  hardware breakpoint** (per-instruction → correct for real, page-shared libart functions; this is
  the one the Vector/LSPlant integration uses — see memory `lsplant-vector-integration`). `bridge`/
  `unbridge` arm a magic-gated `personality()` syscall so an injected agent can run any command
  **without the superkey** (shared dispatcher `shpte_run`). `hidetracer` spoofs `/proc/*/status`
  TracerPid to 0 (anti-debug). `ghosttest`/`ghostredirect`/`ghostfree` (P4.2) implement **VMA-less
  ghost memory**: `vmalloc` a
  page, get its PFN via `vmalloc_to_pfn` (NOT `virt_to_phys` — its `linear_voffset` isn't exported to
  KPMs), copy attrs from a template exec page, `apply_to_page_range`-inject a PTE at a no-VMA VA, and
  (for `ghostredirect`) `sync_icache` + route the UXN redirect there so the DBI clone executes from
  memory the OS can't see. The DBI recompilers live in the targets (`dbitarget.c`..`dbitarget4.c`,
  `ghostexec.c`: verbatim → ADR/ADRP/B/BL → internal/conditional branches → LDR-literal). The full
  pipeline (P1.6→P2→P3→P4.2) is device-verified. **Remaining: P3.5** (`BLRAAZ`→`BRAAZ` PAC demote;
  needs a pauth-built target).

Test targets live in `tools/`: `hbtarget.c` (single thread) and `mttarget.c` (main + 4 workers, for
P1.6). `tools/run_mt_test.sh` is the device-side end-to-end harness; neither target has a build
script — compile them like `shctl` (`--target=aarch64-linux-android33`).
