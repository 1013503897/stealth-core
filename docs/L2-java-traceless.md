# L2 — Traceless Java-method hooking (design spec)

Status: **design** (no code shipped by default; L2a is implemented behind a compile gate — see below).
Builds on L1 (native libart inline hooks already traceless via KPM region clones) +
M2/M2.1 (clone VMAs hidden from /proc/maps and /proc/smaps). See the main `README.md`
"Layer 2" line.

## The problem

LSPlant hooks a Java method `M` by **mutating M's ArtMethod in place** (`DoHook`,
`lsplant.cc:528`):

| Mutation | code | what an in-app anti-cheat reads |
|---|---|---|
| `M.entry_point_from_quick_compiled_code_` ← trampoline | `SetEntryPoint` art_method.cxx:116 | entry points at an anomalous addr (not M's oat/jit code) → "pointer roaming" |
| `M.access_flags`: set `kAccCompileDontBother`, clear `kAccPreCompiled`/`kAccFastInterpreterToInterpreterInvoke` | `SetNonCompilable`/`ClearFastInterpretFlag` art_method.cxx:51-62 | anomalous flags |
| backup ArtMethod (full memcpy, made private) | `BackupTo` art_method.cxx:169 | a duplicate ArtMethod of M |
| trampoline page (PROT_RWX mmap) | `GenerateTrampolineFor` lsplant.cc:483 | anomalous exec map |

Goal: install the same logical hook with **M's ArtMethod left pristine** and **M's
compiled code bytes unmodified**, so none of the above is observable.

## Where a method's quick entry points

Where a method's quick entry actually points (`M.GetEntryPoint()`, art_method.cxx:126 —
a pure read):

- **AOT method** → file-backed `r-xp` in the boot image / app code (`dalvik-cache/arm64/boot.oat`,
  plus per-jar `…@classes.odex`).
- **Interpreted method** → a SINGLE shared libart bridge `art_quick_to_interpreter_bridge`
  inside `libart.so` (one address for ALL interpreted methods).
- **JIT method** → an anon `[anon:jit-code-cache]` RX region (the rarer case; deferrable).

Key consequence: an AOT method's quick code lives in a **file-backed r-xp page**, which is
exactly the shape L1's `pghook` already traps (per-process PTE UXN flip → fault → region
clone; bytes never touched → CRC-clean; clone hidden by M2/M2.1).

## Design: route L2 through the existing L1 KPM, don't touch the ArtMethod

In a forked `DoHook`, **replace** `SetEntryPoint(trampoline)` + the flag mutations with:

1. `void *qc = M.GetEntryPoint();`  // read M's real quick-code address (no write)
2. classify `qc`'s region (read `/proc/self/maps` once, cache): boot.oat / app-odex (AOT) |
   libart bridge (interpreted) | jit-code-cache (JIT).
3. **AOT case (L2a, first slice):** `pghook` the clean-bounded region containing `qc`,
   with an override `(qc - region_base) → trampoline`. Keep LSPlant's per-method
   `GenerateTrampolineFor(hook)` and its dispatch UNCHANGED — only the *delivery* changes:
   instead of M.entry_point pointing at the trampoline, the KPM reroutes M's faulting entry
   PC → the trampoline. The quick-ABI registers are already set for M's call, so the
   trampoline runs exactly as before. **Call-original** = the pghook clone's faithful copy
   of M's code (same backup mechanism L1 returns), invoked without re-faulting.
4. Leave `M.access_flags` and `M.entry_point` UNCHANGED.

Result: M's ArtMethod is byte-identical to an unhooked method; M's oat bytes are pristine
(CRC-clean); the only new exec memory is the region clone, already hidden by M2/M2.1.

### Detection-surface elimination (vs the table above)

| surface | LSPlant today | L2a |
|---|---|---|
| entry_point roaming | trampoline addr | **unchanged** (real oat addr) |
| access_flags | mutated | **unmodified** |
| backup ArtMethod | present | not needed (clone is the backup) |
| oat/.text CRC | n/a (entry swap) | **clean** (UXN trap, no byte write) |
| anomalous exec map | trampoline RWX | clone region (hidden by M2/M2.1) |

## Hard parts / open decisions (resolve before / during impl)

1. **Optimization churn.** LSPlant sets `kAccCompileDontBother` precisely to stop ART from
   re-JITing M and overwriting M.entry_point. If we DON'T set it (for tracelessness), ART may
   compile M → M.entry_point moves to new JIT code → our trap on the old AOT page goes stale
   (hook silently stops firing). Options: (a) accept staleness for cold methods (PoC only);
   (b) **L2b**: hook ART's JIT install path (the L1-traceless `FixupStaticTrampolines` / jit.cxx
   / instrumentation.cxx hooks LSPlant already wires) to OBSERVE the move, read the new
   `GetEntryPoint()`, and re-`pghook` the new page — keeping the ArtMethod pristine throughout.
   This is the robust answer and reuses existing L1 hook points.
2. **Interpreted methods (L2c).** Quick entry is the shared interpreter bridge — cannot trap
   per-method. Need either: force one-shot compilation of M (visible flag → not traceless), or
   hook the interpreter execute path (L1-traceless) + per-method ArtMethod-pointer check to
   reroute. Hardest case; defer past L2a/L2b.
3. **Region pressure.** `MAX_PG=16` regions are shared across ALL hooks (L1 already uses 6 in
   the manager). A real module hooking many Java methods could exceed it. Mitigations: many
   methods often share a few oat pages (one region, multiple overrides — `MAX_OV`), and/or the
   HWBP `hwhookto` path (entry-only, no clone, but ≤~4 HW slots) for a few hot methods.
4. **Driving it from the glue.** Need a `kpm_java_hook(entry_addr, trampoline)` glue entry that
   maps onto `pghook`/`pgunhook` (region containing `entry_addr`, override at the entry offset).
   The KPM itself needs NO change for L2a — pghook already does region-clone + per-offset override.

## Incremental roadmap

- **L2a** — AOT method, no churn handling: read entry, pghook its oat region, override → LSPlant
  trampoline; ArtMethod pristine. Verify on a known AOT framework method: hook fires, original
  callable, `M.entry_point`/`access_flags` byte-unchanged vs an unhooked sibling, oat CRC clean,
  clone hidden. **Smallest end-to-end traceless L2 proof.**
- **L2b** — follow JIT/optimization moves via the existing ART hook points; re-pghook on move.
- **L2c** — interpreted-method path (interpreter choke-point + per-method check).

## Implementation findings (DoHook + the glue)

Three findings that shape the implementation:

1. **The glue already does L2a — no glue change.** `kpm_inline_hooker(target, hooker)`
   (kpmhook.c:323) finds/builds the clean-bounded region containing `target`, DBI-clones it,
   sends `pghook` with override `(target-base) → hooker`, and returns the **in-clone faithful
   copy** of target. For L2a: `kpm_inline_hooker(M.GetEntryPoint(), trampoline)`. Done.

2. **CALL-ORIGINAL RECURSION TRAP (critical).** LSPlant's `backup` ArtMethod normally gets
   target's *original* entry via `BackupTo` (art_method.cxx:169), so calling backup runs M's
   real code. In the traceless path that's WRONG: M's oat entry is now KPM-trapped (the UXN
   trap fires for ANY execution reaching that address, whatever ArtMethod points there), so
   calling backup → faults → reroutes to the trampoline → **infinite recursion**. Fix: point
   backup at the **in-clone copy** returned by `kpm_inline_hooker` (the clone is NOT trapped),
   i.e. `backup->CopyFrom(target); backup->SetEntryPoint(clone_backup); backup->SetNonCompilable();`.
   Target itself stays 100% pristine (no BackupTo, no SetNonCompilable, no SetEntryPoint on it).

3. **Cannot reuse `info_.inline_hooker` for L2a.** That callback (used by HookHandler,
   hook_helper.hpp:171) routes through Vector's `HookInline`, which **falls back to DobbyHook**
   when the KPM path returns null. For a Java method that fallback would *patch the shared,
   CoW boot.oat page* — both detectable (CRC) AND corrupting (the page is shared across procs
   via the page cache; an inline patch there is catastrophic). So DoHook needs a **KPM-ONLY**
   hooker (no Dobby fallback) whose failure falls back to LSPlant's normal *in-place* hook, not
   to Dobby. That means a new `InitInfo` field (e.g. `kpm_only_hooker`) stored globally at Init
   and called by DoHook — a multi-file change (lsplant.hpp InitInfo + Vector Init wiring + DoHook).

**Guarded DoHook shape** (compile-time `LSPLANT_KPM_TRACELESS_L2`, default OFF so the verified
L1 path is untouched; KPM failure falls back to the existing in-place hook):
```
auto *entrypoint = GenerateTrampolineFor(hook);            // unchanged
#ifdef LSPLANT_KPM_TRACELESS_L2
if (kpm_hook_init()==0) {
    void *qc = target->GetEntryPoint();                    // READ, no write
    if (void *clone_backup = kpm_only_hooker(qc, entrypoint)) {
        backup->CopyFrom(target);
        backup->SetEntryPoint(clone_backup);               // call-original via clone (no re-fault)
        backup->SetNonCompilable();
        if (!backup->IsStatic()) backup->SetPrivate();
        return true;                                       // target ArtMethod untouched
    }
}
#endif
target->BackupTo(backup); target->SetNonCompilable(); target->SetEntryPoint(entrypoint); // default
```

**Unvalidated risk — DBI on oat.** `dbi_recompile_range` (lib/dbi) was verified on
libart.so `.text` + a synthetic span fn, NOT on dex2oat output. The clone is used for (a)
neighbor methods sharing M's region and (b) call-original — both need a faithful oat recompile.
dex2oat code may use addressing/runtime-register patterns the DBI doesn't preserve.

## DBI-on-oat feasibility

Static analysis of a device `boot.oat` PF_X segment (via `kpm/oat_census.py`) supports DBI feasibility:

- **Instruction types.** Every PC-relative type present (ADRP/CBZ/CBNZ/B/B.cond/BL/TBZ/LDR-lit/ADR,
  ~16% of instructions) is DBI-rewritten; the rest (~84%: BLR/BR/RET/loads/stores/ALU) is
  PC-independent and safe verbatim. Crucially, **no PAC calls (`BLRAA*`/`BRAA*`) are emitted at
  all**, so the one known DBI gap (P3.5 passthrough) isn't triggered. (Static type coverage,
  not execution proof.)
- **Region boundaries.** The clone needs a clean page boundary (RET/B/NOP before it) within
  `MAX_RGN=64` pages of the target. oat is dense — clean page boundaries are sparse (~3.7%, even
  sparser than libart) — but ~**90%** of AOT start-pages still find a clean region end within 64
  pages (region size median ~17 pages, max 64). The ~10% tail can't be region-cloned and falls
  back to HWBP entry-only or in-place.

**Verdict: DBI-on-oat is feasible for ~90% of AOT methods** (instruction types 100% handled,
clean region findable for ~90%); the uncloneable tail needs a fallback.

## L2a status (AOT, behind `LSPLANT_KPM_TRACELESS_L2`)

L2a is implemented and gated OFF by default (the verified L1 path is unaffected). Key design
points that emerged:

- **KPM-only hooker, never Dobby.** DoHook uses a KPM-only hook path whose failure falls back to
  LSPlant's normal *in-place* hook — **not** Dobby, which would inline-patch the shared, CoW
  `boot.oat` page (detectable via CRC, and corrupting: the page is shared across processes via the
  page cache).
- **Shared-stub guard (`QcIsTraceable`).** Many framework methods are not individually AOT-compiled
  — they share an nterp/bridge stub that itself lives in boot.oat, so a naive "qc in an oat region"
  test wrongly accepts them, and trapping a shared stub reroutes *every* method using it. The guard
  additionally requires a sane `OatQuickMethodHeader.code_size` at `qc-4` (a shared stub's `qc-4`
  is an instruction word, far above any real method's size) → stubs/interp/JIT fall back to the
  in-place hook.
- With the gate on, a hooked AOT method keeps its ArtMethod byte-pristine (`entry_point` /
  `access_flags` unchanged), oat CRC clean, and the clone hidden — the whole detection-surface
  table above goes to CLEAN for AOT methods.

**Remaining for productionizing:** L2b JIT-move follow (a traceless-hooked method that later
JIT-compiles moves its entry off the trapped page → the hook goes stale; re-trap via the existing
L1 ART JIT hook-points); L2c interpreter/nterp (most framework methods — currently fall back,
correct but not traceless); KPM dead-process region GC (repeated kills leak regions until MAX_PG,
reboot clears); a per-app gate so real target apps engage the KPM.

## M-C design — traceless hooking of nterp/interpreted methods

Real-app methods are mostly NOT individually AOT-compiled: their entry_point is a SHARED
nterp/bridge stub in boot.oat, so there is no per-method native code to trap → they fall back to
the in-place hook (entry swap) → surface #3 (ArtMethod entry/flags) DETECTED. To make them
traceless the method must be given its OWN compiled code, then trapped like an AOT method.

Force-compile path (symbols mapped): Jit::EnqueueOptimizedCompilation(jit,method,self) and
AddCompileTask(self,method,kOptimized,false) (jit.cxx — LSPlant HOOKS them but exposes no caller);
nterp detect = entry == art_quick_to_interpreter_bridge (class_linker.cxx); after compile read
method->GetEntryPoint() (now JIT code in [anon:dalvik-jit-code-cache]).

HARD CONSTRAINT: DoHook runs under ScopedSuspendAll (all threads frozen), but JIT compilation is
ASYNC on a background thread that CANNOT run while suspended → can't wait for the compile inside
DoHook (deadlock). So force-compile + trap MUST be deferred out of the suspend.

Design (in-place-then-async-upgrade):
1. DoHook(nterp, traceless): do the normal IN-PLACE hook so it works immediately, AND record
   (target, trampoline) on a "pending traceless upgrade" queue.
2. A Vector worker thread (outside suspend-all): for each pending method — EnqueueOptimized
   Compilation(target), poll GetEntryPoint() until it is JIT code (timeout → leave in-place),
   then under a fresh short suspend: trap the JIT region via kpm_inline_hooker(jitqc, trampoline),
   point the backup at the in-clone copy, and RESTORE target's ArtMethod to pristine (undo the
   entry swap + flags). Net: brief in-place window at startup → traceless thereafter.
3. L2b JIT-move follow: ART may re-JIT/GC-move the method (GarbageCollectCache/DoCollection →
   MoveObsoleteMethod, hooked by LSPlant) → re-read GetEntryPoint, re-pghook the new region. The
   jit region clone is anon RX → hidden by the existing maps-hide; its trampoline by hidergn.

Open risks: restoring the ArtMethod while the method may be executing (race); compile may never
fire for a cold method (timeout → stays in-place/detectable); jit-cache region churn.

## M-C force-compile constraints (for the deferred upgrade path)

Two hard constraints govern the force-compile-then-trap approach:

1. **JIT thread not up during postAppSpecialize.** Vector's own framework bootstrap hooks
   (Thread.dispatchUncaughtException, DexFile.openDexFile/openInMemoryDexFiles, LoadedApk.<init>)
   install in postAppSpecialize, BEFORE the app's main / the JIT compiler thread starts. So an
   EnqueueOptimizedCompilation there never completes → a synchronous poll-wait blocks app init →
   AMS kills the app. A compile-and-wait in DoHook is a non-starter for early hooks.
2. **CompileDontBother conflict.** LSPlant's in-place hook sets kAccCompileDontBother (via
   BackupTo→SetNonCompilable) precisely to STOP ART re-compiling and overwriting the trampoline
   entry. That directly blocks force-compile. More deeply, LSPlant's ENTIRE machinery
   (ShouldUseInterpreterEntrypoint, FixupStaticTrampolines, the jit.cxx/instrumentation.cxx hooks)
   exists to KEEP entry==trampoline against ART optimization. Traceless wants the OPPOSITE: let ART
   compile the method (entry==JIT code) and trap that. So M-C must DISENGAGE LSPlant's keep-the-hook
   path for traceless methods — a real divergence, not a small add.

Design directions (deferred upgrade):
- DoHook(nterp, traceless): record (target,hook,trampoline) on a pending list; do NOT set
  CompileDontBother (so ART can still compile); either skip the in-place hook (method runs
  un-hooked until upgrade — breaks framework hooks that fire at startup) or do a minimal entry
  swap that a later step undoes.
- A post-init worker (JIT up): EnqueueOptimizedCompilation each pending method, wait for a JIT
  body (now compiles), then trap it traceless (kpm_inline_hooker) + set the ArtMethod to the
  pristine compiled state (entry=JIT, normal flags, no backup).
- Hardest open question: the early framework bootstrap hooks MUST fire during startup, but can't be
  compiled then. Options: keep them in-place but EXCLUDE them from the goal's S3 scope (they hook
  obscure framework methods an anti-cheat is unlikely to inspect — weak), OR upgrade them post-init
  too (undo in-place + retrap, racy), OR force-compile them once the JIT is up via LSPlant's
  existing JIT hook-points firing on the first real compile.
- Region pressure: each traceless nterp method = its own JIT-region trap slot; MAX_PG=16 shared.
  Many module hooks could exhaust it even with the GC. May need the HWBP entry-only fallback.

M-C (surface #3, the interpreter/nterp path) is the sole remaining goal blocker; surfaces
1/2/4/5 are already CLEAN in a real gated app.
