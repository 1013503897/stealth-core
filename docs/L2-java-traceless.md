# L2 — Traceless Java-method hooking (design spec)

Status: **design** (investigation + on-device grounding done; no code yet).
Builds on L1 (native libart inline hooks already traceless via KPM region clones) +
M2/M2.1 (clone VMAs hidden from /proc/maps and /proc/smaps). See the main `README.md`
"Layer 2" line and memory `kpm-layer2-java-hook`.

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

## On-device grounding (Pixel 6, live LSPosed-manager host pid 6685)

Where a method's quick entry actually points (`M.GetEntryPoint()`, art_method.cxx:126 —
a pure read):

- **AOT method** → file-backed `r-xp` in the boot image / app code:
  `70cfc000-71762000 r-xp …/dalvik-cache/arm64/boot.oat`, plus per-jar `…@classes.odex`.
- **Interpreted method** → a SINGLE shared libart bridge `art_quick_to_interpreter_bridge`
  inside `73f8077000-73f885a000 r-xp …/libart.so` (one address for ALL interpreted methods).
- **JIT method** → an anon `[anon:jit-code-cache]` RX region. **Not present in this process**
  (manager is AOT/interpreted) — so JIT is the rarer case here, deferrable.

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

First concrete step next session: pick a definitely-AOT framework method in the manager host,
read its `GetEntryPoint()`, confirm it lands in boot.oat and which clean-bounded region — then
wire the `kpm_java_hook` glue for L2a.

## Implementation findings (from reading DoHook + the glue, 2026-06-11)

Read of `lsplant.cc:528 DoHook`, the KPM glue `stealth-poc/lib/kpmhook.c`, and
`hook_helper.hpp:171`. Three findings that change the implementation:

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

**Unvalidated risk — DBI on oat code.** `dbi_recompile_range` (lib/dbi) was verified on
libart.so `.text` + a synthetic span fn, NOT on dex2oat output. The clone is used for (a)
neighbor methods sharing M's region and (b) call-original — both need a faithful oat recompile.
dex2oat code may use addressing/runtime-register patterns the DBI doesn't preserve.

### DBI-on-oat validation step 1 — instruction-type census (2026-06-11, `kpm/oat_census.py`)

Pulled the device's `boot.oat` (14.6 MB ELF) and censused its PF_X segment (10.6 MB,
**2,725,478** arm64 instructions). Result strongly POSITIVE for DBI feasibility:

| bucket | share | DBI |
|---|---|---|
| PC-relative the DBI **rewrites** (ADRP 6.15, CBZ/CBNZ 3.33, B 2.80, B.cond 2.42, BL 0.87, TBZ 0.22, LDR-lit 0.03, ADR 0.00) | **15.83%** | handled |
| PC-independent verbatim (BLR 7.26, BR, RET 1.09, loads/stores/ALU 75.82) | ~84% | verbatim-OK |
| **PAC indirect call/jump `BLRAA*`/`BRAA*`** (the P3.5 verbatim-passthrough gap) | **0.000%** | n/a — NONE present |

Key: this image emits **no PAC** at all (no BLRAA*/BRAA*, no paciasp/retaa) despite the Pixel 6
supporting ARMv8.3 PAC — so the one known DBI gap is NOT triggered. Every PC-relative type
present is already rewritten; everything else is PC-independent and safe verbatim. **No
instruction type in this oat would be mis-handled.**

CAVEAT: this is static TYPE coverage, not execution proof. Two validations remain:
(step 2, offline, cheap) run `dbi_recompile_range` on real oat regions at their runtime VA and
confirm it succeeds (rewrite logic + clean-boundary availability within MAX_RGN=64 — oat may be
denser than libart) — the DBI is host-runnable (`lib/build_dbi_test.ps1`); (step 3, integration)
execute a cloned oat region inside an ART process and confirm correct behavior (the only true
proof; needs the DoHook integration + a Java hook in the gated process).
