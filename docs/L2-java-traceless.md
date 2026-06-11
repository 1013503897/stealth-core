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
