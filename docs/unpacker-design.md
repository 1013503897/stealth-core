# Stealth unpacker — traceless DEX/extraction-shell unpacker on Vector (design spec)

Status: **design** (grounded against the existing Vector/lsplant primitives; no code yet).
Builds on L1 (native libart inline hooks traceless via KPM region clones, `kpm_inline_hooker`)
+ M2/M2.1 (clone VMAs hidden from /proc/maps + /proc/smaps) + M-C infra
(`ForceCompileMethod`, the post-init worker `RunTracelessConvert`). See `L2-java-traceless.md`
and memory `kpm-ultimate-goal` / `kpm-layer2-java-hook`.

## 0. Goal & scope

**Goal:** inside a packed target process, pin the *CodeItem-restore choke point* with Vector's
**traceless** hook, drive the shell to restore method bytecode (active invocation), capture each
method's CodeItem, and reassemble a complete DEX — **with zero detectable surface to the shell's
anti-dump / anti-debug / libart self-CRC**. This stealth property is the *only* differentiation
vs FART (modified ROM = detectable) and BlackDex (ptrace = `TracerPid≠0`). It is what lets us
unpack extraction shells that carry an anti-dump self-check.

**In scope:** whole-DEX shells + **function-extraction shells** (抽取壳: per-method CodeItem
encrypted, restored on first execute/compile).

**Out of scope (the fundamental ceiling of *all* dump-based unpackers — stealth does not help):**
VMP / bytecode virtualization, dex2c / OLLVM native protection. These hold no standard CodeItem
to dump. Do not promise these.

## 1. Architecture — reuse vs new

| Subsystem | Role | Status |
|---|---|---|
| Injection + package gate | run inside the packed process | **reuse** — `kpm_hook_set_process_name` (kpmhook.h), `persist.kpmhook.target` |
| Symbol resolver | resolve libart internals by mangled name | **reuse** — `ElfSymbolCache::GetArt()->getSymbAddress()` (module.cpp:123) |
| Stealth hook primitive | traceless-pin the choke point | **reuse** — `kpm_inline_hooker(code, hooker)` (kpmhook.h), L1-grade DBI |
| Post-init worker | run the driver after the JIT/app is up | **reuse** — the attach-ART-thread scaffold of `RunTracelessConvert` (module.cpp:307) |
| Force-compile driver | trigger shell restore without executing | **reuse** — `ForceCompileMethod` (module.cpp:116): resolves `Runtime::instance_` / `GetJit` / `Jit::EnqueueOptimizedCompilation` |
| Class/method enumeration | walk every ArtMethod to unpack | **new** — `ClassLinker::VisitClasses` (symbol-resolvable) + `mirror::Class` method-array accessors |
| CodeItem capture sink | grab CodeItem in the choke-point cb + persist | **new** |
| DEX reassembler | splice captured CodeItems back into the whole-dex image | **new** — pure host-side, zero Vector coupling |

Net: the unpacker is **the M-C worker with a different verb**. M-C = "enumerate hooked methods →
force-compile → trap". Unpacker = "enumerate *all* methods → force-compile/invoke → *capture
CodeItem*". The worker, the force-compile call, the symbol resolution already exist.

## 2. Choke-point selection (the key decision)

An extraction shell only refills a method's CodeItem when it is actually executed/compiled. The
choke point must (1) see the *restored* CodeItem and (2) be **a single libart function**, so a
single `kpm_inline_hooker` trap covers it (this stays in the L1 regime — it does NOT hit the
per-method DBI scale problem of M-C; see §4).

Candidates (sorted by DBI-clone cost; all symbol-resolved with a fallback set, mirror the
multi-symbol `|` pattern in `dex_file.cxx:21-39`):

| Choke point | Fires when | Yields | DBI clone cost |
|---|---|---|---|
| `ArtMethod::Invoke` / `artInterpreterToInterpreterBridge` | every interpreted/reflect call | ArtMethod → `GetCodeItem()` | **medium (small fn)** |
| `MethodVerifier::Verify` / compile entry | CodeItem read at verify/compile | ArtMethod + CodeItem | medium |
| `art::interpreter::Execute(...)` | interpreter main dispatch | `CodeItemDataAccessor` (restored CodeItem) | **high (huge, multi-page fn)** |

**Recommendation: primary choke = `ArtMethod::Invoke` (or `artInterpreterToInterpreterBridge`),
NOT `Execute`.** Rationale is DBI: `Execute` is one of libart's largest/hottest functions
(multi-page, complex patterns) — cloning it correctly is the single most expensive, most
fault-prone item. `Invoke`/bridge are far smaller, close to the ~20 already-validated libart
functions. Capture inside the callback by reading `method->GetCodeItem()` +
`method->GetDexFile()->Begin()/Size()` ourselves — do not depend on the CodeItem arriving as an
argument.

**Where the stealth lives:** `kpm_inline_hooker` leaves libart `.text` byte-identical, hides the
clone from maps/smaps, no ptrace — the shell's CRC self-check / anti-dump cannot see us capturing.
This is exactly what FART's modified ROM and BlackDex's ptrace cannot do. For shells with **no**
anti-dump self-check, degrade to a plain inline hook (skip the DBI cost); only pay
`kpm_inline_hooker` when the shell self-checks. Make it a switch (`persist.kpmhook.unpack.stealth`).

## 3. Active invocation (reuse `ForceCompileMethod` + the worker)

Many extraction shells never restore a method that is never called — force a sweep. Three tiers,
ascending risk; **default ships at Tier-B**:

- **Tier-A passive:** only pin the choke point, run/drive the UI normally, capture whatever
  naturally executes. Zero risk, lowest coverage.
- **Tier-B force-compile driver (primary):** in the worker, `VisitClasses` → for each ArtMethod
  **reuse `ForceCompileMethod`'s `EnqueueOptimizedCompilation`** to make ART read its CodeItem.
  Enough for "restore-on-verify/compile" shells, and it does **not execute arbitrary code → much
  safer than FART's invoke-everything.**
- **Tier-C FART-style full invoke (switch, risky):** `Invoke` each ArtMethod with a fabricated
  arg frame. Covers "restore-only-on-call" shells, but carries FART's crash/side-effect risk.
  Isolate in a child process / guard if pursued (P4).

Only new dependency for enumeration: `ClassLinker::VisitClasses(ClassVisitor*)` (symbol-resolved);
the visitor walks each `mirror::Class`'s ArtMethod array (`NumMethods`/`GetMethodsPtr`, add as an
accessor in `art_method.cxx`). Scheduling reuses `RunTracelessConvert`'s attach-ART-thread +
poll-`HasCapturedJit` pattern verbatim.

## 4. DBI: the scale problem does NOT apply here (correction)

Earlier framing ("DBI needs to scale to thousands of methods") is wrong after reading the code:

- The stealth hook pins **1 libart function (the choke point), not thousands of app methods.**
  That is the L1 case (equivalent to the existing ~20 libart traps) and runs the
  **DBI-on-libart** path (`oat_census`-validated) — **NOT** the M-C **DBI-on-JIT** path.
- The **2026-06-13 SIGILL (DBI mis-compiles dense JIT code) is OFF this critical path** — the
  unpacker does not per-method KPM-trap app methods; it compiles/invokes them to trigger restore,
  it does not clone their JIT bodies.
- **The only real DBI cost is one item:** make lib/dbi correctly clone *the chosen choke-point
  function*. Pick `Invoke`/bridge (small) → cost near the validated regime. Pick `Execute`
  (large, multi-page) → that is the hard bone. **Selection is risk control** — prefer the small
  function, and first `measure` its instruction mix (run the `oat_census.py` approach over that
  one function) before committing.

Net: **no "DBI scale-up" is needed; a one-time DBI correctness check on a single choke-point
function is, and the cost is bounded by selection — choose the small one.**

## 5. DEX reassembler (new, host-side, offline)

Each capture records `(dex_base_id, method_idx, code_item_offset, code_item_bytes)`; in parallel
dump each DexFile's whole image (`Begin()`/`Size()`). Reassembly = overwrite the nop'd method
bodies in the whole-dex image at their offsets with the captured CodeItems, fix
checksum/signature — the equivalent of FART's `fart.py`/dexfixer. Persist to an app-uid-writable
path (`/data/data/<pkg>/` or an agreed dir; reuse the logging path convention), pull to host,
stitch offline. **No coupling to Vector — can be written/tested independently.**

## 6. Safety & gating

All under the existing `persist.kpmhook.*` pattern, default OFF:
`unpack=1` master switch, `unpack.tier=A|B|C`, `unpack.stealth=0|1` (0 = plain inline hook,
1 = `kpm_inline_hooker`). Every failure fail-safes to no-op (mirror M-C's in-place fallback). The
default/shipped Vector build does nothing unless gated in.

## 7. Repo placement & milestones

**Repo: stay in Vector — do NOT spin up a new repo.** The in-process agent (choke-point hook,
enumerator, force-compile driver, capture sink) is tightly coupled to Vector's primitives
(`ElfSymbolCache`, `kpm_inline_hooker` glue, the lsplant ART wrappers, the module.cpp worker) and
cannot run without Vector's Zygisk injection. A separate repo would force a submodule dance or a
duplicated injection path — pure overhead for a PoC. Keep it gated (`persist.kpmhook.unpack`,
default off) so it ships safely inside Vector. **But isolate it for a future extract:** put the
in-process code under `native/src/unpack/` (mirrors how `native/src/kpm/` is isolated) with a thin
call from the post-init worker. The **offline reassembler** is non-sensitive, zero-coupling
host tooling → a `tools/dexfixer/` dir now, its own tiny repo later if it proves reusable. This
design doc lives in **stealth-poc/docs** (private, with the sensitive design) because it leverages
the stealth primitive; the *code* lives in Vector per the established split.

| Phase | Content | New code | Notes/risk |
|---|---|---|---|
| **P0 PoC** | plain inline hook on `ArtMethod::Invoke` + capture CodeItem to disk (Tier-A, stealth=0) | small | validates the capture chain; no DBI, no enumeration |
| **P1 enumerate + drive** | `VisitClasses` wrapper + Tier-B force-compile driver (reuse `ForceCompileMethod`) | medium | add ART accessors (NumMethods / GetCodeItem / GetDexFile) |
| **P2 reassemble** | DEX reassembler + whole-dex dump → offline jadx-loadable dex | medium | pure host-side, parallelizable |
| **P3 stealth** | choke point → `kpm_inline_hooker` (stealth=1) + one-time DBI correctness check on that fn + maps hide | medium (mostly validation) | the **only** DBI cost point; selection decides difficulty |
| P4 (opt) | Tier-C full invoke + crash isolation (child proc / guard) | large | high risk, on demand |

Critical path: **P0 → P1 → P3** (P2 parallel). **P0+P1 already unpacks extraction shells with no
self-check; P3 unlocks shells with an anti-dump self-check** — the actual edge over FART/BlackDex.

## 8. Limits (do not over-promise)

- VMP / dex2c / bytecode virtualization: **no solution**, stealth cannot fix it.
- Tier-C active invocation carries FART-class crash/side-effect risk; stealth does not reduce it.
- Choosing `Execute` as the choke point pushes lib/dbi into its hardest case; always `measure`
  the function before selecting it.
