# Traceless Java hooking via SSOL ("single-step out of line") — design

**Status:** design, not implemented. Supersedes the region-clone path for COMPLEX apps (see the
"FINAL VERDICT" in the goal memo / `L2-java-traceless.md`). The region-clone (`do_pghook` + `dbi.c`)
stays for L1 native libart hooks and simple-app Java hooks where it is verified; SSOL is the
correct+scalable path for dense framework JIT.

---

## 1. Why — what the region-clone can't do, and SSOL does

The region-clone UXN-traps a hooked method's PAGE, recompiles the whole page (DBI), and reroutes
execution into a relocated **clone**. Verified clean on simple apps (hookdemo, all 5 surfaces). It is
**structurally fragile on dense framework JIT** for two reasons, BOTH because it runs *relocated*
code:

1. **Code/data interleaving.** JIT methods embed literal pools; a raw byte recompiler can't tell code
   from data without parsing every `OatQuickMethodHeader` → it mangles pool words and, on any
   control-flow divergence, executes them → SIGILL.
2. **Clone return addresses.** Dense framework code does constant indirect calls *into* ART
   (`LDR x30,[x19,#8]; BLR x30`). Running that from a clone puts **clone return addresses on the
   stack** that ART's unwinder/GC/deopt can't map to an `ArtMethod` → SIGSEGV/corruption.

**SSOL keeps the original code at its original address and never relocates the bulk.** Between steps
the PC is always at an ORIGINAL address, so ART's PC→method mapping, stack unwinding, GC root scan,
and deopt all work unchanged, and there is no code/data question (we only ever execute what the
*original* control flow reaches, one instruction at a time).

**Prior art: this is exactly what Linux `uprobes` does on arm64** (`arch/arm64/kernel/probes/
uprobes.c` + `simulate-insn.c`): execute-out-of-line (XOL) for most instructions, *simulate*
PC-relative ones, fix up faults that happen mid-step. uprobes' ONLY incompatibility is that it
triggers by **writing a BRK** (modifies code → detectable). **Our trigger is the UXN execute-fault we
already have (no code write).** So: *traceless uprobes = uprobes' XOL machinery, triggered by UXN
instead of BRK.* We reuse/port the proven kernel logic rather than inventing it.

---

## 2. Architecture at a glance

```
hooked method M on page P (in JIT cache or oat):
  - P is UXN-trapped (PTE |= PTE_UXN), exactly as do_pghook does today. NO code modified.
  - do_page_fault hook (before_pf) sees every EL0 execute-fault on P.

On an execute-fault at original VA `pc` in a trapped region (in before_pf):
  if pc == M's entry  ->  regs->pc = trampoline   (the hook fires; unchanged from today's override)
  else                ->  SSOL one instruction at `pc`:
        decode insn = *pc
        if PC-relative (B/BL/B.cond/CBZ/TBZ/BR/BLR/RET/ADR/ADRP/LDR-literal):
              SIMULATE: compute the exact architectural effect (target PC, dest reg, LR),
                        write it into pt_regs, set regs->pc = result. DONE in the handler.
        else (PC-independent: the vast majority — ALU, MOV, LDR/STR reg, etc.):
              XOL: copy the single insn to a per-thread scratch exec page, run it once,
                   then restore regs->pc = pc + 4.
        // P stays UXN-armed, so the NEXT instruction faults again -> repeat.
```

The hooked method's ENTRY is intercepted (trampoline → hook). The hooked method's BODY (for
call-original) and ALL page-neighbors run via SSOL → original semantics, ART-intact.

UXN is page-table state (per-mm) → it traps **every thread** automatically (no per-thread arming, no
thread-creation hook — a key win over HWBP).

---

## 3. The per-instruction handlers

Reuse the `dbi.c` decoders (`is_b/is_bl/is_bcond/is_cbz/is_tbz/is_adr/is_adrp/is_ldrlit`,
`btarget`, `sext`) — they already classify exactly the PC-relative set.

### 3a. SIMULATE (PC-relative, no execution)
| insn | effect to write into pt_regs |
|---|---|
| `B  t` | `pc = t` |
| `BL t` | `x30 = pc+4; pc = t` |
| `B.cond t` | eval NZCV vs cond → `pc = cond ? t : pc+4` |
| `CBZ/CBNZ Rn,t` | `pc = (Rn==0)==(cbz) ? t : pc+4` |
| `TBZ/TBNZ Rn,#b,t` | test bit → `pc = ... ? t : pc+4` |
| `BR Xn` | `pc = Xn` (Xn already holds an ORIGINAL addr → if it lands in a trapped page it just faults again → SSOL/route; no relocation) |
| `BLR Xn` | `x30 = pc+4; pc = Xn` |
| `RET {Xn=x30}` | `pc = Xn` |
| `ADR Rd,t` | `Rd = pc+imm; pc = pc+4` |
| `ADRP Rd,t` | `Rd = (pc&~0xfff)+imm<<12; pc = pc+4` |
| `LDR(literal) Rt,t` | `Rt = *(t)` (read original pool — mapped & readable; UXN blocks EXECUTE not READ); `pc = pc+4`. SIMD/vector-literal: fall back to XOL-with-fixup (can't write a SIMD reg from C easily) |

This is < ~150 lines; it's the SAME math `dbi.c::emit_one` already does, but writing the *result*
into registers instead of emitting a relocated instruction. **Note `BR/BLR/RET` need NO special
handling** — they set `pc` to a register value that is already an original address; if it's in a
trapped page the next fault routes it; if not it runs natively. This is precisely why SSOL kills
"problem 2": the call/return chain uses ORIGINAL addresses throughout.

### 3b. XOL (PC-independent — copy + single execution)
Everything not in 3a runs identically at any address. Copy the one word to a scratch slot and execute
exactly once, then `pc = orig_pc + 4`. Two ways to regain control after the single insn:

- **(Recommended) HW single-step.** Set `SPSR.SS=1` + `MDSCR_EL1.SS=1` before `ERET` to EL0; the one
  insn executes, then a *Software Step* debug exception is taken to EL1. Hook that handler (see §5).
  Clean, exactly one instruction, no guard pages. This is what uprobes uses
  (`arch_uprobe_post_xol` / `uprobe_single_step_handler`).
- **(Fallback, only `do_page_fault`) guard-page.** Place the insn at the last word of an exec page
  whose next page is UXN/`PROT_NONE`; after the insn, `pc` advances into the guard page → another
  execute-fault → `before_pf` recognizes the guard VA → restore `pc = orig_pc+4`. Avoids hooking a
  second exception but costs a 2nd fault per XOL insn and needs the mid-XOL data-fault fixup (§6) to
  also catch the guard.

Recommend HW single-step (matches uprobes, fewer faults). Keep the guard-page idea as a portability
fallback if hooking the step vector proves fragile on a given kernel.

---

## 4. Per-thread SSOL context (concurrency)

Several threads can be mid-SSOL on different pages at once. Keep a small per-thread context, keyed by
`task` (or stored in a hash by `current`/tid), set when we begin an XOL and cleared when it completes:

```c
struct ssol_ctx { int active; uint64_t orig_pc; uint64_t orig_next; void *xol_slot; };
```
- A small pool of XOL scratch slots (per-CPU array, or per-thread on first use). Each slot = one exec
  page holding `[insn][BRK]` (HW-step) or `[insn]` at page end (guard).
- The Software-Step handler (or guard fault) looks up `current`'s ctx, restores `pc=orig_next`, frees
  the slot, clears `active`, returns. UXN on the page is untouched throughout, so other threads keep
  faulting+SSOL-ing correctly — **no UXN-clear race** (this is the whole reason for out-of-line vs
  "clear UXN + step in place").

---

## 5. Kernel exception surface (what the KPM must hook)

Today the KPM hooks `do_page_fault` (`before_pf`). SSOL adds ONE more hook: the **EL0 software-step /
debug exception**. On arm64 6.1 the relevant entry is the debug path used by uprobes/kgdb:
`arch/arm64/kernel/debug-monitors.c::single_step_handler` (registered via `step_hook`) or
`do_el0_softstep` upstream of it. KernelPatch can inline-hook it like it hooks `do_page_fault`.

Plan: register our own `step_hook` (the kernel exposes `register_user_step_hook`/`step_hook_handlers`)
if those symbols resolve — that's the *intended* extension point and avoids an inline hook entirely.
Else inline-hook the single-step dispatcher. Either way the handler is tiny: "is `current` mid-SSOL?
restore pc, return HANDLED."

Interaction with a real debugger: if the app is ptraced/single-stepped by gdb, our SS use conflicts.
Gate SSOL off when `current->ptrace` is set on that thread (fall back to in-place for that thread, or
defer). Bootstrap/anti-cheat targets are not under gdb, so this is a corner case.

---

## 6. Faults DURING an XOL instruction

The copied insn may itself fault (a `LDR/STR` to an address the original would also touch). When
`before_pf` runs and `current` is mid-SSOL **and** the fault VA is the data address (not our guard /
not a trapped-page execute), we must:
1. rewrite `regs->pc` from the XOL slot back to `orig_pc` (so the app sees the fault at the real PC),
2. clear the SSOL ctx,
3. let the real `do_page_fault` run (don't `skip_origin`).
This is uprobes' `arch_uprobe_xol_was_trapped` fixup. Without it, a legit page-in or a real SIGSEGV
would surface with a bogus PC. (HW-step path: the fault is a normal data abort with pc=slot; same
fixup.)

---

## 7. Hooked-method entry & call-original

- **Entry:** unchanged from today — the `g_pg` slot keeps a per-offset override; when the fault VA ==
  M's entry offset, `regs->pc = trampoline` (LSPlant's trampoline / the hook). LR is the *original*
  caller (untouched), so the hook returns to the real caller.
- **call-original:** the hook calls `backup`. Today `backup` points into the clone. Under SSOL there
  is NO clone: `backup` is just **M's original entry, but entered in a mode that SKIPS the entry
  override** (so it doesn't re-trap into the hook). Implement as a tiny per-thread "bypass next entry
  hit" flag, or a second alias VA. M's body then runs entirely via SSOL → original addresses on the
  stack → ART-intact. (This is the path that the clone got *wrong* on katana.)
- ArtMethod stays 100% pristine (we never touched it — same as the clone path). Surfaces 1/3/4 clean
  by construction; 2 (maps/smaps) — SSOL's only anon-exec footprint is the tiny XOL scratch pages
  (a few pages), hidden by the existing `kpm_hide_region` / anon-exec maps-hide. 5 (ptrace) unaffected.

---

## 8. Integration with the existing KPM

- Reuse the `g_pg[]` region table + `before_pf`'s region match (`fpage in [s->page, s->page+npages)`,
  tgid gate). Replace the "route to clone via offmap" branch with the SSOL dispatcher.
- A region no longer needs a `clone`/`offmap` (drop the `dbi_recompile_range` + `make_rgn` clone for
  SSOL regions; keep them for L1 native libart hooks which are verified). So a region is just:
  `{pid, mm, page, npages, ov[]}`.
- `maps-hide`: now only the XOL scratch pages are anon-exec (the big clones are gone) → fewer/smaller
  hides. Surface 2 gets *easier*.
- The Vector side (`kpmhook.c`) `kpm_inline_hooker` no longer DBI-recompiles; it just registers the
  region + entry override via the bridge. `dbi.c` is retained only for the per-instruction SIMULATE
  decoders (port the needed helpers) and L1.

---

## 9. Performance — the one real cost, and mitigations

Every in-page instruction = 1 fault (simulate) or 1 fault + 1 step-exception (XOL). Order
100×–1000× slower for code that runs from a trapped page.

- **Only pages holding a hooked method are trapped.** The cost is paid by (a) the hooked method's
  call-original and (b) neighbors *on the same page*. Framework bootstrap methods + their neighbors
  are mostly cold → acceptable.
- **Hot-method mitigation (hybrid):** for a hooked method that is itself HOT and SIMPLE (leaf-ish, no
  indirect ART calls — detectable: scan its body for `BLR`/`BL` into ART), keep the verified
  region-clone fast path; use SSOL only where the clone is unsafe. Pick per-method at hook time.
- **JIT churn:** if ART re-JITs/moves M, the page changes → re-arm (same L2b follow-up as the clone
  path; SSOL actually makes this easier — no clone to rebuild, just re-UXN the new page).
- Measure first: instrument a fault counter per region; if a neighbor is hot enough to jank, either
  move the hook (force-compile M onto a sparser page) or hybrid-clone that neighbor.

---

## 10. Correctness argument (why this is the "perfect" one)

- **Code/data:** we only ever execute instructions the ORIGINAL control flow reaches; pool data is
  never decoded-as-code (simulate/XOL act on the *actual* dynamic instruction stream). Problem 1 gone.
- **ART introspection:** between steps PC is an original code address; call/return uses original
  addresses (BR/BLR/RET simulated to original targets, LR = original). ART unwind/GC/deopt see a
  normal stack. Problem 2 gone.
- **Traceless:** zero code bytes modified (UXN is a PTE flag, reverted on unhook; CRC clean), ArtMethod
  pristine, only a few hidden scratch pages, no ptrace. All 5 surfaces clean by construction.
- **Scale:** UXN is per-page and per-mm → all-thread, no hardware-slot limit (vs HWBP's ~6).

---

## 11. Phased implementation plan

1. **P0 — SIMULATE core (userspace-validated first).** Port `dbi.c` decoders into a `ssol_simulate
   (pt_regs*, insn) -> handled?` that computes the effect for every PC-relative class. Unit-test it
   off-device against known instruction encodings (reuse `dbi_test` harness style).
2. **P1 — XOL slot + HW single-step.** Per-CPU/per-thread scratch page; set SS; register a
   `step_hook` (or inline-hook the step dispatcher); restore pc. Validate by SSOL-ing ONE trapped
   libart function in the manager process (like the L2a self-test) — assert it runs to its RET with
   correct result.
3. **P2 — wire into before_pf.** Region-match → entry-override OR ssol_simulate OR XOL. Per-thread
   ctx + mid-XOL data-fault fixup (§6).
4. **P3 — call-original bypass** (§7) + LSPlant integration: `traceless_inline_hooker` registers an
   SSOL region instead of a DBI clone.
5. **P4 — device bring-up on a REAL app** with the detector probe; expect all 5 surfaces CLEAN and
   STABLE on katana (the clone's failure case). Then hybrid-clone for hot simple methods (P5,
   optional).

Validate each phase with `[[kpm-device-test-workflow]]` + the probe; commit per phase.

---

## 12. Risks / open questions

- **Step-hook availability/stability across kernels** (the one new exception surface). Mitigation: the
  guard-page fallback (§3b) uses only `do_page_fault` which we already own.
- **SIMD/vector LDR-literal & exotic insns** simulate-unfriendly → route them through XOL-with-fixup
  (they execute fine out-of-line; only PC-relative ones can't, and SIMD-literal is the only awkward
  PC-relative case — handle by XOL: copy + the literal pool is at a fixed original VA reachable via an
  absolute address materialized in a scratch reg, or just accept XOL for it).
- **Performance on an unexpectedly hot neighbor** → the hybrid escape (clone that one neighbor) or
  re-place the hook.
- **Re-entrancy / nested SSOL** (an XOL insn that itself faults into another trapped page): the
  per-thread ctx must be a small stack, not a single slot. Bound depth; in practice XOL insns are
  PC-independent ALU/loads that don't execute-fault into trapped pages.
- **PSTATE.SS vs the app's own use of single-step / hw-breakpoints** (anti-cheat probing debug regs):
  SSOL uses MDSCR_EL1.SS transiently per-thread in-kernel; EL0 can't read MDSCR_EL1, so it's invisible
  to an in-app probe (unlike a *persistent* HWBP in a DBGBVR an app could try to set & collide with).

---

## 13. One-line summary

UXN-trap the hooked method's page (no code write, as today) but instead of running a relocated DBI
clone, **single-step the original instruction stream out-of-line** (simulate PC-relative, execute
PC-independent out-of-line) — i.e. **uprobes' XOL triggered by a page fault instead of a BRK** — so
the original code runs at its original address, ART stays intact, code/data interleaving is a
non-issue, it's all-thread, and there is no hardware-slot ceiling. Cost: a fault per in-page
instruction, mitigated by trapping only hooked pages and hybrid-cloning hot-simple methods.
