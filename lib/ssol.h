/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * libssol: AArch64 single-step-out-of-line (SSOL) instruction simulator.
 * See docs/SSOL-design.md (§3a, §11 phase P0).
 *
 * ssol_simulate() computes the architectural effect of ONE *PC-relative*
 * instruction directly into pt_regs -- WITHOUT executing it -- so the SSOL
 * page-fault handler can advance a UXN-trapped instruction stream while the
 * original code stays at its original address (no clone, no relocation). The
 * vast majority of instructions are PC-independent: those are NOT simulated
 * here, the caller runs them out-of-line (XOL).
 *
 * The PC-relative decoders are PORTED from libdbi (dbi.c): the same classify +
 * immediate math, but writing the *result* into registers instead of emitting a
 * relocated instruction. dbi.c is left untouched (device-verified).
 *
 * This header + ssol.c are the offline-testable P0 core. The kernel wiring (XOL
 * scratch slot, HW single-step, before_pf integration, per-thread ctx) is P1/P2.
 */
#ifndef LIBSSOL_SSOL_H
#define LIBSSOL_SSOL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * pt_regs: in the KPM this comes from <asm/ptrace.h>. For the offline unit test
 * (compiled with -DSSOL_TEST) we shim a struct whose layout matches the arm64
 * kernel `struct pt_regs` (regs[31], sp, pc, pstate) -- exactly the fields the
 * KPM already touches (regs->regs[i], regs->pc, regs->regs[30]).
 */
#ifdef SSOL_TEST
struct pt_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};
#else
#include <asm/ptrace.h>
#endif

enum ssol_action {
    SSOL_SIMULATED = 0, /* PC-relative: effect written into *regs (pc, and maybe a GPR / x30). */
    SSOL_XOL = 1,       /* PC-independent, OR simulate-unfriendly PC-relative (SIMD-literal /
                         * PAC branch): *regs untouched, caller must execute out-of-line. */
};

/*
 * Simulate the single instruction `insn` whose ORIGINAL VA is regs->pc.
 *   SSOL_SIMULATED -> regs->pc (and possibly one GPR or x30) updated per ARM
 *                     semantics; caller does nothing further.
 *   SSOL_XOL       -> *regs untouched; caller copies the insn to a scratch page
 *                     and single-steps it out-of-line.
 *
 * LDR-literal reads the original pool VA directly (UXN blocks EXECUTE, not READ,
 * so the original page is always readable where SSOL runs).
 */
enum ssol_action ssol_simulate(struct pt_regs *regs, uint32_t insn);

#ifdef __cplusplus
}
#endif

#endif /* LIBSSOL_SSOL_H */
