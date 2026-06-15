/* SPDX-License-Identifier: GPL-2.0-or-later */
/* libssol: AArch64 SSOL simulator. See ssol.h / docs/SSOL-design.md §3a. */

#include "ssol.h"

/* ---- ported from dbi.c (verbatim): sext + PC-relative classifiers + btarget.
 * dbi.c emits a relocated instruction; here we reuse the SAME decode to compute
 * the architectural effect. dbi.c itself is left unchanged. ---- */
static int64_t sext(int64_t v, int bits) { int s = 64 - bits; return (v << s) >> s; }

static int is_adr(uint32_t i) { return (i & 0x9F000000u) == 0x10000000u; }
static int is_adrp(uint32_t i) { return (i & 0x9F000000u) == 0x90000000u; }
static int is_b(uint32_t i) { return (i & 0xFC000000u) == 0x14000000u; }
static int is_bl(uint32_t i) { return (i & 0xFC000000u) == 0x94000000u; }
static int is_bcond(uint32_t i) { return (i & 0xFF000010u) == 0x54000000u; }
static int is_cbz(uint32_t i) { return (i & 0x7E000000u) == 0x34000000u; }   /* CBZ / CBNZ */
static int is_tbz(uint32_t i) { return (i & 0x7E000000u) == 0x36000000u; }   /* TBZ / TBNZ */
/* LDR/LDRSW (literal), integer or SIMD, opc 00/01/10 (exclude PRFM opc=11) */
static int is_ldrlit(uint32_t i) { return (i & 0x3B000000u) == 0x18000000u && ((i >> 30) & 3) != 3; }

/* absolute branch target for any immediate branch-ish insn at pc (ported) */
static uint64_t btarget(uint32_t insn, uint64_t pc)
{
    if (is_b(insn) || is_bl(insn)) return pc + ((uint64_t)sext(insn & 0x03ffffff, 26) << 2);
    if (is_bcond(insn) || is_cbz(insn)) return pc + ((uint64_t)sext((insn >> 5) & 0x7ffff, 19) << 2);
    if (is_tbz(insn)) return pc + ((uint64_t)sext((insn >> 5) & 0x3fff, 14) << 2);
    return 0;
}

/* ---- new for SSOL (dbi.c emits these verbatim; SSOL must simulate them) ---- */

/* Unconditional branch (register): plain BR/BLR/RET only. PAC variants
 * (BRAA/BLRAA/RETAA...) set extra bits and DON'T match -> fall through to XOL. */
static int is_br(uint32_t i) { return (i & 0xFFFFFC1Fu) == 0xD61F0000u; }  /* BR  Xn */
static int is_blr(uint32_t i) { return (i & 0xFFFFFC1Fu) == 0xD63F0000u; } /* BLR Xn */
static int is_ret(uint32_t i) { return (i & 0xFFFFFC1Fu) == 0xD65F0000u; } /* RET {Xn=30} */

/* ARM ConditionHolds. NZCV = pstate bits 31/30/29/28. cond[3:1] selects the
 * base test; cond[0] inverts it (except 0b1111 = NV, which is "always" in A64). */
static int eval_cond(uint32_t cond, uint64_t pstate)
{
    int N = (pstate >> 31) & 1, Z = (pstate >> 30) & 1, C = (pstate >> 29) & 1, V = (pstate >> 28) & 1;
    int res;
    switch ((cond >> 1) & 7) {
    case 0: res = (Z == 1); break;             /* EQ / NE */
    case 1: res = (C == 1); break;             /* CS / CC */
    case 2: res = (N == 1); break;             /* MI / PL */
    case 3: res = (V == 1); break;             /* VS / VC */
    case 4: res = (C == 1 && Z == 0); break;   /* HI / LS */
    case 5: res = (N == V); break;             /* GE / LT */
    case 6: res = (N == V && Z == 0); break;   /* GT / LE */
    default: res = 1; break;                   /* AL / NV */
    }
    if ((cond & 1) && cond != 0xf) res = !res;
    return res;
}

/* Read GPR idx. In every encoding SSOL simulates, field value 31 means XZR/WZR
 * (reads 0), NEVER SP. !is64 -> 32-bit (low word). */
static uint64_t reg_read(const struct pt_regs *regs, int idx, int is64)
{
    uint64_t v = (idx == 31) ? 0 : regs->regs[idx];
    return is64 ? v : (v & 0xffffffffu);
}

/* Write GPR idx. idx==31 is XZR -> discard (NEVER write regs[31], that is SP).
 * !is64 -> 32-bit dest (upper 32 bits cleared). */
static void reg_write(struct pt_regs *regs, int idx, uint64_t val, int is64)
{
    if (idx == 31) return;
    regs->regs[idx] = is64 ? val : (val & 0xffffffffu);
}

enum ssol_action ssol_simulate(struct pt_regs *regs, uint32_t insn)
{
    uint64_t pc = regs->pc;

    /* ---- immediate (PC-relative) branches ---- */
    if (is_b(insn)) {
        regs->pc = btarget(insn, pc);
        return SSOL_SIMULATED;
    }
    if (is_bl(insn)) {
        regs->regs[30] = pc + 4;
        regs->pc = btarget(insn, pc);
        return SSOL_SIMULATED;
    }
    if (is_bcond(insn)) {
        regs->pc = eval_cond(insn & 0xf, regs->pstate) ? btarget(insn, pc) : pc + 4;
        return SSOL_SIMULATED;
    }
    if (is_cbz(insn)) {
        int sf = (insn >> 31) & 1;          /* 1 -> Xt, 0 -> Wt */
        int rt = insn & 0x1f;
        int is_cbnz = (insn >> 24) & 1;
        int zero = (reg_read(regs, rt, sf) == 0);
        int taken = zero ^ is_cbnz;          /* CBZ taken if zero; CBNZ if non-zero */
        regs->pc = taken ? btarget(insn, pc) : pc + 4;
        return SSOL_SIMULATED;
    }
    if (is_tbz(insn)) {
        int rt = insn & 0x1f;
        int bitpos = (int)((((insn >> 31) & 1) << 5) | ((insn >> 19) & 0x1f)); /* b5:b40, 0..63 */
        int is_tbnz = (insn >> 24) & 1;
        int bit = (int)((reg_read(regs, rt, 1) >> bitpos) & 1);
        int taken = is_tbnz ? bit : !bit;    /* TBZ taken if bit clear; TBNZ if set */
        regs->pc = taken ? btarget(insn, pc) : pc + 4;
        return SSOL_SIMULATED;
    }

    /* ---- PC-relative address / literal ---- */
    if (is_adr(insn)) {
        int rd = insn & 0x1f;
        int64_t imm = sext((int64_t)(((insn >> 5) & 0x7ffff) << 2 | ((insn >> 29) & 3)), 21);
        reg_write(regs, rd, pc + (uint64_t)imm, 1);
        regs->pc = pc + 4;
        return SSOL_SIMULATED;
    }
    if (is_adrp(insn)) {
        int rd = insn & 0x1f;
        int64_t imm = sext((int64_t)(((insn >> 5) & 0x7ffff) << 2 | ((insn >> 29) & 3)), 21);
        reg_write(regs, rd, (pc & ~0xfffULL) + ((uint64_t)imm << 12), 1);
        regs->pc = pc + 4;
        return SSOL_SIMULATED;
    }
    if (is_ldrlit(insn)) {
        if ((insn >> 26) & 1) return SSOL_XOL; /* V=1: SIMD/FP literal -> XOL (can't write a vector reg from C) */
        int rt = insn & 0x1f;
        int opc = (insn >> 30) & 3;            /* 0 = 32-bit, 1 = 64-bit, 2 = LDRSW */
        int64_t off = sext((int64_t)((insn >> 5) & 0x7ffff), 19) << 2;
        uintptr_t addr = (uintptr_t)(pc + (uint64_t)off);
        uint64_t val;
        if (opc == 1) val = *(volatile uint64_t *)addr;                       /* 64-bit */
        else if (opc == 2) val = (uint64_t)(int64_t) * (volatile int32_t *)addr; /* LDRSW: sign-extend */
        else val = (uint64_t) * (volatile uint32_t *)addr;                    /* 32-bit: zero-extend */
        reg_write(regs, rt, val, opc != 0);    /* opc==0 -> 32-bit dest; else 64-bit */
        regs->pc = pc + 4;
        return SSOL_SIMULATED;
    }

    /* ---- register (indirect) branches: target is a register holding an
     * ORIGINAL address. This is what kills the clone's "problem 2": the
     * call/return chain stays on original addresses (LR = original). ----
     * NOTE: on a PAC-enabled device the register value may be signed; the kernel
     * port must apply STRIP_PAC here (shpte.c already does for LR). P0 uses raw. */
    if (is_br(insn)) {
        regs->pc = reg_read(regs, (insn >> 5) & 0x1f, 1);
        return SSOL_SIMULATED;
    }
    if (is_blr(insn)) {
        regs->regs[30] = pc + 4;
        regs->pc = reg_read(regs, (insn >> 5) & 0x1f, 1);
        return SSOL_SIMULATED;
    }
    if (is_ret(insn)) {
        regs->pc = reg_read(regs, (insn >> 5) & 0x1f, 1);
        return SSOL_SIMULATED;
    }

    /* everything else (ALU, MOV, LDR/STR reg, NOP, atomics, PAC branches, ...) */
    return SSOL_XOL;
}
