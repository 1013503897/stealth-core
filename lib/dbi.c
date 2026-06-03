/* SPDX-License-Identifier: GPL-2.0-or-later */
/* libdbi: AArch64 position-independent function recompiler. See dbi.h. */

#include "dbi.h"

/* ---- AArch64 encode helpers ---- */
static uint32_t enc_ldr_lit64(int rd, int off) { return 0x58000000u | (((uint32_t)(off / 4) & 0x7ffff) << 5) | (rd & 0x1f); }
static uint32_t enc_b(int off) { return 0x14000000u | ((uint32_t)(off / 4) & 0x03ffffff); }
#define BR_X16 0xD61F0200u
#define BLR_X16 0xD63F0200u
#define RET_X30 0xD65F03C0u

static int64_t sext(int64_t v, int bits) { int s = 64 - bits; return (v << s) >> s; }

/* ---- classify ---- */
static int is_adr(uint32_t i) { return (i & 0x9F000000u) == 0x10000000u; }
static int is_adrp(uint32_t i) { return (i & 0x9F000000u) == 0x90000000u; }
static int is_b(uint32_t i) { return (i & 0xFC000000u) == 0x14000000u; }
static int is_bl(uint32_t i) { return (i & 0xFC000000u) == 0x94000000u; }
static int is_bcond(uint32_t i) { return (i & 0xFF000010u) == 0x54000000u; }
static int is_cbz(uint32_t i) { return (i & 0x7E000000u) == 0x34000000u; }
static int is_tbz(uint32_t i) { return (i & 0x7E000000u) == 0x36000000u; }
/* LDR/LDRSW (literal), integer or SIMD, opc 00/01/10 (exclude PRFM opc=11) */
static int is_ldrlit(uint32_t i) { return (i & 0x3B000000u) == 0x18000000u && ((i >> 30) & 3) != 3; }

/* absolute branch target for any branch-ish insn at pc */
static uint64_t btarget(uint32_t insn, uint64_t pc)
{
    if (is_b(insn) || is_bl(insn)) return pc + ((uint64_t)sext(insn & 0x03ffffff, 26) << 2);
    if (is_bcond(insn) || is_cbz(insn)) return pc + ((uint64_t)sext((insn >> 5) & 0x7ffff, 19) << 2);
    if (is_tbz(insn)) return pc + ((uint64_t)sext((insn >> 5) & 0x3fff, 14) << 2);
    return 0;
}

/* re-encode a conditional branch (or cbz/cbnz) / tbz to a new clone-relative offset */
static uint32_t reenc_imm19(uint32_t insn, int rel) { return (insn & 0xFF00001Fu) | (((uint32_t)rel & 0x7ffff) << 5); }
static uint32_t reenc_imm14(uint32_t insn, int rel) { return (insn & 0xFFF8001Fu) | (((uint32_t)rel & 0x3fff) << 5); }
static uint32_t invert_cond(uint32_t insn)
{
    if (is_bcond(insn)) return (insn & 0xFFFFFFF0u) | ((insn & 0xf) ^ 1u); /* flip cond[0] */
    return insn ^ (1u << 24); /* CBZ<->CBNZ, TBZ<->TBNZ: flip op bit */
}

/* emit a far absolute jump to tgt using x16; br (call=0) or blr (call=1) */
static int emit_far(uint32_t *out, uint64_t tgt, int call)
{
    int o = 0;
    if (!call) {
        out[o++] = enc_ldr_lit64(16, 8);
        out[o++] = BR_X16;
        out[o++] = (uint32_t)tgt;
        out[o++] = (uint32_t)(tgt >> 32);
    } else {
        out[o++] = enc_ldr_lit64(16, 12);
        out[o++] = BLR_X16;
        out[o++] = enc_b(12);
        out[o++] = (uint32_t)tgt;
        out[o++] = (uint32_t)(tgt >> 32);
    }
    return o;
}

/* size (in clone insns) of the recompiled form of one instruction */
static int insn_size(uint32_t insn, uint64_t pc, uint64_t fbase, uint64_t fend)
{
    if (is_adr(insn) || is_adrp(insn) || is_ldrlit(insn)) return 4;
    if (is_bl(insn)) return 5;
    if (is_b(insn)) {
        uint64_t t = btarget(insn, pc);
        return (t >= fbase && t < fend) ? 1 : 4;
    }
    if (is_bcond(insn) || is_cbz(insn) || is_tbz(insn)) {
        uint64_t t = btarget(insn, pc);
        return (t >= fbase && t < fend) ? 1 : 5;
    }
    return 1;
}

int dbi_recompile(uintptr_t base, const uint32_t *src, int src_max, uint32_t *out, int out_cap,
                  uint32_t *offmap, int offmap_cap)
{
    /* pass 0: function extent (stop at RET or a tail B leaving the function) */
    int nsrc = 0;
    for (int i = 0; i < src_max; i++) {
        uint32_t insn = src[i];
        nsrc = i + 1;
        if (insn == RET_X30) break;
        if (is_b(insn)) {
            uint64_t t = btarget(insn, base + (uint64_t)i * 4);
            if (t < base || t >= base + (uint64_t)src_max * 4) break; /* tail call */
        }
    }
    if (nsrc == 0) return DBI_ERR_EMPTY;
    if (nsrc > offmap_cap) return DBI_ERR_OFFMAP;
    uint64_t fend = base + (uint64_t)nsrc * 4;

    /* pass 1: sizes + offsets */
    int acc = 0;
    for (int i = 0; i < nsrc; i++) {
        offmap[i] = (uint32_t)acc;
        acc += insn_size(src[i], base + (uint64_t)i * 4, base, fend);
    }
    if (acc > out_cap) return DBI_ERR_RANGE;
    for (int i = nsrc; i < offmap_cap; i++) offmap[i] = (uint32_t)i;

    /* pass 2: emit */
    int o = 0;
    for (int i = 0; i < nsrc; i++) {
        uint32_t insn = src[i];
        uint64_t pc = base + (uint64_t)i * 4;
        int rd = insn & 0x1f;
        if (is_adrp(insn)) {
            int64_t imm = sext(((insn >> 5) & 0x7ffff) << 2 | ((insn >> 29) & 3), 21);
            uint64_t t = (pc & ~0xfffULL) + ((uint64_t)imm << 12);
            out[o++] = enc_ldr_lit64(rd, 8); out[o++] = enc_b(12);
            out[o++] = (uint32_t)t; out[o++] = (uint32_t)(t >> 32);
        } else if (is_adr(insn)) {
            int64_t imm = sext(((insn >> 5) & 0x7ffff) << 2 | ((insn >> 29) & 3), 21);
            uint64_t t = pc + (uint64_t)imm;
            out[o++] = enc_ldr_lit64(rd, 8); out[o++] = enc_b(12);
            out[o++] = (uint32_t)t; out[o++] = (uint32_t)(t >> 32);
        } else if (is_ldrlit(insn)) {
            int64_t imm = sext((insn >> 5) & 0x7ffff, 19);
            uint64_t lit_addr = pc + ((uint64_t)imm << 2);
            int opc = (insn >> 30) & 3;
            uint64_t val = (opc == 1) ? *(volatile uint64_t *)lit_addr
                                      : (uint64_t) * (volatile uint32_t *)lit_addr;
            out[o++] = (insn & 0xFF00001Fu) | (2u << 5); /* same opc/Rt, imm19 -> [pc,#8] */
            out[o++] = enc_b(12);
            out[o++] = (uint32_t)val; out[o++] = (uint32_t)(val >> 32);
        } else if (is_bl(insn)) {
            o += emit_far(&out[o], btarget(insn, pc), 1);
        } else if (is_b(insn)) {
            uint64_t t = btarget(insn, pc);
            if (t >= base && t < fend) {
                int rel = (int)offmap[(int)((t - base) / 4)] - o;
                out[o] = enc_b(rel * 4);
                o++;
            } else {
                o += emit_far(&out[o], t, 0);
            }
        } else if (is_bcond(insn) || is_cbz(insn) || is_tbz(insn)) {
            uint64_t t = btarget(insn, pc);
            if (t >= base && t < fend) {
                int rel = (int)offmap[(int)((t - base) / 4)] - o;
                out[o++] = is_tbz(insn) ? reenc_imm14(insn, rel) : reenc_imm19(insn, rel);
            } else {
                out[o] = is_tbz(insn) ? reenc_imm14(invert_cond(insn), 5) : reenc_imm19(invert_cond(insn), 5);
                o++;
                o += emit_far(&out[o], t, 0);
            }
        } else {
            out[o++] = insn; /* verbatim */
        }
    }
    return o;
}
