// SPDX-License-Identifier: GPL-2.0-or-later
// dbitarget4: P3.4 target + DBI recompiler extended to LDR-literal. lwork() loads
// a 64-bit constant from a PC-relative literal pool (ldr xN,=imm), which a
// verbatim clone would read from the wrong address. The recompiler re-points the
// load to a clone-local copy of the literal value (read from the original pool at
// recompile time). It still also handles ADR (string) + BL (printf).
//
// The 3-pass recompiler:
//   pass 0  find the function extent (scan to RET, or to a B whose target is
//           outside the function = tail call)
//   pass 1  size each instruction (internal branches stay 1 insn; external
//           B/ADR/ADRP/BL and LDR-literal expand) and build offset_map
//   pass 2  emit, resolving internal branch targets via offset_map
//
// Build: -fno-stack-protector.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>

__attribute__((aligned(0x1000), noinline)) long lwork(int n)
{
    long v;
    asm volatile("ldr %0, =0x123456789abcdef0" : "=r"(v)); // -> LDR-literal + pool
    v += n;
    printf("[clone] lwork(%d)=0x%lx\n", n, v);
    return v;
}
__attribute__((aligned(0x1000), noinline)) void wg(void) { asm volatile("nop"); }

/* ---- encode / classify ---- */
static uint32_t enc_ldr_lit64(int rd, int off) { return 0x58000000u | (((uint32_t)(off / 4) & 0x7ffff) << 5) | (rd & 0x1f); }
static uint32_t enc_b(int off) { return 0x14000000u | ((uint32_t)(off / 4) & 0x03ffffff); }
#define BR_X16 0xD61F0200u
#define BLR_X16 0xD63F0200u
#define RET_X30 0xD65F03C0u

static int64_t sext(int64_t v, int bits) { int s = 64 - bits; return (v << s) >> s; }

static int is_adr(uint32_t i) { return (i & 0x9F000000u) == 0x10000000u; }
static int is_adrp(uint32_t i) { return (i & 0x9F000000u) == 0x90000000u; }
static int is_b(uint32_t i) { return (i & 0xFC000000u) == 0x14000000u; }
static int is_bl(uint32_t i) { return (i & 0xFC000000u) == 0x94000000u; }
static int is_bcond(uint32_t i) { return (i & 0xFF000010u) == 0x54000000u; }
static int is_cbz(uint32_t i) { return (i & 0x7E000000u) == 0x34000000u; }
static int is_tbz(uint32_t i) { return (i & 0x7E000000u) == 0x36000000u; }
/* LDR/LDRSW (literal), integer or SIMD, opc 00/01/10 (exclude PRFM opc=11) */
static int is_ldrlit(uint32_t i) { return (i & 0x3B000000u) == 0x18000000u && ((i >> 30) & 3) != 3; }

/* branch target (absolute) for any branch-ish insn at pc */
static uint64_t btarget(uint32_t insn, uint64_t pc)
{
    if (is_b(insn) || is_bl(insn)) return pc + ((uint64_t)sext(insn & 0x03ffffff, 26) << 2);
    if (is_bcond(insn) || is_cbz(insn)) return pc + ((uint64_t)sext((insn >> 5) & 0x7ffff, 19) << 2);
    if (is_tbz(insn)) return pc + ((uint64_t)sext((insn >> 5) & 0x3fff, 14) << 2);
    return 0;
}

/* re-encode a conditional/uncond branch to a new clone-relative offset (insns) */
static uint32_t reenc_imm19(uint32_t insn, int rel) { return (insn & 0xFF00001Fu) | (((uint32_t)rel & 0x7ffff) << 5); }
static uint32_t reenc_imm14(uint32_t insn, int rel) { return (insn & 0xFFF8001Fu) | (((uint32_t)rel & 0x3fff) << 5); }
static uint32_t invert_cond(uint32_t insn)
{
    if (is_bcond(insn)) return (insn & 0xFFFFFFF0u) | ((insn & 0xf) ^ 1u); /* flip cond[0] */
    return insn ^ (1u << 24); /* CBZ<->CBNZ, TBZ<->TBNZ: flip op bit */
}

/* emit a far absolute jump to tgt using x16; br (call=0) or blr (call=1, returns) */
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

/* size of the recompiled form of one instruction (in clone insns) */
static int insn_size(uint32_t insn, uint64_t pc, uint64_t fbase, uint64_t fend)
{
    if (is_adr(insn) || is_adrp(insn)) return 4;
    if (is_ldrlit(insn)) return 4; /* ldr Rt,[pc,#8]; b #12; <8-byte value> */
    if (is_bl(insn)) return 5;
    if (is_b(insn)) {
        uint64_t t = btarget(insn, pc);
        return (t >= fbase && t < fend) ? 1 : 4; /* internal: re-encode; external: far */
    }
    if (is_bcond(insn) || is_cbz(insn) || is_tbz(insn)) {
        uint64_t t = btarget(insn, pc);
        return (t >= fbase && t < fend) ? 1 : 5; /* internal: re-encode; external: invert+far */
    }
    return 1; /* verbatim */
}

/* recompile [fbase..]; fill offmap[i]=clone idx; return clone size in insns */
static int dbi_recompile(uintptr_t fbase, const uint32_t *src, uint32_t *out, uint32_t *offmap, int maxsrc)
{
    /* pass 0: function extent */
    int nsrc = 0;
    for (int i = 0; i < maxsrc && i < 256; i++) {
        uint32_t insn = src[i];
        nsrc = i + 1;
        if (insn == RET_X30) break;
        if (is_b(insn)) {
            uint64_t t = btarget(insn, fbase + (uint64_t)i * 4);
            if (t < fbase || t >= fbase + (uint64_t)maxsrc * 4) break; /* tail call */
        }
    }
    uint64_t fend = fbase + (uint64_t)nsrc * 4;

    /* pass 1: sizes + offsets */
    int acc = 0;
    for (int i = 0; i < nsrc; i++) {
        offmap[i] = (uint32_t)acc;
        acc += insn_size(src[i], fbase + (uint64_t)i * 4, fbase, fend);
    }
    for (int i = nsrc; i < 1024; i++) offmap[i] = (uint32_t)i;

    /* pass 2: emit */
    int o = 0;
    for (int i = 0; i < nsrc; i++) {
        uint32_t insn = src[i];
        uint64_t pc = fbase + (uint64_t)i * 4;
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
            /* re-point the literal load to a clone-local copy of the VALUE */
            int64_t imm = sext((insn >> 5) & 0x7ffff, 19);
            uint64_t lit_addr = pc + ((uint64_t)imm << 2);
            int opc = (insn >> 30) & 3;
            uint64_t val = (opc == 1) ? *(volatile uint64_t *)lit_addr /* 8-byte X/D */
                                      : (uint64_t) * (volatile uint32_t *)lit_addr; /* 4-byte W/SW/S */
            out[o++] = (insn & 0xFF00001Fu) | (2u << 5); /* same opc/Rt, imm19 -> [pc,#8] */
            out[o++] = enc_b(12);
            out[o++] = (uint32_t)val; out[o++] = (uint32_t)(val >> 32);
        } else if (is_bl(insn)) {
            o += emit_far(&out[o], btarget(insn, pc), 1);
        } else if (is_b(insn)) {
            uint64_t t = btarget(insn, pc);
            if (t >= fbase && t < fend) {
                int tidx = (int)((t - fbase) / 4);
                int rel = (int)offmap[tidx] - o; /* compute before o++ (avoid UB) */
                out[o] = enc_b(rel * 4);
                o++;
            } else {
                o += emit_far(&out[o], t, 0);
            }
        } else if (is_bcond(insn) || is_cbz(insn) || is_tbz(insn)) {
            uint64_t t = btarget(insn, pc);
            if (t >= fbase && t < fend) {
                int tidx = (int)((t - fbase) / 4);
                int rel = (int)offmap[tidx] - o;
                out[o++] = is_tbz(insn) ? reenc_imm14(insn, rel) : reenc_imm19(insn, rel);
            } else {
                /* external: invert cond to skip a far jump (5 slots total) */
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

static uint32_t omap[1024];

int main(void)
{
    uintptr_t fn = (uintptr_t)&lwork;
    uintptr_t page = fn & ~0xfffUL;
    uint32_t buf[1024];
    int clone_insns = dbi_recompile(page, (const uint32_t *)page, buf, omap, 256);

    void *clone = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (clone == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    memcpy(clone, buf, sizeof(uint32_t) * clone_insns);
    __builtin___clear_cache((char *)clone, (char *)clone + 0x1000);
    if (mprotect(clone, 0x1000, PROT_READ | PROT_EXEC)) { printf("mprotect failed\n"); return 1; }

    printf("pid=%d lwork=%p page=0x%lx clone=%p omap=%p nmap=1024 clone_insns=%d\n", getpid(),
           (void *)&lwork, (unsigned long)page, clone, (void *)omap, clone_insns);
    fflush(stdout);

    for (int i = 0;; i++) {
        lwork(i); // expect lwork(i) = 0x123456789abcdef0 + i
        fflush(stdout);
        usleep(500000);
    }
    return 0;
}
