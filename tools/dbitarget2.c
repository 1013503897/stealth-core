// SPDX-License-Identifier: GPL-2.0-or-later
// dbitarget2: P3.2 target + minimal userspace DBI recompiler.
//
// hook_me() is page-isolated but, unlike tick(), uses PC-relative instructions:
//   mov w1, w0            ; verbatim
//   nop                   ; verbatim
//   adr x0, <fmt string>  ; PC-relative  -> must be rewritten for the clone addr
//   b   printf@plt        ; PC-relative tail call -> must be rewritten
// A verbatim clone would load a wrong string pointer and branch to a wrong addr
// (crash/garbage). The DBI engine below recompiles hook_me into a clone, turning
// ADR/ADRP into absolute literal loads and B/BL into absolute reg-indirect
// branches, and builds an offset_map (orig insn idx -> clone insn idx). The KPM
// sets UXN on hook_me's page and routes the fault into the clone via that map;
// correct "[clone] hook_me n=K" output then proves the fixups are right.
//
// Build: -fno-stack-protector (no unexpected canary ADRP).

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>

__attribute__((aligned(0x1000), noinline)) void hook_me(int n)
{
    printf("[clone] hook_me n=%d\n", n);
}
__attribute__((aligned(0x1000), noinline)) void hm_guard(void) { asm volatile("nop"); }

/* ---- AArch64 encode helpers ---- */
static uint32_t enc_ldr_lit64(int rd, int off_bytes) /* LDR Xd, [PC, #off] */
{
    return 0x58000000u | (((uint32_t)(off_bytes / 4) & 0x7ffff) << 5) | (rd & 0x1f);
}
static uint32_t enc_b(int off_bytes) /* B #off */
{
    return 0x14000000u | ((uint32_t)(off_bytes / 4) & 0x03ffffff);
}
#define BR_X16 0xD61F0200u
#define BLR_X16 0xD63F0200u

static int64_t sext(int64_t v, int bits)
{
    int s = 64 - bits;
    return (v << s) >> s;
}

/* Recompile [orig_base..] into out[], filling offmap[i] = clone insn index of
 * original instruction i. Stops after the first unconditional B or RET. Returns
 * the clone size in instructions. Handles ADR/ADRP/B/BL; everything else verbatim
 * (sufficient for hook_me; B.cond/CBZ/TBZ/LDR-literal/BLR+PAC are future work). */
static int dbi_recompile(uintptr_t orig_base, const uint32_t *src, uint32_t *out, uint32_t *offmap, int maxsrc)
{
    int sizes[256], nsrc = 0;
    for (int i = 0; i < maxsrc && i < 256; i++) {
        uint32_t insn = src[i];
        int sz;
        if ((insn & 0x9F000000u) == 0x90000000u) sz = 4;       /* ADRP */
        else if ((insn & 0x9F000000u) == 0x10000000u) sz = 4;  /* ADR  */
        else if ((insn & 0xFC000000u) == 0x14000000u) sz = 4;  /* B    */
        else if ((insn & 0xFC000000u) == 0x94000000u) sz = 5;  /* BL   */
        else sz = 1;                                            /* verbatim */
        sizes[i] = sz;
        nsrc = i + 1;
        if ((insn & 0xFC000000u) == 0x14000000u) break; /* tail B ends the function */
        if (insn == 0xD65F03C0u) break;                 /* RET ends the function */
    }

    int acc = 0;
    for (int i = 0; i < nsrc; i++) {
        offmap[i] = (uint32_t)acc;
        acc += sizes[i];
    }
    for (int i = nsrc; i < 1024; i++) offmap[i] = (uint32_t)i; /* unused tail: identity */

    int o = 0;
    for (int i = 0; i < nsrc; i++) {
        uint32_t insn = src[i];
        uintptr_t pc = orig_base + (uintptr_t)i * 4;
        int rd = insn & 0x1f;
        if ((insn & 0x9F000000u) == 0x90000000u) { /* ADRP Xd, imm */
            int immlo = (insn >> 29) & 3, immhi = (insn >> 5) & 0x7ffff;
            int64_t imm = sext((immhi << 2) | immlo, 21);
            uint64_t tgt = (pc & ~0xfffULL) + ((uint64_t)imm << 12);
            out[o++] = enc_ldr_lit64(rd, 8);
            out[o++] = enc_b(12);
            out[o++] = (uint32_t)tgt;
            out[o++] = (uint32_t)(tgt >> 32);
        } else if ((insn & 0x9F000000u) == 0x10000000u) { /* ADR Xd, imm */
            int immlo = (insn >> 29) & 3, immhi = (insn >> 5) & 0x7ffff;
            int64_t imm = sext((immhi << 2) | immlo, 21);
            uint64_t tgt = pc + (uint64_t)imm;
            out[o++] = enc_ldr_lit64(rd, 8);
            out[o++] = enc_b(12);
            out[o++] = (uint32_t)tgt;
            out[o++] = (uint32_t)(tgt >> 32);
        } else if ((insn & 0xFC000000u) == 0x14000000u) { /* B (far, tail) */
            int64_t imm = sext(insn & 0x03ffffff, 26);
            uint64_t tgt = pc + ((uint64_t)imm << 2);
            out[o++] = enc_ldr_lit64(16, 8);
            out[o++] = BR_X16;
            out[o++] = (uint32_t)tgt;
            out[o++] = (uint32_t)(tgt >> 32);
        } else if ((insn & 0xFC000000u) == 0x94000000u) { /* BL (far, returns) */
            int64_t imm = sext(insn & 0x03ffffff, 26);
            uint64_t tgt = pc + ((uint64_t)imm << 2);
            out[o++] = enc_ldr_lit64(16, 12);
            out[o++] = BLR_X16;
            out[o++] = enc_b(12);
            out[o++] = (uint32_t)tgt;
            out[o++] = (uint32_t)(tgt >> 32);
        } else {
            out[o++] = insn; /* verbatim */
        }
    }
    return o;
}

static uint32_t omap[1024];

int main(void)
{
    uintptr_t hm = (uintptr_t)&hook_me;
    uintptr_t page = hm & ~0xfffUL;

    uint32_t buf[1024];
    int clone_insns = dbi_recompile(page, (const uint32_t *)page, buf, omap, 256);

    void *clone = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (clone == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    memcpy(clone, buf, sizeof(uint32_t) * clone_insns);
    __builtin___clear_cache((char *)clone, (char *)clone + 0x1000);
    if (mprotect(clone, 0x1000, PROT_READ | PROT_EXEC) != 0) { printf("mprotect failed\n"); return 1; }

    printf("pid=%d hook_me=%p page=0x%lx clone=%p omap=%p nmap=1024 clone_insns=%d\n", getpid(),
           (void *)&hook_me, (unsigned long)page, clone, (void *)omap, clone_insns);
    fflush(stdout);

    for (int i = 0;; i++) {
        hook_me(i);      // its printf output is produced here (from the clone once redirected)
        fflush(stdout);  // flush from main so the buffered hook_me output is visible
        usleep(500000);
    }
    return 0;
}
