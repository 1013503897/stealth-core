/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Unit test for libssol (SSOL P0). Two layers:
 *   1. Golden vectors -- hand-encoded instructions + asserted pt_regs effects.
 *      Pure computation, runs anywhere (host or device).
 *   2. Native cross-check (#ifdef __aarch64__) -- execute the REAL instruction on
 *      the silicon and diff the actual effect against ssol_simulate(). Validates
 *      eval_cond / sign-extension / width / pc-relative math against the CPU.
 *
 * Build (offline, arm64 binary):  lib/build_ssol_test.ps1  (passes -DSSOL_TEST
 * to BOTH ssol.c and ssol_test.c so the pt_regs shim is used).
 * Run:  adb push lib/ssol_test /data/local/tmp/ ; adb shell /data/local/tmp/ssol_test
 */
#include "ssol.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int fails = 0;
#define CHECK(cond, ...)                               \
    do {                                               \
        if (!(cond)) {                                 \
            printf("FAIL: " __VA_ARGS__);              \
            printf("  (%s:%d)\n", __FILE__, __LINE__); \
            fails++;                                   \
        }                                              \
    } while (0)

typedef unsigned long long ull;

static struct pt_regs mk(uint64_t pc)
{
    struct pt_regs r;
    memset(&r, 0, sizeof r);
    r.pc = pc;
    return r;
}

/* =================== Layer 1: golden vectors =================== */

static void g_branches(void)
{
    struct pt_regs r;

    /* B #+0x1000  (0x14000400) */
    r = mk(0x100000);
    CHECK(ssol_simulate(&r, 0x14000400u) == SSOL_SIMULATED, "B: action\n");
    CHECK(r.pc == 0x101000, "B fwd: pc=%llx\n", (ull)r.pc);

    /* B #-0x10  (0x17fffffc) */
    r = mk(0x100000);
    ssol_simulate(&r, 0x17fffffcu);
    CHECK(r.pc == 0x0ffff0, "B back: pc=%llx\n", (ull)r.pc);

    /* BL #+0x20  (0x94000008): LR = pc+4 */
    r = mk(0x100000);
    CHECK(ssol_simulate(&r, 0x94000008u) == SSOL_SIMULATED, "BL: action\n");
    CHECK(r.pc == 0x100020, "BL: pc=%llx\n", (ull)r.pc);
    CHECK(r.regs[30] == 0x100004, "BL: lr=%llx\n", (ull)r.regs[30]);
}

static void g_bcond(void)
{
    struct pt_regs r;
    /* B.EQ #+0x40  (0x54000200) -- taken iff Z=1 */
    r = mk(0x100000);
    r.pstate = 1ull << 30; /* Z=1 */
    ssol_simulate(&r, 0x54000200u);
    CHECK(r.pc == 0x100040, "B.EQ Z=1 taken: pc=%llx\n", (ull)r.pc);

    r = mk(0x100000);
    r.pstate = 0; /* Z=0 */
    ssol_simulate(&r, 0x54000200u);
    CHECK(r.pc == 0x100004, "B.EQ Z=0 not-taken: pc=%llx\n", (ull)r.pc);

    /* B.NE #+0x40  (0x54000201) -- taken iff Z=0 */
    r = mk(0x100000);
    r.pstate = 0;
    ssol_simulate(&r, 0x54000201u);
    CHECK(r.pc == 0x100040, "B.NE Z=0 taken: pc=%llx\n", (ull)r.pc);
}

static void g_cbz_tbz(void)
{
    struct pt_regs r;
    /* CBZ x0, #+8  (0xB4000040) */
    r = mk(0x100000);
    r.regs[0] = 0;
    ssol_simulate(&r, 0xB4000040u);
    CHECK(r.pc == 0x100008, "CBZ x0==0 taken: pc=%llx\n", (ull)r.pc);
    r = mk(0x100000);
    r.regs[0] = 1;
    ssol_simulate(&r, 0xB4000040u);
    CHECK(r.pc == 0x100004, "CBZ x0!=0 not-taken: pc=%llx\n", (ull)r.pc);

    /* CBZ xzr, #+8  (0xB400005F) -- Rt=31 reads XZR=0 -> taken */
    r = mk(0x100000);
    r.regs[30] = 0xdead; /* unrelated */
    ssol_simulate(&r, 0xB400005Fu);
    CHECK(r.pc == 0x100008, "CBZ xzr taken: pc=%llx\n", (ull)r.pc);

    /* CBNZ w1, #+8  (0x35000041) -- 32-bit: low32(x1)==0 -> NOT taken */
    r = mk(0x100000);
    r.regs[1] = 0x100000000ull; /* high bit set, low 32 == 0 */
    ssol_simulate(&r, 0x35000041u);
    CHECK(r.pc == 0x100004, "CBNZ w1 (32-bit width) not-taken: pc=%llx\n", (ull)r.pc);

    /* TBZ x0, #5, #+8  (0x36280040) */
    r = mk(0x100000);
    r.regs[0] = 0;
    ssol_simulate(&r, 0x36280040u);
    CHECK(r.pc == 0x100008, "TBZ bit5=0 taken: pc=%llx\n", (ull)r.pc);
    r = mk(0x100000);
    r.regs[0] = 1ull << 5;
    ssol_simulate(&r, 0x36280040u);
    CHECK(r.pc == 0x100004, "TBZ bit5=1 not-taken: pc=%llx\n", (ull)r.pc);

    /* TBNZ x0, #40, #+8  (0xB7400040) -- bit>=32 */
    r = mk(0x100000);
    r.regs[0] = 1ull << 40;
    ssol_simulate(&r, 0xB7400040u);
    CHECK(r.pc == 0x100008, "TBNZ bit40=1 taken: pc=%llx\n", (ull)r.pc);
    r = mk(0x100000);
    r.regs[0] = 0;
    ssol_simulate(&r, 0xB7400040u);
    CHECK(r.pc == 0x100004, "TBNZ bit40=0 not-taken: pc=%llx\n", (ull)r.pc);
}

static void g_adr(void)
{
    struct pt_regs r;
    /* ADR x0, #+0x100  (0x10000800) */
    r = mk(0x100000);
    ssol_simulate(&r, 0x10000800u);
    CHECK(r.regs[0] == 0x100100, "ADR +0x100: x0=%llx\n", (ull)r.regs[0]);
    CHECK(r.pc == 0x100004, "ADR: pc=%llx\n", (ull)r.pc);

    /* ADR x0, #-4  (0x10FFFFE0) */
    r = mk(0x100000);
    ssol_simulate(&r, 0x10FFFFE0u);
    CHECK(r.regs[0] == 0x0ffffc, "ADR -4: x0=%llx\n", (ull)r.regs[0]);

    /* ADRP x0, #+0x1000  (0xB0000000), unaligned pc -> page-aligned base */
    r = mk(0x100abc);
    ssol_simulate(&r, 0xB0000000u);
    CHECK(r.regs[0] == 0x101000, "ADRP: x0=%llx\n", (ull)r.regs[0]);
    CHECK(r.pc == 0x100ac0, "ADRP: pc=%llx\n", (ull)r.pc);
}

static void g_ldrlit(void)
{
    struct pt_regs r;
    uint32_t buf[8];

    /* LDR x8, [pc,#8]  (0x58000048) -- 64-bit */
    memset(buf, 0, sizeof buf);
    *(uint64_t *)&buf[2] = 0x123456789abcdef0ull;
    r = mk((uint64_t)(uintptr_t)&buf[0]);
    ssol_simulate(&r, 0x58000048u);
    CHECK(r.regs[8] == 0x123456789abcdef0ull, "LDR x8 lit64: %llx\n", (ull)r.regs[8]);
    CHECK(r.pc == (uint64_t)(uintptr_t)&buf[0] + 4, "LDR lit: pc advanced\n");

    /* LDR w0, [pc,#8]  (0x18000040) -- 32-bit zero-extend */
    memset(buf, 0xff, sizeof buf);
    *(uint32_t *)&buf[2] = 0xCAFEBABEu;
    r = mk((uint64_t)(uintptr_t)&buf[0]);
    ssol_simulate(&r, 0x18000040u);
    CHECK(r.regs[0] == 0x00000000CAFEBABEull, "LDR w0 lit32 zero-ext: %llx\n", (ull)r.regs[0]);

    /* LDRSW x0, [pc,#8]  (0x98000040) -- sign-extend */
    memset(buf, 0, sizeof buf);
    *(int32_t *)&buf[2] = -2;
    r = mk((uint64_t)(uintptr_t)&buf[0]);
    ssol_simulate(&r, 0x98000040u);
    CHECK(r.regs[0] == 0xFFFFFFFFFFFFFFFEull, "LDRSW x0 sign-ext: %llx\n", (ull)r.regs[0]);

    /* LDR s0, [pc,#8]  (0x1C000040) -- SIMD literal -> XOL, regs untouched */
    r = mk(0x100000);
    CHECK(ssol_simulate(&r, 0x1C000040u) == SSOL_XOL, "SIMD lit -> XOL\n");
    CHECK(r.pc == 0x100000, "SIMD lit: pc untouched\n");
}

static void g_reg_branches(void)
{
    struct pt_regs r;
    /* BR x5  (0xD61F00A0) */
    r = mk(0x100000);
    r.regs[5] = 0x200000;
    CHECK(ssol_simulate(&r, 0xD61F00A0u) == SSOL_SIMULATED, "BR: action\n");
    CHECK(r.pc == 0x200000, "BR x5: pc=%llx\n", (ull)r.pc);

    /* BLR x9  (0xD63F0120): LR = pc+4 */
    r = mk(0x100000);
    r.regs[9] = 0x300000;
    ssol_simulate(&r, 0xD63F0120u);
    CHECK(r.pc == 0x300000, "BLR x9: pc=%llx\n", (ull)r.pc);
    CHECK(r.regs[30] == 0x100004, "BLR x9: lr=%llx\n", (ull)r.regs[30]);

    /* RET (x30)  (0xD65F03C0) */
    r = mk(0x100000);
    r.regs[30] = 0x400000;
    ssol_simulate(&r, 0xD65F03C0u);
    CHECK(r.pc == 0x400000, "RET x30: pc=%llx\n", (ull)r.pc);

    /* RET x7  (0xD65F00E0) */
    r = mk(0x100000);
    r.regs[7] = 0x500000;
    ssol_simulate(&r, 0xD65F00E0u);
    CHECK(r.pc == 0x500000, "RET x7: pc=%llx\n", (ull)r.pc);
}

static void g_xol_passthrough(void)
{
    struct pt_regs r;
    /* MOV w1, w0  (0x2a0003e1) -> XOL */
    r = mk(0x100000);
    CHECK(ssol_simulate(&r, 0x2a0003e1u) == SSOL_XOL, "MOV -> XOL\n");
    CHECK(r.pc == 0x100000, "MOV: regs untouched\n");

    /* NOP  (0xd503201f) -> XOL */
    r = mk(0x100000);
    CHECK(ssol_simulate(&r, 0xd503201fu) == SSOL_XOL, "NOP -> XOL\n");

    /* BRAAZ x0  (0xD61F081F) -- PAC branch must NOT be mis-simulated as BR */
    r = mk(0x100000);
    r.regs[0] = 0xdead;
    CHECK(ssol_simulate(&r, 0xD61F081Fu) == SSOL_XOL, "BRAAZ (PAC) -> XOL\n");
    CHECK(r.pc == 0x100000, "BRAAZ: regs untouched\n");
}

/* =================== Layer 2: native cross-check (real CPU) =================== */
#ifdef __aarch64__
#include <sys/mman.h>
#include <unistd.h>

/* reference eval_cond replica used only to drive the loop labels (we compare HW
 * to ssol's, not to this) -- ssol_simulate is exercised via B.cond below. */

/* HW condition: assemble `msr nzcv,x; cset x0,<cond>` for each named cond. cset
 * cannot encode AL/NV, so 14/15 are handled as "always" outside this table. */
static int hw_cset(int cond, uint64_t flags)
{
    uint64_t r = 0;
    switch (cond) {
    case 0:  __asm__ volatile("msr nzcv,%1; cset %0,eq" : "=r"(r) : "r"(flags) : "cc"); break;
    case 1:  __asm__ volatile("msr nzcv,%1; cset %0,ne" : "=r"(r) : "r"(flags) : "cc"); break;
    case 2:  __asm__ volatile("msr nzcv,%1; cset %0,cs" : "=r"(r) : "r"(flags) : "cc"); break;
    case 3:  __asm__ volatile("msr nzcv,%1; cset %0,cc" : "=r"(r) : "r"(flags) : "cc"); break;
    case 4:  __asm__ volatile("msr nzcv,%1; cset %0,mi" : "=r"(r) : "r"(flags) : "cc"); break;
    case 5:  __asm__ volatile("msr nzcv,%1; cset %0,pl" : "=r"(r) : "r"(flags) : "cc"); break;
    case 6:  __asm__ volatile("msr nzcv,%1; cset %0,vs" : "=r"(r) : "r"(flags) : "cc"); break;
    case 7:  __asm__ volatile("msr nzcv,%1; cset %0,vc" : "=r"(r) : "r"(flags) : "cc"); break;
    case 8:  __asm__ volatile("msr nzcv,%1; cset %0,hi" : "=r"(r) : "r"(flags) : "cc"); break;
    case 9:  __asm__ volatile("msr nzcv,%1; cset %0,ls" : "=r"(r) : "r"(flags) : "cc"); break;
    case 10: __asm__ volatile("msr nzcv,%1; cset %0,ge" : "=r"(r) : "r"(flags) : "cc"); break;
    case 11: __asm__ volatile("msr nzcv,%1; cset %0,lt" : "=r"(r) : "r"(flags) : "cc"); break;
    case 12: __asm__ volatile("msr nzcv,%1; cset %0,gt" : "=r"(r) : "r"(flags) : "cc"); break;
    case 13: __asm__ volatile("msr nzcv,%1; cset %0,le" : "=r"(r) : "r"(flags) : "cc"); break;
    default: r = 1; break; /* AL/NV: always */
    }
    return (int)(r & 1);
}

/* Cross-check eval_cond (via a simulated B.cond) against the silicon for EVERY
 * (cond, NZCV) pair. B.cond #+8 -> taken means pc=orig+8, else orig+4. */
static void n_eval_cond(void)
{
    for (int cond = 0; cond < 16; cond++) {
        uint32_t insn = 0x54000040u | (uint32_t)cond; /* B.<cond> #+8 (imm19=2) */
        for (int nzcv = 0; nzcv < 16; nzcv++) {
            uint64_t flags = (uint64_t)nzcv << 28;
            int hw = hw_cset(cond, flags);
            struct pt_regs r = mk(0x100000);
            r.pstate = flags;
            ssol_simulate(&r, insn);
            int sim = (r.pc == 0x100008) ? 1 : 0;
            CHECK(sim == hw, "eval_cond mismatch cond=%d nzcv=%x sim=%d hw=%d\n",
                  cond, nzcv, sim, hw);
        }
    }
}

/* Run a 2-word stub [insn][ret] natively at a known address P; return x0. Used
 * for ADR/ADRP/LDR-lit where the result lands in x0 and pc just advances. */
static uint64_t run_x0(uint32_t insn, uint32_t w1, uint32_t w2, uint32_t w3, void **page_out)
{
    long ps = sysconf(_SC_PAGESIZE);
    uint32_t *p = mmap(NULL, ps, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { CHECK(0, "mmap failed\n"); *page_out = NULL; return 0; }
    p[0] = insn;
    p[1] = w1;
    p[2] = w2;
    p[3] = w3;
    __builtin___clear_cache((char *)p, (char *)p + 4 * sizeof(uint32_t));
    uint64_t (*f)(void) = (uint64_t(*)(void))p;
    uint64_t r = f();
    *page_out = p;
    return r;
}

/* Cross-check the pc-relative dest-register math (ADR/ADRP/LDR-lit) against the
 * CPU: same insn, real pc vs ssol_simulate(pc=P). */
static void n_pcrel_regs(void)
{
    void *pg;
    uint64_t hw;
    struct pt_regs r;

    /* ADR x0, #+0x100 ; ret */
    hw = run_x0(0x10000800u, 0xD65F03C0u, 0, 0, &pg);
    if (pg) {
        r = mk((uint64_t)(uintptr_t)pg);
        ssol_simulate(&r, 0x10000800u);
        CHECK(r.regs[0] == hw, "native ADR: sim=%llx hw=%llx\n", (ull)r.regs[0], (ull)hw);
        munmap(pg, sysconf(_SC_PAGESIZE));
    }

    /* ADRP x0, #+0x1000 ; ret */
    hw = run_x0(0xB0000000u, 0xD65F03C0u, 0, 0, &pg);
    if (pg) {
        r = mk((uint64_t)(uintptr_t)pg);
        ssol_simulate(&r, 0xB0000000u);
        CHECK(r.regs[0] == hw, "native ADRP: sim=%llx hw=%llx\n", (ull)r.regs[0], (ull)hw);
        munmap(pg, sysconf(_SC_PAGESIZE));
    }

    /* LDR x0, [pc,#8] ; ret ; .quad 0xA5A5A5A5DEADBEEF (words 2,3) */
    hw = run_x0(0x58000040u, 0xD65F03C0u, 0xDEADBEEFu, 0xA5A5A5A5u, &pg);
    if (pg) {
        r = mk((uint64_t)(uintptr_t)pg);
        ssol_simulate(&r, 0x58000040u);
        CHECK(r.regs[0] == hw && hw == 0xA5A5A5A5DEADBEEFull,
              "native LDR lit64: sim=%llx hw=%llx\n", (ull)r.regs[0], (ull)hw);
        munmap(pg, sysconf(_SC_PAGESIZE));
    }

    /* LDRSW x0, [pc,#8] ; ret ; .word -2 (sign-extend) */
    hw = run_x0(0x98000040u, 0xD65F03C0u, (uint32_t)-2, 0, &pg);
    if (pg) {
        r = mk((uint64_t)(uintptr_t)pg);
        ssol_simulate(&r, 0x98000040u);
        CHECK(r.regs[0] == hw && hw == 0xFFFFFFFFFFFFFFFEull,
              "native LDRSW: sim=%llx hw=%llx\n", (ull)r.regs[0], (ull)hw);
        munmap(pg, sysconf(_SC_PAGESIZE));
    }

    /* LDR w0, [pc,#8] ; ret ; .word 0xCAFEBABE (zero-extend) */
    hw = run_x0(0x18000040u, 0xD65F03C0u, 0xCAFEBABEu, 0, &pg);
    if (pg) {
        r = mk((uint64_t)(uintptr_t)pg);
        ssol_simulate(&r, 0x18000040u);
        CHECK(r.regs[0] == hw && hw == 0x00000000CAFEBABEull,
              "native LDR w lit32: sim=%llx hw=%llx\n", (ull)r.regs[0], (ull)hw);
        munmap(pg, sysconf(_SC_PAGESIZE));
    }
}
#endif /* __aarch64__ */

int main(void)
{
    g_branches();
    g_bcond();
    g_cbz_tbz();
    g_adr();
    g_ldrlit();
    g_reg_branches();
    g_xol_passthrough();
#ifdef __aarch64__
    printf("[native cross-check enabled]\n");
    n_eval_cond();
    n_pcrel_regs();
#else
    printf("[native cross-check skipped: not __aarch64__]\n");
#endif

    if (fails == 0)
        printf("ssol: ALL TESTS PASSED\n");
    else
        printf("ssol: %d CHECK(s) FAILED\n", fails);
    return fails ? 1 : 0;
}
