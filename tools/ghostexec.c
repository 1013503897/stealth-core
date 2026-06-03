// SPDX-License-Identifier: GPL-2.0-or-later
// ghostexec: P4.2 step B target. Recompiles a PC-relative hook_me() (ADR+B) into
// a position-independent clone held in a plain DATA buffer (not an executable
// mapping) + an offset_map, and picks a free no-VMA ghost VA. The KPM copies the
// clone bytes into a VMA-less ghost page and redirects hook_me there, so the
// clone executes from memory the OS doesn't know exists. Build: -fno-stack-protector.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>

__attribute__((aligned(0x1000), noinline)) void hook_me(int n)
{
    printf("[ghost] hook_me n=%d\n", n); // ADR (fmt) + B printf@plt
}
__attribute__((aligned(0x1000), noinline)) void hm_guard(void) { asm volatile("nop"); }

static uint32_t enc_ldr_lit64(int rd, int off) { return 0x58000000u | (((uint32_t)(off / 4) & 0x7ffff) << 5) | (rd & 0x1f); }
static uint32_t enc_b(int off) { return 0x14000000u | ((uint32_t)(off / 4) & 0x03ffffff); }
#define BR_X16 0xD61F0200u
#define BLR_X16 0xD63F0200u
static int64_t sext(int64_t v, int bits) { int s = 64 - bits; return (v << s) >> s; }

/* recompile ADR/ADRP/B/BL -> absolute; verbatim otherwise; stop after a B/RET */
static int dbi_recompile(uintptr_t base, const uint32_t *src, uint32_t *out, uint32_t *offmap, int maxsrc)
{
    int sizes[256], nsrc = 0;
    for (int i = 0; i < maxsrc && i < 256; i++) {
        uint32_t in = src[i];
        int sz = ((in & 0x9F000000u) == 0x90000000u || (in & 0x9F000000u) == 0x10000000u ||
                  (in & 0xFC000000u) == 0x14000000u) ? 4 : ((in & 0xFC000000u) == 0x94000000u ? 5 : 1);
        sizes[i] = sz;
        nsrc = i + 1;
        if ((in & 0xFC000000u) == 0x14000000u) break;
        if (in == 0xD65F03C0u) break;
    }
    int acc = 0;
    for (int i = 0; i < nsrc; i++) { offmap[i] = (uint32_t)acc; acc += sizes[i]; }
    for (int i = nsrc; i < 1024; i++) offmap[i] = (uint32_t)i;

    int o = 0;
    for (int i = 0; i < nsrc; i++) {
        uint32_t in = src[i];
        uint64_t pc = base + (uint64_t)i * 4;
        int rd = in & 0x1f;
        if ((in & 0x9F000000u) == 0x90000000u) { /* ADRP */
            int64_t imm = sext(((in >> 5) & 0x7ffff) << 2 | ((in >> 29) & 3), 21);
            uint64_t t = (pc & ~0xfffULL) + ((uint64_t)imm << 12);
            out[o++] = enc_ldr_lit64(rd, 8); out[o++] = enc_b(12);
            out[o++] = (uint32_t)t; out[o++] = (uint32_t)(t >> 32);
        } else if ((in & 0x9F000000u) == 0x10000000u) { /* ADR */
            int64_t imm = sext(((in >> 5) & 0x7ffff) << 2 | ((in >> 29) & 3), 21);
            uint64_t t = pc + (uint64_t)imm;
            out[o++] = enc_ldr_lit64(rd, 8); out[o++] = enc_b(12);
            out[o++] = (uint32_t)t; out[o++] = (uint32_t)(t >> 32);
        } else if ((in & 0xFC000000u) == 0x14000000u) { /* B */
            uint64_t t = pc + ((uint64_t)sext(in & 0x03ffffff, 26) << 2);
            out[o++] = enc_ldr_lit64(16, 8); out[o++] = BR_X16;
            out[o++] = (uint32_t)t; out[o++] = (uint32_t)(t >> 32);
        } else if ((in & 0xFC000000u) == 0x94000000u) { /* BL */
            uint64_t t = pc + ((uint64_t)sext(in & 0x03ffffff, 26) << 2);
            out[o++] = enc_ldr_lit64(16, 12); out[o++] = BLR_X16; out[o++] = enc_b(12);
            out[o++] = (uint32_t)t; out[o++] = (uint32_t)(t >> 32);
        } else {
            out[o++] = in;
        }
    }
    return o;
}

static uint32_t clonebuf[1024];
static uint32_t omap[1024];

// A fixed VA in a far, rarely-used region (well below the 39-bit limit and away
// from the top-down mmap area), so it stays free for the lifetime of the process
// -- unlike mmap+munmap, which the allocator reuses once we call printf().
static unsigned long pick_free_va(void)
{
    return 0x6000000000UL;
}

int main(void)
{
    uintptr_t fn = (uintptr_t)&hook_me;
    uintptr_t page = fn & ~0xfffUL;
    int n = dbi_recompile(page, (const uint32_t *)page, clonebuf, omap, 256);
    unsigned long ghost = pick_free_va() & ~0xfffUL;

    printf("pid=%d hook_me=%p page=0x%lx clonebuf=%p nclone=%d omap=%p nmap=1024 ghost_va=0x%lx template_va=%p\n",
           getpid(), (void *)&hook_me, (unsigned long)page, (void *)clonebuf, n, (void *)omap, ghost,
           (void *)&main);
    fflush(stdout);

    for (int i = 0;; i++) {
        hook_me(i);
        fflush(stdout);
        usleep(500000);
    }
    return 0;
}
