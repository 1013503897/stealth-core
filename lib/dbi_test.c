/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Unit test for libdbi. Pure computation -> runnable on host or device.
 *   cc dbi.c dbi_test.c -o dbi_test && ./dbi_test   (any C compiler) */

#include "dbi.h"
#include <stdio.h>
#include <stdint.h>

static int fails = 0;
#define CHECK(cond, ...)                            \
    do {                                            \
        if (!(cond)) {                              \
            printf("FAIL: " __VA_ARGS__);           \
            printf("  (%s:%d)\n", __FILE__, __LINE__); \
            fails++;                                \
        }                                           \
    } while (0)

/* Case 1: hook_me-like  mov w1,w0 / nop / adr x0,#0x100 / b #0x1000(external) */
static void test_adr_b(void)
{
    uint32_t src[4] = {
        0x2a0003e1u, /* mov w1, w0 */
        0xd503201fu, /* nop        */
        0x10000800u, /* adr x0, #0x100 */
        0x14000400u, /* b #0x1000 (tail, external) */
    };
    uint32_t out[64], omap[1024];
    int n = dbi_recompile(0x100000, src, 4, out, 64, omap, 1024);

    CHECK(n == 10, "adr_b: clone size %d != 10\n", n);
    CHECK(omap[0] == 0 && omap[1] == 1 && omap[2] == 2 && omap[3] == 6,
          "adr_b: offmap %u,%u,%u,%u\n", omap[0], omap[1], omap[2], omap[3]);
    CHECK(out[0] == 0x2a0003e1u, "adr_b: mov not verbatim %08x\n", out[0]);
    CHECK(out[1] == 0xd503201fu, "adr_b: nop not verbatim %08x\n", out[1]);
    CHECK(out[2] == 0x58000040u, "adr_b: ldr x0,[pc,#8] %08x\n", out[2]); /* ADR -> abs load */
    CHECK(out[3] == 0x14000003u, "adr_b: b #12 %08x\n", out[3]);
    CHECK(out[4] == 0x00100108u && out[5] == 0, "adr_b: adr target %08x%08x\n", out[5], out[4]);
    CHECK(out[6] == 0x58000050u, "adr_b: ldr x16,[pc,#8] %08x\n", out[6]); /* B -> far */
    CHECK(out[7] == 0xd61f0200u, "adr_b: br x16 %08x\n", out[7]);
    CHECK(out[8] == 0x0010100cu && out[9] == 0, "adr_b: b target %08x%08x\n", out[9], out[8]);
}

/* Case 2: LDR-literal  ldr x8, [pc,#8] ; ret ; <8-byte value> */
static void test_ldrlit(void)
{
    uint32_t arr[4];
    arr[0] = 0x58000048u; /* ldr x8, [pc,#8] -> arr[2] */
    arr[1] = 0xd65f03c0u; /* ret */
    arr[2] = 0x9abcdef0u; /* literal lo */
    arr[3] = 0x12345678u; /* literal hi -> 0x123456789abcdef0 */

    uint32_t out[64], omap[1024];
    int n = dbi_recompile((uintptr_t)arr, arr, 4, out, 64, omap, 1024);

    CHECK(n == 5, "ldrlit: clone size %d != 5\n", n);
    CHECK(omap[0] == 0 && omap[1] == 4, "ldrlit: offmap %u,%u\n", omap[0], omap[1]);
    CHECK(out[0] == 0x58000048u, "ldrlit: ldr x8,[pc,#8] %08x\n", out[0]);
    CHECK(out[1] == 0x14000003u, "ldrlit: b #12 %08x\n", out[1]);
    CHECK(out[2] == 0x9abcdef0u && out[3] == 0x12345678u, "ldrlit: value %08x%08x\n", out[3], out[2]);
    CHECK(out[4] == 0xd65f03c0u, "ldrlit: ret verbatim %08x\n", out[4]);
}

/* Case 3: internal conditional + backward branch (a loop), then ret.
 *   0: cmp-like (verbatim)   1: b.ne -4 (internal backward)   2: ret  */
static void test_internal_bcond(void)
{
    uint32_t src[3] = {
        0x6b08003fu, /* cmp w1, w8 (verbatim) */
        0x54ffffe1u, /* b.ne #-4 -> index 0 (internal backward) */
        0xd65f03c0u, /* ret */
    };
    uint32_t out[64], omap[1024];
    int n = dbi_recompile(0x200000, src, 3, out, 64, omap, 1024);

    CHECK(n == 3, "bcond: clone size %d != 3 (internal stays 1 insn)\n", n);
    CHECK(out[0] == 0x6b08003fu, "bcond: cmp verbatim %08x\n", out[0]);
    /* b.ne re-encoded clone-relative: target index0 -> clone idx 0, emitted at o=1,
       rel = 0 - 1 = -1 -> imm19 = -1 (0x7ffff); cond ne(0x1) preserved */
    CHECK((out[1] & 0xFF00001Fu) == (0x54000000u | 0x1u), "bcond: cond/opcode %08x\n", out[1]);
    CHECK(((out[1] >> 5) & 0x7ffffu) == 0x7ffffu, "bcond: rel imm19 %08x\n", out[1]);
    CHECK(out[2] == 0xd65f03c0u, "bcond: ret verbatim %08x\n", out[2]);
}

int main(void)
{
    test_adr_b();
    test_ldrlit();
    test_internal_bcond();
    if (fails == 0)
        printf("libdbi: ALL TESTS PASSED\n");
    else
        printf("libdbi: %d CHECK(s) FAILED\n", fails);
    return fails ? 1 : 0;
}
