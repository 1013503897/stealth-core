// SPDX-License-Identifier: GPL-2.0-or-later
// hwhooktool: tests the HWBP-redirect inline_hooker on a NON-page-isolated target.
// victimA and victimB are ordinary adjacent functions (NOT aligned/isolated), so
// they share a code page. We hook victimA -> replaceA via a hardware breakpoint
// (per-instruction). Proof: after hwhookto, victimA(i) prints
//   [R] replaced A .. / [A] orig .. (from ghost backup)
// while victimB(i) keeps printing [B] normally -- i.e. only victimA's entry is
// trapped, the page-neighbor victimB is untouched (which UXN-per-page would break).
// Build: -fno-stack-protector, link lib/dbi.c.

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include "../lib/dbi.h"

#define GHOST_VA 0x6000000000UL

// adjacent, NOT page-isolated -> share a page
__attribute__((noinline)) void victimA(int n) { printf("[A] orig n=%d\n", n); }
__attribute__((noinline)) void victimB(int n) { printf("[B] orig n=%d\n", n); }

__attribute__((noinline)) void replaceA(int n)
{
    printf("[R] replaced A n=%d -> backup:\n", n);
    ((void (*)(int))GHOST_VA)(n); // backup = ghost clone of victimA
    printf("[R] done n=%d\n", n);
}

static uint32_t clonebuf[1024];
static uint32_t omap[1024];

int main(void)
{
    uintptr_t a = (uintptr_t)&victimA;
    int n = dbi_recompile(a, (const uint32_t *)a, 256, clonebuf, 1024, omap, 1024);
    if (n < 0) { printf("dbi_recompile failed %d\n", n); return 1; }

    unsigned long pageA = a & ~0xfffUL, pageB = (uintptr_t)&victimB & ~0xfffUL;
    printf("pid=%d victimA=%p victimB=%p same_page=%d replaceA=%p clonebuf=%p nclone=%d template_va=%p ghost_va=0x%lx\n",
           getpid(), (void *)&victimA, (void *)&victimB, pageA == pageB, (void *)&replaceA, (void *)clonebuf,
           n, (void *)&main, GHOST_VA);
    fflush(stdout);

    for (int i = 0;; i++) {
        victimA(i);
        victimB(i);
        fflush(stdout);
        usleep(700000);
    }
    return 0;
}
