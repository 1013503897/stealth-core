// SPDX-License-Identifier: GPL-2.0-or-later
// hooktool: tests the KPM inline_hooker primitive (hookto), the piece LSPlant's
// InitInfo.inline_hooker maps onto. funcA() is the hook target; funcB() is the
// replacement. After `hookto`, calling funcA() is rerouted to funcB(), and funcB
// calls `backup` (a ghost clone of funcA at a fixed VA) to run the original.
// Expected per call:  [B] hooked .. -> [A] orig ..  -> [B] done ..
// proving target->replace routing + a working backup, all traceless.
// Build: -fno-stack-protector, link lib/dbi.c.

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include "../lib/dbi.h"

#define GHOST_VA 0x6000000000UL // fixed backup VA (kernel injects the clone here)

// hook target: page-isolated + PC-relative (ADR fmt + B printf) so it can be
// UXN-trapped and DBI-cloned.
__attribute__((aligned(0x1000), noinline)) void funcA(int n)
{
    printf("[A] orig n=%d\n", n);
}
__attribute__((aligned(0x1000), noinline)) void fa_guard(void) { asm volatile("nop"); }

// replacement: runs instead of funcA, then calls the original via backup.
__attribute__((noinline)) void funcB(int n)
{
    printf("[B] hooked n=%d -> backup:\n", n);
    ((void (*)(int))GHOST_VA)(n); // call backup = ghost clone of funcA
    printf("[B] done n=%d\n", n);
}

static uint32_t clonebuf[1024];
static uint32_t omap[1024];

int main(void)
{
    uintptr_t target = (uintptr_t)&funcA;
    uintptr_t page = target & ~0xfffUL;
    int n = dbi_recompile(page, (const uint32_t *)page, 256, clonebuf, 1024, omap, 1024);
    if (n < 0) { printf("dbi_recompile failed %d\n", n); return 1; }

    printf("pid=%d funcA=%p funcB=%p clonebuf=%p nclone=%d template_va=%p ghost_va=0x%lx\n", getpid(),
           (void *)&funcA, (void *)&funcB, (void *)clonebuf, n, (void *)&main, GHOST_VA);
    fflush(stdout);

    for (int i = 0;; i++) {
        funcA(i);
        fflush(stdout);
        usleep(700000);
    }
    return 0;
}
