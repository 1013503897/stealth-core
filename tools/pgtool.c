// SPDX-License-Identifier: GPL-2.0-or-later
// pgtool: MULTI-page hook test (exercises the KPM `pghook`/`pgdisarm` table).
// funcA (page-aligned -> page P_A) and funcB (page-aligned -> page P_B != P_A)
// each share their page with a neighbor (funcA_nb / funcB_nb). We recompile EACH
// page into its own whole-page clone (dbi_recompile_range) and use the kernel's
// multi-page table to UXN-trap BOTH pages at once: `pghook` page A routes funcA's
// entry -> replaceA, `pghook` page B routes funcB's entry -> replaceB, and the
// neighbors keep running (from their respective clones). Proves several
// page-shared (libart-style) functions on DIFFERENT pages can be hooked
// simultaneously, with the original .text never modified. One `pgdisarm` tears
// the whole table down. Build: -fno-stack-protector, link lib/dbi.c.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include "../lib/dbi.h"

/* ---- page A: funcA + a page-neighbor ---- */
__attribute__((aligned(0x1000), noinline)) void funcA(int n) { printf("[A] n=%d sq=%d\n", n, n * n); }
__attribute__((noinline)) void funcA_nb(int n) { printf("[A-nb] n=%d dbl=%d\n", n, n + n); }

/* ---- page B: funcB (internal loop branch) + a page-neighbor ---- */
__attribute__((aligned(0x1000), noinline)) void funcB(int n)
{
    int s = 0;
    for (int i = 0; i <= n; i++) s += i;
    printf("[B] n=%d sum=%d\n", n, s);
}
__attribute__((noinline)) void funcB_nb(int n) { printf("[B-nb] n=%d cube=%d\n", n, n * n * n); }

/* guard: force the following content onto a fresh page so page B is self-contained */
__attribute__((aligned(0x1000), noinline)) void pg_guard(void) { asm volatile("nop"); }

/* replacements live AFTER the guard -> on an untrapped page. Each calls its
 * backup (= the clone's faithful copy of the original) to run the real function. */
static void (*g_backupA)(int) = 0;
static void (*g_backupB)(int) = 0;
__attribute__((noinline)) void replaceA(int n)
{
    printf("[HOOK A] intercept n=%d -> backup:\n", n);
    if (g_backupA) g_backupA(n);
    printf("[HOOK A] done n=%d\n", n);
}
__attribute__((noinline)) void replaceB(int n)
{
    printf("[HOOK B] intercept n=%d -> backup:\n", n);
    if (g_backupB) g_backupB(n);
    printf("[HOOK B] done n=%d\n", n);
}

static uint32_t cloneA_buf[6144], cloneB_buf[6144]; /* 1024 insns can expand ~5x */
static uint32_t omapA[1024], omapB[1024];

static void *make_clone(uintptr_t page, uint32_t *buf, uint32_t *omap)
{
    /* bound literal-pool reads to +-8MB around the page (mapped binary segments) */
    int n = dbi_recompile_range(page, (const uint32_t *)page, 1024, buf, 6144, omap, 1024,
                                (uintptr_t)(page - 0x800000), (uintptr_t)(page + 0x800000));
    if (n < 0) {
        printf("recompile_range(0x%lx) failed %d\n", (unsigned long)page, n);
        return 0;
    }
    size_t sz = ((size_t)n * 4 + 0xfff) & ~(size_t)0xfff;
    void *clone = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (clone == MAP_FAILED) {
        printf("mmap failed\n");
        return 0;
    }
    memcpy(clone, buf, (size_t)n * 4);
    __builtin___clear_cache((char *)clone, (char *)clone + sz);
    if (mprotect(clone, sz, PROT_READ | PROT_EXEC)) {
        printf("mprotect failed\n");
        return 0;
    }
    return clone;
}

int main(void)
{
    uintptr_t pageA = (uintptr_t)&funcA & ~0xfffUL;
    uintptr_t pageB = (uintptr_t)&funcB & ~0xfffUL;
    int distinct = (pageA != pageB);
    int nbA_same = ((((uintptr_t)&funcA_nb) & ~0xfffUL) == pageA);
    int nbB_same = ((((uintptr_t)&funcB_nb) & ~0xfffUL) == pageB);
    if (!distinct) {
        printf("ERROR: funcA/funcB landed on the same page (0x%lx) -- bad layout\n",
               (unsigned long)pageA);
        return 1;
    }

    void *cloneA = make_clone(pageA, cloneA_buf, omapA);
    void *cloneB = make_clone(pageB, cloneB_buf, omapB);
    if (!cloneA || !cloneB) return 1;

    /* funcA / funcB are page-aligned -> their entry is at page+0 -> omap[0] */
    g_backupA = (void (*)(int))((char *)cloneA + (size_t)omapA[0] * 4);
    g_backupB = (void (*)(int))((char *)cloneB + (size_t)omapB[0] * 4);

    printf("pid=%d distinct=%d nbA_same=%d nbB_same=%d\n", getpid(), distinct, nbA_same, nbB_same);
    printf("pageA=0x%lx cloneA=%p omapA=%p replaceA=%p funcA=%p funcA_nb=%p\n", (unsigned long)pageA,
           cloneA, (void *)omapA, (void *)&replaceA, (void *)&funcA, (void *)&funcA_nb);
    printf("pageB=0x%lx cloneB=%p omapB=%p replaceB=%p funcB=%p funcB_nb=%p\n", (unsigned long)pageB,
           cloneB, (void *)omapB, (void *)&replaceB, (void *)&funcB, (void *)&funcB_nb);
    fflush(stdout);

    for (int i = 0;; i++) {
        funcA(i % 5);
        funcA_nb(i % 5);
        funcB(i % 5 + 1);
        funcB_nb(i % 5 + 2);
        fflush(stdout);
        usleep(700000);
    }
    return 0;
}
