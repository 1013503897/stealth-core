// SPDX-License-Identifier: GPL-2.0-or-later
// pagetool: whole-page DBI test. funcA (page-aligned) + funcB + funcC share one
// code page (guard forces the next fn to the next page). We recompile the WHOLE
// page with dbi_recompile_range and route the whole page to the clone. After the
// KPM UXN-traps the page, every call to A/B/C faults at its entry and is routed to
// the clone, so all three run correctly FROM the clone while the original page is
// never modified -- the core capability for process-wide UXN hooking of real
// (page-shared) libart functions. Build: -fno-stack-protector, link lib/dbi.c.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include "../lib/dbi.h"

__attribute__((aligned(0x1000), noinline)) void funcA(int n) { printf("[A] n=%d sq=%d\n", n, n * n); }
__attribute__((noinline)) void funcB(int n)
{
    int s = 0;
    for (int i = 0; i <= n; i++) s += i; // internal loop branch
    printf("[B] n=%d sum=%d\n", n, s);
}
__attribute__((noinline)) void funcC(int n) { printf("[C] n=%d cube=%d\n", n, n * n * n); }
__attribute__((aligned(0x1000), noinline)) void pg_guard(void) { asm volatile("nop"); }

static uint32_t clonebuf[6144]; // 1024 insns can expand up to ~5x
static uint32_t omap[1024];

int main(void)
{
    uintptr_t page = (uintptr_t)&funcA & ~0xfffUL;
    int same = ((((uintptr_t)&funcB) & ~0xfffUL) == page) && ((((uintptr_t)&funcC) & ~0xfffUL) == page);

    // bound literal-pool reads to +-8MB around the page (mapped binary segments)
    int n = dbi_recompile_range(page, (const uint32_t *)page, 1024, clonebuf, 6144, omap, 1024,
                                (uintptr_t)(page - 0x800000), (uintptr_t)(page + 0x800000));
    if (n < 0) { printf("recompile_range failed %d\n", n); return 1; }

    size_t sz = ((size_t)n * 4 + 0xfff) & ~(size_t)0xfff;
    void *clone = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (clone == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    memcpy(clone, clonebuf, (size_t)n * 4);
    __builtin___clear_cache((char *)clone, (char *)clone + sz);
    if (mprotect(clone, sz, PROT_READ | PROT_EXEC)) { printf("mprotect failed\n"); return 1; }

    printf("pid=%d page=0x%lx same_page=%d funcA=%p funcB=%p funcC=%p clone=%p clone_insns=%d omap=%p nmap=1024\n",
           getpid(), (unsigned long)page, same, (void *)&funcA, (void *)&funcB, (void *)&funcC, clone, n,
           (void *)omap);
    fflush(stdout);

    for (int i = 0;; i++) {
        funcA(i % 5);
        funcB(i % 5 + 1);
        funcC(i % 5 + 2);
        fflush(stdout);
        usleep(700000);
    }
    return 0;
}
