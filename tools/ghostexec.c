// SPDX-License-Identifier: GPL-2.0-or-later
// ghostexec: P4.2 step B target, now using the shared libdbi recompiler.
// Recompiles a PC-relative hook_me() (ADR+B) into a position-independent clone in
// a plain DATA buffer + offset_map, and picks a free no-VMA ghost VA. The KPM
// copies the clone into a VMA-less ghost page and redirects hook_me there, so the
// clone executes from memory the OS doesn't know exists. Build: -fno-stack-protector.

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include "../lib/dbi.h"

__attribute__((aligned(0x1000), noinline)) void hook_me(int n)
{
    printf("[ghost] hook_me n=%d\n", n); // ADR (fmt) + B printf@plt
}
__attribute__((aligned(0x1000), noinline)) void hm_guard(void) { asm volatile("nop"); }

static uint32_t clonebuf[1024];
static uint32_t omap[1024];

// A fixed VA in a far, rarely-used region (well below the 39-bit limit, away from
// the top-down mmap area) so it stays free for the process lifetime.
static unsigned long pick_free_va(void) { return 0x6000000000UL; }

int main(void)
{
    uintptr_t fn = (uintptr_t)&hook_me;
    uintptr_t page = fn & ~0xfffUL;
    int n = dbi_recompile(page, (const uint32_t *)page, 256, clonebuf, 1024, omap, 1024);
    if (n < 0) {
        printf("dbi_recompile failed: %d\n", n);
        return 1;
    }
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
