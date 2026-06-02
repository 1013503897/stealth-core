// SPDX-License-Identifier: GPL-2.0-or-later
// dbitarget: target for the P2.2 single-function DBI redirect PoC.
//
// tick() is forced onto its OWN page (aligned(4096) + a guard function aligned to
// the next page) and kept PC-relative-free (only local stack ops, no globals, no
// literals -- built with -fno-stack-protector so there's no canary ADRP), so a
// VERBATIM page copy is a valid "recompiled" clone (no instruction fixups needed).
//
// At startup it mmaps a clone page, copies tick's whole page into it, makes it
// executable, and prints pid + &tick + tick_page + clone_page. The driver then
// asks the KPM to set UXN on tick's page and reroute the resulting do_page_fault
// PC into the clone -- so tick runs from the clone while its original .text is
// never touched (CRC-clean) and there is no extra executable VMA at tick's addr.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>

__attribute__((aligned(0x1000), noinline)) void tick(int who, int n)
{
    volatile int x = who + n; // local stack only -> no ADRP / literal / global
    (void)x;
}

// aligned(4096) pushes the next function to the next page, isolating tick's page
__attribute__((aligned(0x1000), noinline)) void tick_guard(void)
{
    asm volatile("nop");
}

int main(void)
{
    uintptr_t tk = (uintptr_t)&tick;
    uintptr_t page = tk & ~0xfffUL;

    void *clone = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (clone == MAP_FAILED) {
        printf("mmap failed\n");
        return 1;
    }
    memcpy(clone, (void *)page, 0x1000);                       // verbatim clone of tick's page
    __builtin___clear_cache((char *)clone, (char *)clone + 0x1000); // I/D cache coherency for new code
    if (mprotect(clone, 0x1000, PROT_READ | PROT_EXEC) != 0) {  // W^X-friendly: flip to RX
        printf("mprotect failed\n");
        return 1;
    }

    printf("pid=%d tick=%p page=0x%lx clone=%p\n", getpid(), (void *)&tick, (unsigned long)page, clone);
    fflush(stdout);

    unsigned long c = 0;
    for (;;) {
        tick(1, (int)c);
        c++;
        if ((c % 30) == 0) {
            printf("calls=%lu\n", c);
            fflush(stdout);
        }
        usleep(100000); // ~10 calls/sec
    }
    return 0;
}
