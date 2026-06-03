// SPDX-License-Identifier: GPL-2.0-or-later
// ghosttool: P4.2 VMA-less ghost-memory test target.
//
// Picks a high user VA with no VMA, prints it (+ a template VA = a real mapped
// code page), then SIGSEGV-protected-probes that VA in a loop. Before the KPM
// injects a PTE there, the read faults (no mapping). After `ghosttest`, the read
// returns the kernel-stamped magic, while mincore() reports "not mapped" and the
// VA is absent from /proc/self/maps -- i.e. the page exists to the CPU but not to
// the OS. That information-difference is the "ghost memory".

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>

static sigjmp_buf jb;
static void on_segv(int s) { (void)s; siglongjmp(jb, 1); }

/* Pick a valid, in-range, currently-free user VA: let the kernel choose one via
 * mmap, then munmap it so the VA has no VMA (but stays inside the addressable
 * user range, unlike "highest map + N" which can overflow the 39-bit limit). */
static unsigned long pick_free_va(void)
{
    void *probe = mmap(NULL, 0x1000, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe == MAP_FAILED) return 0;
    munmap(probe, 0x1000);
    return (unsigned long)probe;
}

static int va_in_maps(unsigned long va)
{
    unsigned long a, b;
    char line[512];
    int found = 0;
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "%lx-%lx", &a, &b) == 2 && va >= a && va < b) { found = 1; break; }
    fclose(f);
    return found;
}

int main(void)
{
    unsigned long ghost = pick_free_va() & ~0xfffUL; // valid, in-range, no-VMA VA
    printf("pid=%d ghost_va=0x%lx template_va=%p\n", getpid(), ghost, (void *)&main);
    fflush(stdout);

    signal(SIGSEGV, on_segv);
    for (;;) {
        unsigned long val = 0;
        int ok = 0;
        if (sigsetjmp(jb, 1) == 0) {
            val = *(volatile unsigned long *)ghost; // faults if not injected
            ok = 1;
        }
        if (ok) {
            unsigned char vec = 0;
            int mc = mincore((void *)ghost, 4096, &vec);
            int me = (mc < 0) ? errno : 0;
            printf("GHOST READ ok val=0x%lx  mincore=%d(errno=%d)  in_maps=%d\n", val, mc, me,
                   va_in_maps(ghost));
        } else {
            printf("ghost not mapped yet (read faulted)\n");
        }
        fflush(stdout);
        usleep(700000);
    }
    return 0;
}
