// SPDX-License-Identifier: GPL-2.0-or-later
// rgntool: RV-2 multi-page (clean-bounded REGION) clone test. The L1a single whole-
// page clone breaks any function that spans a page boundary; RV-2 clones a clean-
// bounded multi-page region so the whole function is in the clone and RETs normally.
//
// spanfn is page-aligned and ~1100 instructions (> 4 KiB), so it SPANS into the next
// page; it returns n + 1100 (a value only reachable if its ENTIRE body runs). nbfn
// sits right after it -> on spanfn's SECOND page (a page-neighbor inside the region),
// and is NOT hooked. We hook spanfn -> replace_span (which calls the backup):
//   - hooked: prints [R span] and the backup returns n+1100  => the full multi-page
//     body ran via the region clone (a single-page clone would crash / return wrong);
//   - nbfn keeps returning n*2 (the 2nd region page runs correctly from the clone);
//   - after unhook spanfn returns n+1100 directly again.
// Build: -fno-stack-protector, link lib/dbi.c + lib/kpmhook.c (+ -llog). Driven over
// the no-superkey bridge (privileged setup: load shpte.kpm + probe + bridge).

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "../lib/kpmhook.h"

/* spanfn: page-aligned, 1100 straight-line adds + epilogue -> ~4.4 KiB, crosses one
 * page boundary. spanfn(n) == n + 1100. nbfn(n) == n*2, placed on spanfn's 2nd page. */
extern int spanfn(int n);
extern int nbfn(int n);
asm(".text\n"
    ".balign 0x1000\n"
    ".globl spanfn\n"
    "spanfn:\n"
    "  mov w1, #0\n"
    "  .rept 1100\n"
    "  add w1, w1, #1\n"
    "  .endr\n"
    "  add w0, w0, w1\n"
    "  ret\n"
    ".globl nbfn\n"
    "nbfn:\n"
    "  lsl w0, w0, #1\n"
    "  ret\n");

/* push the replacements onto a fresh, untrapped page */
__attribute__((aligned(0x1000), noinline)) void guard(void) { asm volatile("nop"); }

static void *bk_span;
__attribute__((noinline)) int replace_span(int n)
{
    int r = bk_span ? ((int (*)(int))bk_span)(n) : -999;
    printf("[R span] n=%d -> backup=%d (expect %d) %s\n", n, r, n + 1100,
           r == n + 1100 ? "OK" : "WRONG");
    return r;
}

int main(void)
{
    kpm_hook_force_enable(); /* standalone: bypass the Vector-only process gate */
    if (kpm_hook_init() != 0) {
        printf("FATAL: bridge not armed (run: shctl KEY control shpte bridge)\n");
        return 1;
    }

    uint64_t sp = (uint64_t)(uintptr_t)&spanfn;
    uint64_t spend = sp + 1103 * 4; /* mov + 1100 add + add + ret */
    uint64_t nb = (uint64_t)(uintptr_t)&nbfn;
    int span_pages = (int)((spend - 1) / 0x1000 - sp / 0x1000 + 1);
    int nb_2nd = ((nb & ~0xfffUL) == ((sp & ~0xfffUL) + 0x1000));
    int rep_outside = ((((uint64_t)(uintptr_t)&replace_span) & ~0xfffUL) != (sp & ~0xfffUL));
    printf("pid=%d spanfn=0x%lx end=0x%lx span_pages=%d nbfn=0x%lx nb_on_2nd_page=%d rep_outside=%d\n",
           getpid(), (unsigned long)sp, (unsigned long)spend, span_pages, (unsigned long)nb, nb_2nd,
           rep_outside);
    if (span_pages < 2 || !nb_2nd) {
        printf("ERROR: layout not as expected (need spanfn to cross a page, nbfn on its 2nd page)\n");
        return 1;
    }

    bk_span = kpm_inline_hooker((void *)&spanfn, (void *)&replace_span);
    printf("hooked spanfn: backup=%p\n", bk_span);
    if (!bk_span) {
        printf("ERROR: hook failed (NULL backup)\n");
        return 1;
    }
    fflush(stdout);

    printf("\n=== phase 1: spanfn hooked (multi-page region clone) ===\n");
    for (int i = 0; i < 4; i++) {
        int s = spanfn(i);           /* -> replace_span -> backup (full 1100-add body) */
        int b = nbfn(i + 1);         /* neighbor on the 2nd region page -> run from clone */
        printf("  spanfn(%d)=%d (expect %d %s)  nbfn(%d)=%d (expect %d %s)\n", i, s, i + 1100,
               s == i + 1100 ? "OK" : "WRONG", i + 1, b, (i + 1) * 2, b == (i + 1) * 2 ? "OK" : "WRONG");
        fflush(stdout);
        usleep(300000);
    }

    printf("\n=== unhook spanfn (region disarms) ===\n");
    printf("unhook: %d\n", kpm_inline_unhooker((void *)&spanfn));
    for (int i = 0; i < 3; i++) {
        int s = spanfn(i);           /* back to original -> i+1100, no [R span] */
        int b = nbfn(i + 1);
        printf("  spanfn(%d)=%d (expect %d %s)  nbfn(%d)=%d\n", i, s, i + 1100,
               s == i + 1100 ? "OK" : "WRONG", i + 1, b);
        fflush(stdout);
        usleep(300000);
    }

    kpm_hook_shutdown();
    printf("=== done ===\n");
    return 0;
}
