// SPDX-License-Identifier: GPL-2.0-or-later
// kpmhooktool: end-to-end test of the userspace glue (lib/kpmhook) that mimics
// LSPlant's call pattern -- it inline-hooks several functions one at a time, some
// SHARING a code page, via the KPM's multi-page `pghook` table over the syscall
// bridge (no superkey). It is the in-process agent; the privileged setup
// (load shpte.kpm + probe + bridge) is done out-of-band by run_kpmhook_test.sh.
//
// Layout:
//   page X: vx1, vx2, vx3  (ALL hooked -> 3 overrides on ONE page) + vx_nb (neighbor, not hooked)
//   page Y: vy1            (hooked)                                  + vy_nb (neighbor, not hooked)
// Proof: hooked funcs print "[R ..] -> backup [orig ..]"; the un-hooked neighbors
// on the SAME trapped page keep printing normally (whole-page clone intact);
// after a partial unhook the reverted funcs print normally again while their
// page-mates stay hooked; a full unhook disarms each page (nov -> 0).
// Build: -fno-stack-protector, link lib/dbi.c + lib/kpmhook.c.

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "../lib/kpmhook.h"

/* ---- page X: three hook targets + one neighbor, all on one page ---- */
__attribute__((aligned(0x1000), noinline)) int vx1(int n) { printf("  [X1] n=%d sq=%d\n", n, n * n); return n * n; }
__attribute__((noinline)) int vx2(int n) { printf("  [X2] n=%d dbl=%d\n", n, n + n); return n + n; }
__attribute__((noinline)) int vx3(int n) { printf("  [X3] n=%d inc=%d\n", n, n + 1); return n + 1; }
__attribute__((noinline)) int vx_nb(int n) { printf("  [X-nb] n=%d neg=%d\n", n, -n); return -n; }

/* ---- page Y: one hook target + one neighbor ---- */
__attribute__((aligned(0x1000), noinline)) int vy1(int n)
{
    int s = 0;
    for (int i = 0; i <= n; i++) s += i; /* internal loop branch -> exercises DBI re-encode */
    printf("  [Y1] n=%d sum=%d\n", n, s);
    return s;
}
__attribute__((noinline)) int vy_nb(int n) { printf("  [Y-nb] n=%d cube=%d\n", n, n * n * n); return n * n * n; }

/* guard: push the replacements onto a fresh, untrapped page */
__attribute__((aligned(0x1000), noinline)) void guard(void) { asm volatile("nop"); }

static void *bk_x1, *bk_x2, *bk_x3, *bk_y1;

#define CALL_BK(bk, n) do { if (bk) ((int (*)(int))(bk))(n); } while (0)
__attribute__((noinline)) int replace_x1(int n) { printf("[R x1] intercept n=%d -> backup:\n", n); CALL_BK(bk_x1, n); return 0; }
__attribute__((noinline)) int replace_x2(int n) { printf("[R x2] intercept n=%d -> backup:\n", n); CALL_BK(bk_x2, n); return 0; }
__attribute__((noinline)) int replace_x3(int n) { printf("[R x3] intercept n=%d -> backup:\n", n); CALL_BK(bk_x3, n); return 0; }
__attribute__((noinline)) int replace_y1(int n) { printf("[R y1] intercept n=%d -> backup:\n", n); CALL_BK(bk_y1, n); return 0; }

static void round_calls(int i)
{
    vx1(i % 5);
    vx2(i % 5);
    vx3(i % 5);
    vx_nb(i % 5);
    vy1(i % 5 + 1);
    vy_nb(i % 5 + 2);
    fflush(stdout);
    usleep(300000); /* pace the run so an external `shctl ... dump` can observe the slots */
}

int main(void)
{
    kpm_hook_force_enable(); /* standalone test: bypass the Vector-only process gate */
    if (kpm_hook_init() != 0) {
        printf("FATAL: bridge not armed (run: shctl KEY control shpte bridge)\n");
        return 1;
    }

    uint64_t pageX = (uint64_t)(uintptr_t)&vx1 & ~0xfffUL;
    uint64_t pageY = (uint64_t)(uintptr_t)&vy1 & ~0xfffUL;
    int x_shared = ((((uint64_t)(uintptr_t)&vx2) & ~0xfffUL) == pageX) &&
                   ((((uint64_t)(uintptr_t)&vx3) & ~0xfffUL) == pageX) &&
                   ((((uint64_t)(uintptr_t)&vx_nb) & ~0xfffUL) == pageX);
    int y_distinct = (pageY != pageX);
    printf("pid=%d pageX=0x%lx pageY=0x%lx x_shared=%d y_distinct=%d\n", getpid(),
           (unsigned long)pageX, (unsigned long)pageY, x_shared, y_distinct);
    printf("vx1=%p vx2=%p vx3=%p vx_nb=%p vy1=%p vy_nb=%p\n", (void *)&vx1, (void *)&vx2,
           (void *)&vx3, (void *)&vx_nb, (void *)&vy1, (void *)&vy_nb);
    if (!x_shared || !y_distinct) {
        printf("ERROR: bad code layout (need vx1/2/3/nb on one page, vy on another)\n");
        return 1;
    }

    /* hook one function at a time -- the LSPlant pattern (3 land on page X) */
    bk_x1 = kpm_inline_hooker((void *)&vx1, (void *)&replace_x1);
    bk_x2 = kpm_inline_hooker((void *)&vx2, (void *)&replace_x2);
    bk_x3 = kpm_inline_hooker((void *)&vx3, (void *)&replace_x3);
    bk_y1 = kpm_inline_hooker((void *)&vy1, (void *)&replace_y1);
    printf("backups: x1=%p x2=%p x3=%p y1=%p\n", bk_x1, bk_x2, bk_x3, bk_y1);
    if (!bk_x1 || !bk_x2 || !bk_x3 || !bk_y1) {
        printf("ERROR: a hook failed (NULL backup)\n");
        return 1;
    }
    fflush(stdout);

    printf("\n=== phase 1: all 4 hooked (page X has 3 overrides) ===\n");
    fflush(stdout);
    for (int i = 0; i < 8; i++) round_calls(i);

    printf("\n=== unhook vx2 + vy1 (page X keeps vx1/vx3; page Y disarms) ===\n");
    printf("unhook vx2: %d  unhook vy1: %d\n", kpm_inline_unhooker((void *)&vx2),
           kpm_inline_unhooker((void *)&vy1));
    for (int i = 0; i < 4; i++) round_calls(i);

    printf("\n=== unhook vx1 + vx3 (page X now disarms, nov->0) ===\n");
    printf("unhook vx1: %d  unhook vx3: %d\n", kpm_inline_unhooker((void *)&vx1),
           kpm_inline_unhooker((void *)&vx3));
    for (int i = 0; i < 3; i++) round_calls(i);

    printf("\n=== all unhooked: every line should be plain ===\n");
    kpm_hook_shutdown();
    fflush(stdout);
    return 0;
}
