/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SSOL P1 self-test target. Two page-aligned LEAF functions (each on its own page,
 * isolated from main) that the shpte KPM UXN-traps as SSOL regions: every
 * instruction then runs via simulate (PC-relative) or XOL+single-step
 * (PC-independent). If SSOL is correct, the functions still return the right value.
 *
 * Flow: print pid + function VAs + a suggested (unmapped) xol_va, then WAIT for
 * /data/local/tmp/ssol_go. The driver arms `ssoltest <pid> <func_va> 1 <xol_va>`,
 * then `touch`es the go-file; we call the trapped function and print PASS/FAIL.
 *
 * Build: tools/build_ssoltarget.ps1  (NDK clang -> aarch64 static-ish binary).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

/* aligned(4096): start on a fresh page so the function is page-isolated (main and
 * page-neighbors don't share the trapped page). noinline: keep it a real call. */
__attribute__((aligned(4096), noinline)) int ssol_add(int a, int b)
{
    return a + b; /* add w0,w0,w1 (XOL) ; ret (simulate) -- the minimal XOL proof */
}

/* richer leaf: a loop (branches + ALU, all XOL/simulate) + a 64-bit literal
 * (LDR-literal, simulated from the snapshot) + RET. `volatile` keeps the loop. */
__attribute__((aligned(4096), noinline)) long ssol_mix(int n)
{
    volatile long sum = 0;
    for (int i = 1; i <= n; i++) sum += i;
    sum += (long)0x1234567890ABCDEFLL; /* forces an LDR-literal pool load */
    return sum;
}

/* page-isolated leaf callees (own pages, NOT trapped -> run native) */
__attribute__((aligned(4096), noinline)) int leaf_a(int x) { return x + 7; }
__attribute__((aligned(4096), noinline)) int leaf_b(int x) { return x * 3; }

/* indirect-call heavy: BLR via volatile fn pointers -- the clone's "problem 2"
 * pattern (calls OUT of the trapped page). Under SSOL the BLR is simulated
 * (pc=original target, x30=original orig+4), the callee runs native and RETs back
 * INTO the trapped page (faults -> SSOL continues). LR is an ORIGINAL address
 * throughout -> no clone return addresses on the stack (what broke the clone). */
__attribute__((aligned(4096), noinline)) int ssol_indirect(int n)
{
    int (*volatile fa)(int) = leaf_a;
    int (*volatile fb)(int) = leaf_b;
    int acc = n;
    for (int i = 0; i < 3; i++) {
        acc = fa(acc);
        acc = fb(acc);
    }
    return acc;
}

/* ---- P3 hook self-test: entry-override + call-original via LR discrimination ----
 * hook_me = the "hooked method" (page-isolated, SSOL-trapped with entry override).
 * tramp   = the "trampoline/replacement" (page-isolated, NOT trapped): it runs, then
 * calls the ORIGINAL hook_me -- which the KPM bypasses because the call's LR points
 * INTO tramp -- and adds 1000. A direct hook_me(3,4) is redirected by the KPM to
 * tramp (LR in main, not tramp), so it must return 7+1000=1007 with tramp having run. */
__attribute__((aligned(4096), noinline)) int hook_me(int a, int b)
{
    return a + b; /* leaf: x30 flows through, so call-original RETs back into tramp */
}
volatile int g_tramp_ran = 0;
__attribute__((aligned(4096), noinline)) int tramp(int a, int b)
{
    g_tramp_ran = 1;
    return hook_me(a, b) + 1000; /* bl hook_me -> LR in tramp -> call-original (bypass) */
}

/* page-aligned TEXT separator so `tramp` OWNS its page (main/neighbors land on the
 * NEXT page) -- otherwise main packs into tramp's page and its LR would wrongly fall
 * inside [replace, replace+0x1000). An aligned data array does NOT separate .text. */
__attribute__((aligned(4096), noinline, used)) static int _pgsep(void) { return 0; }

static int file_exists(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0;
}

int main(int argc, char **argv)
{
    const char *go = (argc > 1) ? argv[1] : "/data/local/tmp/ssol_go";
    unlink(go); /* fresh run */

    printf("pid=%d\n", getpid());
    printf("ssol_add=%p\n", (void *)&ssol_add);
    printf("ssol_mix=%p\n", (void *)&ssol_mix);
    printf("ssol_indirect=%p\n", (void *)&ssol_indirect);
    printf("hook_me=%p\n", (void *)&hook_me);
    printf("tramp=%p\n", (void *)&tramp);
    printf("xol_va=0x5550000000\n");
    printf("go_file=%s\n", go);
    fflush(stdout);

    /* wait (up to ~60s) for the driver to arm the SSOL region(s) */
    for (int i = 0; i < 600 && !file_exists(go); i++) usleep(100000);
    if (!file_exists(go)) {
        printf("TIMEOUT waiting for %s\n", go);
        return 2;
    }

    int r1 = ssol_add(3, 4);
    long r2 = ssol_mix(100);
    int r3 = ssol_indirect(1);
    long e2 = (long)(100 * 101 / 2) + (long)0x1234567890ABCDEFLL;

    g_tramp_ran = 0;
    int (*volatile hm)(int, int) = hook_me; /* volatile fn-ptr -> real call (no fold) */
    int r4 = hm(3, 4);                       /* hooked: redirected to tramp, which call-originals */

    printf("ssol_add(3,4)=%d expect=7 %s\n", r1, r1 == 7 ? "PASS" : "FAIL");
    printf("ssol_mix(100)=%ld expect=%ld %s\n", r2, e2, r2 == e2 ? "PASS" : "FAIL");
    printf("ssol_indirect(1)=%d expect=300 %s\n", r3, r3 == 300 ? "PASS" : "FAIL");
    printf("hook_me(3,4)=%d expect=1007 tramp_ran=%d %s\n", r4, g_tramp_ran,
           (r4 == 1007 && g_tramp_ran) ? "PASS" : "FAIL");
    printf("DONE\n");
    fflush(stdout);
    return (r1 == 7 && r2 == e2 && r3 == 300 && r4 == 1007 && g_tramp_ran) ? 0 : 1;
}
