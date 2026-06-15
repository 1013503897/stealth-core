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

/* push whatever the linker places next off ssol_mix's page */
__attribute__((aligned(4096))) volatile char _pad[4096] = {0};

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
    long e2 = (long)(100 * 101 / 2) + (long)0x1234567890ABCDEFLL;

    printf("ssol_add(3,4)=%d expect=7 %s\n", r1, r1 == 7 ? "PASS" : "FAIL");
    printf("ssol_mix(100)=%ld expect=%ld %s\n", r2, e2, r2 == e2 ? "PASS" : "FAIL");
    printf("DONE\n");
    fflush(stdout);
    return (r1 == 7 && r2 == e2) ? 0 : 1;
}
