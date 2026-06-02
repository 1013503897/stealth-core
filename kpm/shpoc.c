/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * stealth-poc P0 KPM: toolchain + KPM bridge + syscall-hook smoke test.
 *
 * Goal: prove on the target device that (a) our NDK-clang build produces a
 * loadable .kpm, (b) APatch/KernelPatch loads it, and (c) a kernel hook fires.
 * It hooks __NR_execve and logs the first few hits. It does NOT modify any
 * target-process memory -- this is just the foundation for the later HWBP /
 * PTE-UXN work.
 *
 * Clean-room: written against the KernelPatch kpm SDK headers (0.13.1 / kpimg
 * d01) only. No code copied from third-party stealth-hook projects.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <log.h>
#include <hook.h>
#include <syscall.h>

KPM_NAME("shpoc");
KPM_VERSION("0.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("stealth-poc");
KPM_DESCRIPTION("P0: syscall-hook smoke test (toolchain + KPM bridge)");

/* updated from hook context; only used for coarse logging, not synchronization */
static long g_execve_hits = 0;

static void before_execve(hook_fargs3_t *args, void *udata)
{
    long n = ++g_execve_hits;
    if (n <= 20) {
        unsigned long long fn = (unsigned long long)syscall_argn(args, 0);
        logki("shpoc: execve #%ld filename_uptr=0x%llx\n", n, fn);
    }
}

static long shpoc_init(const char *args, const char *event, void *reserved)
{
    hook_err_t err;

    logki("shpoc: init args='%s' event='%s'\n", args ? args : "(null)", event ? event : "(null)");

    err = hook_syscalln(__NR_execve, 3, (void *)before_execve, 0, 0);
    if (err != HOOK_NO_ERR) {
        logke("shpoc: hook_syscalln(__NR_execve) failed err=%d\n", err);
        return -1;
    }

    logki("shpoc: hooked __NR_execve=%d ok\n", __NR_execve);
    return 0;
}

static long shpoc_exit(void *reserved)
{
    unhook_syscalln(__NR_execve, (void *)before_execve, 0);
    logki("shpoc: exit, total execve hits=%ld\n", g_execve_hits);
    return 0;
}

KPM_INIT(shpoc_init);
KPM_EXIT(shpoc_exit);
