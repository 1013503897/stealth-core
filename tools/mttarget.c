// SPDX-License-Identifier: GPL-2.0-or-later
// mttarget: multi-threaded HWBP test target for P1.6 (per-thread following).
//
// HWBP is per-thread, so a hook installed on one TID only catches that thread.
// This target spawns NTHREADS workers plus the main thread, each calling the
// same noinline tick(who, n) in a loop. It prints the pid, the runtime address
// of tick(), and every thread's tid, so the driver can enumerate /proc/<pid>/task
// and verify that a per-thread breakpoint table follows ALL threads (each thread
// independently runs the entry<->return state machine with its own x0=who).

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>

#define NTHREADS 4

__attribute__((noinline)) void tick(int who, int n)
{
    volatile int x = who * 1000 + n; // keep the call + args observable
    (void)x;
}

static pid_t gettid_(void)
{
    return (pid_t)syscall(SYS_gettid);
}

static void *worker(void *arg)
{
    int who = (int)(long)arg;
    printf("thread who=%d tid=%d\n", who, gettid_());
    fflush(stdout);
    for (int i = 0;; i++) {
        tick(who, i);
        usleep(300000);
    }
    return 0;
}

int main(void)
{
    printf("pid=%d tick=%p nthreads=%d\n", getpid(), (void *)&tick, NTHREADS + 1);
    fflush(stdout);

    pthread_t th[NTHREADS];
    for (int i = 0; i < NTHREADS; i++)
        pthread_create(&th[i], 0, worker, (void *)(long)(i + 1));

    // main thread (who=0) ticks too, so the full thread group is exercised
    printf("thread who=0 tid=%d (main)\n", gettid_());
    fflush(stdout);
    for (int i = 0;; i++) {
        tick(0, i);
        usleep(300000);
    }
    return 0;
}
