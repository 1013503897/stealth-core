// SPDX-License-Identifier: GPL-2.0-or-later
// mttarget: multi-threaded HWBP test target for P1.6 (per-thread following).
//
// HWBP is per-thread, so a hook on one TID only catches that thread. This target
// spawns worker threads *gradually* (one every ~2.4s) so the test can hook only
// the threads that exist at t0, arm new-thread following, and watch later threads
// get auto-followed.
//
//   mttarget        grow  (default): spawn up to MAXW workers, all persist
//   mttarget churn        : keep spawning workers; each exits after a few ticks
//                           (exercises thread exit / slot GC, P1.6b/B2)
//
// Each worker loops calling the same noinline tick(who, n) with its own `who`,
// so a per-thread breakpoint sees x0 == who. Prints pid, &tick, and each tid.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>

#define MAXW 6           // max workers in grow mode
#define SPAWN_EVERY 8    // spawn a worker every SPAWN_EVERY main ticks (~2.4s)
#define CHURN_TICKS 6    // in churn mode, a worker exits after this many ticks

static int g_churn = 0;

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
    printf("thread who=%d tid=%d start\n", who, gettid_());
    fflush(stdout);
    for (int i = 0;; i++) {
        tick(who, i);
        usleep(300000);
        if (g_churn && i >= CHURN_TICKS) {
            printf("thread who=%d tid=%d exit\n", who, gettid_());
            fflush(stdout);
            return 0;
        }
    }
    return 0;
}

static void spawn_worker(int who)
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t th;
    pthread_create(&th, &attr, worker, (void *)(long)who);
    pthread_attr_destroy(&attr);
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "churn")) g_churn = 1;

    printf("pid=%d tick=%p churn=%d\n", getpid(), (void *)&tick, g_churn);
    printf("thread who=0 tid=%d (main)\n", getpid());
    fflush(stdout);

    int spawned = 0;
    for (int t = 0;; t++) {
        tick(0, t);
        if (t % SPAWN_EVERY == 0) {
            if (g_churn || spawned < MAXW) spawn_worker(++spawned);
        }
        usleep(300000);
    }
    return 0;
}
