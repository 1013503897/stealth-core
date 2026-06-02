// SPDX-License-Identifier: GPL-2.0-or-later
// hbtarget: self-contained HWBP test target.
// Prints its pid and the runtime address of tick(), then calls tick(i) in a loop
// so a hardware execute breakpoint placed on &tick fires repeatedly with x0 = i.

#include <stdio.h>
#include <unistd.h>

__attribute__((noinline)) void tick(int n)
{
    volatile int x = n; // keep the call + arg observable
    (void)x;
}

int main(void)
{
    printf("pid=%d tick=%p\n", getpid(), (void *)&tick);
    fflush(stdout);
    for (int i = 0;; i++) {
        tick(i);
        usleep(300000);
    }
    return 0;
}
