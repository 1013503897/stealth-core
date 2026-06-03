// SPDX-License-Identifier: GPL-2.0-or-later
// tracertest: forks a child and PTRACE_ATTACHes it, then prints the child's
// TracerPid from /proc/<child>/status. Without the KPM spoof, TracerPid == this
// process's pid (the tracer); with `hidetracer` armed, it must read 0 -- defeating
// the most common anti-debug/anti-Frida check.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

int main(void)
{
    pid_t child = fork();
    if (child == 0) {
        for (;;) pause(); // child just waits
    }

    if (ptrace(PTRACE_ATTACH, child, 0, 0) != 0) {
        perror("PTRACE_ATTACH");
        kill(child, SIGKILL);
        return 1;
    }
    waitpid(child, 0, 0); // wait for the trap-stop

    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/%d/status", child);
    FILE *f = fopen(path, "r");
    if (f) {
        while (fgets(line, sizeof(line), f))
            if (strncmp(line, "TracerPid:", 10) == 0) {
                // strip trailing newline for clean printing
                line[strcspn(line, "\n")] = 0;
                printf("child(%d) %s   [tracer pid=%d]\n", child, line, getpid());
                break;
            }
        fclose(f);
    }

    ptrace(PTRACE_DETACH, child, 0, 0);
    kill(child, SIGKILL);
    waitpid(child, 0, 0);
    return 0;
}
