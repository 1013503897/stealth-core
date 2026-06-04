// SPDX-License-Identifier: GPL-2.0-or-later
// bridgetool: exercises the KPM syscall bridge WITHOUT the APatch superkey, as an
// injected agent (e.g. Vector's native layer) would. A privileged controller arms
// the bridge once (shctl ... control shpte bridge); thereafter any process can run
// KPM commands via:  syscall(__NR_personality, BRIDGE_MAGIC, cmd, len, out, outlen)
// Real personality() calls (arg0 != magic) are unaffected.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>

#define BRIDGE_MAGIC 0x5348505442524447ULL /* "SHPTBRDG" */
#define BRIDGE_NR 179 /* __NR_sysinfo (arm64): seccomp-allowed for apps, unlike personality */

int main(int argc, char **argv)
{
    const char *cmd = (argc > 1) ? argv[1] : "probe";
    char out[2048];
    memset(out, 0, sizeof(out));

    long rc = syscall(BRIDGE_NR, BRIDGE_MAGIC, cmd, (long)strlen(cmd) + 1, out, (long)sizeof(out));
    printf("== bridge cmd \"%s\" rc=%ld ==\n%s\n", cmd, rc, out[0] ? out : "(empty: bridge off?)\n");

    // a real sysinfo(&info) call (arg0 != magic) must pass straight through
    struct sysinfo info;
    long cur = syscall(BRIDGE_NR, &info);
    printf("real sysinfo passthrough rc=%ld uptime=%lds (passthrough OK if rc==0)\n", cur,
           cur == 0 ? info.uptime : -1);
    return 0;
}
