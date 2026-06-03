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

#define BRIDGE_MAGIC 0x5348505442524447ULL /* "SHPTBRDG" */
#ifndef __NR_personality
#define __NR_personality 92 /* arm64 asm-generic */
#endif

int main(int argc, char **argv)
{
    const char *cmd = (argc > 1) ? argv[1] : "probe";
    char out[2048];
    memset(out, 0, sizeof(out));

    long rc = syscall(__NR_personality, BRIDGE_MAGIC, cmd, (long)strlen(cmd) + 1, out, (long)sizeof(out));
    printf("== bridge cmd \"%s\" rc=%ld ==\n%s\n", cmd, rc, out[0] ? out : "(empty: bridge off?)\n");

    // real personality(0xffffffff) just queries the current value -> must pass through
    long cur = syscall(__NR_personality, 0xffffffffUL);
    printf("real personality query rc=%ld (passthrough OK if >= 0)\n", cur);
    return 0;
}
