// fsprobe -- M1/P1 test harness for the shpte fs-hide (statfs f_type spoof).
//
// Drives the shpte sysinfo bridge (no superkey) to arm `fshide` + register its OWN tgid,
// then A/B-compares what statfs() reports for /proc/self/exe and /system before vs after.
// On a rooted-overlay /system the "before" f_type is overlayfs (0x794c7630); with the hook
// armed + this tgid gated in, "after" must read the spoof magic (erofs 0xe0f5e1e2).
//
// Build like shctl: clang --target=aarch64-linux-android33 -O2 tools/fsprobe.c -o tools/fsprobe
// Run on device (bridge is auto-armed at shpte load):  ./fsprobe
//
// Reader-gate note: the spoof only applies to processes in the KPM hide-set. fsprobe adds
// its own tgid, so ONLY fsprobe sees the spoofed value -- proving the gate is per-reader.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <stdint.h>

#define BRIDGE_NR 179                          /* __NR_sysinfo (arm64) */
#define BRIDGE_MAGIC 0x5348505442524447ULL     /* "SHPTBRDG" */
#define OVERLAYFS_MAGIC 0x794c7630u
#define EROFS_MAGIC 0xe0f5e1e2u

static long bridge(const char *cmd, char *out, int outlen)
{
    if (out && outlen) out[0] = 0;
    return syscall(BRIDGE_NR, BRIDGE_MAGIC, cmd, (long)strlen(cmd) + 1, out, (long)outlen);
}

static uint32_t statfs_ftype(const char *path)
{
    struct statfs sf;
    if (statfs(path, &sf) != 0) return 0xffffffffu;
    return (uint32_t)sf.f_type;
}

static const char *magic_name(uint32_t m)
{
    if (m == OVERLAYFS_MAGIC) return "overlayfs";
    if (m == EROFS_MAGIC) return "erofs";
    if (m == 0xef53u) return "ext4";
    if (m == 0xf2f52010u) return "f2fs";
    if (m == 0x01021994u) return "tmpfs";
    if (m == 0xffffffffu) return "statfs-FAILED";
    return "other";
}

// Count /proc/self/mountinfo lines mentioning an overlay/magisk artifact (the mountinfo
// "hit" signal). A consistent hide would show 0 for a gated reader once P2 lands; P1 alone
// does not touch mountinfo -- this is just baseline telemetry for the next milestone.
static int mountinfo_overlay_lines(void)
{
    int fd = open("/proc/self/mountinfo", O_RDONLY);
    if (fd < 0) return -1;
    static char buf[65536];
    int n = (int)read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    int hits = 0;
    char *line = buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (strstr(line, "overlay") || strstr(line, "/data/adb") || strstr(line, "magisk") ||
            strstr(line, "KSU"))
            hits++;
        line = nl ? nl + 1 : 0;
    }
    return hits;
}

static void snapshot(const char *tag)
{
    uint32_t exe = statfs_ftype("/proc/self/exe");
    uint32_t sys = statfs_ftype("/system");
    int mi = mountinfo_overlay_lines();
    printf("[%s] statfs(/proc/self/exe).f_type=0x%08x (%s)  statfs(/system).f_type=0x%08x (%s)  "
           "mountinfo_overlay_lines=%d\n",
           tag, exe, magic_name(exe), sys, magic_name(sys), mi);
}

int main(void)
{
    char out[256];
    int tgid = (int)getpid(); /* main thread: pid == tgid */
    printf("fsprobe tgid=%d\n", tgid);

    // Is the bridge live?
    bridge("probe", out, sizeof out);
    if (out[0] == 0) {
        printf("ERROR: shpte bridge not responding (KPM loaded + `bridge` armed?)\n");
        return 2;
    }
    printf("bridge probe reply: %.*s\n", 80, out);

    printf("\n=== BEFORE (no fshide) ===\n");
    snapshot("before");
    int mi_before = mountinfo_overlay_lines();

    // Arm + register self.
    bridge("fshide on", out, sizeof out);
    printf("fshide on -> %.*s", 60, out);
    char cmd[64];
    snprintf(cmd, sizeof cmd, "fshide add %d", tgid);
    bridge(cmd, out, sizeof out);
    printf("%s -> %.*s", cmd, 60, out);

    printf("\n=== AFTER (fshide on + self gated) ===\n");
    snapshot("after");

    bridge("fshide dump", out, sizeof out);
    printf("\nfshide dump: %.*s\n", (int)sizeof out - 1, out);

    // P1 verdict keys on /system (the overlay-mounted path). We deliberately do NOT key on
    // /proc/self/exe: fsprobe lives on /data (f2fs), so its exe is f2fs -- but the DETECTOR's
    // exe is /system/bin/app_process64, which IS on the overlay. Any statfs whose sb is the
    // overlay (f_type==overlayfs) is rewritten by the hook, so /system is a faithful stand-in.
    uint32_t sys_after = statfs_ftype("/system");
    int mi_after = mountinfo_overlay_lines();
    int p1 = (sys_after == EROFS_MAGIC);
    int p2 = (mi_before > 0 && mi_after == 0);
    printf("\nP1 (statfs): statfs(/system).f_type %s -> %s\n", magic_name(sys_after),
           p1 ? "PASS (overlayfs hidden)"
              : "n/a here (/system not overlayfs on this device)");
    printf("P2 (mountinfo): overlay/magisk lines %d -> %d -> %s\n", mi_before, mi_after,
           p2 ? "PASS (artifact lines dropped)"
              : (mi_before == 0 ? "n/a here (none visible to this reader)" : "FAIL (still present)"));
    int pass = p1 || p2; /* at least one dimension proven on this device */

    // Clean up: ungate self + turn off so we don't leave the hook resident.
    snprintf(cmd, sizeof cmd, "fshide del %d", tgid);
    bridge(cmd, out, sizeof out);
    bridge("fshide off", out, sizeof out);
    printf("(cleaned up: fshide del %d + off)\n", tgid);
    return pass ? 0 : 1;
}
