// SPDX-License-Identifier: GPL-2.0-or-later
// s0probe: EMPIRICAL measurement of the "clone is readable" residual exposure of the
// stealth KPM (shpte) traceless-hook stack -- upgrade-plan step S0 (see
// docs/2026-07-28-无痕栈升级-shadowpage与ghostVA钉死-评估与patch.md §6).
//
// It self-hooks ONE victim function via lib/kpmhook (the Vector/LSPlant path) over the
// no-superkey syscall bridge, then proves that the resulting DBI clone -- a private
// anonymous RX mapping the kernel routes execution into -- is simultaneously:
//   [1] ABSENT from /proc/self/maps        (show_map auto-hide works: the list is clean)
//   [2] directly READABLE at its VA        (memcpy succeeds -> real code bytes dumped)
//   [3] EXECUTABLE / live                  (calling backup() runs the original logic)
//   [4] PRESENT per /proc/self/pagemap     (the kernel confirms the page IS mapped)
// [1]+[4] together = maps-hide is only a listing filter; the memory is real and readable.
// That readable-but-hidden window is exactly what the Shadow-Page (S1..S3) upgrade closes:
// it turns the DABT (read) on this page into a fault that serves the original .text, so a
// RASP memory scan sees clean code instead of the recompiled clone.
//
// This is a READ-ONLY probe: it changes no kernel state beyond the normal hook it arms and
// then removes. It does not modify shpte.c, does not reboot, and needs no superkey (the
// bridge is auto-armed on boot via /data/adb/kpms + shpte auto-bridge).
//
// Run as root so /proc/self/pagemap exposes the PRESENT bit unconditionally:
//   adb shell su -c '/data/local/tmp/s0probe'
// Build: build_s0probe.ps1 (links lib/dbi.c + lib/kpmhook.c, like kpmhooktool).

#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../lib/kpmhook.h"

/* speak to the KPM directly over the same no-superkey bridge lib/kpmhook uses, so we can
 * read the KPM's own view (maps_hooked / maps_hidden / npg) at the exact armed moment. */
#define BRIDGE_MAGIC 0x5348505442524447ULL /* "SHPTBRDG" */
#define BRIDGE_NR 179                       /* __NR_sysinfo (arm64) */
static long kpm_query(const char *cmd, char *out, size_t n)
{
    if (out && n) out[0] = 0;
    return syscall(BRIDGE_NR, BRIDGE_MAGIC, cmd, (long)strlen(cmd) + 1, out, (long)n);
}

/* victim on its own page so the whole-page clone is clean-bounded */
__attribute__((aligned(0x1000), noinline)) int victim(int n)
{
    volatile int a = n * 3;
    volatile int b = a + 7;
    return a ^ b;
}

/* guard forces the replacement + probe code onto a page AFTER victim's (never trapped) */
__attribute__((aligned(0x1000), noinline)) void guard(void) { asm volatile("nop"); }

static void *g_bk; /* backup = in-clone faithful copy of victim */
__attribute__((noinline)) int replace_victim(int n)
{
    printf("  [replace] intercept n=%d -> backup:\n", n);
    if (g_bk) return ((int (*)(int))g_bk)(n);
    return -1;
}

/* maps line whose [lo,hi) covers `addr`; returns 1 + fills `linebuf`, else 0. */
static int maps_line_covering(uint64_t addr, char *linebuf, size_t linelen)
{
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        uint64_t lo, hi;
        if (sscanf(line, "%" SCNx64 "-%" SCNx64, &lo, &hi) != 2) continue;
        if (addr >= lo && addr < hi) {
            found = 1;
            snprintf(linebuf, linelen, "%s", line);
            break;
        }
    }
    fclose(f);
    return found;
}

/* count anonymous executable (r-x, no pathname, no [label]) mappings -- the injection
 * signature a RASP maps-scan hunts for. Our clone is a plain anon mmap: no '/' path,
 * no '[' label. (A plain C binary has no ART JIT, so no legit [anon:*] exec regions.) */
static int count_anon_exec(void)
{
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return -1;
    char line[512];
    int n = 0;
    while (fgets(line, sizeof line, f)) {
        uint64_t lo, hi;
        char perms[8];
        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %7s", &lo, &hi, perms) != 3) continue;
        if (perms[2] != 'x') continue;                        /* executable only */
        if (strchr(line, '/') || strchr(line, '[')) continue; /* file-backed or labeled */
        n++;
    }
    fclose(f);
    return n;
}

/* PRESENT bit (bit 63) of /proc/self/pagemap for `addr`'s page. -1 on read error. */
static int pagemap_present(uint64_t addr)
{
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) return -1;
    uint64_t entry = 0;
    off_t off = (off_t)((addr / 0x1000) * sizeof(uint64_t));
    ssize_t r = pread(fd, &entry, sizeof entry, off);
    close(fd);
    if (r != (ssize_t)sizeof entry) return -1;
    return (int)((entry >> 63) & 1);
}

static void hexdump(const unsigned char *b, int n)
{
    for (int i = 0; i < n; i++) {
        printf("%02x", b[i]);
        if ((i & 15) == 15) printf("\n    ");
        else if ((i & 3) == 3) printf(" ");
    }
    printf("\n");
}

int main(void)
{
    kpm_hook_force_enable(); /* standalone: bypass the Vector-only process gate */
    if (kpm_hook_init() != 0) {
        printf("FATAL: bridge not armed -- need shpte.kpm loaded + bridge armed.\n");
        printf("       (on this device that is automatic: /data/adb/kpms + auto-bridge)\n");
        return 1;
    }
    printf("== S0 probe: measuring the clone-readable exposure ==\n");
    printf("KPM bridge is LIVE (probe replied) -> shpte loaded + auto-bridge armed.\n");
    printf("pid=%d victim=%p replace=%p\n", getpid(), (void *)&victim, (void *)&replace_victim);

    volatile int warm = victim(1); /* page in victim .text so resolve_pte finds it present */
    printf("baseline victim(1)=%d (real, pre-hook)\n", warm);

    int anon_before = count_anon_exec();

    g_bk = kpm_inline_hooker((void *)&victim, (void *)&replace_victim);
    if (!g_bk) {
        printf("ERROR: hook failed (NULL backup) -- KPM pghook rejected. Nothing to measure.\n");
        kpm_hook_shutdown();
        return 1;
    }
    uint64_t bk = (uint64_t)(uintptr_t)g_bk;
    printf("hooked OK: backup(clone entry)=0x%" PRIx64 "\n", bk);

    printf("\n-- sanity: victim(7) now routes through the hook --\n");
    int r = victim(7);
    printf("victim(7)=%d (executed the replacement -> backup -> original)\n", r);
    fflush(stdout);

    /* the KPM's own view WHILE armed -- tells maps-hide apart from an offset bug:
     *   maps_hooked=1 maps_hidden>0 -> hide fired (clone should be absent below)
     *   maps_hooked=1 maps_hidden=0 -> show_map hooked but no VMA matched (offset/mm gate)
     *   maps_hooked=0               -> ensure_maps_hooked never installed the hook */
    char dbg[1024];
    kpm_query("dump", dbg, sizeof dbg);
    printf("\n-- KPM state while armed --\n%s\n", dbg);
    fflush(stdout);

    /* [1] ABSENT from /proc/self/maps? */
    char line[512];
    int covered = maps_line_covering(bk, line, sizeof line);
    printf("\n[1] maps line covering clone 0x%" PRIx64 ": %s", bk,
           covered ? line : "(NONE -- clone VMA is not listed)\n");
    int anon_after = count_anon_exec();
    printf("    anon r-x exec mappings: before=%d after=%d (clone added no VISIBLE exec region)\n",
           anon_before, anon_after);

    /* [2] READABLE directly at its VA? */
    unsigned char buf[64];
    memcpy(buf, (void *)(uintptr_t)bk, sizeof buf);
    printf("\n[2] direct read of clone @0x%" PRIx64 " (64 bytes -> readable):\n    ", bk);
    hexdump(buf, 64);

    /* [3] EXECUTABLE / live? */
    int r2 = ((int (*)(int))g_bk)(11);
    printf("[3] direct backup(11)=%d (original victim logic executed from inside the clone)\n", r2);

    /* [4] PRESENT per pagemap (independent of the maps filter)? */
    int present = pagemap_present(bk);
    printf("[4] /proc/self/pagemap PRESENT bit for clone page: %d %s\n", present,
           present == 1  ? "(kernel confirms the page is mapped)"
           : present < 0 ? "(pagemap read failed)"
                         : "(reported NOT present)");

    /* contrast: victim's ORIGINAL .text is untouched (CRC-clean); the clone above is the
     * DBI-recompiled copy, so the two byte streams differ -- proving the clone is a real,
     * separate, readable code image, not a view onto the original. */
    unsigned char vbuf[32];
    memcpy(vbuf, (void *)&victim, sizeof vbuf);
    printf("\n[contrast] original victim .text @%p first 32 bytes (unmodified / CRC-clean):\n    ",
           (void *)&victim);
    hexdump(vbuf, 32);

    printf("== VERDICT ==\n");
    if (!covered && present == 1) {
        printf("EXPOSURE CONFIRMED: the clone at 0x%" PRIx64 " is HIDDEN from /proc/self/maps yet\n", bk);
        printf("  directly READABLE + EXECUTABLE + PRESENT. A detector that scans memory by\n");
        printf("  address (walking the gaps, not trusting maps) still reads the hook clone.\n");
        printf("  => This is the residual attack surface the Shadow-Page (S1..S3) upgrade closes.\n");
    } else if (covered) {
        printf("clone is STILL LISTED in maps (auto-hide inactive?) -- the readable exposure is\n");
        printf("  even more direct: line above shows an anon r-x region a maps-scan flags outright.\n");
    } else {
        printf("INCONCLUSIVE: covered=%d present=%d (investigate before drawing S0 conclusions)\n",
               covered, present);
    }

    kpm_inline_unhooker((void *)&victim);
    kpm_hook_shutdown();
    printf("\n== done (unhooked + shutdown; kernel state restored) ==\n");
    return 0;
}
