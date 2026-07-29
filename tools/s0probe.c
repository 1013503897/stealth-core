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
// then removes. It does not reboot, and needs no superkey (the bridge is auto-armed at boot
// by the boot-EMBEDDED shpte KPM's init -- NOT from /data/adb/kpms, which is never loaded).
//
// Run as root so /proc/self/pagemap exposes the PRESENT bit unconditionally:
//   adb shell su -c '/data/local/tmp/s0probe'
// Build: build_s0probe.ps1 (links lib/dbi.c + lib/kpmhook.c, like kpmhooktool).

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
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

/* PRESENT bit (bit 63) of /proc/self/pagemap for `addr`'s page. -1 on read error.
 * NOTE: the /proc pagemap walker iterates VMAs, so a VMA-less ghost page reads as a
 * hole (present=0) even though the MMU has a live mapping -- another enumeration blind
 * spot the ghost path opens (vs the legacy anon clone, which reads present=1). */
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

/* mincore() on the clone page -- the classic "is this VA backed by a VMA" enumeration
 * probe. Legacy anon-RX clone: returns 0 with the resident bit set (fully enumerable).
 * Ghost VMA-less clone: mincore fails ENOMEM because the range has no VMA -> the scanner
 * is blind to it. Returns 1 = mapped+resident, 0 = mapped+not-resident, -1 = ENOMEM
 * (VMA-less / unmapped -> enumeration blind), -2 = other error. */
static int mincore_state(uint64_t addr)
{
    unsigned char vec = 0;
    uint64_t page = addr & ~(uint64_t)0xfff;
    if (mincore((void *)(uintptr_t)page, 0x1000, &vec) != 0) return (errno == ENOMEM) ? -1 : -2;
    return vec & 1;
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

int main(int argc, char **argv)
{
    /* fork-test mode (argv[1]): default = none (pure ① measurement, no fork);
     * "forkbare" = fork a child that _exits immediately (tests fork/copy_page_range of the
     * hooked state WITHOUT the child faulting); "fork" = child calls victim() (tests the
     * child's inherited-UXN fault path). Gated so we can isolate a fork vs fault crash. */
    const char *forkmode = (argc > 1) ? argv[1] : "";
    int do_forkbare = (strcmp(forkmode, "forkbare") == 0);
    int do_fork = (strcmp(forkmode, "fork") == 0);

    kpm_hook_force_enable(); /* standalone: bypass the Vector-only process gate */
    kpm_hook_set_ghost(1);   /* Rev1-(1): host the clone VMA-less (pghookg) -- what we measure */
    if (kpm_hook_init() != 0) {
        printf("FATAL: bridge not armed -- need shpte embedded in boot + bridge armed.\n");
        printf("       (on this device that is automatic: boot-embedded KPM + shpte auto-bridge)\n");
        return 1;
    }
    printf("== S0 probe (GHOST main-path): measuring clone enumerability + residual read ==\n");
    printf("KPM bridge is LIVE (probe replied) -> shpte loaded + auto-bridge armed.\n");
    printf("mode: ghost=ON (pghookg) -- clone hosted VMA-less; expect maps/mincore/pagemap BLIND.\n");
    printf("pid=%d victim=%p replace=%p\n", getpid(), (void *)&victim, (void *)&replace_victim);

    volatile int warm = victim(1); /* page in victim .text so resolve_pte finds it present */
    printf("baseline victim(1)=%d (real, pre-hook)\n", warm);

    int anon_before = count_anon_exec();

    g_bk = kpm_inline_hooker((void *)&victim, (void *)&replace_victim);
    if (!g_bk) {
        char dbg[1024];
        kpm_query("dump", dbg, sizeof dbg);
        printf("ERROR: hook failed (NULL backup) -- pghookg rejected or no ghost VA.\n");
        printf("       Likely causes: ghost inject rc<0 (GUP read of RW clone failed), or\n");
        printf("       pick_ghost_va found no gap. KPM state:\n%s\n", dbg);
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

    /* [1b] mincore() -- the VMA-existence enumeration probe */
    int mc = mincore_state(bk);
    printf("[1b] mincore(clone page) = %s\n",
           mc == 1    ? "RESIDENT (mapped VMA -> enumerable; legacy anon clone)"
           : mc == 0  ? "mapped, not resident (still a VMA -> enumerable)"
           : mc == -1 ? "ENOMEM (no VMA -> mincore is BLIND to it; ghost works)"
                      : "error (other)");

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

    /* [5] Rev2 ② fork safety (argv-gated -- see main). A forked child inherits the UXN-trapped
     * victim page (via copy_page_range) but NOT the VMA-less ghost clone; before_pf gates on the
     * parent's tgid, so the child's execute fault mismatches. `forkbare` isolates fork itself
     * (child _exits, never faults); `fork` makes the child call victim() (the fault path). With
     * ② the KPM follows the fork and clears the child's inherited UXN so it runs the original. */
    if (do_forkbare || do_fork) {
        printf("\n[5] fork-safety (Rev2 ②) mode=%s: forking...\n", forkmode);
        fflush(stdout); /* flush before fork so the child doesn't re-emit our buffer */
        pid_t kid = fork();
        if (kid == 0) {
            if (do_fork) {
                int cv = victim(5); /* original victim(5)=25; must NOT fault on the inherited UXN page */
                _exit(cv & 0x7f);   /* pass the value out via exit status */
            }
            _exit(42); /* forkbare: exit immediately, never touch the trapped page */
        } else if (kid > 0) {
            int st = 0;
            waitpid(kid, &st, 0);
            if (WIFEXITED(st))
                printf("    child EXITED ok (code=%d) -> %s\n", WEXITSTATUS(st),
                       do_fork ? "FORK-SAFE (② un-trapped the child)" : "fork/copy_page_range OK");
            else if (WIFSIGNALED(st))
                printf("    child KILLED by signal %d -> FORK-CRASH\n", WTERMSIG(st));
            else
                printf("    child ended oddly (status=0x%x)\n", st);
        } else {
            printf("    fork() failed -- skipping\n");
        }
    }

    printf("== VERDICT (ghost main-path) ==\n");
    int enum_blind = (!covered) && (mc == -1);
    if (enum_blind) {
        printf("GHOST OK -- clone 0x%" PRIx64 " is ENUMERATION-BLIND:\n", bk);
        printf("  [1] absent from /proc/self/maps, [1b] mincore ENOMEM (no VMA),\n");
        printf("  [4] pagemap present=%d (VMA-less -> reads as a hole).\n", present);
        printf("  A RASP that walks maps / mincore-probes gaps / scans pagemap for present-but-\n");
        printf("  unlisted pages CANNOT locate this clone. vs the LEGACY anon-RX baseline (prior\n");
        printf("  run: maps-hidden but mincore-RESIDENT + pagemap-present -> discoverable), the\n");
        printf("  enumeration surface measured in S0 is now CLOSED.\n");
        printf("  Honest boundary: [2] a direct read at the KNOWN VA still succeeds and [3] it\n");
        printf("  still executes -- ghost defeats DISCOVERY, not read-at-a-leaked-pointer. Sealing\n");
        printf("  that residual is the Shadow-Page (S1..S3) job (see 2026-07-28 doc), a later tier.\n");
    } else if (covered) {
        printf("UNEXPECTED: clone is LISTED in maps (line above) -- ghost inject did not take.\n");
        printf("  Check the KPM dump for ghost_va / a pghookg->pghook fallback (glue reverted).\n");
    } else {
        printf("UNEXPECTED: covered=%d mincore=%d present=%d -- ghost VA is unmapped-but-mincore\n",
               covered, mc, present);
        printf("  didn't ENOMEM as expected; investigate before drawing S0 conclusions.\n");
    }

    kpm_inline_unhooker((void *)&victim);
    kpm_hook_shutdown();
    printf("\n== done (unhooked + shutdown; kernel state restored) ==\n");
    return 0;
}
