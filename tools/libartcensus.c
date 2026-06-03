// SPDX-License-Identifier: GPL-2.0-or-later
// libartcensus: standalone, zero-risk page-span census of a system library's code.
// Parses the on-disk ELF (default /apex/com.android.art/lib64/libart.so), isolates
// .text, segments it into RET-delimited instruction runs (a conservative proxy for
// functions -- internal early-RETs only SPLIT runs, never merge, so the spanning rate
// it reports is a LOWER BOUND), and reports what fraction of those runs cross a 4 KiB
// page boundary. That number decides RV-2: a whole-page UXN clone covers exactly one
// page, so any run that spans pages would have an incomplete clone -> the multi-page
// clone work is needed iff this fraction is non-trivial. No dlopen, no runtime, no
// mapping of the target library -- pure file analysis.
//
// Build like shctl: NDK clang --target=aarch64-linux-android33. Run on device:
//   adb push tools/libartcensus /data/local/tmp/ ; adb shell /data/local/tmp/libartcensus

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define INSN_RET 0xD65F03C0u
#define INSN_NOP 0xD503201Fu
#define PAGE 0x1000ULL

static uint16_t rd16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

// Locate the code region [file_off, size) and its virtual base. Prefer the .text
// section (precise); fall back to the largest executable PT_LOAD if section headers
// are stripped. Returns 0 on success.
static int find_text(const uint8_t *m, size_t msz, uint64_t *off, uint64_t *va, uint64_t *sz,
                     const char **how)
{
    if (msz < 64 || m[0] != 0x7f || m[1] != 'E' || m[2] != 'L' || m[3] != 'F') return -1;

    uint64_t e_shoff = rd64(m + 0x28);
    uint16_t e_shentsize = rd16(m + 0x3a);
    uint16_t e_shnum = rd16(m + 0x3c);
    uint16_t e_shstrndx = rd16(m + 0x3e);

    if (e_shoff && e_shnum && e_shstrndx < e_shnum) {
        const uint8_t *shstr = m + rd64(m + e_shoff + (uint64_t)e_shstrndx * e_shentsize + 0x18);
        for (int i = 0; i < e_shnum; i++) {
            const uint8_t *sh = m + e_shoff + (uint64_t)i * e_shentsize;
            const char *name = (const char *)(shstr + rd32(sh + 0));
            if (strcmp(name, ".text") == 0) {
                *off = rd64(sh + 0x18);
                *sz = rd64(sh + 0x20);
                *va = rd64(sh + 0x10); /* sh_addr */
                *how = ".text section";
                return 0;
            }
        }
    }

    // fallback: largest executable PT_LOAD
    uint64_t e_phoff = rd64(m + 0x20);
    uint16_t e_phentsize = rd16(m + 0x36);
    uint16_t e_phnum = rd16(m + 0x38);
    uint64_t best = 0;
    int found = 0;
    for (int i = 0; i < e_phnum; i++) {
        const uint8_t *ph = m + e_phoff + (uint64_t)i * e_phentsize;
        if (rd32(ph + 0) == 1 && (rd32(ph + 4) & 1)) { /* PT_LOAD && PF_X */
            uint64_t fsz = rd64(ph + 0x20);
            if (fsz > best) {
                best = fsz;
                *off = rd64(ph + 0x08);
                *va = rd64(ph + 0x10);
                *sz = fsz;
                found = 1;
            }
        }
    }
    if (found) { *how = "exec PT_LOAD (no .text section)"; return 0; }
    return -1;
}

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : "/apex/com.android.art/lib64/libart.so";
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("open(%s) failed\n", path); return 1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 64) { printf("fstat failed\n"); close(fd); return 1; }
    const uint8_t *m = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) { printf("mmap failed\n"); return 1; }

    uint64_t off = 0, va = 0, sz = 0;
    const char *how = "?";
    if (find_text(m, st.st_size, &off, &va, &sz, &how) != 0) { printf("no code region\n"); return 1; }

    const uint8_t *code = m + off;
    uint64_t n = sz / 4;

    long total = 0, fit1 = 0, span2 = 0, span3p = 0;
    uint64_t maxlen = 0, span_insns = 0, total_insns = 0;
    uint64_t i = 0;
    while (i < n) {
        while (i < n) { uint32_t w = rd32(code + i * 4); if (w != INSN_NOP && w != 0) break; i++; }
        if (i >= n) break;
        uint64_t start = i;
        while (i < n && rd32(code + i * 4) != INSN_RET) i++;
        uint64_t endincl = (i < n) ? i : n - 1;
        i++; /* past the RET */

        uint64_t len = endincl - start + 1;
        uint64_t sva = va + start * 4;
        uint64_t eva = va + (endincl + 1) * 4; /* byte after the last insn */
        int pages = (int)((eva - 1) / PAGE - sva / PAGE + 1);
        total++;
        total_insns += len;
        if (len > maxlen) maxlen = len;
        if (pages <= 1) {
            fit1++;
        } else {
            if (pages == 2) span2++; else span3p++;
            span_insns += len;
        }
    }

    printf("== page-span census: %s ==\n", path);
    printf("code region: %s  vaddr=0x%llx fileoff=0x%llx size=%llu B (%llu insns, %llu pages)\n", how,
           (unsigned long long)va, (unsigned long long)off, (unsigned long long)sz,
           (unsigned long long)n, (unsigned long long)(sz / PAGE));
    if (total == 0) { printf("no runs found\n"); return 1; }
    printf("RET-delimited runs: total=%ld  avg_len=%llu insns  max_len=%llu insns\n", total,
           (unsigned long long)(total_insns / (uint64_t)total), (unsigned long long)maxlen);
    printf("  fit in 1 page : %ld (%.1f%%)\n", fit1, 100.0 * fit1 / total);
    printf("  span 2 pages  : %ld (%.1f%%)\n", span2, 100.0 * span2 / total);
    printf("  span 3+ pages : %ld (%.1f%%)\n", span3p, 100.0 * span3p / total);
    printf("=> %.1f%% of runs (lower bound) cross a page boundary; %.1f%% of code bytes live in\n",
           100.0 * (span2 + span3p) / total, 100.0 * span_insns / total_insns);
    printf("   spanning runs. A whole-page single-page clone breaks every spanning run, so a\n");
    printf("   non-trivial figure here means multi-page clones are required for real libart.\n");
    return 0;
}
