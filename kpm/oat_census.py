#!/usr/bin/env python3
# DBI-on-oat feasibility census: scan boot.oat's executable segments and classify
# arm64 instructions into (a) what lib/dbi rewrites, (b) PAC branches it passes
# verbatim (the P3.5 TODO), (c) other PC-relative it might miss, (d) the rest.
# Statistical (method headers etc. are negligible noise). NOT a correctness proof.
import struct, sys, collections

path = sys.argv[1] if len(sys.argv) > 1 else "boot.oat"
data = open(path, "rb").read()
assert data[:4] == b"\x7fELF", "not ELF"
is64 = data[4] == 2
assert is64
# ELF64 header
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
e_phnum = struct.unpack_from("<H", data, 0x38)[0]
PT_LOAD, PF_X = 1, 1
segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", data, off)
    p_offset, p_vaddr, p_paddr, p_filesz = struct.unpack_from("<QQQQ", data, off + 8)
    if p_type == PT_LOAD and (p_flags & PF_X):
        segs.append((p_offset, p_vaddr, p_filesz, p_flags))
        print(f"PF_X LOAD: off=0x{p_offset:x} vaddr=0x{p_vaddr:x} filesz=0x{p_filesz:x} ({p_filesz//1024} KiB)")

def classify(w):
    # DBI-rewritten (PC-relative, handled by lib/dbi)
    if (w & 0x9F000000) == 0x90000000: return "adrp"        # ADRP
    if (w & 0x9F000000) == 0x10000000: return "adr"         # ADR
    if (w & 0xFC000000) == 0x14000000: return "b"           # B (uncond)
    if (w & 0xFC000000) == 0x94000000: return "bl"          # BL
    if (w & 0xFF000010) == 0x54000000: return "b.cond"      # B.cond
    if (w & 0x7E000000) == 0x34000000: return "cbz/cbnz"    # CBZ/CBNZ
    if (w & 0x7E000000) == 0x36000000: return "tbz/tbnz"    # TBZ/TBNZ
    if (w & 0x3B000000) == 0x18000000: return "ldr-literal" # LDR/LDRSW/SIMD literal (opc!=11 PRFM)
    # Branch-to-register family: bits[31:25]=1101011
    if (w >> 25) == 0x6B:
        pac = (w >> 11) & 1
        opc = (w >> 21) & 0xF
        if pac:
            if opc == 0:  return "PAC-BRAA*"   # BRAA/BRAAZ (tail/indirect jump, signed)
            if opc == 1:  return "PAC-BLRAA*"  # BLRAA/BLRAAZ (indirect CALL, signed) <-- P3.5 TODO
            if opc == 2:  return "PAC-RETAA*"  # RETAA/RETAB (PC-independent, passes fine)
            return "PAC-other"
        if opc == 0:  return "br"
        if opc == 1:  return "blr"
        if opc == 2:  return "ret"
        return "br-other"
    return "other(verbatim-ok)"

cnt = collections.Counter()
total = 0
for (off, vaddr, filesz, _) in segs:
    seg = data[off:off + filesz]
    n = len(seg) // 4
    for i in range(n):
        w = struct.unpack_from("<I", seg, i * 4)[0]
        cnt[classify(w)] += 1
        total += 1

print(f"\ntotal words scanned: {total:,}")
dbi_handled = sum(cnt[k] for k in ("adrp","adr","b","bl","b.cond","cbz/cbnz","tbz/tbnz","ldr-literal"))
print(f"\n{'class':<20}{'count':>12}{'pct':>9}")
for k, v in cnt.most_common():
    print(f"{k:<20}{v:>12,}{100*v/total:>8.2f}%")
print(f"\nDBI-rewritten PC-relative total: {dbi_handled:,} ({100*dbi_handled/total:.2f}%)")
pac_calls = cnt['PAC-BLRAA*'] + cnt['PAC-BRAA*']
print(f"PAC indirect call/jump (BLRAA*/BRAA*, the P3.5 verbatim-passthrough risk): "
      f"{pac_calls:,} ({100*pac_calls/total:.3f}%)")
print(f"PAC-RET (paciasp/retaa, PC-independent, fine): {cnt['PAC-RETAA*']:,}")

# --- region-boundary feasibility (mirrors kpmhook.c make_rgn_locked / clean_boundary) ---
# A page boundary b is "clean" if the word at b-4 is RET / NOP / 0 / unconditional-B, so no
# function straddles it. A region clone needs a clean boundary within MAX_RGN=64 pages of the
# target's page. Measure how reachable that is across the oat exec segment.
MAX_RGN = 64
PAGE = 0x1000
def is_clean_word(w):
    if w == 0xD65F03C0: return True           # RET
    if w == 0xD503201F or w == 0: return True  # NOP / zero padding
    if (w & 0xFC000000) == 0x14000000: return True  # unconditional B (tail)
    return False

seg_off, seg_vaddr, seg_filesz = segs[0][0], segs[0][1], segs[0][2]
seg = data[seg_off:seg_off + seg_filesz]
# page boundaries are at vaddr multiples of 0x1000; seg_vaddr is page-aligned
npages_seg = seg_filesz // PAGE
clean = [False] * (npages_seg + 1)
for p in range(1, npages_seg + 1):          # boundary at start of page p (= end of page p-1)
    bptr = p * PAGE
    if bptr - 4 + 4 <= len(seg):
        w = struct.unpack_from("<I", seg, bptr - 4)[0]
        clean[p] = is_clean_word(w)
nclean = sum(clean)
print(f"\n--- region-boundary feasibility (MAX_RGN={MAX_RGN} pages) ---")
print(f"exec pages: {npages_seg:,}   clean page boundaries: {nclean:,} ({100*nclean/npages_seg:.1f}% of boundaries)")
# for each start page, distance (pages) to the next clean boundary, capped at MAX_RGN
reachable = 0; dist_hist = collections.Counter()
for sp in range(npages_seg):
    d = 0
    for k in range(1, MAX_RGN + 1):
        if sp + k > npages_seg: break
        if clean[sp + k]: d = k; break
    if d:
        reachable += 1
        dist_hist[d] += 1
print(f"start-pages that find a clean region end within {MAX_RGN} pages: "
      f"{reachable:,}/{npages_seg:,} ({100*reachable/npages_seg:.2f}%)")
import statistics
dists = [d for d, c in dist_hist.items() for _ in range(c)]
if dists:
    print(f"region size to clean end (pages): min={min(dists)} median={int(statistics.median(dists))} "
          f"mean={statistics.mean(dists):.1f} max={max(dists)}")
    over = npages_seg - reachable
    print(f"start-pages with NO clean end within {MAX_RGN} (would fall back to Dobby): {over:,} ({100*over/npages_seg:.2f}%)")
