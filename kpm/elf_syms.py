#!/usr/bin/env python3
# Minimal ELF64 symbol dumper: list .dynsym + .symtab symbols matching a pattern.
import struct, sys
path = sys.argv[1]
pat = sys.argv[2] if len(sys.argv) > 2 else "GetJit"
data = open(path, "rb").read()
assert data[:4] == b"\x7fELF" and data[4] == 2, "not ELF64"
e_shoff, = struct.unpack_from("<Q", data, 0x28)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3a)
secs = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    name, typ, flags, addr, offset, size, link, info, align, entsize = struct.unpack_from("<IIQQQQIIQQ", data, off)
    secs.append((name, typ, offset, size, link, entsize))
shstr_off = secs[e_shstrndx][2]
def secname(n):
    end = data.index(b"\x00", shstr_off + n)
    return data[shstr_off + n:end].decode()
named = [(secname(s[0]),) + s[1:] for s in secs]
total = 0
for nm, typ, offset, size, link, entsize in named:
    if nm not in (".dynsym", ".symtab"):
        continue
    stroff = named[link][2]
    cnt = size // entsize if entsize else 0
    for j in range(cnt):
        so = offset + j * entsize
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", data, so)
        if st_name == 0:
            continue
        e = data.index(b"\x00", stroff + st_name)
        sym = data[stroff + st_name:e].decode("utf-8", "replace")
        if pat in sym:
            print(f"{nm} 0x{st_value:x} {sym}")
            total += 1
print(f"# {total} matches for '{pat}'")
