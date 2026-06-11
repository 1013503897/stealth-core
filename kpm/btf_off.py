#!/usr/bin/env python3
# Minimal BTF parser: print byte offsets of selected struct members.
# Used to verify vm_area_struct.vm_mm (and friends) against the device kernel.
import struct, sys

BTF = sys.argv[1] if len(sys.argv) > 1 else "vmlinux.btf"
WANT = {  # struct name -> member names to report
    "vm_area_struct": ["vm_start", "vm_end", "vm_mm", "vm_flags"],
    "seq_file": ["buf", "count", "pad_until"],
}

data = open(BTF, "rb").read()
magic, version, flags, hdr_len = struct.unpack_from("<HBBI", data, 0)
assert magic == 0xEB9F, f"bad BTF magic {magic:#x}"
type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", data, 8)
type_base = hdr_len + type_off
str_base = hdr_len + str_off

def name(off):
    if off == 0:
        return ""
    end = data.index(b"\x00", str_base + off)
    return data[str_base + off:end].decode("utf-8", "replace")

# trailing payload after the 12-byte btf_type, by kind
K_INT, K_PTR, K_ARRAY, K_STRUCT, K_UNION, K_ENUM, K_FWD, K_TYPEDEF = 1,2,3,4,5,6,7,8
K_VOLATILE, K_CONST, K_RESTRICT, K_FUNC, K_FUNC_PROTO, K_VAR = 9,10,11,12,13,14
K_DATASEC, K_FLOAT, K_DECL_TAG, K_TYPE_TAG, K_ENUM64 = 15,16,17,18,19

def payload_size(kind, vlen):
    if kind == K_INT:        return 4
    if kind == K_ARRAY:      return 12
    if kind in (K_STRUCT, K_UNION): return vlen * 12
    if kind == K_ENUM:       return vlen * 8
    if kind == K_FUNC_PROTO: return vlen * 8
    if kind == K_VAR:        return 4
    if kind == K_DATASEC:    return vlen * 12
    if kind == K_DECL_TAG:   return 4
    if kind == K_ENUM64:     return vlen * 12
    return 0  # PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FLOAT, TYPE_TAG

pos = type_base
end = type_base + type_len
results = {}
while pos < end:
    name_off, info, size = struct.unpack_from("<III", data, pos)
    pos += 12
    vlen = info & 0xFFFF
    kind = (info >> 24) & 0x1F
    kflag = (info >> 31) & 1
    tname = name(name_off)
    if kind in (K_STRUCT, K_UNION) and tname in WANT and vlen:
        members = {}
        mp = pos
        for _ in range(vlen):
            m_name_off, m_type, m_off = struct.unpack_from("<III", data, mp)
            mp += 12
            bit_off = (m_off & 0xFFFFFF) if kflag else m_off
            members[name(m_name_off)] = bit_off // 8
        results.setdefault(tname, members)
    pos += payload_size(kind, vlen)

for sname, mlist in WANT.items():
    got = results.get(sname)
    if not got:
        print(f"{sname}: NOT FOUND")
        continue
    for m in mlist:
        print(f"{sname}.{m} = {got.get(m, 'MISSING')}")
