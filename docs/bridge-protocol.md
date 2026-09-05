# shpte sysinfo-bridge protocol — `version` handshake contract

Authoritative wire contract for the KPM ↔ userspace-client (Vector `lib/kpmhook`) bridge
**version handshake**. The Vector-side client calls `version` once at init and uses the reply for
**diagnostics only** — it logs an ABI-drift warning if the two sides' proto/capacities disagree, but
it **never** disables the KPM backend or changes a hook decision on the result (see "Parsing rules"
below for why: the fallback path is fatal on protected targets).

> ⚠️ **Compile-verified only.** The `version` command is a NEW kernel bridge command. It was
> verified to compile (both product and `-DSHPTE_POC_LADDER` configs) but **has NOT been run on
> a device**. It is a pure read-only query (no state, no locks, same safety class as the sysinfo
> passthrough), but it must still be exercised on the test device before the Vector side relies on
> it. See `kpm/shpte.c` `do_version()` + `BRIDGE_PROTO_VER`.

## Transport (unchanged)

All bridge commands ride the magic-gated `sysinfo` carrier syscall:

```
syscall(179 /*__NR_sysinfo*/, BRIDGE_MAGIC, cmd_ptr, cmd_len, out_ptr, out_len)
        BRIDGE_MAGIC = 0x5348505442524447  ("SHPTBRDG")
```

A real `sysinfo()` (arg0 != magic) passes straight through. The KPM copies the NUL-terminated
reply into `out_ptr` (truncated to `out_len-1`). `version` has no side effects.

## Command

```
version
```

No arguments. (The client sends the literal string `"version"`.)

## Reply

A single NUL-terminated line. Prefix `ok: shptbridge` then space-separated `key=value` tokens,
all decimal, terminated by `\n`:

```
ok: shptbridge proto=1 MAX_RGN=64 MAX_PG=16 MAX_OV=8 MAX_GHOST_PG=512 MAX_SSOL_RGN=16 MAX_SSOL_OV=16 MAX_SSOL_CTX=64 MAX_HIDE=64 MAX_FSHIDE=64 OFFMAP_MAX=1024
```

### Field order and meaning (frozen at proto=1)

| token          | KPM constant (`kpm/shpte.c`) | value | meaning (client-side name)                                   |
|----------------|------------------------------|-------|--------------------------------------------------------------|
| `proto`        | `BRIDGE_PROTO_VER`           | 1     | bridge protocol version                                       |
| `MAX_RGN`      | `MAX_RGN`                    | 64    | max pages in ONE clean-bounded region (client `MAX_RGN_PAGES`)|
| `MAX_PG`       | `MAX_PG`                     | 16    | max simultaneous trapped clone REGIONS (client `KPM_MAX_REGIONS`)|
| `MAX_OV`       | `MAX_OV`                     | 8     | max function-entry overrides per clone region (client `KPM_MAX_OV`)|
| `MAX_GHOST_PG` | `MAX_GHOST_PG`               | 512   | max pages in one VMA-less ghost clone region                  |
| `MAX_SSOL_RGN` | `MAX_SSOL_RGN`               | 16    | max simultaneous SSOL regions                                 |
| `MAX_SSOL_OV`  | `MAX_SSOL_OV`                | 16    | max hooked entries per SSOL region                            |
| `MAX_SSOL_CTX` | `MAX_SSOL_CTX`               | 64    | per-thread SSOL/step contexts (also the one-shot bypass table)|
| `MAX_HIDE`     | `MAX_HIDE`                   | 64    | general maps-hide set size (trampoline pool + xol scratch)    |
| `MAX_FSHIDE`   | `MAX_FSHIDE`                 | 64    | fs-hide reader-gate set size (tgids)                          |
| `OFFMAP_MAX`   | `OFFMAP_MAX`                 | 1024  | single-page offset_map cap (one 4 KiB page = 1024 insns)      |

### Parsing rules (client) — ADVISORY-ONLY

> ⚠️ **The `version` handshake is advisory (diagnostic) only. It MUST NOT change any hook or fallback
> decision — it only produces log output.** The reason is a hard operational constraint: the client's
> fallback from the KPM traceless backend is a Dobby *inline* patch, and on a hardened anti-tamper
> target an inline patch trips the app's self-check and the process is **SIGKILL'd**. So a
> handshake failure/mismatch must NEVER disable the KPM backend — a newer client running against an
> in-service KPM that predates the `version` command has to keep working exactly as it did before.
> `probe` (not `version`) is the real liveness gate; `version` only tells a human whether the two
> sides' ABI agree. Historic note: an earlier draft of this doc told the client to "refuse to arm" on
> mismatch — that was reversed precisely because refusing to arm is the fatal path on protected apps.

1. If the reply begins with `ok: shptbridge`, parse it (below). Anything else (empty reply, `error:`,
   or a stray real `sysinfo`) → the KPM predates the `version` command; log an INFO note and **keep
   using the KPM in compat mode** (do NOT treat this as "bridge unavailable").
2. Parse `key=value` tokens by name, not by position — **appending NEW keys at the end is
   backward-compatible** (an old client ignores unknown trailing keys).
3. Compare `proto` against the client's expected version; on mismatch, log a **prominent error** for
   ABI-drift triage — but still keep the KPM enabled.
4. Compare each client compile-time capacity constant against the KPM's reported value, e.g.
   `MAX_RGN_PAGES <= MAX_RGN`, `KPM_MAX_REGIONS <= MAX_PG`, `KPM_MAX_OV <= MAX_OV`. If any exceeds the
   KPM's, log a **prominent error** (the client is newer than the loaded KPM) — but still keep the KPM
   enabled. Do NOT refuse to arm and do NOT clamp silently; surface it for a human to reconcile.

### Compatibility policy

- Adding a NEW trailing key: no `proto` bump (backward-compatible; rule 2).
- Changing an existing key's name, order, units, or removing a key, or changing any OTHER bridge
  command's wire format incompatibly: **bump `BRIDGE_PROTO_VER`**.
