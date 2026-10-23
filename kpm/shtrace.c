/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * shtrace — syscall path tracer to reverse-engineer GCash 6.03.0's Appdome watchdog.
 *
 * Boot-safe: at load it ONLY arms the sysinfo bridge; it hooks the file-probe syscalls
 * (openat/faccessat/newfstatat/readlinkat) only on a `traceon` bridge command, and removes
 * them on `traceoff`. Each hooked call reads the path; if the path matches a root/tamper
 * indicator it records "[comm] syscall path" into a dedup'd kernel buffer readable via the
 * `dump` bridge command (logki does NOT reach dmesg on this KP, so we self-buffer).
 *
 * No comm-gate: we filter by SUSPICIOUS PATH so a comm-renamed watchdog child is still caught;
 * the recorded comm just labels who probed.
 *
 * Clean-room; KernelPatch kpm SDK 0.13.1. Bridge mirrors kpm/shpte.c.
 */
#include <compiler.h>
#include <kpmodule.h>
#include <log.h>
#include <kallsyms.h>
#include <hook.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/sched.h>

KPM_NAME("shtrace");
KPM_VERSION("0.0.12");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("wxy");
KPM_DESCRIPTION("syscall path tracer (Appdome watchdog RE)");

#define BRIDGE_MAGIC 0x5348545241434552ULL /* "SHTRACER" */
#define BRIDGE_NR 179                       /* __NR_sysinfo on arm64 */

#define PIDTYPE_TGID 1
/* seq_file layout (BTF-hardcoded for 6.1.145; validated in seq_ok) */
#define SEQ_COUNT_OFF 24
#define SEQ_PAD_OFF 32
#define SEQ_SKIP 1

static void *g_addr_show_map = 0, *g_addr_show_mnt = 0;
static volatile int g_maps_hooked = 0, g_mnt_hooked = 0;
static long g_maps_hidden = 0, g_mnt_hidden = 0;

static volatile int g_bridge_hooked = 0;
static volatile int g_trace_on = 0;
static volatile int g_spoof_on = 0;
static volatile int g_gcash_tgid = 0;   /* auto-learned from a gcash-comm thread */
static long g_hits = 0;
static long g_spoofed = 0;

/* __get_task_comm(char *buf, size_t size, struct task_struct *tsk) — get_task_comm is a macro */
static char *(*fn_get_task_comm)(char *, unsigned long, void *);
static int (*fn_task_pid_nr_ns)(void *, int, void *);

/* dedup'd capture buffer (static; kernel stacks are tiny) */
#define LOGCAP 8000
static char g_log[LOGCAP];
static volatile int g_loglen = 0;

/* ---- freestanding string helpers ---- */
static char *apps(char *p, char *e, const char *s) { while (*s && p < e) *p++ = *s++; if (p <= e) *p = 0; return p; }
static int starts(const char *s, const char *pfx) { while (*pfx) { if (*s++ != *pfx++) return 0; } return 1; }
static int contains(const char *hay, const char *needle)
{
    for (const char *h = hay; *h; h++) {
        const char *a = h, *b = needle;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b) return 1;
    }
    return 0;
}
static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }
static void put_int(char **pp, char *e, long v); /* fwd (defined later) */

/* root/tamper indicators — specific enough that normal system daemons rarely hit them */
static const char *SUS[] = {
    "magisk", "apatch", "kpatch", "kernelpatch", "zygisk", "riru", "xposed", "lsposed",
    "edxposed", "frida", "gum", "substrate", "/data/adb", "busybox", "supersu", "superuser",
    "daemonsu", "/sbin/su", "/system/bin/su", "/system/xbin", "magisksu", "which",
    "mountinfo", "/proc/self/maps", "/proc/self/status", "/proc/self/task", "TracerPid",
    "shpte", "shtrace", "vector", "denylist", "/dev/.magisk", "/debug_ramdisk",
    "/system/bin/magisk", "supolicy", "ro.debuggable", "ro.build.tags",
};
#define NSUS (int)(sizeof(SUS) / sizeof(SUS[0]))
static int suspicious(const char *p)
{
    for (int i = 0; i < NSUS; i++) if (contains(p, SUS[i])) return 1;
    return 0;
}

/* paths to spoof to ENOENT for the GCash process (root/injection artifacts it has no
 * legit reason to touch). NOT /proc/* (those are legit and need content-spoof elsewhere). */
static const char *SPOOF[] = {
    "/data/adb", "magisk", "topjohnwu", "me.bmax.apatch", "apatch", "kernelpatch", "kpatch",
    "zygisk", "riru", "xposed", "lsposed", "edxposed", "de.robv", "frida", "substrate",
    "zygiskdebug", "supersu", "daemonsu", "busybox", "superuser",
    /* su / root binaries (APatch installs su at /system/bin/su -> real, must hide) */
    "/su", "sudo", "sutemp", "bbksu", "bdsu", "ku.sud", "/bstk", "supolicy", "magiskpolicy",
    "/system/addon.d", "magisk_patched", "/system/bin/which", "/system/xbin", "/sbin/.magisk",
    "/debug_ramdisk", "/dev/.magisk", "mirror/magisk",
};
#define NSPOOF (int)(sizeof(SPOOF) / sizeof(SPOOF[0]))
/* runtime-extendable spoof substrings (via `addspoof <s>`) so tuning needs no reload */
#define MAX_USPOOF 48
#define USPOOF_LEN 64
static char g_uspoof[MAX_USPOOF][USPOOF_LEN];
static volatile int g_nuspoof = 0;
static int spoof_path(const char *p)
{
    for (int i = 0; i < NSPOOF; i++) if (contains(p, SPOOF[i])) return 1;
    for (int i = 0; i < g_nuspoof; i++) if (g_uspoof[i][0] && contains(p, g_uspoof[i])) return 1;
    return 0;
}
static int cur_tgid(void)
{
    return fn_task_pid_nr_ns ? fn_task_pid_nr_ns((void *)get_current(), PIDTYPE_TGID, 0) : 0;
}
/* current task's uid via KP-provided get_task_cred + version-independent cred_offset.uid_offset.
 * Only called on a spoof_path match (rare) + once at learn time, so the ref get/put is cheap. */
static volatile int g_gcash_uid = -1;   /* auto-learned; GCash app uid (covers its sh/exec children) */
/* SAFE uid read: direct memory via KP-provided offsets (task->cred @ task_struct_offset.cred_offset,
 * cred->uid @ cred_offset.uid_offset). NO get_task_cred() call (that crashed the kernel), NO ref.
 * Every offset + the cred pointer is range-validated before deref, so bad offsets return -1 (never
 * a wild read that would panic). */
static uint32_t cur_uid(void)
{
    int co = task_struct_offset.cred_offset;
    int uo = cred_offset.uid_offset;
    if (co <= 0 || co > 8192 || uo < 0 || uo > 512) return (uint32_t)-1;
    void *task = (void *)get_current();
    if ((uint64_t)task < 0xffff000000000000ULL) return (uint32_t)-1;
    void *cred = *(void *volatile *)((char *)task + co);
    if ((uint64_t)cred < 0xffff000000000000ULL) return (uint32_t)-1;
    return *(volatile uint32_t *)((char *)cred + uo);
}

/* ---- ported seq_file line-hide (maps / mountinfo), reader-gated to the GCash tgid ---- */
static int seq_ok(void *m)
{
    if (!m) return 0;
    void *buf = *(void *volatile *)((char *)m + 0);
    uint64_t size = *(volatile uint64_t *)((char *)m + 8);
    uint64_t from = *(volatile uint64_t *)((char *)m + 16);
    uint64_t count = *(volatile uint64_t *)((char *)m + SEQ_COUNT_OFF);
    return ((uint64_t)buf >= 0xffff000000000000ULL && size > 0 && size <= 0x400000ULL &&
            from <= size && count <= size);
}
static int mem_find(const char *buf, uint64_t s, uint64_t e, const char *pat)
{
    int pl = 0; while (pat[pl]) pl++;
    if (pl == 0 || e < s || (e - s) < (uint64_t)pl) return 0;
    for (uint64_t i = s; i + pl <= e; i++) {
        int k = 0; while (k < pl && buf[i + k] == pat[k]) k++;
        if (k == pl) return 1;
    }
    return 0;
}
static int reader_is_gcash(void) { return g_gcash_tgid && cur_tgid() == g_gcash_tgid; }

static void before_showmap(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    if (!g_maps_hooked || !g_spoof_on || !reader_is_gcash()) return;
    void *m = (void *)fargs->arg0;
    fargs->local.data0 = *(volatile uint64_t *)((char *)m + SEQ_COUNT_OFF);
    fargs->local.data1 = 1; /* mark: we snapshotted, so after should check */
}
static void after_showmap(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    if (!g_maps_hooked || fargs->local.data1 != 1) return;
    void *m = (void *)fargs->arg0;
    if (!seq_ok(m)) return;
    char *buf = *(char **)((char *)m + 0);
    if (!buf) return;
    uint64_t s = fargs->local.data0;
    uint64_t e = *(volatile uint64_t *)((char *)m + SEQ_COUNT_OFF);
    if (mem_find(buf, s, e, "/data/adb") || mem_find(buf, s, e, "zygisk") ||
        mem_find(buf, s, e, "apatch") || mem_find(buf, s, e, "magisk") ||
        mem_find(buf, s, e, "me.bmax") || mem_find(buf, s, e, "rwxp")) {
        *(volatile uint64_t *)((char *)m + SEQ_COUNT_OFF) = s;
        *(volatile uint64_t *)((char *)m + SEQ_PAD_OFF) = 0;
        fargs->ret = SEQ_SKIP;
        g_maps_hidden++;
    }
}
static void before_mnt(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    if (!g_mnt_hooked || !g_spoof_on || !reader_is_gcash()) return;
    void *m = (void *)fargs->arg0;
    fargs->local.data0 = *(volatile uint64_t *)((char *)m + SEQ_COUNT_OFF);
    fargs->local.data1 = 1;
}
static void after_mnt(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    if (!g_mnt_hooked || fargs->local.data1 != 1) return;
    void *m = (void *)fargs->arg0;
    if (!seq_ok(m)) return;
    char *buf = *(char **)((char *)m + 0);
    if (!buf) return;
    uint64_t s = fargs->local.data0;
    uint64_t e = *(volatile uint64_t *)((char *)m + SEQ_COUNT_OFF);
    if (mem_find(buf, s, e, "/data/adb") || mem_find(buf, s, e, "overlay") ||
        mem_find(buf, s, e, "magisk") || mem_find(buf, s, e, "KSU") ||
        mem_find(buf, s, e, "worker")) {
        *(volatile uint64_t *)((char *)m + SEQ_COUNT_OFF) = s;
        *(volatile uint64_t *)((char *)m + SEQ_PAD_OFF) = 0;
        fargs->ret = SEQ_SKIP;
        g_mnt_hidden++;
    }
}
static void ensure_seqhooks(void)
{
    if (!g_maps_hooked) {
        if (!g_addr_show_map) g_addr_show_map = (void *)kallsyms_lookup_name("show_map");
        if (g_addr_show_map && hook_wrap2(g_addr_show_map, (void *)before_showmap, (void *)after_showmap, 0) == HOOK_NO_ERR)
            g_maps_hooked = 1;
    }
    if (!g_mnt_hooked) {
        if (!g_addr_show_mnt) g_addr_show_mnt = (void *)kallsyms_lookup_name("show_mountinfo");
        if (g_addr_show_mnt && hook_wrap2(g_addr_show_mnt, (void *)before_mnt, (void *)after_mnt, 0) == HOOK_NO_ERR)
            g_mnt_hooked = 1;
    }
}
static void remove_seqhooks(void)
{
    if (g_maps_hooked && g_addr_show_map) { hook_unwrap(g_addr_show_map, (void *)before_showmap, (void *)after_showmap); g_maps_hooked = 0; }
    if (g_mnt_hooked && g_addr_show_mnt) { hook_unwrap(g_addr_show_mnt, (void *)before_mnt, (void *)after_mnt); g_mnt_hooked = 0; }
}

static void record(const char *comm, const char *name, const char *path)
{
    /* dedup: skip if this exact "path" substring already present (cheap) */
    if (contains(g_log, path)) return;
    char line[320];
    char *p = line, *e = line + sizeof(line) - 1;
    p = apps(p, e, "["); p = apps(p, e, comm && comm[0] ? comm : "?"); p = apps(p, e, "] ");
    p = apps(p, e, name); p = apps(p, e, " "); p = apps(p, e, path); p = apps(p, e, "\n");
    int n = slen(line);
    if (g_loglen + n < LOGCAP - 1) {
        for (int i = 0; i < n; i++) g_log[g_loglen + i] = line[i];
        g_loglen += n;
        g_log[g_loglen] = 0;
    }
}

static void before_fileop(hook_fargs3_t *args, void *udata)
{
    const char *name = (const char *)udata;
    const char *upath = (const char *)syscall_argn(args, 1);
    char path[256];
    long n = compat_strncpy_from_user(path, upath, sizeof(path));
    if (n < 0) return;
    path[sizeof(path) - 1] = 0;

    /* learn GCash's tgid from any gcash-comm thread's file activity */
    char comm[20];
    for (int i = 0; i < (int)sizeof(comm); i++) comm[i] = 0;
    if (fn_get_task_comm) fn_get_task_comm(comm, sizeof(comm), (void *)get_current());
    comm[sizeof(comm) - 1] = 0;
    if (contains(comm, "gcash") || contains(comm, "globe")) {
        int t = cur_tgid();
        if (t) g_gcash_tgid = t;
        if (g_gcash_uid < 0) g_gcash_uid = (int)cur_uid();  /* learn app uid once */
    }

    /* spoof: for the GCash app UID (covers main + sh/exec children + forked watchdog),
     * make root/injection artifacts ENOENT. Gate by UID, not tgid: the su-check runs in
     * a Runtime.exec'd `sh` child with a different tgid but the same app uid. */
    if (g_spoof_on && spoof_path(path)) {
        int u = (int)cur_uid();
        if (g_gcash_uid >= 0 && u == g_gcash_uid) {
            args->skip_origin = 1;
            args->ret = (uint64_t)(-2); /* -ENOENT */
            g_spoofed++;
            if (g_trace_on) record(comm, name ? name : "?", path); /* log what we hid */
            return;
        }
        if (g_trace_on) { /* debug: spoof_path matched but uid gate missed */
            char l[96]; char *pp = l, *ee = l + sizeof(l) - 1;
            pp = apps(pp, ee, "MISS uid="); put_int(&pp, ee, u);
            pp = apps(pp, ee, " ggu="); put_int(&pp, ee, g_gcash_uid);
            pp = apps(pp, ee, " "); pp = apps(pp, ee, path);
            record(comm, name ? name : "?", l);
        }
    }

    if (g_trace_on && suspicious(path)) {
        g_hits++;
        record(comm, name ? name : "?", path);
    }
}

static void put_int(char **pp, char *e, long v); /* fwd */
/* ---- death-syscall trace/block (catches inline-syscall self-kill the watchdog uses) ---- */
static volatile int g_killhooked = 0;
static volatile int g_blockkill = 0;
static long g_killseen = 0, g_killblocked = 0;
#ifndef __NR_kill
#define __NR_kill 129
#endif
#ifndef __NR_tgkill
#define __NR_tgkill 131
#endif
#ifndef __NR_exit_group
#define __NR_exit_group 94
#endif
static void before_kill(hook_fargs3_t *args, void *udata)
{
    if (!g_gcash_tgid || cur_tgid() != g_gcash_tgid) return;
    const char *name = (const char *)udata;
    char comm[20]; for (int i = 0; i < (int)sizeof(comm); i++) comm[i] = 0;
    if (fn_get_task_comm) fn_get_task_comm(comm, sizeof(comm), (void *)get_current());
    g_killseen++;
    /* log: "[comm] <name> KILL a0 a1 a2" */
    char line[128]; char *p = line, *e = line + sizeof(line) - 1;
    p = apps(p, e, "["); p = apps(p, e, comm[0] ? comm : "?"); p = apps(p, e, "] KILL ");
    p = apps(p, e, name); p = apps(p, e, " a0="); put_int(&p, e, (long)syscall_argn(args, 0));
    p = apps(p, e, " a1="); put_int(&p, e, (long)syscall_argn(args, 1));
    record("", "", line);
    if (g_blockkill) { args->skip_origin = 1; args->ret = 0; g_killblocked++; }
}

struct traced { int nr; const char *name; };
static struct traced g_traced[] = {
#ifdef __NR_openat
    { __NR_openat, "openat" },
#endif
#ifdef __NR_faccessat
    { __NR_faccessat, "faccessat" },
#endif
#ifdef __NR_faccessat2
    { __NR_faccessat2, "faccessat2" },
#endif
#ifdef __NR_newfstatat
    { __NR_newfstatat, "newfstatat" },
#endif
#ifdef __NR_readlinkat
    { __NR_readlinkat, "readlinkat" },
#endif
#ifdef __NR_statx
    { __NR_statx, "statx" },
#endif
#ifndef __NR_statx
    { 291, "statx" },
#endif
#ifndef __NR_faccessat2
    { 439, "faccessat2" },
#endif
};
#define NTRACED (int)(sizeof(g_traced) / sizeof(g_traced[0]))

static void put_int(char **pp, char *e, long v)
{
    char t[20]; int m = 0; if (!v) t[m++] = '0';
    while (v) { t[m++] = '0' + v % 10; v /= 10; }
    while (m) { if (*pp < e) *(*pp)++ = t[--m]; else m = 0; }
    if (*pp <= e) **pp = 0;
}

static volatile int g_hooked = 0;
static int ensure_hooks(void)
{
    int ok = 0;
    if (g_hooked) return NTRACED;
    for (int i = 0; i < NTRACED; i++)
        if (hook_syscalln(g_traced[i].nr, 3, (void *)before_fileop, 0, (void *)g_traced[i].name) == HOOK_NO_ERR) ok++;
    g_hooked = 1;
    return ok;
}
static void maybe_remove_hooks(void)
{
    if (g_trace_on || g_spoof_on || !g_hooked) return;
    for (int i = 0; i < NTRACED; i++)
        unhook_syscalln(g_traced[i].nr, (void *)before_fileop, (void *)g_traced[i].name);
    g_hooked = 0;
}
static long trace_on(char *p, char *e)  { int ok = ensure_hooks(); g_trace_on = 1; p = apps(p, e, "ok: trace on hooked="); put_int(&p, e, ok); apps(p, e, "\n"); return 0; }
static long trace_off(char *p, char *e) { g_trace_on = 0; maybe_remove_hooks(); return apps(p, e, "ok: trace off\n"), 0; }
static void kill_on(void)
{
    if (g_killhooked) return;
    hook_syscalln(__NR_kill, 3, (void *)before_kill, 0, (void *)"kill");
    hook_syscalln(__NR_tgkill, 3, (void *)before_kill, 0, (void *)"tgkill");
    hook_syscalln(__NR_exit_group, 3, (void *)before_kill, 0, (void *)"exit_group");
    g_killhooked = 1;
}
static void kill_off(void)
{
    if (!g_killhooked) return;
    unhook_syscalln(__NR_kill, (void *)before_kill, (void *)"kill");
    unhook_syscalln(__NR_tgkill, (void *)before_kill, (void *)"tgkill");
    unhook_syscalln(__NR_exit_group, (void *)before_kill, (void *)"exit_group");
    g_killhooked = 0;
}

static long spoof_on(char *p, char *e)  { int ok = ensure_hooks(); ensure_seqhooks(); g_spoof_on = 1; p = apps(p, e, "ok: spoof on hooked="); put_int(&p, e, ok); p = apps(p, e, " maps="); put_int(&p, e, g_maps_hooked); p = apps(p, e, " mnt="); put_int(&p, e, g_mnt_hooked); apps(p, e, "\n"); return 0; }
static long spoof_off(char *p, char *e) { g_spoof_on = 0; remove_seqhooks(); maybe_remove_hooks(); return apps(p, e, "ok: spoof off\n"), 0; }

static long shtrace_run(const char *args, char *buf, int bufcap)
{
    char *p = buf, *e = buf + bufcap - 1;
    if (starts(args, "ping")) { apps(p, e, "ok: shtrace alive\n"); return 0; }
    if (starts(args, "testuid")) {  /* safe: returns caller uid + the offsets used */
        p = apps(p, e, "caller_uid="); put_int(&p, e, (long)(int)cur_uid());
        p = apps(p, e, " task.cred_off="); put_int(&p, e, task_struct_offset.cred_offset);
        p = apps(p, e, " cred.uid_off="); put_int(&p, e, cred_offset.uid_offset);
        apps(p, e, "\n"); return 0;
    }
    if (starts(args, "traceon")) return trace_on(p, e);
    if (starts(args, "traceoff")) return trace_off(p, e);
    if (starts(args, "spoofon")) return spoof_on(p, e);
    if (starts(args, "spoofoff")) return spoof_off(p, e);
    if (starts(args, "killon")) { kill_on(); apps(p, e, "ok: killtrace on\n"); return 0; }
    if (starts(args, "killoff")) { kill_off(); apps(p, e, "ok: killtrace off\n"); return 0; }
    if (starts(args, "blockkill on")) { g_blockkill = 1; kill_on(); apps(p, e, "ok: blockkill on\n"); return 0; }
    if (starts(args, "blockkill off")) { g_blockkill = 0; apps(p, e, "ok: blockkill off\n"); return 0; }
    if (starts(args, "killstat")) {
        p = apps(p, e, "killseen="); put_int(&p, e, g_killseen);
        p = apps(p, e, " killblocked="); put_int(&p, e, g_killblocked); apps(p, e, "\n"); return 0;
    }
    if (starts(args, "addspoof ")) {
        const char *s = args + 9;
        if (g_nuspoof < MAX_USPOOF) {
            int i = 0; for (; s[i] && i < USPOOF_LEN - 1; i++) g_uspoof[g_nuspoof][i] = s[i];
            g_uspoof[g_nuspoof][i] = 0; g_nuspoof++;
            p = apps(p, e, "ok: addspoof n="); put_int(&p, e, g_nuspoof); apps(p, e, "\n");
        } else apps(p, e, "err: full\n");
        return 0;
    }
    if (starts(args, "settgid ")) {  /* manual tgid override (race-free arming) */
        uint64_t t = 0; const char *s = args + 8; while (*s >= '0' && *s <= '9') t = t*10 + (*s++ - '0');
        g_gcash_tgid = (int)t; p = apps(p, e, "ok: tgid="); put_int(&p, e, g_gcash_tgid); apps(p, e, "\n");
        return 0;
    }
    if (starts(args, "clear")) { g_loglen = 0; g_log[0] = 0; g_hits = 0; g_spoofed = 0; g_gcash_tgid = 0; g_gcash_uid = -1; apps(p, e, "ok: cleared\n"); return 0; }
    if (starts(args, "status")) {
        p = apps(p, e, "trace="); put_int(&p, e, g_trace_on);
        p = apps(p, e, " spoof="); put_int(&p, e, g_spoof_on);
        p = apps(p, e, " tgid="); put_int(&p, e, g_gcash_tgid); p = apps(p, e, " uid="); put_int(&p, e, g_gcash_uid);
        p = apps(p, e, " hits="); put_int(&p, e, g_hits);
        p = apps(p, e, " spoofed="); put_int(&p, e, g_spoofed);
        p = apps(p, e, " mapshid="); put_int(&p, e, g_maps_hidden); p = apps(p, e, " mnthid="); put_int(&p, e, g_mnt_hidden); p = apps(p, e, " loglen="); put_int(&p, e, g_loglen); apps(p, e, "\n"); return 0;
    }
    if (starts(args, "dump")) {
        /* copy g_log into the reply buffer (truncated to bufcap) */
        int i = 0; for (; i < g_loglen && i < bufcap - 1; i++) buf[i] = g_log[i];
        buf[i] = 0; return 0;
    }
    apps(p, e, "usage: ping|traceon|traceoff|status|dump|clear\n");
    return -1;
}

/* ---- sysinfo bridge (mirrors shpte.c) ---- */
static void before_bridge(hook_fargs6_t *fargs, void *udata)
{
    (void)udata;
    if ((uint64_t)syscall_argn(fargs, 0) != BRIDGE_MAGIC) return;
    const char *ucmd = (const char *)syscall_argn(fargs, 1);
    void *uout = (void *)syscall_argn(fargs, 3);
    long outlen = (long)syscall_argn(fargs, 4);
    char cmd[256];
    static char buf[LOGCAP + 64]; /* static: dump reply can be large; serialized by bridge use */
    long n = compat_strncpy_from_user(cmd, ucmd, sizeof(cmd));
    if (n < 0) { fargs->ret = -1; fargs->skip_origin = 1; return; }
    cmd[sizeof(cmd) - 1] = 0;
    buf[0] = 0;
    long rc = shtrace_run(cmd, buf, (int)sizeof(buf));
    int len = 0; while (buf[len] && len < (int)sizeof(buf) - 1) len++;
    if (uout && outlen > 0) { if (len >= outlen) len = (int)outlen - 1; buf[len] = 0; compat_copy_to_user(uout, buf, len + 1); }
    fargs->ret = rc; fargs->skip_origin = 1;
}

static long shtrace_init(const char *args, const char *event, void *reserved)
{
    fn_get_task_comm = (void *)kallsyms_lookup_name("__get_task_comm");
    if (!fn_get_task_comm) fn_get_task_comm = (void *)kallsyms_lookup_name("get_task_comm");
    fn_task_pid_nr_ns = (void *)kallsyms_lookup_name("__task_pid_nr_ns");
    logki("shtrace: init get_task_comm=%llx pid_nr_ns=%llx\n",
          (unsigned long long)(void *)fn_get_task_comm, (unsigned long long)(void *)fn_task_pid_nr_ns);
    g_bridge_hooked = (hook_syscalln(BRIDGE_NR, 6, (void *)before_bridge, 0, 0) == HOOK_NO_ERR);
    logki("shtrace: bridge armed=%d\n", g_bridge_hooked);
    return 0;
}
static long shtrace_exit(void *reserved)
{
    g_trace_on = 0; g_spoof_on = 0; remove_seqhooks(); kill_off(); maybe_remove_hooks();
    if (g_bridge_hooked) unhook_syscalln(BRIDGE_NR, (void *)before_bridge, 0);
    return 0;
}
KPM_INIT(shtrace_init);
KPM_EXIT(shtrace_exit);
