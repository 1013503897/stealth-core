/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * stealth-poc P1.5 KPM: ARM64 hardware-breakpoint hook with single-breakpoint
 * state machine (entry <-> return), controlled via the KPM control bridge.
 *
 * Why a state machine: arm64's breakpoint_handler only single-steps over the
 * instruction when the perf event uses the DEFAULT overflow handler. We need a
 * custom handler to capture registers, so the kernel won't step for us and a
 * plain execute breakpoint re-triggers forever (livelock). Instead, on an ENTRY
 * hit we move the breakpoint to the return address (LR); on the RETURN hit we
 * move it back to ENTRY. The breakpointed entry instruction is thus uncovered
 * before it re-executes, so the target runs normally -- and we capture both the
 * arguments (X0..X7 at entry) and the return value (X0 at return).
 *
 * Safety: register/unregister/modify of the perf breakpoint must NOT be called
 * from the breakpoint-exception handler context (it wedges, holding KP locks).
 * So the handler only snapshots regs + queues task_work; the actual perf calls
 * run via task_work in the target's own context (sleepable) on return-to-user,
 * which also happens BEFORE the faulting instruction re-executes -> no burst.
 *
 * Commands (shctl <key> control shhwbp "<cmd> ..."):
 *   probe                  - resolve kernel symbols, report them
 *   hook  <pid> <hexaddr>  - queue an execute HWBP at addr in process pid
 *   dump                   - report state, hits, last entry args + return value
 *   unhook                 - queue removal of the breakpoint
 *
 * Clean-room: written against the KernelPatch kpm SDK only; perf/breakpoint and
 * task_work ABI are stable Linux layouts reproduced to call kallsyms-resolved
 * kernel APIs.  PoC: one task ref leaked per hook; unhook needs target alive.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <log.h>
#include <kallsyms.h>
#include <kputils.h>
#include <asm/ptrace.h>
#include <stdint.h>

KPM_NAME("shhwbp");
KPM_VERSION("0.3.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("stealth-poc");
KPM_DESCRIPTION("P1.5: ARM64 HWBP hook + entry/return state machine (no mem mod)");

/* ---- minimal stable perf / hw_breakpoint ABI ---- */
#define PERF_TYPE_BREAKPOINT 5u
#define HW_BREAKPOINT_X 4u
#define HW_BREAKPOINT_LEN_4 4u

struct kp_perf_event_attr {
    uint32_t type;
    uint32_t size;
    uint64_t config;
    uint64_t sample_period;
    uint64_t sample_type;
    uint64_t read_format;
    uint64_t flags;
    uint32_t wakeup;
    uint32_t bp_type;
    uint64_t bp_addr;
    uint64_t bp_len;
    uint64_t branch_sample_type;
    uint64_t sample_regs_user;
    uint32_t sample_stack_user;
    int32_t clockid;
    uint64_t sample_regs_intr;
    uint32_t aux_watermark;
    uint16_t sample_max_stack;
    uint16_t __res2;
    uint32_t aux_sample_size;
    uint32_t __res3;
    uint64_t sig_data;
};

#define ATTR_PINNED (1ull << 2)
#define ATTR_EXCLUDE_KERNEL (1ull << 5)
#define ATTR_EXCLUDE_HV (1ull << 6)
#define STRIP_PAC(x) ((uint64_t)(x) & 0x0000ffffffffffffULL)

struct kp_callback_head {
    struct kp_callback_head *next;
    void (*func)(struct kp_callback_head *);
};
#define TWA_RESUME 1

enum { ST_ENTRY = 0, ST_RETURN = 1 };

/* ---- resolved kernel symbols ---- */
static void *(*fn_register_user_hw_breakpoint)(struct kp_perf_event_attr *, void *, void *, void *) = 0;
static void (*fn_unregister_hw_breakpoint)(void *) = 0;
static int (*fn_modify_user_hw_breakpoint)(void *bp, struct kp_perf_event_attr *attr) = 0;
static void *(*fn_find_get_task_by_vpid)(int) = 0;
static int (*fn_task_work_add)(void *task, void *work, int notify) = 0;

/* ---- state ---- */
static struct kp_perf_event_attr g_attr;
static struct kp_callback_head g_tw_hook;
static struct kp_callback_head g_tw_unhook;
static struct kp_callback_head g_tw_move;
static void *g_bp = 0;
static void *g_task = 0;
static uint64_t g_entry_addr = 0;
static volatile int g_state = ST_ENTRY;
static volatile int g_move_pending = 0;
static uint64_t g_next_addr = 0;
static volatile int g_next_state = ST_ENTRY;
static volatile long g_hits = 0;
static volatile long g_entry_hits = 0;
static volatile long g_ret_hits = 0;
static uint64_t g_args[8]; /* X0..X7 captured at entry */
static uint64_t g_entry_pc = 0;
static uint64_t g_ret_x0 = 0; /* X0 captured at return */
static uint64_t g_ret_pc = 0;
static volatile int g_have_entry = 0;
static volatile int g_have_ret = 0;

/* ---- tiny string/number helpers (freestanding) ---- */
static char *apps(char *p, char *e, const char *s)
{
    while (*s && p < e) *p++ = *s++;
    return p;
}
static char *apphex(char *p, char *e, uint64_t v)
{
    p = apps(p, e, "0x");
    char t[16];
    int n = 0;
    if (v == 0) {
        if (p < e) *p++ = '0';
        return p;
    }
    while (v) {
        t[n++] = "0123456789abcdef"[v & 0xf];
        v >>= 4;
    }
    for (int i = n - 1; i >= 0; i--)
        if (p < e) *p++ = t[i];
    return p;
}
static char *appdec(char *p, char *e, long v)
{
    char t[24];
    int n = 0;
    unsigned long u = (v < 0) ? (unsigned long)(-v) : (unsigned long)v;
    if (v < 0 && p < e) *p++ = '-';
    if (u == 0) {
        if (p < e) *p++ = '0';
        return p;
    }
    while (u) {
        t[n++] = '0' + (u % 10);
        u /= 10;
    }
    for (int i = n - 1; i >= 0; i--)
        if (p < e) *p++ = t[i];
    return p;
}
static const char *skipsp(const char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    return s;
}
static const char *parse_ull(const char *s, uint64_t *out)
{
    s = skipsp(s);
    uint64_t v = 0;
    int base = 10;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        s += 2;
    }
    for (;;) {
        char c = *s;
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (base == 16 && c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        v = v * base + d;
        s++;
    }
    *out = v;
    return s;
}
static int starts(const char *s, const char *pfx)
{
    while (*pfx) {
        if (*s++ != *pfx++) return 0;
    }
    return 1;
}
static int is_err_or_null(void *p)
{
    unsigned long v = (unsigned long)p;
    return (p == 0) || (v >= 0xfffffffffffff000UL);
}

static void tw_move(struct kp_callback_head *head); /* fwd decl */

/* ---- breakpoint handler: snapshot + queue a deferred move; NO perf calls ---- */
static void hwbp_handler(void *bp, void *data, struct pt_regs *regs)
{
    (void)bp;
    (void)data;
    g_hits++;

    if (g_state == ST_ENTRY) {
        for (int i = 0; i < 8; i++) g_args[i] = regs->regs[i];
        g_entry_pc = regs->pc;
        g_have_entry = 1;
        g_entry_hits++;
        if (!g_move_pending) {
            g_next_addr = STRIP_PAC(regs->regs[30]); /* LR -> return address */
            g_next_state = ST_RETURN;
            g_move_pending = 1;
            g_tw_move.next = 0;
            g_tw_move.func = tw_move;
            fn_task_work_add(g_task, &g_tw_move, TWA_RESUME);
        }
    } else { /* ST_RETURN */
        g_ret_x0 = regs->regs[0];
        g_ret_pc = regs->pc;
        g_have_ret = 1;
        g_ret_hits++;
        if (!g_move_pending) {
            g_next_addr = g_entry_addr; /* back to entry */
            g_next_state = ST_ENTRY;
            g_move_pending = 1;
            g_tw_move.next = 0;
            g_tw_move.func = tw_move;
            fn_task_work_add(g_task, &g_tw_move, TWA_RESUME);
        }
    }
}

/* runs in target ctx (return-to-user), sleepable: actually move the breakpoint */
static void tw_move(struct kp_callback_head *head)
{
    (void)head;
    if (!g_bp || !fn_modify_user_hw_breakpoint) {
        g_move_pending = 0;
        return;
    }
    g_attr.bp_addr = g_next_addr;
    fn_modify_user_hw_breakpoint(g_bp, &g_attr);
    g_state = g_next_state;
    g_move_pending = 0;
}

static void tw_install(struct kp_callback_head *head)
{
    (void)head;
    void *bp = fn_register_user_hw_breakpoint(&g_attr, (void *)hwbp_handler, 0, g_task);
    if (is_err_or_null(bp)) {
        g_bp = 0;
        logke("shhwbp: register failed in target ctx ret=%llx\n", (unsigned long long)bp);
        return;
    }
    g_bp = bp;
    logki("shhwbp: hwbp installed bp=%llx addr=%llx\n", (unsigned long long)bp, (unsigned long long)g_entry_addr);
}
static void tw_remove(struct kp_callback_head *head)
{
    (void)head;
    if (g_bp) {
        fn_unregister_hw_breakpoint(g_bp);
        g_bp = 0;
        logki("shhwbp: hwbp removed\n");
    }
}

static void resolve_syms(void)
{
    if (!fn_register_user_hw_breakpoint)
        fn_register_user_hw_breakpoint = (void *)kallsyms_lookup_name("register_user_hw_breakpoint");
    if (!fn_unregister_hw_breakpoint)
        fn_unregister_hw_breakpoint = (void *)kallsyms_lookup_name("unregister_hw_breakpoint");
    if (!fn_modify_user_hw_breakpoint)
        fn_modify_user_hw_breakpoint = (void *)kallsyms_lookup_name("modify_user_hw_breakpoint");
    if (!fn_find_get_task_by_vpid)
        fn_find_get_task_by_vpid = (void *)kallsyms_lookup_name("find_get_task_by_vpid");
    if (!fn_task_work_add) fn_task_work_add = (void *)kallsyms_lookup_name("task_work_add");
}

static long do_hook(uint64_t pid, uint64_t addr, char *p, char *e)
{
    resolve_syms();
    if (!fn_register_user_hw_breakpoint || !fn_modify_user_hw_breakpoint || !fn_find_get_task_by_vpid ||
        !fn_task_work_add) {
        apps(p, e, "error: symbols not resolved (run probe)\n");
        return -1;
    }
    if (g_bp || g_task) {
        apps(p, e, "error: already hooked; unhook first\n");
        return -1;
    }
    void *task = fn_find_get_task_by_vpid((int)pid);
    if (is_err_or_null(task)) {
        p = apps(p, e, "error: task not found for pid=");
        p = appdec(p, e, (long)pid);
        apps(p, e, "\n");
        return -1;
    }

    char *z = (char *)&g_attr;
    for (unsigned i = 0; i < sizeof(g_attr); i++) z[i] = 0;
    g_attr.type = PERF_TYPE_BREAKPOINT;
    g_attr.size = sizeof(g_attr);
    g_attr.sample_period = 1;
    g_attr.flags = ATTR_PINNED | ATTR_EXCLUDE_KERNEL | ATTR_EXCLUDE_HV;
    g_attr.bp_type = HW_BREAKPOINT_X;
    g_attr.bp_addr = addr;
    g_attr.bp_len = HW_BREAKPOINT_LEN_4;

    g_task = task;
    g_entry_addr = addr;
    g_state = ST_ENTRY;
    g_move_pending = 0;
    g_hits = g_entry_hits = g_ret_hits = 0;
    g_have_entry = g_have_ret = 0;
    g_bp = 0;

    g_tw_hook.next = 0;
    g_tw_hook.func = tw_install;
    int r = fn_task_work_add(g_task, &g_tw_hook, TWA_RESUME);
    if (r) {
        p = apps(p, e, "error: task_work_add failed rc=");
        p = appdec(p, e, r);
        apps(p, e, "\n");
        g_task = 0;
        return -1;
    }
    p = apps(p, e, "ok: queued install pid=");
    p = appdec(p, e, (long)pid);
    p = apps(p, e, " addr=");
    p = apphex(p, e, addr);
    apps(p, e, " (entry/return state machine)\n");
    return 0;
}

static long do_unhook(char *p, char *e)
{
    if (!g_task) {
        apps(p, e, "error: not hooked\n");
        return -1;
    }
    g_tw_unhook.next = 0;
    g_tw_unhook.func = tw_remove;
    int r = fn_task_work_add(g_task, &g_tw_unhook, TWA_RESUME);
    if (r) {
        apps(p, e, "error: task_work_add(unhook) failed (target gone?)\n");
        return -1;
    }
    p = apps(p, e, "ok: queued unhook, entry_hits=");
    p = appdec(p, e, g_entry_hits);
    p = apps(p, e, " ret_hits=");
    p = appdec(p, e, g_ret_hits);
    apps(p, e, "\n");
    g_task = 0;
    return 0;
}

static long do_dump(char *p, char *e)
{
    p = apps(p, e, "entry_addr=");
    p = apphex(p, e, g_entry_addr);
    p = apps(p, e, " bp=");
    p = apphex(p, e, (uint64_t)g_bp);
    p = apps(p, e, " state=");
    p = apps(p, e, g_state == ST_ENTRY ? "ENTRY" : "RETURN");
    p = apps(p, e, "\nhits=");
    p = appdec(p, e, g_hits);
    p = apps(p, e, " entry_hits=");
    p = appdec(p, e, g_entry_hits);
    p = apps(p, e, " ret_hits=");
    p = appdec(p, e, g_ret_hits);
    p = apps(p, e, "\n");
    if (g_have_entry) {
        p = apps(p, e, "entry: pc=");
        p = apphex(p, e, g_entry_pc);
        for (int i = 0; i < 4; i++) {
            p = apps(p, e, i == 0 ? " x0=" : (i == 1 ? " x1=" : (i == 2 ? " x2=" : " x3=")));
            p = apphex(p, e, g_args[i]);
        }
        p = apps(p, e, "\n");
    }
    if (g_have_ret) {
        p = apps(p, e, "return: pc=");
        p = apphex(p, e, g_ret_pc);
        p = apps(p, e, " x0=");
        p = apphex(p, e, g_ret_x0);
        p = apps(p, e, "\n");
    }
    if (!g_have_entry && !g_have_ret) apps(p, e, "(no hit captured yet)\n");
    return 0;
}

static long do_probe(char *p, char *e)
{
    resolve_syms();
    p = apps(p, e, "register_user_hw_breakpoint=");
    p = apphex(p, e, (uint64_t)fn_register_user_hw_breakpoint);
    p = apps(p, e, "\nunregister_hw_breakpoint=");
    p = apphex(p, e, (uint64_t)fn_unregister_hw_breakpoint);
    p = apps(p, e, "\nmodify_user_hw_breakpoint=");
    p = apphex(p, e, (uint64_t)fn_modify_user_hw_breakpoint);
    p = apps(p, e, "\nfind_get_task_by_vpid=");
    p = apphex(p, e, (uint64_t)fn_find_get_task_by_vpid);
    p = apps(p, e, "\ntask_work_add=");
    p = apphex(p, e, (uint64_t)fn_task_work_add);
    apps(p, e, "\n");
    return 0;
}

static long shhwbp_init(const char *args, const char *event, void *__user reserved)
{
    logki("shhwbp: init event=%s\n", event ? event : "");
    resolve_syms();
    return 0;
}

static long shhwbp_control0(const char *args, char *__user out_msg, int outlen)
{
    char buf[1024];
    for (int i = 0; i < (int)sizeof(buf); i++) buf[i] = 0;
    char *p = buf;
    char *e = buf + sizeof(buf) - 1;
    long rc = 0;
    const char *a = skipsp(args ? args : "");

    if (starts(a, "probe")) {
        rc = do_probe(p, e);
    } else if (starts(a, "hook")) {
        uint64_t pid = 0, addr = 0;
        const char *s = parse_ull(a + 4, &pid);
        parse_ull(s, &addr);
        rc = do_hook(pid, addr, p, e);
    } else if (starts(a, "unhook")) {
        rc = do_unhook(p, e);
    } else if (starts(a, "dump")) {
        rc = do_dump(p, e);
    } else {
        apps(p, e, "usage: probe | hook <pid> <hexaddr> | dump | unhook\n");
        rc = -1;
    }

    int len = 0;
    while (buf[len] && len < (int)sizeof(buf) - 1) len++;
    if (len >= outlen) len = outlen - 1;
    buf[len] = 0;
    compat_copy_to_user(out_msg, buf, len + 1);
    return rc;
}

static long shhwbp_exit(void *__user reserved)
{
    if (g_bp && fn_unregister_hw_breakpoint) {
        fn_unregister_hw_breakpoint(g_bp);
        g_bp = 0;
    }
    logki("shhwbp: exit entry_hits=%ld ret_hits=%ld\n", g_entry_hits, g_ret_hits);
    return 0;
}

KPM_INIT(shhwbp_init);
KPM_CTL0(shhwbp_control0);
KPM_EXIT(shhwbp_exit);
