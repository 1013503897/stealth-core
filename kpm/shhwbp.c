/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * stealth-poc P1.6 KPM: ARM64 hardware-breakpoint hook with MULTI-THREAD
 * following, including threads created AFTER the hook. A per-thread breakpoint
 * table; each thread runs its own single-breakpoint entry<->return state
 * machine, controlled via the KPM bridge.
 *
 * Why per-thread: HWBP is a per-thread CPU debug-register state, NOT process
 * wide. A breakpoint installed on one TID only fires for that thread; sibling
 * threads execute the target with no trap. So to follow a whole process we keep
 * a table of slots, one perf_event per thread, and install on each TID.
 *
 * New-thread following (P1.6b/B1): once hooked, we inline-hook wake_up_new_task
 * (KP hook_wrap). Every task creation system-wide calls our callback; if the new
 * task's tgid == the target's, we allocate a slot and queue an install on it.
 * The install (a perf register) is deferred to the new task's OWN context via
 * task_work, so it runs on the new thread's first return-to-user -- before it
 * can reach the target function, and in a sleepable context (never from the
 * wake_up_new_task entry, which is the supercall/hook safety rule).
 *
 * State machine (per slot): arm64 only auto-single-steps over an execute bp with
 * the DEFAULT overflow handler. We use a custom handler to capture regs, so a
 * plain execute bp re-triggers forever. Instead, on an ENTRY hit we move that
 * thread's bp to its return address (LR); on the RETURN hit we move it back to
 * ENTRY. Per-thread isolation is automatic: the CPU saves/restores debug regs
 * per task, so each thread only ever trips its OWN bp.
 *
 * Safety: register/unregister/modify of a perf breakpoint must NOT run in the
 * breakpoint-exception handler, the supercall context, or the wake_up_new_task
 * hook (it wedges holding KP locks -> physical reboot). All of those only
 * snapshot/allocate and queue task_work; the perf calls run via task_work in the
 * owning thread's context (sleepable). Each slot owns its task_work heads so
 * concurrent threads never collide on a shared list node.
 *
 * Thread-exit GC (B2): we also inline-hook do_exit. At its entry (exiting task =
 * current, perf events not yet torn down) we retire that task's slot -- clear bp
 * (kernel reaps the perf_event itself) and active, no unregister. Pure memory
 * ops, so safe in that context. Belt-and-suspenders: a task ref is leaked per
 * slot (task_struct stays alive), dump never derefs task/bp, and unhook drops a
 * slot without unregister if task_work_add fails on a dead thread -- so even a
 * missed GC cannot UAF. (Full RCU on the slot table, article 5.1, is overkill
 * for this static-array PoC and is not implemented.)
 *
 * Commands (shctl <key> control shhwbp "<cmd> ..."):
 *   probe                            - resolve kernel symbols, report them
 *   hook <hexaddr> <pid> <tid>...    - HWBP at addr on each TID, and follow new
 *                                      threads of process <pid> (tgid)
 *   dump                             - per-thread state, hits, last args + ret
 *   unhook                           - stop following + queue removal of all bps
 *
 * Clean-room: written against the KernelPatch kpm SDK only.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <log.h>
#include <kallsyms.h>
#include <kputils.h>
#include <hook.h>
#include <asm/ptrace.h>
#include <asm/current.h>
#include <stdint.h>

KPM_NAME("shhwbp");
KPM_VERSION("0.6.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("stealth-poc");
KPM_DESCRIPTION("P1.6: HWBP per-thread table + follow new threads + GC on exit");

#ifndef offsetof
#define offsetof(t, m) __builtin_offsetof(t, m)
#endif
#ifndef container_of
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#endif

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

/* __task_pid_nr_ns(task, type, ns); types per linux/pid.h */
enum { PIDTYPE_PID = 0, PIDTYPE_TGID = 1 };

enum { ST_ENTRY = 0, ST_RETURN = 1 };

/* ---- per-thread breakpoint slot ---- */
#define MAX_SLOTS 64

struct bp_slot {
    volatile int active;
    int tid;
    void *task;                       /* task_struct* (one ref leaked, on purpose) */
    void *bp;                         /* perf_event* handle */
    uint64_t entry_addr;              /* the hooked function entry (return target) */
    struct kp_perf_event_attr attr;   /* per-slot: bp_addr is rewritten on each move */
    volatile int state;               /* ST_ENTRY / ST_RETURN */
    volatile int move_pending;
    uint64_t next_addr;
    volatile int next_state;
    /* per-slot task_work heads: concurrent threads must not share a list node */
    struct kp_callback_head tw_install;
    struct kp_callback_head tw_move;
    struct kp_callback_head tw_remove;
    /* capture */
    volatile long entry_hits;
    volatile long ret_hits;
    uint64_t args[8];                 /* X0..X7 at entry */
    uint64_t entry_pc;
    uint64_t ret_x0;                  /* X0 at return */
    uint64_t ret_pc;
    volatile int have_entry;
    volatile int have_ret;
    volatile int from_auto;           /* 1 if added by new-thread follow */
};

/* ---- resolved kernel symbols ---- */
static void *(*fn_register_user_hw_breakpoint)(struct kp_perf_event_attr *, void *, void *, void *) = 0;
static void (*fn_unregister_hw_breakpoint)(void *) = 0;
static int (*fn_modify_user_hw_breakpoint)(void *bp, struct kp_perf_event_attr *attr) = 0;
static void *(*fn_find_get_task_by_vpid)(int) = 0;
static int (*fn_task_work_add)(void *task, void *work, int notify) = 0;
static int (*fn_task_pid_nr_ns)(void *task, int type, void *ns) = 0;
static void *g_addr_wake = 0; /* wake_up_new_task */
static void *g_addr_exit = 0; /* do_exit */

/* ---- state ---- */
static struct bp_slot g_slots[MAX_SLOTS];
static volatile long g_hits = 0;
static uint64_t g_entry_addr = 0;      /* target entry addr, shared by all threads */
static volatile int g_target_tgid = 0;
static volatile int g_armed = 0;       /* following new threads? */
static volatile int g_wake_hooked = 0; /* wake_up_new_task wrapped? */
static volatile int g_exit_hooked = 0; /* do_exit wrapped? */
static volatile long g_auto_added = 0;
static volatile long g_auto_removed = 0;

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

/* ---- slot table helpers ---- */
static struct bp_slot *slot_by_bp(void *bp)
{
    for (int i = 0; i < MAX_SLOTS; i++)
        if (g_slots[i].active && g_slots[i].bp == bp) return &g_slots[i];
    return 0;
}
static struct bp_slot *slot_by_tid(int tid)
{
    for (int i = 0; i < MAX_SLOTS; i++)
        if (g_slots[i].active && g_slots[i].tid == tid) return &g_slots[i];
    return 0;
}
static struct bp_slot *slot_free(void)
{
    for (int i = 0; i < MAX_SLOTS; i++)
        if (!g_slots[i].active) return &g_slots[i];
    return 0;
}
static int slot_count(void)
{
    int n = 0;
    for (int i = 0; i < MAX_SLOTS; i++)
        if (g_slots[i].active) n++;
    return n;
}

/* ---- breakpoint handler: snapshot + queue a deferred move; NO perf calls ---- */
static void tw_move(struct kp_callback_head *head);

static void hwbp_handler(void *bp, void *data, struct pt_regs *regs)
{
    (void)data;
    struct bp_slot *s = slot_by_bp(bp);
    if (!s) return;
    g_hits++;

    if (s->state == ST_ENTRY) {
        for (int i = 0; i < 8; i++) s->args[i] = regs->regs[i];
        s->entry_pc = regs->pc;
        s->have_entry = 1;
        s->entry_hits++;
        if (!s->move_pending) {
            s->next_addr = STRIP_PAC(regs->regs[30]); /* LR -> return address */
            s->next_state = ST_RETURN;
            s->move_pending = 1;
            s->tw_move.next = 0;
            s->tw_move.func = tw_move;
            fn_task_work_add(s->task, &s->tw_move, TWA_RESUME);
        }
    } else { /* ST_RETURN */
        s->ret_x0 = regs->regs[0];
        s->ret_pc = regs->pc;
        s->have_ret = 1;
        s->ret_hits++;
        if (!s->move_pending) {
            s->next_addr = s->entry_addr; /* back to entry */
            s->next_state = ST_ENTRY;
            s->move_pending = 1;
            s->tw_move.next = 0;
            s->tw_move.func = tw_move;
            fn_task_work_add(s->task, &s->tw_move, TWA_RESUME);
        }
    }
}

/* all three run in the slot's target task ctx (return-to-user), sleepable */
static void tw_move(struct kp_callback_head *head)
{
    struct bp_slot *s = container_of(head, struct bp_slot, tw_move);
    if (!s->bp || !fn_modify_user_hw_breakpoint) {
        s->move_pending = 0;
        return;
    }
    s->attr.bp_addr = s->next_addr;
    fn_modify_user_hw_breakpoint(s->bp, &s->attr);
    s->state = s->next_state;
    s->move_pending = 0;
}

static void tw_install(struct kp_callback_head *head)
{
    struct bp_slot *s = container_of(head, struct bp_slot, tw_install);
    void *bp = fn_register_user_hw_breakpoint(&s->attr, (void *)hwbp_handler, s, s->task);
    if (is_err_or_null(bp)) {
        s->bp = 0;
        logke("shhwbp: register failed tid=%d ret=%llx\n", s->tid, (unsigned long long)bp);
        return;
    }
    s->bp = bp;
    logki("shhwbp: installed tid=%d%s bp=%llx addr=%llx\n", s->tid, s->from_auto ? " (auto)" : "",
          (unsigned long long)bp, (unsigned long long)s->entry_addr);
}

static void tw_remove(struct kp_callback_head *head)
{
    struct bp_slot *s = container_of(head, struct bp_slot, tw_remove);
    if (s->bp && fn_unregister_hw_breakpoint) {
        fn_unregister_hw_breakpoint(s->bp);
        s->bp = 0;
    }
    logki("shhwbp: removed tid=%d entry=%ld ret=%ld\n", s->tid, s->entry_hits, s->ret_hits);
    s->active = 0; /* slot reusable; task ref intentionally leaked (PoC) */
}

/* allocate + arm one slot for (tid, ref'd task) at addr; queue install. */
static int slot_arm(int tid, void *task, uint64_t addr, int from_auto)
{
    struct bp_slot *s = slot_free();
    if (!s) return -2;

    char *z = (char *)s; /* freestanding: no memset */
    for (unsigned i = 0; i < sizeof(*s); i++) z[i] = 0;

    s->attr.type = PERF_TYPE_BREAKPOINT;
    s->attr.size = sizeof(s->attr);
    s->attr.sample_period = 1;
    s->attr.flags = ATTR_PINNED | ATTR_EXCLUDE_KERNEL | ATTR_EXCLUDE_HV;
    s->attr.bp_type = HW_BREAKPOINT_X;
    s->attr.bp_addr = addr;
    s->attr.bp_len = HW_BREAKPOINT_LEN_4;

    s->tid = tid;
    s->task = task;
    s->entry_addr = addr;
    s->state = ST_ENTRY;
    s->bp = 0;
    s->from_auto = from_auto;
    s->active = 1; /* publish last: handler ignores until active */

    s->tw_install.next = 0;
    s->tw_install.func = tw_install;
    if (fn_task_work_add(task, &s->tw_install, TWA_RESUME)) {
        s->active = 0;
        return -3;
    }
    return 0;
}

/* inline-hook callback for wake_up_new_task(struct task_struct *p) */
static void before_wake(hook_fargs1_t *fargs, void *udata)
{
    (void)udata;
    if (!g_armed || !fn_task_pid_nr_ns || !fn_find_get_task_by_vpid) return;
    void *p = (void *)fargs->arg0;
    if (g_target_tgid && fn_task_pid_nr_ns(p, PIDTYPE_TGID, 0) != g_target_tgid) return;

    int tid = fn_task_pid_nr_ns(p, PIDTYPE_PID, 0);
    if (tid <= 0 || slot_by_tid(tid)) return;

    /* take a ref'd task pointer (leak it) so slot->task can't be freed */
    void *task = fn_find_get_task_by_vpid(tid);
    if (is_err_or_null(task)) return;

    if (slot_arm(tid, task, g_entry_addr, 1) == 0) g_auto_added++;
}

/* inline-hook callback for do_exit(long code): retire the exiting thread's slot.
 * Runs at do_exit entry in the exiting task's context (current), BEFORE the
 * kernel tears down its perf events -- so we must NOT unregister (the kernel
 * will); we just stop tracking. Pure memory ops, no perf/blocking calls. */
static void before_exit(hook_fargs1_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    if (!g_armed || !fn_task_pid_nr_ns) return;
    void *t = (void *)get_current();
    if (g_target_tgid && fn_task_pid_nr_ns(t, PIDTYPE_TGID, 0) != g_target_tgid) return;
    int tid = fn_task_pid_nr_ns(t, PIDTYPE_PID, 0);
    struct bp_slot *s = slot_by_tid(tid);
    if (!s) return;
    s->bp = 0;     /* kernel reaps the perf_event in this same do_exit */
    s->active = 0; /* retire slot (task ref still leaked) */
    g_auto_removed++;
    logki("shhwbp: gc tid=%d on exit (entry=%ld ret=%ld)\n", tid, s->entry_hits, s->ret_hits);
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
    if (!fn_task_pid_nr_ns) fn_task_pid_nr_ns = (void *)kallsyms_lookup_name("__task_pid_nr_ns");
    if (!g_addr_wake) g_addr_wake = (void *)kallsyms_lookup_name("wake_up_new_task");
    if (!g_addr_exit) g_addr_exit = (void *)kallsyms_lookup_name("do_exit");
}

/* install one slot for one explicit tid at addr; returns 0 on queued, <0 on error */
static int do_hook_one(int tid, uint64_t addr)
{
    if (slot_by_tid(tid)) return 0; /* already followed; skip silently */
    void *task = fn_find_get_task_by_vpid(tid);
    if (is_err_or_null(task)) return -1;
    return slot_arm(tid, task, addr, 0);
}

static long do_hook(const char *args, char *p, char *e)
{
    resolve_syms();
    if (!fn_register_user_hw_breakpoint || !fn_modify_user_hw_breakpoint || !fn_find_get_task_by_vpid ||
        !fn_task_work_add) {
        apps(p, e, "error: symbols not resolved (run probe)\n");
        return -1;
    }

    uint64_t addr = 0, pid = 0;
    const char *s = parse_ull(args, &addr);
    s = parse_ull(s, &pid);
    if (!addr || !pid) {
        apps(p, e, "usage: hook <hexaddr> <pid> <tid> [tid ...]\n");
        return -1;
    }

    g_entry_addr = addr;
    g_target_tgid = (int)pid;

    /* arm new-thread following: inline-hook wake_up_new_task (create) + do_exit (gc) */
    int wake_ok = 0;
    if (!g_wake_hooked && fn_task_pid_nr_ns && g_addr_wake) {
        hook_err_t he = hook_wrap1(g_addr_wake, (void *)before_wake, 0, 0);
        if (he == HOOK_NO_ERR) {
            g_wake_hooked = 1;
            wake_ok = 1;
        } else {
            logke("shhwbp: hook_wrap1(wake_up_new_task) err=%d\n", (int)he);
        }
    } else if (g_wake_hooked) {
        wake_ok = 1;
    }
    g_armed = wake_ok;

    if (g_armed && !g_exit_hooked && g_addr_exit) {
        hook_err_t he = hook_wrap1(g_addr_exit, (void *)before_exit, 0, 0);
        if (he == HOOK_NO_ERR)
            g_exit_hooked = 1;
        else
            logke("shhwbp: hook_wrap1(do_exit) err=%d (no exit-GC)\n", (int)he);
    }

    int queued = 0, skipped = 0, errs = 0;
    const char *cur = skipsp(s);
    while (*cur) {
        uint64_t tid = 0;
        const char *ns = parse_ull(cur, &tid);
        if (ns == cur) break;
        cur = skipsp(ns);
        if (!tid) continue;
        if (slot_by_tid((int)tid)) {
            skipped++;
            continue;
        }
        int r = do_hook_one((int)tid, addr);
        if (r == 0)
            queued++;
        else
            errs++;
    }

    p = apps(p, e, "ok: addr=");
    p = apphex(p, e, addr);
    p = apps(p, e, " tgid=");
    p = appdec(p, e, (long)pid);
    p = apps(p, e, " queued=");
    p = appdec(p, e, queued);
    p = apps(p, e, " skipped=");
    p = appdec(p, e, skipped);
    p = apps(p, e, " errs=");
    p = appdec(p, e, errs);
    p = apps(p, e, " follow_new=");
    p = apps(p, e, g_armed ? "on" : "OFF");
    p = apps(p, e, " slots=");
    p = appdec(p, e, slot_count());
    apps(p, e, "\n");
    return errs ? -1 : 0;
}

static long do_unhook(char *p, char *e)
{
    /* stop following new threads first, so no slots are added mid-teardown */
    g_armed = 0;
    if (g_wake_hooked && g_addr_wake) {
        hook_unwrap(g_addr_wake, (void *)before_wake, 0);
        g_wake_hooked = 0;
    }
    if (g_exit_hooked && g_addr_exit) {
        hook_unwrap(g_addr_exit, (void *)before_exit, 0);
        g_exit_hooked = 0;
    }

    int n = slot_count();
    if (!n) {
        apps(p, e, "ok: unfollowed; no slots\n");
        return 0;
    }
    int queued = 0;
    for (int i = 0; i < MAX_SLOTS; i++) {
        struct bp_slot *s = &g_slots[i];
        if (!s->active) continue;
        s->tw_remove.next = 0;
        s->tw_remove.func = tw_remove;
        if (fn_task_work_add(s->task, &s->tw_remove, TWA_RESUME) == 0)
            queued++;
        else
            s->active = 0; /* target gone: drop slot (bp auto-reaped on exit) */
    }
    p = apps(p, e, "ok: unfollowed; queued unhook for ");
    p = appdec(p, e, queued);
    apps(p, e, " thread(s)\n");
    return 0;
}

static long do_dump(char *p, char *e)
{
    p = apps(p, e, "slots=");
    p = appdec(p, e, slot_count());
    p = apps(p, e, " total_hits=");
    p = appdec(p, e, g_hits);
    p = apps(p, e, " follow_new=");
    p = apps(p, e, g_armed ? "on" : "off");
    p = apps(p, e, " tgid=");
    p = appdec(p, e, g_target_tgid);
    p = apps(p, e, " auto_added=");
    p = appdec(p, e, g_auto_added);
    p = apps(p, e, " auto_removed=");
    p = appdec(p, e, g_auto_removed);
    apps(p, e, "\n");

    for (int i = 0; i < MAX_SLOTS; i++) {
        struct bp_slot *s = &g_slots[i];
        if (!s->active) continue;
        if (p >= e - 96) {
            p = apps(p, e, "...(truncated)\n");
            break;
        }
        p = apps(p, e, "tid=");
        p = appdec(p, e, s->tid);
        p = apps(p, e, s->from_auto ? "* st=" : " st=");
        p = apps(p, e, s->state == ST_ENTRY ? "E" : "R");
        p = apps(p, e, " e=");
        p = appdec(p, e, s->entry_hits);
        p = apps(p, e, " r=");
        p = appdec(p, e, s->ret_hits);
        if (s->have_entry) {
            p = apps(p, e, " x0=");
            p = apphex(p, e, s->args[0]);
        }
        if (s->have_ret) {
            p = apps(p, e, " ret=");
            p = apphex(p, e, s->ret_x0);
        }
        apps(p, e, "\n");
    }
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
    p = apps(p, e, "\n__task_pid_nr_ns=");
    p = apphex(p, e, (uint64_t)fn_task_pid_nr_ns);
    p = apps(p, e, "\nwake_up_new_task=");
    p = apphex(p, e, (uint64_t)g_addr_wake);
    p = apps(p, e, "\ndo_exit=");
    p = apphex(p, e, (uint64_t)g_addr_exit);
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
    char buf[2048];
    for (int i = 0; i < (int)sizeof(buf); i++) buf[i] = 0;
    char *p = buf;
    char *e = buf + sizeof(buf) - 1;
    long rc = 0;
    const char *a = skipsp(args ? args : "");

    if (starts(a, "probe")) {
        rc = do_probe(p, e);
    } else if (starts(a, "unhook")) {
        rc = do_unhook(p, e);
    } else if (starts(a, "hook")) {
        rc = do_hook(a + 4, p, e);
    } else if (starts(a, "dump")) {
        rc = do_dump(p, e);
    } else {
        apps(p, e, "usage: probe | hook <hexaddr> <pid> <tid> [tid ...] | dump | unhook\n");
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
    g_armed = 0;
    if (g_wake_hooked && g_addr_wake) {
        hook_unwrap(g_addr_wake, (void *)before_wake, 0);
        g_wake_hooked = 0;
    }
    if (g_exit_hooked && g_addr_exit) {
        hook_unwrap(g_addr_exit, (void *)before_exit, 0);
        g_exit_hooked = 0;
    }
    long te = 0, tr = 0;
    for (int i = 0; i < MAX_SLOTS; i++) {
        struct bp_slot *s = &g_slots[i];
        if (s->bp && fn_unregister_hw_breakpoint) {
            fn_unregister_hw_breakpoint(s->bp);
            s->bp = 0;
        }
        te += s->entry_hits;
        tr += s->ret_hits;
        s->active = 0;
    }
    logki("shhwbp: exit total_entry=%ld total_ret=%ld auto_added=%ld\n", te, tr, g_auto_added);
    return 0;
}

KPM_INIT(shhwbp_init);
KPM_CTL0(shhwbp_control0);
KPM_EXIT(shhwbp_exit);
