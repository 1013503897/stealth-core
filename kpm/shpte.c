/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * stealth-poc P2 KPM: PTE/UXN "high-voltage net" (article 5.6), step by step.
 *
 *   P2.0  read + decode any process's leaf PTE (no modification).
 *   P2.1  arm: flip the target code page's UXN bit so EL0 execute faults, hook
 *         do_page_fault, and SELF-HEAL the fault (clear UXN, re-execute). This
 *         proves the page-table-write + fault-interception + safe-EL0-resume
 *         machinery without a clone page, so a gating bug self-heals rather than
 *         crashing the target. (P2.2 will keep UXN set and redirect PC to a
 *         recompiled clone instead of self-healing -- the actual no-trace hook.)
 *
 * Safety: do_page_fault is the hottest path in the kernel. The before-callback
 * is gated hard -- if not armed, return immediately; otherwise only act when the
 * fault address is on our exact target page AND the faulting task's tgid matches
 * the target (so we never swallow another process's fault). The PTE pointer is
 * resolved once at arm time and cached, so the handler does no page-table walk /
 * locking -- just a u64 write + TLB flush.
 *
 *   P2.2  redirect: keep UXN set and reroute the faulting PC to the same offset
 *         in a userspace clone page (a verbatim copy of the page-isolated,
 *         PC-relative-free target function). The target's .text is never
 *         modified (CRC-clean) and no extra executable VMA appears at the
 *         function's address -- the article's no-trace execute redirect.
 *
 * Commands (shctl <key> control shpte "<cmd> ..."):
 *   probe                          - resolve kernel symbols, report them
 *   pte  <pid> <hexaddr>           - read + decode the leaf PTE for VA addr in pid
 *   arm  <pid> <hexaddr>           - hook do_page_fault + UXN on addr's page (self-heal)
 *   redirect <pid> <addr> <clone>  - same, but reroute faults into the clone page
 *   disarm                         - clear UXN + unhook do_page_fault
 *   dump                           - armed state, mode, target, fault/redirect counts
 *
 * Clean-room: KernelPatch kpm SDK only. PoC: leaks a task ref per arm/pte.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <log.h>
#include <kallsyms.h>
#include <kputils.h>
#include <hook.h>
#include <pgtable.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <stdint.h>

KPM_NAME("shpte");
KPM_VERSION("0.4.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("stealth-poc");
KPM_DESCRIPTION("P2/P3: UXN net + clone redirect with offset_map routing");

enum { PIDTYPE_PID = 0, PIDTYPE_TGID = 1 };

/* ---- resolved kernel symbols ---- */
static void *(*fn_find_get_task_by_vpid)(int) = 0;
static void *(*fn_get_task_mm)(void *task) = 0;
static void (*fn_mmput)(void *mm) = 0;
static int (*fn_apply_existing)(void *mm, unsigned long addr, unsigned long size, void *fn, void *data) = 0;
static int (*fn_task_pid_nr_ns)(void *task, int type, void *ns) = 0;
/* int access_process_vm(struct task_struct *tsk, unsigned long addr, void *buf, int len, uint flags) */
static int (*fn_access_process_vm)(void *tsk, unsigned long addr, void *buf, int len, unsigned int flags) = 0;
static void *g_addr_pf = 0; /* do_page_fault */

/* ---- arm state ---- */
enum { MODE_SELFHEAL = 0, MODE_REDIRECT = 1, MODE_REDIRECT_MAP = 2 };

/* offset_map: original instruction index (page offset/4) -> recompiled insn index
 * in the clone region. One source page = 1024 instructions. Filled from the
 * target's user memory via access_process_vm at redirect-map time. */
#define OFFMAP_MAX 1024
static uint32_t g_offmap[OFFMAP_MAX];
static volatile int g_nmap = 0;
static volatile int g_armed = 0;
static volatile int g_pf_hooked = 0;
static volatile int g_mode = MODE_SELFHEAL;
static volatile int g_target_pid = 0;
static volatile uint64_t g_target_page = 0;
static volatile uint64_t g_clone_page = 0; /* MODE_REDIRECT: clone of the target page */
static uint64_t *g_ptep = 0;        /* cached kernel VA of the leaf PTE */
static uint64_t g_pte_orig = 0;     /* original PTE value (UXN clear) */
static volatile long g_faults = 0;
static volatile long g_redirects = 0;

/* ---- tiny freestanding string/number helpers ---- */
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

/* ---- apply_to_existing_page_range callback: capture the leaf PTE ---- */
struct pte_out {
    volatile uint64_t ptep;
    volatile uint64_t val;
    volatile int n;
};
static int pte_cb(void *pte, unsigned long addr, void *data)
{
    (void)addr;
    struct pte_out *o = (struct pte_out *)data;
    o->ptep = (uint64_t)pte;
    o->val = *(volatile uint64_t *)pte;
    o->n++;
    return 0;
}

/* resolve the leaf PTE for VA `base` in process `pid`; returns ptep/val via out.
 * Leaks the task ref (PoC); releases the mm ref. */
static int resolve_pte(uint64_t pid, uint64_t base, struct pte_out *o)
{
    o->ptep = 0;
    o->val = 0;
    o->n = 0;
    void *task = fn_find_get_task_by_vpid((int)pid);
    if (is_err_or_null(task)) return -1;
    void *mm = fn_get_task_mm(task);
    if (is_err_or_null(mm)) return -2;
    int rc = fn_apply_existing(mm, base, 0x1000, (void *)pte_cb, o);
    fn_mmput(mm);
    if (o->n == 0) return -3;
    (void)rc;
    return 0;
}

/* ---- do_page_fault before-callback: self-heal the UXN execute fault ----
 * do_page_fault(unsigned long far, unsigned long esr, struct pt_regs *regs) */
static void before_pf(hook_fargs3_t *fargs, void *udata)
{
    (void)udata;
    if (!g_armed) return;
    uint64_t far = fargs->arg0;
    if ((far & ~0xfffUL) != g_target_page) return;
    if (fn_task_pid_nr_ns) {
        void *t = (void *)get_current();
        if (fn_task_pid_nr_ns(t, PIDTYPE_TGID, 0) != g_target_pid) return;
    }
    g_faults++;

    if ((g_mode == MODE_REDIRECT || g_mode == MODE_REDIRECT_MAP) && g_clone_page) {
        /* keep UXN set; reroute PC into the clone region. The target's .text is
         * never touched and every call re-faults+reroutes. With an offset_map,
         * recompiled instructions may have shifted, so map orig-insn-idx ->
         * recompiled-insn-idx; otherwise route to the same page offset. */
        struct pt_regs *regs = (struct pt_regs *)fargs->arg2;
        uint64_t off = far & 0xfffUL;
        if (g_mode == MODE_REDIRECT_MAP) {
            uint32_t idx = (uint32_t)(off >> 2);
            if (idx < (uint32_t)g_nmap) off = (uint64_t)g_offmap[idx] << 2;
        }
        regs->pc = g_clone_page + off;
        g_redirects++;
    } else {
        /* self-heal: restore UXN-clear PTE so the instruction re-executes */
        if (g_ptep) {
            *(volatile uint64_t *)g_ptep = g_pte_orig;
            flush_tlb_all();
        }
    }
    fargs->skip_origin = 1; /* we handled it; don't run the real do_page_fault */
    fargs->ret = 0;
}

static void resolve_syms(void)
{
    if (!fn_find_get_task_by_vpid)
        fn_find_get_task_by_vpid = (void *)kallsyms_lookup_name("find_get_task_by_vpid");
    if (!fn_get_task_mm) fn_get_task_mm = (void *)kallsyms_lookup_name("get_task_mm");
    if (!fn_mmput) fn_mmput = (void *)kallsyms_lookup_name("mmput");
    if (!fn_apply_existing)
        fn_apply_existing = (void *)kallsyms_lookup_name("apply_to_existing_page_range");
    if (!fn_task_pid_nr_ns) fn_task_pid_nr_ns = (void *)kallsyms_lookup_name("__task_pid_nr_ns");
    if (!fn_access_process_vm) fn_access_process_vm = (void *)kallsyms_lookup_name("access_process_vm");
    if (!g_addr_pf) g_addr_pf = (void *)kallsyms_lookup_name("do_page_fault");
}

static char *decode_pte(char *p, char *e, uint64_t v)
{
    p = apps(p, e, v & PTE_VALID ? " VALID" : " !VALID");
    if ((v & PTE_TYPE_MASK) == PTE_TYPE_PAGE) p = apps(p, e, " PAGE");
    p = apps(p, e, v & PTE_USER ? " USER" : " kern");
    p = apps(p, e, v & PTE_RDONLY ? " RO" : " RW");
    p = apps(p, e, v & PTE_AF ? " AF" : " !AF");
    p = apps(p, e, v & PTE_PXN ? " PXN" : " pexec");
    p = apps(p, e, v & PTE_UXN ? " UXN" : " uexec");
    p = apps(p, e, v & PTE_NG ? " nG" : "");
    return p;
}

static long do_pte(uint64_t pid, uint64_t addr, char *p, char *e)
{
    resolve_syms();
    if (!fn_find_get_task_by_vpid || !fn_get_task_mm || !fn_mmput || !fn_apply_existing) {
        apps(p, e, "error: symbols not resolved (run probe)\n");
        return -1;
    }
    uint64_t base = addr & ~0xFFFUL;
    struct pte_out o;
    int r = resolve_pte(pid, base, &o);
    if (r) {
        p = apps(p, e, "addr=");
        p = apphex(p, e, addr);
        p = apps(p, e, r == -3 ? " : no leaf PTE (unmapped)\n" : " : task/mm lookup failed\n");
        return -1;
    }
    p = apps(p, e, "addr=");
    p = apphex(p, e, addr);
    p = apps(p, e, " page=");
    p = apphex(p, e, base);
    p = apps(p, e, "\nptep=");
    p = apphex(p, e, o.ptep);
    p = apps(p, e, " pte=");
    p = apphex(p, e, o.val);
    p = apps(p, e, " pa=");
    p = apphex(p, e, o.val & 0x0000fffffffff000UL);
    p = apps(p, e, "\nflags:");
    p = decode_pte(p, e, o.val);
    apps(p, e, "\n");
    return 0;
}

/* shared arm path: mode = MODE_SELFHEAL or MODE_REDIRECT (clone used iff redirect) */
static long arm_common(uint64_t pid, uint64_t addr, int mode, uint64_t clone, char *p, char *e)
{
    resolve_syms();
    if (!fn_find_get_task_by_vpid || !fn_get_task_mm || !fn_mmput || !fn_apply_existing || !g_addr_pf ||
        !fn_task_pid_nr_ns) {
        apps(p, e, "error: symbols not resolved (run probe)\n");
        return -1;
    }
    if (g_armed) {
        apps(p, e, "error: already armed; disarm first\n");
        return -1;
    }

    uint64_t base = addr & ~0xFFFUL;
    struct pte_out o;
    int r = resolve_pte(pid, base, &o);
    if (r || !(o.val & PTE_VALID)) {
        apps(p, e, "error: target page not present/valid (run it first)\n");
        return -1;
    }

    g_target_pid = (int)pid;
    g_target_page = base;
    g_clone_page = (mode != MODE_SELFHEAL) ? (clone & ~0xFFFUL) : 0;
    g_mode = mode;
    g_ptep = (uint64_t *)o.ptep;
    g_pte_orig = o.val;
    g_faults = 0;
    g_redirects = 0;

    /* hook do_page_fault BEFORE arming UXN so the first fault is caught */
    if (!g_pf_hooked) {
        hook_err_t he = hook_wrap3(g_addr_pf, (void *)before_pf, 0, 0);
        if (he != HOOK_NO_ERR) {
            apps(p, e, "error: hook_wrap3(do_page_fault) failed\n");
            g_ptep = 0;
            return -1;
        }
        g_pf_hooked = 1;
    }
    g_armed = 1;

    /* set UXN -> EL0 execute on this page now faults into our handler */
    *(volatile uint64_t *)g_ptep = g_pte_orig | PTE_UXN;
    flush_tlb_all();

    p = apps(p, e, "ok: armed pid=");
    p = appdec(p, e, (long)pid);
    p = apps(p, e, " page=");
    p = apphex(p, e, base);
    if (mode == MODE_SELFHEAL) {
        p = apps(p, e, " mode=SELFHEAL");
    } else {
        p = apps(p, e, mode == MODE_REDIRECT_MAP ? " mode=REDIRECT_MAP clone=" : " mode=REDIRECT clone=");
        p = apphex(p, e, g_clone_page);
    }
    p = apps(p, e, " pte_now=");
    p = apphex(p, e, *(volatile uint64_t *)g_ptep);
    apps(p, e, "\n");
    return 0;
}

static long do_arm(uint64_t pid, uint64_t addr, char *p, char *e)
{
    return arm_common(pid, addr, MODE_SELFHEAL, 0, p, e);
}

static long do_redirect(uint64_t pid, uint64_t addr, uint64_t clone, char *p, char *e)
{
    return arm_common(pid, addr, MODE_REDIRECT, clone, p, e);
}

/* redirectmap: like redirect, but route via an offset_map read from the target's
 * user memory (mapaddr points at ninsn u32 entries: orig-insn-idx -> clone-idx). */
static long do_redirectmap(uint64_t pid, uint64_t addr, uint64_t clone, uint64_t mapaddr, uint64_t ninsn,
                           char *p, char *e)
{
    resolve_syms();
    if (!fn_access_process_vm || !fn_find_get_task_by_vpid) {
        apps(p, e, "error: symbols not resolved (run probe)\n");
        return -1;
    }
    if (ninsn == 0 || ninsn > OFFMAP_MAX) {
        apps(p, e, "error: ninsn out of range (1..1024)\n");
        return -1;
    }
    void *task = fn_find_get_task_by_vpid((int)pid);
    if (is_err_or_null(task)) {
        apps(p, e, "error: task not found\n");
        return -1;
    }
    int want = (int)(ninsn * 4);
    int got = fn_access_process_vm(task, mapaddr, g_offmap, want, 0 /*read*/);
    if (got != want) {
        p = apps(p, e, "error: access_process_vm read offset_map got=");
        p = appdec(p, e, got);
        p = apps(p, e, " want=");
        p = appdec(p, e, want);
        apps(p, e, "\n");
        return -1;
    }
    g_nmap = (int)ninsn;
    return arm_common(pid, addr, MODE_REDIRECT_MAP, clone, p, e);
}

static long do_disarm(char *p, char *e)
{
    g_armed = 0;
    if (g_ptep) {
        *(volatile uint64_t *)g_ptep = g_pte_orig; /* clear UXN */
        flush_tlb_all();
    }
    if (g_pf_hooked && g_addr_pf) {
        hook_unwrap(g_addr_pf, (void *)before_pf, 0);
        g_pf_hooked = 0;
    }
    p = apps(p, e, "ok: disarmed, faults=");
    p = appdec(p, e, g_faults);
    p = apps(p, e, " redirects=");
    p = appdec(p, e, g_redirects);
    apps(p, e, "\n");
    g_ptep = 0;
    g_mode = MODE_SELFHEAL;
    g_clone_page = 0;
    g_nmap = 0;
    return 0;
}

static long do_state(char *p, char *e)
{
    p = apps(p, e, "armed=");
    p = appdec(p, e, g_armed);
    p = apps(p, e, " mode=");
    p = apps(p, e, g_mode == MODE_REDIRECT_MAP ? "REDIRECT_MAP" : (g_mode == MODE_REDIRECT ? "REDIRECT" : "SELFHEAL"));
    p = apps(p, e, " nmap=");
    p = appdec(p, e, g_nmap);
    p = apps(p, e, " pf_hooked=");
    p = appdec(p, e, g_pf_hooked);
    p = apps(p, e, " pid=");
    p = appdec(p, e, g_target_pid);
    p = apps(p, e, " page=");
    p = apphex(p, e, g_target_page);
    p = apps(p, e, " clone=");
    p = apphex(p, e, g_clone_page);
    p = apps(p, e, " faults=");
    p = appdec(p, e, g_faults);
    p = apps(p, e, " redirects=");
    p = appdec(p, e, g_redirects);
    if (g_ptep) {
        p = apps(p, e, "\npte_now=");
        p = apphex(p, e, *(volatile uint64_t *)g_ptep);
        p = decode_pte(p, e, *(volatile uint64_t *)g_ptep);
    }
    apps(p, e, "\n");
    return 0;
}

static long do_probe(char *p, char *e)
{
    resolve_syms();
    p = apps(p, e, "find_get_task_by_vpid=");
    p = apphex(p, e, (uint64_t)fn_find_get_task_by_vpid);
    p = apps(p, e, "\nget_task_mm=");
    p = apphex(p, e, (uint64_t)fn_get_task_mm);
    p = apps(p, e, "\nmmput=");
    p = apphex(p, e, (uint64_t)fn_mmput);
    p = apps(p, e, "\napply_to_existing_page_range=");
    p = apphex(p, e, (uint64_t)fn_apply_existing);
    p = apps(p, e, "\n__task_pid_nr_ns=");
    p = apphex(p, e, (uint64_t)fn_task_pid_nr_ns);
    p = apps(p, e, "\naccess_process_vm=");
    p = apphex(p, e, (uint64_t)fn_access_process_vm);
    p = apps(p, e, "\ndo_page_fault=");
    p = apphex(p, e, (uint64_t)g_addr_pf);
    apps(p, e, "\n");
    return 0;
}

static long shpte_init(const char *args, const char *event, void *__user reserved)
{
    logki("shpte: init event=%s\n", event ? event : "");
    resolve_syms();
    return 0;
}

static long shpte_control0(const char *args, char *__user out_msg, int outlen)
{
    char buf[1024];
    for (int i = 0; i < (int)sizeof(buf); i++) buf[i] = 0;
    char *p = buf;
    char *e = buf + sizeof(buf) - 1;
    long rc = 0;
    const char *a = skipsp(args ? args : "");

    if (starts(a, "probe")) {
        rc = do_probe(p, e);
    } else if (starts(a, "pte")) {
        uint64_t pid = 0, addr = 0;
        const char *s = parse_ull(a + 3, &pid);
        parse_ull(s, &addr);
        if (!pid || !addr)
            apps(p, e, "usage: pte <pid> <hexaddr>\n"), rc = -1;
        else
            rc = do_pte(pid, addr, p, e);
    } else if (starts(a, "disarm")) {
        rc = do_disarm(p, e);
    } else if (starts(a, "redirectmap")) {
        uint64_t pid = 0, addr = 0, clone = 0, map = 0, n = 0;
        const char *s = parse_ull(a + 11, &pid);
        s = parse_ull(s, &addr);
        s = parse_ull(s, &clone);
        s = parse_ull(s, &map);
        parse_ull(s, &n);
        if (!pid || !addr || !clone || !map || !n)
            apps(p, e, "usage: redirectmap <pid> <hexaddr> <cloneaddr> <mapaddr> <ninsn>\n"), rc = -1;
        else
            rc = do_redirectmap(pid, addr, clone, map, n, p, e);
    } else if (starts(a, "redirect")) {
        uint64_t pid = 0, addr = 0, clone = 0;
        const char *s = parse_ull(a + 8, &pid);
        s = parse_ull(s, &addr);
        parse_ull(s, &clone);
        if (!pid || !addr || !clone)
            apps(p, e, "usage: redirect <pid> <hexaddr> <cloneaddr>\n"), rc = -1;
        else
            rc = do_redirect(pid, addr, clone, p, e);
    } else if (starts(a, "arm")) {
        uint64_t pid = 0, addr = 0;
        const char *s = parse_ull(a + 3, &pid);
        parse_ull(s, &addr);
        if (!pid || !addr)
            apps(p, e, "usage: arm <pid> <hexaddr>\n"), rc = -1;
        else
            rc = do_arm(pid, addr, p, e);
    } else if (starts(a, "dump")) {
        rc = do_state(p, e);
    } else {
        apps(p, e,
             "usage: probe | pte <pid> <addr> | arm <pid> <addr> | "
             "redirect <pid> <addr> <clone> | redirectmap <pid> <addr> <clone> <map> <n> | "
             "disarm | dump\n");
        rc = -1;
    }

    int len = 0;
    while (buf[len] && len < (int)sizeof(buf) - 1) len++;
    if (len >= outlen) len = outlen - 1;
    buf[len] = 0;
    compat_copy_to_user(out_msg, buf, len + 1);
    return rc;
}

static long shpte_exit(void *__user reserved)
{
    /* always restore + unhook so unload can't leave a UXN'd page or live hook */
    g_armed = 0;
    if (g_ptep) {
        *(volatile uint64_t *)g_ptep = g_pte_orig;
        flush_tlb_all();
        g_ptep = 0;
    }
    if (g_pf_hooked && g_addr_pf) {
        hook_unwrap(g_addr_pf, (void *)before_pf, 0);
        g_pf_hooked = 0;
    }
    logki("shpte: exit faults=%ld\n", g_faults);
    return 0;
}

KPM_INIT(shpte_init);
KPM_CTL0(shpte_control0);
KPM_EXIT(shpte_exit);
