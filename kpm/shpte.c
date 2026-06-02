/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * stealth-poc P2 KPM (step 0): page-table / PTE inspection.
 *
 * Foundation for the "UXN high-voltage net" technique (article 5.6): to hook
 * without touching the target's .text, we will flip the UXN bit on the target
 * code page so any EL0 execute traps into do_page_fault, then route it. Before
 * any of that page-table surgery (which can reboot the device), this step only
 * READS a user VA's leaf PTE and decodes it -- proving we can walk an arbitrary
 * process's page table on this kernel. NOTHING is modified here.
 *
 * Approach (clean-room, matches the article's primitives): resolve get_task_mm
 * + apply_to_existing_page_range via kallsyms; apply_to_existing_page_range
 * hands our callback the leaf pte_t* directly, so we avoid hard-coding any
 * mm_struct/pgd struct offsets. KP's pgtable.h gives the ARM64 PTE bit layout.
 *
 * Commands (shctl <key> control shpte "<cmd> ..."):
 *   probe                  - resolve kernel symbols, report them
 *   pte <pid> <hexaddr>    - read + decode the leaf PTE for VA addr in pid
 *
 * PoC: leaks one task ref per query (consistent with the rest of the PoC); the
 * mm ref taken by get_task_mm is released with mmput.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <log.h>
#include <kallsyms.h>
#include <kputils.h>
#include <pgtable.h>
#include <stdint.h>

KPM_NAME("shpte");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("stealth-poc");
KPM_DESCRIPTION("P2 step0: read + decode a user VA's PTE (no modification)");

/* ---- resolved kernel symbols ---- */
static void *(*fn_find_get_task_by_vpid)(int) = 0;
static void *(*fn_get_task_mm)(void *task) = 0;
static void (*fn_mmput)(void *mm) = 0;
/* int apply_to_existing_page_range(mm, addr, size, pte_fn_t fn, void *data) */
static int (*fn_apply_existing)(void *mm, unsigned long addr, unsigned long size, void *fn, void *data) = 0;

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
    volatile uint64_t ptep; /* kernel VA of the PTE slot */
    volatile uint64_t val;  /* raw PTE value */
    volatile int n;         /* #entries visited */
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

static void resolve_syms(void)
{
    if (!fn_find_get_task_by_vpid)
        fn_find_get_task_by_vpid = (void *)kallsyms_lookup_name("find_get_task_by_vpid");
    if (!fn_get_task_mm) fn_get_task_mm = (void *)kallsyms_lookup_name("get_task_mm");
    if (!fn_mmput) fn_mmput = (void *)kallsyms_lookup_name("mmput");
    if (!fn_apply_existing)
        fn_apply_existing = (void *)kallsyms_lookup_name("apply_to_existing_page_range");
}

static char *decode_pte(char *p, char *e, uint64_t v)
{
    p = apps(p, e, v & PTE_VALID ? " VALID" : " !VALID");
    if ((v & PTE_TYPE_MASK) == PTE_TYPE_PAGE) p = apps(p, e, " PAGE");
    p = apps(p, e, v & PTE_USER ? " USER" : " kern");
    p = apps(p, e, v & PTE_RDONLY ? " RO" : " RW");
    p = apps(p, e, v & PTE_AF ? " AF" : " !AF");
    p = apps(p, e, v & PTE_PXN ? " PXN" : " pexec");
    p = apps(p, e, v & PTE_UXN ? " UXN" : " uexec"); /* uexec = EL0-executable */
    p = apps(p, e, v & PTE_NG ? " nG" : "");
    p = apps(p, e, v & PTE_DBM ? " DBM/W" : "");
    return p;
}

static long do_pte(uint64_t pid, uint64_t addr, char *p, char *e)
{
    resolve_syms();
    if (!fn_find_get_task_by_vpid || !fn_get_task_mm || !fn_mmput || !fn_apply_existing) {
        apps(p, e, "error: symbols not resolved (run probe)\n");
        return -1;
    }
    void *task = fn_find_get_task_by_vpid((int)pid);
    if (is_err_or_null(task)) {
        apps(p, e, "error: task not found\n");
        return -1;
    }
    void *mm = fn_get_task_mm(task); /* leaks task ref (PoC) */
    if (is_err_or_null(mm)) {
        apps(p, e, "error: no mm (kernel thread or exiting?)\n");
        return -1;
    }

    uint64_t base = addr & ~0xFFFUL;
    struct pte_out o;
    o.ptep = 0;
    o.val = 0;
    o.n = 0;
    int rc = fn_apply_existing(mm, base, 0x1000, (void *)pte_cb, &o);
    fn_mmput(mm);

    if (o.n == 0) {
        p = apps(p, e, "addr=");
        p = apphex(p, e, addr);
        p = apps(p, e, " : no leaf PTE (unmapped / not faulted in) rc=");
        p = appdec(p, e, rc);
        apps(p, e, "\n");
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
    p = apphex(p, e, o.val & 0x0000fffffffff000UL); /* output addr bits [47:12] */
    p = apps(p, e, "\nflags:");
    p = decode_pte(p, e, o.val);
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
    } else {
        apps(p, e, "usage: probe | pte <pid> <hexaddr>\n");
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
    logki("shpte: exit\n");
    return 0;
}

KPM_INIT(shpte_init);
KPM_CTL0(shpte_control0);
KPM_EXIT(shpte_exit);
