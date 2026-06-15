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
#include <syscall.h>
#include <stdint.h>

KPM_NAME("shpte");
KPM_VERSION("0.6.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("wxy");
KPM_DESCRIPTION("P2/P3/P4: UXN redirect + maps hide + VMA-less ghost memory");

/* struct offsets verified from this device's kernel BTF (6.1 GKI):
 *   seq_file.count=+24, seq_file.pad_until=+32 ; vm_area_struct.vm_start=+0, vm_mm=+16 */
#define SEQ_COUNT_OFF 24
#define SEQ_PAD_OFF 32
#define VMA_START_OFF 0
#define VMA_END_OFF 8
#define VMA_VM_MM_OFF 16
#define SEQ_SKIP 1

#define GHOST_MAGIC 0xDEADBEEFCAFEF00DULL
#define PFN_MASK 0x0000FFFFFFFFF000ULL /* PTE output-address bits [47:12] */

/* ---- minimal perf / hw_breakpoint ABI (HWBP-redirect inline_hooker) ---- */
#define PERF_TYPE_BREAKPOINT 5u
#define HW_BREAKPOINT_X 4u
#define HW_BREAKPOINT_LEN_4 4u
#define ATTR_PINNED (1ull << 2)
#define ATTR_EXCLUDE_KERNEL (1ull << 5)
#define ATTR_EXCLUDE_HV (1ull << 6)
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
struct kp_callback_head {
    struct kp_callback_head *next;
    void (*func)(struct kp_callback_head *);
};
#define TWA_RESUME 1

enum { PIDTYPE_PID = 0, PIDTYPE_TGID = 1 };

/* ---- resolved kernel symbols ---- */
static void *(*fn_find_get_task_by_vpid)(int) = 0;
static void *(*fn_get_task_mm)(void *task) = 0;
static void (*fn_mmput)(void *mm) = 0;
static int (*fn_apply_existing)(void *mm, unsigned long addr, unsigned long size, void *fn, void *data) = 0;
static int (*fn_task_pid_nr_ns)(void *task, int type, void *ns) = 0;
/* int access_process_vm(struct task_struct *tsk, unsigned long addr, void *buf, int len, uint flags) */
static int (*fn_access_process_vm)(void *tsk, unsigned long addr, void *buf, int len, unsigned int flags) = 0;
static void *g_addr_pf = 0;        /* do_page_fault */
static void *g_addr_show_map = 0;  /* show_map (/proc/pid/maps per-VMA) */
static void *g_addr_show_smap = 0; /* show_smap (/proc/pid/smaps per-VMA, same sig as show_map) */
static void *g_addr_status = 0;    /* proc_pid_status (/proc/pid/status) */
/* int apply_to_page_range(mm, addr, size, pte_fn_t fn, void *data) -- allocating */
static int (*fn_apply)(void *mm, unsigned long addr, unsigned long size, void *fn, void *data) = 0;
/* vmalloc + vmalloc_to_pfn: avoids KP-unexported virt_to_phys/linear_voffset */
static void *(*fn_vmalloc)(unsigned long size) = 0;
static void (*fn_vfree)(void *addr) = 0;
static unsigned long (*fn_vmalloc_to_pfn)(void *addr) = 0;
/* SSOL single-step primitive (uprobes-style); resolved lazily in resolve_syms */
static void (*fn_register_user_step_hook)(void *hook) = 0;
static void (*fn_unregister_user_step_hook)(void *hook) = 0;
static void (*fn_user_enable_single_step)(void *task) = 0;
static void (*fn_user_disable_single_step)(void *task) = 0;

/* ---- arm state ---- */
enum { MODE_SELFHEAL = 0, MODE_REDIRECT = 1, MODE_REDIRECT_MAP = 2, MODE_REDIRECT_FIXED = 3 };

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
static volatile uint64_t g_clone_page = 0;     /* MODE_REDIRECT*: clone of the target page */
static volatile uint64_t g_redirect_fixed = 0; /* MODE_REDIRECT_FIXED: route entry -> here */
/* pagehook: on a whole-page MODE_REDIRECT_MAP clone, route ONE function's entry
 * (page + g_hook_off) to g_hook_replace; everything else runs from the clone. */
static volatile uint64_t g_hook_off = 0;     /* byte offset of hooked fn in the page */
static volatile uint64_t g_hook_replace = 0; /* 0 = no override */

/* multi-page hook table: LSPlant inline-hooks ~20 libart functions that live on
 * (and often SHARE) code pages, all active at once. Each slot UXN-traps one page,
 * routes it to a whole-page clone, and overrides any of MAX_OV function entries on
 * that page -> their replacements (several hooked funcs can share a page).
 *
 * Concurrency: overrides are appended/removed from the sleepable bridge/supercall
 * context while before_pf (the page-fault handler, another thread of the same
 * process) scans them. The override table is a fixed array scanned [0,MAX_OV) with
 * a SENTINEL key for inert slots, so the handler NEVER sees a half-built entry and
 * NEVER dereferences a garbage replacement: an entry is published key-last (write
 * ov_replace, store barrier, then ov_off) and retired key-first (single store of
 * the SENTINEL). ov_replace always holds a valid pointer or a stale-but-valid one
 * -- never garbage. nlive counts non-inert slots (when it hits 0 the page disarms). */
#define MAX_PG 16            /* trapped REGIONS live at once (LSPlant ~20 funcs grouped by region) */
#define MAX_OV 8             /* hooked function entries per trapped region */
#define MAX_RGN 64           /* RV-2: max pages in one clean-bounded region (64: reach farther clean boundaries in dense libart) */
#define OV_NONE (~0ULL)      /* sentinel: inert override slot (a real region offset is < npages*0x1000) */
/* RV-2: each slot now traps a clean-bounded MULTI-PAGE region [page, page+npages) and
 * routes it to one whole-region clone. The clone covers complete functions (region
 * boundaries fall in inter-function gaps), so a function spanning a page is wholly in
 * the clone and RETs normally -- no spill. ov_off/the fault offset are REGION-relative
 * (far - page), not page-relative. offmap is vmalloc'd (region-sized, too big for BSS). */
struct pghook {
    volatile int active;
    int pid;
    void *mm;          /* target's mm_struct* -- maps-hide gates the clone on the vma OWNER
                        * (hides for self-scans AND external readers, never another process) */
    uint64_t page;     /* region base (R_lo) -- first UXN-trapped page */
    volatile int npages; /* pages in the region [page, page+npages*0x1000) */
    uint64_t clone;    /* whole-region clone base (user VA) */
    volatile int nlive;             /* live (non-inert) overrides; 0 => region can disarm */
    volatile uint64_t ov_off[MAX_OV];     /* REGION-relative byte offset, or OV_NONE if inert */
    volatile uint64_t ov_replace[MAX_OV]; /* replacement VA for ov_off[k] */
    int nmap;                /* region instruction count = npages*1024 */
    uint32_t *offmap;        /* vmalloc'd, nmap entries: orig insn idx -> clone insn idx */
    uint64_t *ptep[MAX_RGN]; /* cached leaf PTE pointer per region page */
    uint64_t pte_orig[MAX_RGN]; /* original PTE (UXN clear) per region page */
    volatile long redirects;
};
static struct pghook g_pg[MAX_PG];
static volatile int g_npg = 0;

/* publish a new override key-last so a racing before_pf never matches an offset
 * before its replacement pointer is in place */
static inline void pg_set_ov(struct pghook *s, int k, uint64_t off, uint64_t replace)
{
    s->ov_replace[k] = replace;
    asm volatile("dmb ishst" ::: "memory"); /* replace visible before the key */
    s->ov_off[k] = off;
}
static uint64_t *g_ptep = 0;        /* cached kernel VA of the leaf PTE */
static uint64_t g_pte_orig = 0;     /* original PTE value (UXN clear) */
static volatile long g_faults = 0;
static volatile long g_redirects = 0;
/* P4.1 maps-hide state */
static volatile int g_maps_hooked = 0;
static volatile uint64_t g_hide_page = 0; /* VMA vm_start to drop from maps */
static volatile long g_maps_hidden = 0;
/* smaps shares the maps-hide callbacks (show_smap has the same (seq_file*, vma*)
 * signature) -- armed together with show_map; separate counter for telemetry */
static volatile int g_smaps_hooked = 0;
static volatile long g_smaps_hidden = 0;
/* general region hide-set (mm-gated): in addition to the auto-hidden pghook clones, the glue
 * registers arbitrary anomalous regions here -- chiefly the LSPlant trampoline pool (an rwxp
 * anon region GenerateTrampolineFor mmaps for EVERY hook, which an anti-tamper maps-scan flags).
 * Keyed by (owner mm, page) like the clone hide; cleared per-mm when the process is GC'd. */
#define MAX_HIDE 64
struct hidereg {
    void *mm;
    uint64_t page;
};
static struct hidereg g_hide[MAX_HIDE];
static volatile int g_nhide = 0;
/* TracerPid spoof state (anti-debug / anti-ptrace-detection) */
static volatile int g_tracer_hooked = 0;
static volatile long g_tracer_spoofed = 0;
/* P4.2 ghost-memory state */
static void *g_ghost_kaddr = 0; /* vmalloc page backing the ghost VA */
static volatile uint64_t g_ghost_va = 0;
static volatile int g_ghost_pid = 0;
/* syscall bridge: lets an injected agent drive the KPM without the superkey.
 * Carrier syscall = sysinfo (arm64 #179), NOT personality: Android's app seccomp
 * filter ARG-FILTERS personality() (allows the 0xffffffff query, blocks other args
 * with ERRNO), so a personality-magic bridge is unreachable from real (zygote-forked,
 * seccomp'd) app processes -- exactly the in-app agent case. sysinfo is allowed for
 * apps with arbitrary args and is rarely called, so the magic-gated passthrough is
 * cheap. A real sysinfo(arg0!=magic) passes straight through. */
#define BRIDGE_MAGIC 0x5348505442524447ULL /* "SHPTBRDG" */
#define BRIDGE_NR 179                       /* __NR_sysinfo on arm64 (asm-generic) */
static volatile int g_bridge_hooked = 0;
/* HWBP-redirect inline_hooker: per-instruction trap, so it doesn't disturb other
 * functions sharing the target's page (real libart funcs aren't page-isolated) */
static void *(*fn_reg_hwbp)(struct kp_perf_event_attr *, void *, void *, void *) = 0;
static void (*fn_unreg_hwbp)(void *) = 0;
static int (*fn_task_work_add)(void *, void *, int) = 0;
static struct kp_perf_event_attr g_hwbp_attr;
static void *g_hwbp = 0;
static void *g_hwbp_task = 0;
static volatile uint64_t g_hwbp_replace = 0;
static struct kp_callback_head g_hwbp_tw_install, g_hwbp_tw_remove;
static volatile int g_hwbp_armed = 0;
static volatile long g_hw_redirects = 0;

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

/* ===================== SSOL simulator (ported from lib/ssol.c) =====================
 * Computes the architectural effect of one PC-relative instruction directly into
 * pt_regs (NO execution), for the SSOL before_pf dispatch (P1b). The bulk is PORTED
 * VERBATIM from the P0 lib/ssol.c (device-verified off-device), with two on-device
 * adaptations: (1) LDR-literal pool reads go through ssol_rd32/64 (P1a: plain reads
 * to compile clean; P1b makes them PAN-safe -- a direct user deref from the EL1
 * fault handler faults under PAN); (2) BR/BLR/RET register targets are STRIP_PAC'd.
 * All helpers are ssol_-prefixed to avoid any symbol clash in this large module. */
#ifndef STRIP_PAC
#define STRIP_PAC(x) ((uint64_t)(x) & 0x0000ffffffffffffULL)
#endif

enum ssol_action { SSOL_SIMULATED = 0, SSOL_XOL = 1 };

/* LDR-literal pool reads come from the trapped region's kernel-side instruction
 * snapshot (set by before_pf right before each ssol_simulate call) -- so the fault
 * path never does a PAN-unsafe user deref. Out-of-region literals return 0 (P1 keeps
 * literals in-region; P2 adds a PAN-safe user read for cross-region pools). NOTE:
 * these globals are single-fault-at-a-time correct; concurrent faults on different
 * CPUs would race them -- fine for the P1 single-thread self-test, made per-fault
 * safe in P2. */
static const uint32_t *volatile g_rd_insns = 0;
static volatile uint64_t g_rd_base = 0;
static volatile int g_rd_n = 0;
static uint32_t ssol_rd32(uintptr_t a)
{
    if (g_rd_insns && a >= g_rd_base && a + 4 <= g_rd_base + (uint64_t)g_rd_n * 4)
        return g_rd_insns[(a - g_rd_base) / 4];
    return 0;
}
static uint64_t ssol_rd64(uintptr_t a)
{
    if (g_rd_insns && a >= g_rd_base && a + 8 <= g_rd_base + (uint64_t)g_rd_n * 4) {
        uint64_t i = (a - g_rd_base) / 4;
        return (uint64_t)g_rd_insns[i] | ((uint64_t)g_rd_insns[i + 1] << 32);
    }
    return 0;
}

static int64_t ssol_sext(int64_t v, int bits) { int s = 64 - bits; return (v << s) >> s; }

static int ssol_is_adr(uint32_t i) { return (i & 0x9F000000u) == 0x10000000u; }
static int ssol_is_adrp(uint32_t i) { return (i & 0x9F000000u) == 0x90000000u; }
static int ssol_is_b(uint32_t i) { return (i & 0xFC000000u) == 0x14000000u; }
static int ssol_is_bl(uint32_t i) { return (i & 0xFC000000u) == 0x94000000u; }
static int ssol_is_bcond(uint32_t i) { return (i & 0xFF000010u) == 0x54000000u; }
static int ssol_is_cbz(uint32_t i) { return (i & 0x7E000000u) == 0x34000000u; }   /* CBZ/CBNZ */
static int ssol_is_tbz(uint32_t i) { return (i & 0x7E000000u) == 0x36000000u; }   /* TBZ/TBNZ */
static int ssol_is_ldrlit(uint32_t i) { return (i & 0x3B000000u) == 0x18000000u && ((i >> 30) & 3) != 3; }
static int ssol_is_br(uint32_t i) { return (i & 0xFFFFFC1Fu) == 0xD61F0000u; }  /* BR  Xn */
static int ssol_is_blr(uint32_t i) { return (i & 0xFFFFFC1Fu) == 0xD63F0000u; } /* BLR Xn */
static int ssol_is_ret(uint32_t i) { return (i & 0xFFFFFC1Fu) == 0xD65F0000u; } /* RET {Xn=30} */

static uint64_t ssol_btarget(uint32_t insn, uint64_t pc)
{
    if (ssol_is_b(insn) || ssol_is_bl(insn)) return pc + ((uint64_t)ssol_sext(insn & 0x03ffffff, 26) << 2);
    if (ssol_is_bcond(insn) || ssol_is_cbz(insn)) return pc + ((uint64_t)ssol_sext((insn >> 5) & 0x7ffff, 19) << 2);
    if (ssol_is_tbz(insn)) return pc + ((uint64_t)ssol_sext((insn >> 5) & 0x3fff, 14) << 2);
    return 0;
}

/* ARM ConditionHolds. NZCV = pstate bits 31/30/29/28. */
static int ssol_eval_cond(uint32_t cond, uint64_t pstate)
{
    int N = (pstate >> 31) & 1, Z = (pstate >> 30) & 1, C = (pstate >> 29) & 1, V = (pstate >> 28) & 1;
    int res;
    switch ((cond >> 1) & 7) {
    case 0: res = (Z == 1); break;             /* EQ / NE */
    case 1: res = (C == 1); break;             /* CS / CC */
    case 2: res = (N == 1); break;             /* MI / PL */
    case 3: res = (V == 1); break;             /* VS / VC */
    case 4: res = (C == 1 && Z == 0); break;   /* HI / LS */
    case 5: res = (N == V); break;             /* GE / LT */
    case 6: res = (N == V && Z == 0); break;   /* GT / LE */
    default: res = 1; break;                   /* AL / NV */
    }
    if ((cond & 1) && cond != 0xf) res = !res;
    return res;
}

/* field value 31 => XZR/WZR (reads 0), NEVER SP, in every encoding SSOL handles. */
static uint64_t ssol_reg_read(const struct pt_regs *regs, int idx, int is64)
{
    uint64_t v = (idx == 31) ? 0 : regs->regs[idx];
    return is64 ? v : (v & 0xffffffffu);
}
static void ssol_reg_write(struct pt_regs *regs, int idx, uint64_t val, int is64)
{
    if (idx == 31) return; /* XZR: discard -- NEVER write regs[31] (= SP). */
    regs->regs[idx] = is64 ? val : (val & 0xffffffffu);
}

static enum ssol_action ssol_simulate(struct pt_regs *regs, uint32_t insn)
{
    uint64_t pc = regs->pc;

    if (ssol_is_b(insn)) {
        regs->pc = ssol_btarget(insn, pc);
        return SSOL_SIMULATED;
    }
    if (ssol_is_bl(insn)) {
        regs->regs[30] = pc + 4;
        regs->pc = ssol_btarget(insn, pc);
        return SSOL_SIMULATED;
    }
    if (ssol_is_bcond(insn)) {
        regs->pc = ssol_eval_cond(insn & 0xf, regs->pstate) ? ssol_btarget(insn, pc) : pc + 4;
        return SSOL_SIMULATED;
    }
    if (ssol_is_cbz(insn)) {
        int sf = (insn >> 31) & 1;
        int rt = insn & 0x1f;
        int is_cbnz = (insn >> 24) & 1;
        int zero = (ssol_reg_read(regs, rt, sf) == 0);
        int taken = zero ^ is_cbnz;
        regs->pc = taken ? ssol_btarget(insn, pc) : pc + 4;
        return SSOL_SIMULATED;
    }
    if (ssol_is_tbz(insn)) {
        int rt = insn & 0x1f;
        int bitpos = (int)((((insn >> 31) & 1) << 5) | ((insn >> 19) & 0x1f));
        int is_tbnz = (insn >> 24) & 1;
        int bit = (int)((ssol_reg_read(regs, rt, 1) >> bitpos) & 1);
        int taken = is_tbnz ? bit : !bit;
        regs->pc = taken ? ssol_btarget(insn, pc) : pc + 4;
        return SSOL_SIMULATED;
    }
    if (ssol_is_adr(insn)) {
        int rd = insn & 0x1f;
        int64_t imm = ssol_sext((int64_t)(((insn >> 5) & 0x7ffff) << 2 | ((insn >> 29) & 3)), 21);
        ssol_reg_write(regs, rd, pc + (uint64_t)imm, 1);
        regs->pc = pc + 4;
        return SSOL_SIMULATED;
    }
    if (ssol_is_adrp(insn)) {
        int rd = insn & 0x1f;
        int64_t imm = ssol_sext((int64_t)(((insn >> 5) & 0x7ffff) << 2 | ((insn >> 29) & 3)), 21);
        ssol_reg_write(regs, rd, (pc & ~0xfffULL) + ((uint64_t)imm << 12), 1);
        regs->pc = pc + 4;
        return SSOL_SIMULATED;
    }
    if (ssol_is_ldrlit(insn)) {
        if ((insn >> 26) & 1) return SSOL_XOL; /* V=1: SIMD/FP literal -> XOL */
        int rt = insn & 0x1f;
        int opc = (insn >> 30) & 3; /* 0 = 32-bit, 1 = 64-bit, 2 = LDRSW */
        int64_t off = ssol_sext((int64_t)((insn >> 5) & 0x7ffff), 19) << 2;
        uintptr_t addr = (uintptr_t)(pc + (uint64_t)off);
        uint64_t val;
        if (opc == 1) val = ssol_rd64(addr);
        else if (opc == 2) val = (uint64_t)(int64_t)(int32_t)ssol_rd32(addr); /* LDRSW: sign-extend */
        else val = (uint64_t)ssol_rd32(addr);                                  /* 32-bit: zero-extend */
        ssol_reg_write(regs, rt, val, opc != 0);
        regs->pc = pc + 4;
        return SSOL_SIMULATED;
    }
    /* register (indirect) branches: target is a register holding an ORIGINAL address
     * (STRIP_PAC for this device's pointer-auth). LR stays original -> ART-intact. */
    if (ssol_is_br(insn)) {
        regs->pc = STRIP_PAC(ssol_reg_read(regs, (insn >> 5) & 0x1f, 1));
        return SSOL_SIMULATED;
    }
    if (ssol_is_blr(insn)) {
        regs->regs[30] = pc + 4;
        regs->pc = STRIP_PAC(ssol_reg_read(regs, (insn >> 5) & 0x1f, 1));
        return SSOL_SIMULATED;
    }
    if (ssol_is_ret(insn)) {
        regs->pc = STRIP_PAC(ssol_reg_read(regs, (insn >> 5) & 0x1f, 1));
        return SSOL_SIMULATED;
    }
    return SSOL_XOL; /* PC-independent (ALU/MOV/LDR-STR reg/NOP/atomics/PAC branches) */
}

/* ===================== SSOL single-step engine (P1b) =====================
 * uprobes' XOL trigger, driven by our UXN fault: for a PC-INDEPENDENT trapped
 * instruction we copy it to a per-thread scratch slot, set pc there, and arm a HW
 * single-step via the kernel's OWN exported primitives (user_enable_single_step +
 * a registered user step-hook -- exactly what uprobes does). After the one insn
 * runs at EL0, the software-step exception fires -> ssol_step_fn restores pc to the
 * original next instruction and disables stepping. UXN stays armed throughout, so
 * the next ORIGINAL instruction faults again -> the loop advances the stream with
 * the original code at its original address (ART-intact, no clone, no code/data).
 *
 * P1b-1 (this commit) wires the step primitive + a `selfstep` self-test only; the
 * full before_pf XOL dispatch is P1b-2. */

#define DBG_HOOK_HANDLED 0
#define DBG_HOOK_ERROR 1
struct kp_list_head {
    struct kp_list_head *next, *prev;
};
struct kp_step_hook {
    struct kp_list_head node; /* kernel-managed list node; zero-init */
    int (*fn)(struct pt_regs *regs, unsigned long esr);
};

/* per-thread SSOL context (keyed by tid, shhwbp slot-table style) */
#define MAX_SSOL_CTX 64
enum { SSOL_K_SELFSTEP = 1, SSOL_K_XOL = 2 };
struct ssol_ctx {
    volatile int active;
    int tid;
    int kind;
    uint64_t resume_pc; /* pc ssol_step_fn restores after the step (XOL: orig+4) */
    uint64_t xol_va;    /* scratch slot user VA (XOL) */
};
static struct ssol_ctx g_ctx[MAX_SSOL_CTX];
static struct kp_step_hook g_step_hook;
static volatile int g_step_registered = 0;
static volatile long g_step_fires = 0; /* total step exceptions we consumed */
static volatile long g_selfstep_armed = 0;
static volatile long g_selfstep_fired = 0;

/* SSOL region table (separate from g_pg[] clone regions -> zero risk to the
 * verified clone path). A region UXN-traps [page, page+npages) and routes every
 * fault through simulate (PC-relative) or XOL+single-step (PC-independent). P1
 * uses one region for the self-test. */
#define MAX_SSOL_RGN 16  /* trapped SSOL regions live at once (matches MAX_PG) */
#define MAX_SSOL_OV 16   /* hooked method entries per SSOL region (LSPlant groups many qc per page) */
struct ssol_rgn {
    volatile int active;
    int pid;            /* tgid gate */
    void *mm;           /* equality-only (future maps-hide), never dereferenced */
    uint64_t page;      /* region base */
    int npages;
    /* Multi-target override table (mirrors pghook's ov_off[]/ov_replace[]): one SSOL
     * region [page,page+npages) can host MAX_SSOL_OV hooked entries -- LSPlant hooks
     * ~20 qc, many sharing a code page. Published key-last / retired key-first via
     * ssol_set_ov, so a racing before_pf never sees a half-built entry. nov == 0 is a
     * pure pass-through region (ssoltest: no entry override, every insn just runs). */
    volatile int nov;
    volatile uint64_t ov_off[MAX_SSOL_OV];     /* region-relative entry byte offset; OV_NONE = inert */
    volatile uint64_t ov_replace[MAX_SSOL_OV]; /* entry override target = trampoline for ov_off[k] */
    volatile uint64_t ov_bk[MAX_SSOL_OV];      /* call-original `backup` VA (UNMAPPED) for ov_off[k]:
                                                * a fault here arms a one-shot bypass + redirects pc to
                                                * that entry -> body via SSOL */
    uint32_t *insns;      /* vmalloc'd snapshot, npages*1024 words (insn + literal pool) */
    uint64_t xol_kaddr;   /* kernel alias of the scratch page (write copied insns here) */
    uint64_t xol_va;      /* user VA of the scratch page (EL0 single-steps here) */
    uint64_t *ptep[MAX_RGN];
    uint64_t pte_orig[MAX_RGN];
    volatile long n_sim, n_xol, n_hook, n_orig;
};
static struct ssol_rgn g_ssol[MAX_SSOL_RGN];
static volatile int g_nssol = 0;

/* publish a new SSOL override key-last (replace + bk_va visible before the off key),
 * so a racing before_pf never matches an offset before its replacement/backup land. */
static inline void ssol_set_ov(struct ssol_rgn *s, int k, uint64_t off, uint64_t replace, uint64_t bk)
{
    s->ov_replace[k] = replace;
    s->ov_bk[k] = bk;
    asm volatile("dmb ishst" ::: "memory"); /* replace+bk visible before the key */
    s->ov_off[k] = off;
}

static void sync_icache(void *addr, unsigned long size); /* defined below; used by the XOL copy */

static struct ssol_ctx *ctx_by_tid(int tid)
{
    for (int i = 0; i < MAX_SSOL_CTX; i++)
        if (g_ctx[i].active && g_ctx[i].tid == tid) return &g_ctx[i];
    return 0;
}
static struct ssol_ctx *ctx_free(void)
{
    for (int i = 0; i < MAX_SSOL_CTX; i++)
        if (!g_ctx[i].active) return &g_ctx[i];
    return 0;
}

/* one-shot call-original bypass, keyed by (tid, entry VA): armed when a hook's bk_va
 * is hit, consumed at that hook's entry (the very next fault on the same thread). The
 * entry VA (not a region index) is the key, so a region hosting several hooked entries
 * bypasses exactly the one whose original is being called. */
static volatile int g_byp_tid[MAX_SSOL_CTX];        /* tid, 0 = empty slot */
static volatile uint64_t g_byp_entry[MAX_SSOL_CTX]; /* entry VA armed to bypass once for that tid */
static void byp_arm(int tid, uint64_t entry)
{
    for (int i = 0; i < MAX_SSOL_CTX; i++)
        if (g_byp_tid[i] == tid) { g_byp_entry[i] = entry; return; } /* re-arm existing */
    for (int i = 0; i < MAX_SSOL_CTX; i++)
        if (g_byp_tid[i] == 0) { g_byp_entry[i] = entry; g_byp_tid[i] = tid; return; }
}
static int byp_take(int tid, uint64_t entry) /* 1 + consume if armed for (tid,entry) */
{
    for (int i = 0; i < MAX_SSOL_CTX; i++)
        if (g_byp_tid[i] == tid && g_byp_entry[i] == entry) { g_byp_tid[i] = 0; return 1; }
    return 0;
}

/* registered user step-hook: fires on EVERY EL0 software-step exception (system
 * wide). If current isn't mid-SSOL we return DBG_HOOK_ERROR so the kernel handles
 * the step normally -- we never swallow a foreign stepper. */
static int ssol_step_fn(struct pt_regs *regs, unsigned long esr)
{
    (void)esr;
    if (!fn_task_pid_nr_ns) return DBG_HOOK_ERROR;
    int tid = fn_task_pid_nr_ns((void *)get_current(), PIDTYPE_PID, 0);
    struct ssol_ctx *c = ctx_by_tid(tid);
    if (!c) return DBG_HOOK_ERROR;
    g_step_fires++;
    if (c->kind == SSOL_K_XOL)
        regs->pc = c->resume_pc; /* resume original stream at orig+4 */
    else
        g_selfstep_fired++; /* SELFSTEP: just observe one step */
    if (fn_user_disable_single_step) fn_user_disable_single_step((void *)get_current());
    c->active = 0;
    return DBG_HOOK_HANDLED;
}

static int ssol_ensure_step_hook(void)
{
    if (g_step_registered) return 0;
    if (!fn_register_user_step_hook) return -1;
    g_step_hook.node.next = 0;
    g_step_hook.node.prev = 0;
    g_step_hook.fn = ssol_step_fn;
    fn_register_user_step_hook(&g_step_hook);
    g_step_registered = 1;
    return 0;
}
/* Teardown is just clearing ctxs. We DELIBERATELY do NOT call
 * unregister_user_step_hook here: it does synchronize_rcu(), and KernelPatch runs
 * BOTH the module exit (unload_module) AND every control command (module_control0)
 * INSIDE rcu_read_lock() -- so synchronize_rcu() would wait for the very read-side
 * section it is running in => guaranteed self-deadlock (observed: a live
 * `shctl unload shpte` HUNG the kernel, needing a physical reboot). There is no
 * KP-reachable context outside that rcu_read_lock from which to sync, and unload
 * frees the module memory immediately after exit() returns, so the hook genuinely
 * cannot be cleanly removed under this KP. Consequence + rule: the step hook stays
 * registered for the module's lifetime (cheap -- it only fires on EL0 software
 * steps, and returns DBG_HOOK_ERROR for non-SSOL steppers). The bootstrap NEVER
 * unloads (load;probe;bridge at boot), so production is unaffected. For DEV: NEVER
 * live-unload shpte -- REBOOT to reload (a reboot doesn't run exit()/sync). */
static void ssol_remove_step_hook(void)
{
    for (int i = 0; i < MAX_SSOL_CTX; i++) g_ctx[i].active = 0;
}

/* ---- do_page_fault before-callback: self-heal the UXN execute fault ----
 * do_page_fault(unsigned long far, unsigned long esr, struct pt_regs *regs) */
static void before_pf(hook_fargs3_t *fargs, void *udata)
{
    (void)udata;
    if (!g_armed && g_npg == 0 && g_nssol == 0) return;
    uint64_t far = fargs->arg0;
    uint64_t fpage = far & ~0xfffUL;
    struct pt_regs *regs = (struct pt_regs *)fargs->arg2;

    /* ---- single-page path (arm / redirect / redirectmap / pagehook) ----
     * cheap fast-path: page compare first, only then compute the faulting tgid
     * (do_page_fault runs for every fault system-wide while we're hooked). On a
     * page match with a mismatched tgid (same VA, different process) we fall
     * through to the multi-page scan rather than claiming the fault. */
    if (g_armed && fpage == g_target_page &&
        (!fn_task_pid_nr_ns ||
         fn_task_pid_nr_ns((void *)get_current(), PIDTYPE_TGID, 0) == g_target_pid)) {
        g_faults++;
        if (g_mode == MODE_REDIRECT_FIXED) {
            /* inline_hooker: route the target's entry to a fixed `replace` function
             * (LR untouched -> replace returns to the original caller); replace can
             * call the original via the ghost-clone `backup`. */
            regs->pc = g_redirect_fixed;
            g_redirects++;
        } else if ((g_mode == MODE_REDIRECT || g_mode == MODE_REDIRECT_MAP) && g_clone_page) {
            /* keep UXN set; reroute PC into the clone region. The target's .text is
             * never touched and every call re-faults+reroutes. With an offset_map,
             * recompiled instructions may have shifted, so map orig-insn-idx ->
             * recompiled-insn-idx; otherwise route to the same page offset. pagehook:
             * one function's entry routes to `replace` instead of the clone. */
            uint64_t poff = far & 0xfffUL;
            if (g_mode == MODE_REDIRECT_MAP && g_hook_replace && poff == g_hook_off) {
                regs->pc = g_hook_replace; /* hooked fn entry -> replacement */
            } else {
                uint64_t off = poff;
                if (g_mode == MODE_REDIRECT_MAP) {
                    uint32_t idx = (uint32_t)(off >> 2);
                    if (idx < (uint32_t)g_nmap) off = (uint64_t)g_offmap[idx] << 2;
                }
                regs->pc = g_clone_page + off;
            }
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
        return;
    }

    /* ---- multi-page hook table (pghook, RV-2 region slots) ----
     * Each slot UXN-traps a clean-bounded MULTI-PAGE region and routes it to one
     * whole-region clone. The faulting offset is REGION-relative (far - s->page), so
     * a function spanning a page is wholly in the clone and runs to its own RET. */
    if (g_npg > 0) {
        for (int i = 0; i < MAX_PG; i++) {
            struct pghook *s = &g_pg[i];
            if (!s->active) continue;
            if (fpage < s->page || fpage >= s->page + (uint64_t)s->npages * 0x1000UL) continue;
            if (fn_task_pid_nr_ns &&
                fn_task_pid_nr_ns((void *)get_current(), PIDTYPE_TGID, 0) != s->pid)
                continue; /* same VA in another process -> not our trap */
            uint64_t roff = far - s->page; /* region-relative byte offset */
            uint64_t rep = 0;
            for (int k = 0; k < MAX_OV; k++) /* inert slots hold OV_NONE -> never match roff */
                if (roff == s->ov_off[k]) { rep = s->ov_replace[k]; break; }
            if (rep) {
                regs->pc = rep; /* a hooked fn entry in this region -> its replacement */
            } else {
                uint64_t off = roff;
                uint32_t idx = (uint32_t)(off >> 2);
                if (s->offmap && idx < (uint32_t)s->nmap) off = (uint64_t)s->offmap[idx] << 2;
                regs->pc = s->clone + off; /* everything else runs from the clone */
            }
            s->redirects++;
            fargs->skip_origin = 1;
            fargs->ret = 0;
            return;
        }
    }

    /* ---- SSOL regions: advance the ORIGINAL instruction stream via simulate
     * (PC-relative) or XOL+single-step (PC-independent). No clone, no relocation ->
     * ART-intact, no code/data interleaving. UXN stays armed, so each original
     * instruction faults in turn. ---- */
    if (g_nssol > 0) {
        int tid = fn_task_pid_nr_ns ? fn_task_pid_nr_ns((void *)get_current(), PIDTYPE_PID, 0) : 0;
        int tgid = fn_task_pid_nr_ns ? fn_task_pid_nr_ns((void *)get_current(), PIDTYPE_TGID, 0) : 0;

        /* call-original dispatch: a hook's bk_va is the UNMAPPED VA handed to the hook
         * frontend as `backup`. When the original is invoked (ART jumps to bk_va) the
         * instruction fetch faults here -> arm a one-shot bypass for this thread+entry
         * and redirect pc to that hooked entry. The entry then faults, sees the bypass,
         * and runs the body via SSOL (hook skipped); x30 is untouched so the body RETs
         * to the real caller. Robust for the ART-invoke path, where LR cannot
         * distinguish a real call from a call-original (both arrive via ART invoke
         * stubs). Scan every region's whole override table. */
        for (int i = 0; i < MAX_SSOL_RGN; i++) {
            struct ssol_rgn *s = &g_ssol[i];
            if (!s->active) continue;
            if (s->pid && tgid != s->pid) continue;
            for (int k = 0; k < MAX_SSOL_OV; k++) {
                if (s->ov_off[k] == OV_NONE || !s->ov_bk[k] || far != s->ov_bk[k]) continue;
                uint64_t entry = s->page + s->ov_off[k];
                byp_arm(tid, entry);
                regs->pc = entry;
                s->n_orig++;
                fargs->skip_origin = 1;
                fargs->ret = 0;
                return;
            }
        }

        for (int i = 0; i < MAX_SSOL_RGN; i++) {
            struct ssol_rgn *s = &g_ssol[i];
            if (!s->active) continue;
            if (fpage < s->page || fpage >= s->page + (uint64_t)s->npages * 0x1000UL) continue;
            if (s->pid && tgid != s->pid) continue; /* same VA in another process -> not ours */
            uint64_t roff = far - s->page;
            uint32_t insn = s->insns[roff >> 2];

            /* hooked-fn entry: if this fault is at one of the region's hooked entries,
             * redirect to its trampoline -- UNLESS a one-shot call-original bypass is
             * armed for this thread+entry (set when that entry's bk_va was hit), in
             * which case run the body via SSOL instead. Inert slots hold OV_NONE, which
             * never equals a real region offset (roff < npages*0x1000). */
            for (int k = 0; k < MAX_SSOL_OV; k++) {
                if (s->ov_off[k] != roff) continue;
                if (byp_take(tid, far)) break; /* call-original: fall through to SSOL */
                regs->pc = s->ov_replace[k];   /* hook fires */
                s->n_hook++;
                fargs->skip_origin = 1;
                fargs->ret = 0;
                return;
            }

            /* PC-relative -> simulate in place (literal pool read from the snapshot) */
            g_rd_base = s->page;
            g_rd_insns = s->insns;
            g_rd_n = s->npages * 1024;
            if (ssol_simulate(regs, insn) == SSOL_SIMULATED) {
                s->n_sim++;
                fargs->skip_origin = 1;
                fargs->ret = 0;
                return; /* UXN stays set -> the next original insn faults again */
            }

            /* PC-independent -> XOL: copy the one insn to this thread's scratch slot,
             * set pc there, arm a single step (uprobes flow). ssol_step_fn restores
             * pc = far+4 after the one insn runs at EL0. */
            if (s->xol_kaddr && g_step_registered && fn_user_enable_single_step) {
                struct ssol_ctx *c = ctx_by_tid(tid);
                if (!c) c = ctx_free();
                if (c) {
                    int slot = (int)(c - g_ctx);
                    uint64_t koff = (uint64_t)slot * 8;
                    *(volatile uint32_t *)(s->xol_kaddr + koff) = insn;
                    *(volatile uint32_t *)(s->xol_kaddr + koff + 4) = 0xD4200000u; /* BRK #0 guard */
                    sync_icache((void *)(s->xol_kaddr + koff), 8);
                    c->tid = tid;
                    c->kind = SSOL_K_XOL;
                    c->resume_pc = far + 4;
                    c->xol_va = s->xol_va + koff;
                    c->active = 1;
                    regs->pc = s->xol_va + koff;
                    fn_user_enable_single_step((void *)get_current());
                    s->n_xol++;
                    fargs->skip_origin = 1;
                    fargs->ret = 0;
                    return;
                }
            }
            /* couldn't XOL (no ctx / no scratch): let the real fault surface (visible
             * failure) rather than silently spin on the UXN'd page. */
            return;
        }
    }
    /* not one of ours: let the real do_page_fault run */
}

/* shared do_page_fault hook lifecycle: single-page (arm_common) and multi-page
 * (do_pghook) both route through before_pf, so the hook is reference-counted by
 * (g_armed, g_npg) -- install on first arm, remove only when both are inactive. */
static int ensure_pf_hooked(char *p, char *e)
{
    if (g_pf_hooked) return 0;
    if (!g_addr_pf) {
        apps(p, e, "error: do_page_fault not resolved (run probe)\n");
        return -1;
    }
    hook_err_t he = hook_wrap3(g_addr_pf, (void *)before_pf, 0, 0);
    if (he != HOOK_NO_ERR) {
        apps(p, e, "error: hook_wrap3(do_page_fault) failed\n");
        return -1;
    }
    g_pf_hooked = 1;
    return 0;
}
static void maybe_unhook_pf(void)
{
    if (!g_armed && g_npg == 0 && g_pf_hooked && g_addr_pf) {
        hook_unwrap(g_addr_pf, (void *)before_pf, 0);
        g_pf_hooked = 0;
    }
}

/* ---- P4.1: hide the clone VMA from /proc/pid/{maps,smaps} ----
 * show_map / show_smap (struct seq_file *m, void *v): v is the vm_area_struct being
 * printed (smaps writes the same header line + per-VMA stats in one show() call).
 * before: snapshot m->count; after: if this VMA is our clone, rewind m->count
 * (dropping the whole just-written entry) + SEQ_SKIP, so it never appears. */
static void before_showmap(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    if (!g_maps_hooked && !g_smaps_hooked) return;
    void *m = (void *)fargs->arg0;
    fargs->local.data0 = *(volatile uint64_t *)((char *)m + SEQ_COUNT_OFF);
}
/* shared core: returns 1 (and rewinds the seq entry) if `vma` is one of our clones.
 * Gate on the vma's OWNER mm (not the reader): hides the clone whether the host scans
 * its own /proc/self/{maps,smaps} OR an external process scans /proc/<host>/..., while a
 * DIFFERENT process that merely shares the same library VA (zygote-forked apps all map
 * libart around here) keeps its line -- no cross-process maps corruption. */
static int maps_hide_vma(hook_fargs2_t *fargs)
{
    void *vma = (void *)fargs->arg1;
    if (!vma) return 0;
    uint64_t vm_start = *(volatile uint64_t *)((char *)vma + VMA_START_OFF);

    int hit = 0;
    /* legacy single-page redirect clone (manual `hidemaps`, P4.1 demo) */
    if (g_hide_page && vm_start == g_hide_page) hit = 1;
    /* auto-hide: any active pghook region clone. The hide-set IS the g_pg[] table --
     * a clone is hidden the moment its region is armed and revealed when it disarms.
     * Match by RANGE (clone within [vm_start,vm_end)), NOT vm_start==clone: the kernel
     * MERGES an anon r-xp clone with an adjacent anon r-xp VMA, so the merged VMA's start
     * can sit a page below the registered clone addr -- an exact-start match would leak the
     * whole merged VMA (the residual S2 anon-r-xp the in-app probe flags). The containing VMA
     * is all-ours anon r-xp (nothing legit is anon r-xp under W^X), so hiding it whole is safe. */
    if (!hit && g_npg > 0) {
        void *vmm = *(void *volatile *)((char *)vma + VMA_VM_MM_OFF);
        uint64_t vm_end = *(volatile uint64_t *)((char *)vma + VMA_END_OFF);
        for (int i = 0; i < MAX_PG; i++) {
            struct pghook *s = &g_pg[i];
            if (!s->active || !s->clone) continue;
            if ((uint64_t)s->clone < vm_start || (uint64_t)s->clone >= vm_end) continue;
            if (s->mm && vmm != s->mm) continue; /* vma must belong to the host's mm */
            hit = 1;
            break;
        }
    }
    /* general hide-set (e.g. the LSPlant trampoline pool), mm-gated like the clones */
    if (!hit && g_nhide > 0) {
        void *vmm = *(void *volatile *)((char *)vma + VMA_VM_MM_OFF);
        for (int i = 0; i < MAX_HIDE; i++) {
            if (g_hide[i].page != vm_start || g_hide[i].mm != vmm) continue;
            hit = 1;
            break;
        }
    }
    if (!hit) return 0;

    void *m = (void *)fargs->arg0;
    *(volatile uint64_t *)((char *)m + SEQ_COUNT_OFF) = fargs->local.data0; /* rewind */
    *(volatile uint64_t *)((char *)m + SEQ_PAD_OFF) = 0;                    /* pad_until=0 */
    fargs->ret = SEQ_SKIP;
    return 1;
}
static void after_showmap(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    if (!g_maps_hooked) return;
    if (maps_hide_vma(fargs)) g_maps_hidden++;
}
static void after_showsmap(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    if (!g_smaps_hooked) return;
    if (maps_hide_vma(fargs)) g_smaps_hidden++;
}

/* {show_map, show_smap} hide-hook lifecycle, ref-counted by (g_npg, g_hide_page):
 * install on the first armed pghook region (or manual hidemaps), remove only when the
 * last region disarms AND no manual hidemaps is active. Runs in the sleepable
 * supercall/bridge context (same as do_pghook's ensure_pf_hooked), so inline-patching
 * is safe. smaps is best-effort: if show_smap won't resolve/hook, maps is still hidden. */
static int ensure_maps_hooked(void)
{
    if (g_maps_hooked) return 0;
    if (!g_addr_show_map) g_addr_show_map = (void *)kallsyms_lookup_name("show_map");
    if (!g_addr_show_map) return -1;
    if (hook_wrap2(g_addr_show_map, (void *)before_showmap, (void *)after_showmap, 0) != HOOK_NO_ERR)
        return -1;
    g_maps_hooked = 1;
    /* also hide from /proc/pid/smaps (same VMA, same callbacks) -- best effort */
    if (!g_smaps_hooked) {
        if (!g_addr_show_smap) g_addr_show_smap = (void *)kallsyms_lookup_name("show_smap");
        if (g_addr_show_smap &&
            hook_wrap2(g_addr_show_smap, (void *)before_showmap, (void *)after_showsmap, 0) == HOOK_NO_ERR)
            g_smaps_hooked = 1;
    }
    return 0;
}
static void maybe_unhook_maps(void)
{
    if (g_npg != 0 || g_hide_page || g_nhide != 0) return; /* still needed */
    if (g_smaps_hooked && g_addr_show_smap) {
        hook_unwrap(g_addr_show_smap, (void *)before_showmap, (void *)after_showsmap);
        g_smaps_hooked = 0;
    }
    if (g_maps_hooked && g_addr_show_map) {
        hook_unwrap(g_addr_show_map, (void *)before_showmap, (void *)after_showmap);
        g_maps_hooked = 0;
    }
}

/* ---- TracerPid spoof: rewrite "TracerPid:\t<n>" -> "TracerPid:\t0" in the
 * /proc/pid/status output (length-preserving), so anti-debug checks see 0. ---- */
static void before_status(hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    if (!g_tracer_hooked) return;
    void *m = (void *)fargs->arg0;
    fargs->local.data0 = *(volatile uint64_t *)((char *)m + SEQ_COUNT_OFF);
}
static void after_status(hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    if (!g_tracer_hooked) return;
    void *m = (void *)fargs->arg0;
    char *buf = *(char **)((char *)m + 0); /* seq_file.buf @ +0 */
    if (!buf) return;
    uint64_t start = fargs->local.data0;
    uint64_t end = *(volatile uint64_t *)((char *)m + SEQ_COUNT_OFF);
    static const char pat[] = "TracerPid:";
    for (uint64_t i = start; i + 10 <= end; i++) {
        int m2 = 1;
        for (int k = 0; k < 10; k++)
            if (buf[i + k] != pat[k]) {
                m2 = 0;
                break;
            }
        if (!m2) continue;
        uint64_t j = i + 10;
        while (j < end && (buf[j] == '\t' || buf[j] == ' ')) j++;
        int first = 1;
        while (j < end && buf[j] >= '0' && buf[j] <= '9') {
            buf[j] = first ? '0' : ' '; /* "12345" -> "0    " (reader parses 0) */
            first = 0;
            j++;
        }
        g_tracer_spoofed++;
        break;
    }
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
    if (!g_addr_show_map) g_addr_show_map = (void *)kallsyms_lookup_name("show_map");
    if (!g_addr_show_smap) g_addr_show_smap = (void *)kallsyms_lookup_name("show_smap");
    if (!g_addr_status) g_addr_status = (void *)kallsyms_lookup_name("proc_pid_status");
    if (!fn_apply) fn_apply = (void *)kallsyms_lookup_name("apply_to_page_range");
    if (!fn_vmalloc) fn_vmalloc = (void *)kallsyms_lookup_name("vmalloc");
    if (!fn_vfree) fn_vfree = (void *)kallsyms_lookup_name("vfree");
    if (!fn_vmalloc_to_pfn) fn_vmalloc_to_pfn = (void *)kallsyms_lookup_name("vmalloc_to_pfn");
    if (!fn_reg_hwbp) fn_reg_hwbp = (void *)kallsyms_lookup_name("register_user_hw_breakpoint");
    if (!fn_unreg_hwbp) fn_unreg_hwbp = (void *)kallsyms_lookup_name("unregister_hw_breakpoint");
    if (!fn_task_work_add) fn_task_work_add = (void *)kallsyms_lookup_name("task_work_add");
    if (!fn_register_user_step_hook)
        fn_register_user_step_hook = (void *)kallsyms_lookup_name("register_user_step_hook");
    if (!fn_unregister_user_step_hook)
        fn_unregister_user_step_hook = (void *)kallsyms_lookup_name("unregister_user_step_hook");
    if (!fn_user_enable_single_step)
        fn_user_enable_single_step = (void *)kallsyms_lookup_name("user_enable_single_step");
    if (!fn_user_disable_single_step)
        fn_user_disable_single_step = (void *)kallsyms_lookup_name("user_disable_single_step");
}

/* HWBP overflow handler: reroute the trapped target entry to `replace`. No perf
 * calls here (would wedge); just set PC. Backup is a ghost clone, so calling the
 * original from `replace` does NOT re-trip this breakpoint (no livelock). */
static void hwbp_handler(void *bp, void *data, struct pt_regs *regs)
{
    (void)bp;
    (void)data;
    if (!g_hwbp_armed || !g_hwbp_replace) return;
    regs->pc = g_hwbp_replace;
    g_hw_redirects++;
}

/* run in the target task's own context (sleepable): the perf register/unregister */
static void tw_hwinstall(struct kp_callback_head *h)
{
    (void)h;
    void *bp = fn_reg_hwbp(&g_hwbp_attr, (void *)hwbp_handler, 0, g_hwbp_task);
    if (is_err_or_null(bp)) {
        g_hwbp = 0;
        logke("shpte: hwbp register failed ret=%llx\n", (unsigned long long)bp);
        return;
    }
    g_hwbp = bp;
    logki("shpte: hwbp installed addr=%llx -> replace=%llx\n", (unsigned long long)g_hwbp_attr.bp_addr,
          (unsigned long long)g_hwbp_replace);
}
static void tw_hwremove(struct kp_callback_head *h)
{
    (void)h;
    if (g_hwbp && fn_unreg_hwbp) {
        fn_unreg_hwbp(g_hwbp);
        g_hwbp = 0;
    }
    logki("shpte: hwbp removed redirects=%ld\n", g_hw_redirects);
}

/* apply_to_page_range callback: write a hand-crafted PTE value (*data) */
static int inject_cb(void *ptep, unsigned long addr, void *data)
{
    (void)addr;
    *(volatile uint64_t *)ptep = *(uint64_t *)data;
    return 0;
}

/* make freshly-written code visible to EL0 execution: clean D-cache to PoU +
 * invalidate I-cache (PIPT, so by the kernel VA covers the user mapping too). */
static void sync_icache(void *addr, unsigned long size)
{
    unsigned long s = (unsigned long)addr & ~63UL;
    unsigned long en = (unsigned long)addr + size;
    for (unsigned long a = s; a < en; a += 64) asm volatile("dc cvau, %0" ::"r"(a) : "memory");
    asm volatile("dsb ish" ::: "memory");
    for (unsigned long a = s; a < en; a += 64) asm volatile("ic ivau, %0" ::"r"(a) : "memory");
    asm volatile("dsb ish\nisb" ::: "memory");
}

/* P4.2: inject a kernel page at a no-VMA user VA. Attributes are copied from an
 * existing user page (template_va) so memory type/AP/SH/AttrIndx/UXN exactly
 * match a known-good page -- no hard-coded MAIR index. The page is mapped to the
 * MMU but has NO VMA, so it is invisible to /proc/maps and mincore. */
static long do_ghosttest(uint64_t pid, uint64_t ghost_va, uint64_t template_va, char *p, char *e)
{
    resolve_syms();
    if (!fn_vmalloc || !fn_vfree || !fn_vmalloc_to_pfn || !fn_apply || !fn_apply_existing ||
        !fn_get_task_mm || !fn_mmput || !fn_find_get_task_by_vpid) {
        apps(p, e, "error: symbols not resolved (run probe)\n");
        return -1;
    }
    if (g_ghost_kaddr) {
        apps(p, e, "error: ghost already active; ghostfree first\n");
        return -1;
    }
    ghost_va &= ~0xFFFUL;

    void *task = fn_find_get_task_by_vpid((int)pid);
    if (is_err_or_null(task)) {
        apps(p, e, "error: task not found\n");
        return -1;
    }
    void *mm = fn_get_task_mm(task);
    if (is_err_or_null(mm)) {
        apps(p, e, "error: no mm\n");
        return -1;
    }

    /* 1. ghost_va must currently have NO valid leaf PTE (don't clobber a live map) */
    struct pte_out chk;
    chk.n = 0;
    chk.val = 0;
    fn_apply_existing(mm, ghost_va, 0x1000, (void *)pte_cb, &chk);
    if (chk.n > 0 && (chk.val & PTE_VALID)) {
        fn_mmput(mm);
        apps(p, e, "error: ghost_va already mapped; pick a free VA\n");
        return -1;
    }
    /* 2. template attributes from an existing mapped user page */
    struct pte_out tpl;
    tpl.n = 0;
    tpl.val = 0;
    fn_apply_existing(mm, template_va & ~0xFFFUL, 0x1000, (void *)pte_cb, &tpl);
    if (tpl.n == 0 || !(tpl.val & PTE_VALID)) {
        fn_mmput(mm);
        apps(p, e, "error: template_va not mapped\n");
        return -1;
    }
    uint64_t attrs = tpl.val & ~PFN_MASK;

    /* 3. allocate a kernel page (vmalloc -> resolvable PFN), stamp the magic */
    void *kaddr = fn_vmalloc(0x1000);
    if (is_err_or_null(kaddr)) {
        fn_mmput(mm);
        apps(p, e, "error: vmalloc failed\n");
        return -1;
    }
    *(volatile uint64_t *)kaddr = GHOST_MAGIC;
    *(volatile uint64_t *)((char *)kaddr + 8) = GHOST_MAGIC;
    asm volatile("dsb ish" ::: "memory");

    /* 4. PFN of the vmalloc page -> PTE value with template attrs */
    uint64_t pfn = fn_vmalloc_to_pfn(kaddr);
    uint64_t pte_val = ((pfn << 12) & PFN_MASK) | attrs;

    /* 5. inject the PTE (allocates page tables for ghost_va), flush TLB */
    int ir = fn_apply(mm, ghost_va, 0x1000, (void *)inject_cb, &pte_val);
    flush_tlb_all();
    fn_mmput(mm);
    if (ir) {
        fn_vfree(kaddr);
        apps(p, e, "error: apply_to_page_range failed\n");
        return -1;
    }

    g_ghost_kaddr = kaddr;
    g_ghost_va = ghost_va;
    g_ghost_pid = (int)pid;

    p = apps(p, e, "ok: ghost injected va=");
    p = apphex(p, e, ghost_va);
    p = apps(p, e, " pa=");
    p = apphex(p, e, (pfn << 12) & PFN_MASK);
    p = apps(p, e, " pte=");
    p = apphex(p, e, pte_val);
    p = apps(p, e, " magic=");
    p = apphex(p, e, GHOST_MAGIC);
    apps(p, e, " (no VMA: invisible to maps/mincore)\n");
    return 0;
}

static long do_ghostfree(char *p, char *e)
{
    if (!g_ghost_kaddr) {
        apps(p, e, "error: no ghost active\n");
        return -1;
    }
    /* clear the injected PTE first (so nothing references the page), then free */
    void *task = fn_find_get_task_by_vpid(g_ghost_pid);
    if (!is_err_or_null(task)) {
        void *mm = fn_get_task_mm(task);
        if (!is_err_or_null(mm)) {
            uint64_t zero = 0;
            fn_apply_existing(mm, g_ghost_va, 0x1000, (void *)inject_cb, &zero);
            flush_tlb_all();
            fn_mmput(mm);
        }
    }
    fn_vfree(g_ghost_kaddr);
    g_ghost_kaddr = 0;
    g_ghost_va = 0;
    g_ghost_pid = 0;
    apps(p, e, "ok: ghost freed (PTE cleared + page released)\n");
    return 0;
}

static long arm_common(uint64_t pid, uint64_t addr, int mode, uint64_t clone, char *p, char *e); /* fwd */

/* P4.2 step B: place the (position-independent) DBI clone into a VMA-less ghost
 * page and redirect the UXN-trapped function there. The clone then executes from
 * memory the OS doesn't know exists -- invisible to maps AND mincore, with no
 * maps-hide hook. Teardown = disarm (restore UXN/unhook) + ghostfree. */
static long do_ghostredirect(uint64_t pid, uint64_t func, uint64_t ghost_va, uint64_t clonebytes,
                             uint64_t nins_clone, uint64_t mapaddr, uint64_t ninsn, uint64_t template_va,
                             char *p, char *e)
{
    resolve_syms();
    if (!fn_vmalloc || !fn_vfree || !fn_vmalloc_to_pfn || !fn_apply || !fn_apply_existing ||
        !fn_access_process_vm || !fn_get_task_mm || !fn_mmput || !fn_find_get_task_by_vpid) {
        apps(p, e, "error: symbols not resolved (run probe)\n");
        return -1;
    }
    if (g_armed || g_ghost_kaddr) {
        apps(p, e, "error: busy; disarm + ghostfree first\n");
        return -1;
    }
    if (nins_clone == 0 || nins_clone * 4 > 0x1000) {
        apps(p, e, "error: clone must fit one page\n");
        return -1;
    }
    if (ninsn == 0 || ninsn > OFFMAP_MAX) {
        apps(p, e, "error: ninsn out of range\n");
        return -1;
    }
    ghost_va &= ~0xFFFUL;

    void *task = fn_find_get_task_by_vpid((int)pid);
    if (is_err_or_null(task)) {
        apps(p, e, "error: task not found\n");
        return -1;
    }
    void *mm = fn_get_task_mm(task);
    if (is_err_or_null(mm)) {
        apps(p, e, "error: no mm\n");
        return -1;
    }
    struct pte_out chk;
    chk.n = 0;
    chk.val = 0;
    fn_apply_existing(mm, ghost_va, 0x1000, (void *)pte_cb, &chk);
    if (chk.n > 0 && (chk.val & PTE_VALID)) {
        fn_mmput(mm);
        apps(p, e, "error: ghost_va already mapped\n");
        return -1;
    }
    struct pte_out tpl;
    tpl.n = 0;
    tpl.val = 0;
    fn_apply_existing(mm, template_va & ~0xFFFUL, 0x1000, (void *)pte_cb, &tpl);
    if (tpl.n == 0 || !(tpl.val & PTE_VALID)) {
        fn_mmput(mm);
        apps(p, e, "error: template_va not mapped (need an exec page)\n");
        return -1;
    }
    uint64_t attrs = tpl.val & ~PFN_MASK;

    /* vmalloc the ghost page, copy the clone bytes in, sync I-cache for exec */
    void *kaddr = fn_vmalloc(0x1000);
    if (is_err_or_null(kaddr)) {
        fn_mmput(mm);
        apps(p, e, "error: vmalloc failed\n");
        return -1;
    }
    int want = (int)(nins_clone * 4);
    if (fn_access_process_vm(task, clonebytes, kaddr, want, 0) != want) {
        fn_vfree(kaddr);
        fn_mmput(mm);
        apps(p, e, "error: copy clone bytes failed\n");
        return -1;
    }
    sync_icache(kaddr, 0x1000);

    uint64_t pfn = fn_vmalloc_to_pfn(kaddr);
    uint64_t pte_val = ((pfn << 12) & PFN_MASK) | attrs;
    int ir = fn_apply(mm, ghost_va, 0x1000, (void *)inject_cb, &pte_val);
    flush_tlb_all();
    fn_mmput(mm);
    if (ir) {
        fn_vfree(kaddr);
        apps(p, e, "error: apply_to_page_range failed\n");
        return -1;
    }
    g_ghost_kaddr = kaddr;
    g_ghost_va = ghost_va;
    g_ghost_pid = (int)pid;

    /* read the offset_map, then arm the UXN redirect to the ghost VA */
    if (fn_access_process_vm(task, mapaddr, g_offmap, (int)(ninsn * 4), 0) != (int)(ninsn * 4)) {
        apps(p, e, "error: read offset_map failed (ghost left; ghostfree)\n");
        return -1;
    }
    g_nmap = (int)ninsn;
    return arm_common(pid, func, MODE_REDIRECT_MAP, ghost_va, p, e);
}

/* alloc a ghost page, copy `nbytes` clone bytes from the target's `clonebytes`,
 * sync I-cache, inject a no-VMA PTE at ghost_va (attrs from template_va). Sets
 * g_ghost_*. Caller holds task+mm and does mmput. Returns 0 or <0. */
static int ghost_inject(int pid, void *task, void *mm, uint64_t ghost_va, uint64_t clonebytes, int nbytes,
                        uint64_t template_va)
{
    if (g_ghost_kaddr) return -1;
    if (nbytes <= 0 || nbytes > 0x1000) return -2;
    ghost_va &= ~0xFFFUL;
    struct pte_out chk;
    chk.n = 0;
    chk.val = 0;
    fn_apply_existing(mm, ghost_va, 0x1000, (void *)pte_cb, &chk);
    if (chk.n > 0 && (chk.val & PTE_VALID)) return -3;
    struct pte_out tpl;
    tpl.n = 0;
    tpl.val = 0;
    fn_apply_existing(mm, template_va & ~0xFFFUL, 0x1000, (void *)pte_cb, &tpl);
    if (tpl.n == 0 || !(tpl.val & PTE_VALID)) return -4;
    uint64_t attrs = tpl.val & ~PFN_MASK;
    void *kaddr = fn_vmalloc(0x1000);
    if (is_err_or_null(kaddr)) return -5;
    if (fn_access_process_vm(task, clonebytes, kaddr, nbytes, 0) != nbytes) {
        fn_vfree(kaddr);
        return -6;
    }
    sync_icache(kaddr, 0x1000);
    uint64_t pfn = fn_vmalloc_to_pfn(kaddr);
    uint64_t pte_val = ((pfn << 12) & PFN_MASK) | attrs;
    if (fn_apply(mm, ghost_va, 0x1000, (void *)inject_cb, &pte_val)) {
        fn_vfree(kaddr);
        return -7;
    }
    flush_tlb_all();
    g_ghost_kaddr = kaddr;
    g_ghost_va = ghost_va;
    g_ghost_pid = pid;
    return 0;
}

/* inline_hooker primitive (for LSPlant): route `target`'s entry to `replace`, and
 * stash a ghost clone of `target` at ghost_va as the `backup` the caller can call
 * to run the original. target.text is never modified; backup lives in VMA-less
 * memory. Teardown = disarm + ghostfree. */
static long do_hookto(uint64_t pid, uint64_t target, uint64_t replace, uint64_t clonebytes,
                      uint64_t nclone, uint64_t template_va, uint64_t ghost_va, char *p, char *e)
{
    resolve_syms();
    if (!fn_vmalloc || !fn_vfree || !fn_vmalloc_to_pfn || !fn_apply || !fn_apply_existing ||
        !fn_access_process_vm || !fn_get_task_mm || !fn_mmput || !fn_find_get_task_by_vpid || !g_addr_pf ||
        !fn_task_pid_nr_ns) {
        apps(p, e, "error: symbols not resolved (run probe)\n");
        return -1;
    }
    if (g_armed || g_ghost_kaddr) {
        apps(p, e, "error: busy; disarm + ghostfree first\n");
        return -1;
    }
    if (nclone == 0 || nclone * 4 > 0x1000) {
        apps(p, e, "error: backup clone must fit one page\n");
        return -1;
    }
    void *task = fn_find_get_task_by_vpid((int)pid);
    if (is_err_or_null(task)) {
        apps(p, e, "error: task not found\n");
        return -1;
    }
    void *mm = fn_get_task_mm(task);
    if (is_err_or_null(mm)) {
        apps(p, e, "error: no mm\n");
        return -1;
    }
    int gr = ghost_inject((int)pid, task, mm, ghost_va, clonebytes, (int)(nclone * 4), template_va);
    fn_mmput(mm);
    if (gr) {
        p = apps(p, e, "error: ghost backup inject failed rc=");
        p = appdec(p, e, gr);
        apps(p, e, "\n");
        return -1;
    }
    g_redirect_fixed = replace;
    long rc = arm_common(pid, target, MODE_REDIRECT_FIXED, 0, p, e);
    /* append the backup pointer after arm_common's message (buf is zero-filled) */
    char *q = p;
    while (*q) q++;
    q = apps(q, e, "backup=");
    q = apphex(q, e, g_ghost_va);
    apps(q, e, " (call backup to run original)\n");
    return rc;
}

/* HWBP variant of hookto: traps ONLY the target's entry instruction (per-thread
 * hardware breakpoint), so functions sharing the target's page are untouched --
 * the correct primitive for real libart functions (LSPlant inline_hooker). The
 * perf register is deferred to the target's own context via task_work. backup is
 * a ghost clone, as in hookto. Teardown = hwunhook + ghostfree. */
static long do_hwhookto(uint64_t pid, uint64_t target, uint64_t replace, uint64_t clonebytes,
                        uint64_t nclone, uint64_t template_va, uint64_t ghost_va, char *p, char *e)
{
    resolve_syms();
    if (!fn_reg_hwbp || !fn_unreg_hwbp || !fn_task_work_add || !fn_vmalloc || !fn_vfree ||
        !fn_vmalloc_to_pfn || !fn_apply || !fn_apply_existing || !fn_access_process_vm || !fn_get_task_mm ||
        !fn_mmput || !fn_find_get_task_by_vpid) {
        apps(p, e, "error: symbols not resolved (run probe)\n");
        return -1;
    }
    if (g_hwbp_armed || g_hwbp || g_ghost_kaddr) {
        apps(p, e, "error: busy; hwunhook + ghostfree first\n");
        return -1;
    }
    if (nclone == 0 || nclone * 4 > 0x1000) {
        apps(p, e, "error: backup clone must fit one page\n");
        return -1;
    }
    void *task = fn_find_get_task_by_vpid((int)pid);
    if (is_err_or_null(task)) {
        apps(p, e, "error: task not found\n");
        return -1;
    }
    void *mm = fn_get_task_mm(task);
    if (is_err_or_null(mm)) {
        apps(p, e, "error: no mm\n");
        return -1;
    }
    int gr = ghost_inject((int)pid, task, mm, ghost_va, clonebytes, (int)(nclone * 4), template_va);
    fn_mmput(mm);
    if (gr) {
        p = apps(p, e, "error: ghost backup inject failed rc=");
        p = appdec(p, e, gr);
        apps(p, e, "\n");
        return -1;
    }

    char *z = (char *)&g_hwbp_attr;
    for (unsigned i = 0; i < sizeof(g_hwbp_attr); i++) z[i] = 0;
    g_hwbp_attr.type = PERF_TYPE_BREAKPOINT;
    g_hwbp_attr.size = sizeof(g_hwbp_attr);
    g_hwbp_attr.sample_period = 1;
    g_hwbp_attr.flags = ATTR_PINNED | ATTR_EXCLUDE_KERNEL | ATTR_EXCLUDE_HV;
    g_hwbp_attr.bp_type = HW_BREAKPOINT_X;
    g_hwbp_attr.bp_addr = target;
    g_hwbp_attr.bp_len = HW_BREAKPOINT_LEN_4;
    g_hwbp_task = task; /* leaked ref keeps task alive for the bp */
    g_hwbp_replace = replace;
    g_hwbp = 0;
    g_hw_redirects = 0;
    g_hwbp_armed = 1;

    g_hwbp_tw_install.next = 0;
    g_hwbp_tw_install.func = tw_hwinstall;
    if (fn_task_work_add(task, &g_hwbp_tw_install, TWA_RESUME)) {
        g_hwbp_armed = 0;
        apps(p, e, "error: task_work_add(hwinstall) failed\n");
        return -1;
    }
    p = apps(p, e, "ok: hwhookto queued target=");
    p = apphex(p, e, target);
    p = apps(p, e, " -> replace=");
    p = apphex(p, e, replace);
    p = apps(p, e, " backup=");
    p = apphex(p, e, g_ghost_va);
    apps(p, e, " (HWBP: page-neighbors untouched)\n");
    return 0;
}

static long do_hwunhook(char *p, char *e)
{
    if (!g_hwbp_armed && !g_hwbp) {
        apps(p, e, "error: hwbp not armed\n");
        return -1;
    }
    g_hwbp_armed = 0;
    if (g_hwbp_task && fn_task_work_add) {
        g_hwbp_tw_remove.next = 0;
        g_hwbp_tw_remove.func = tw_hwremove;
        fn_task_work_add(g_hwbp_task, &g_hwbp_tw_remove, TWA_RESUME);
    }
    p = apps(p, e, "ok: queued hwunhook, redirects=");
    p = appdec(p, e, g_hw_redirects);
    apps(p, e, " (then ghostfree)\n");
    g_hwbp_task = 0;
    g_hwbp_replace = 0;
    return 0;
}

static long do_hidemaps(uint64_t page, char *p, char *e)
{
    resolve_syms();
    if (!g_addr_show_map) {
        apps(p, e, "error: show_map not resolved\n");
        return -1;
    }
    g_hide_page = page ? (page & ~0xFFFUL) : g_clone_page;
    if (!g_hide_page) {
        apps(p, e, "error: no page given and no active clone\n");
        return -1;
    }
    if (ensure_maps_hooked() != 0) {
        g_hide_page = 0;
        apps(p, e, "error: hook_wrap2(show_map) failed\n");
        return -1;
    }
    p = apps(p, e, "ok: hiding vma vm_start=");
    p = apphex(p, e, g_hide_page);
    apps(p, e, " from /proc/*/maps\n");
    return 0;
}

static long do_unhidemaps(char *p, char *e)
{
    /* drop only the manual single-page hide; keep the hook installed if pghook
     * regions are still auto-hiding (maybe_unhook_maps refcounts on g_npg) */
    g_hide_page = 0;
    maybe_unhook_maps();
    p = apps(p, e, "ok: maps unhidden, hidden_count=");
    p = appdec(p, e, g_maps_hidden);
    if (g_maps_hooked) apps(p, e, " (hook kept: pghook regions still hidden)");
    apps(p, e, "\n");
    return 0;
}

/* hidergn <pid> <addr>: add the page containing `addr` (in pid's mm) to the general hide-set,
 * so an in-process maps/smaps scan never sees it. Used by the glue to hide the LSPlant
 * trampoline pool (rwxp anon). mm-gated like the clone hide; auto-cleared when the process is
 * GC'd (gc_dead_slots_locked). */
static long do_hidergn(uint64_t pid, uint64_t addr, char *p, char *e)
{
    resolve_syms();
    if (!fn_find_get_task_by_vpid || !fn_get_task_mm || !fn_mmput) {
        apps(p, e, "error: symbols not resolved\n");
        return -1;
    }
    void *task = fn_find_get_task_by_vpid((int)pid);
    if (is_err_or_null(task)) {
        apps(p, e, "error: task not found\n");
        return -1;
    }
    void *mm = fn_get_task_mm(task);
    if (is_err_or_null(mm)) {
        apps(p, e, "error: no mm\n");
        return -1;
    }
    fn_mmput(mm); /* pointer used for equality only, never dereferenced */
    uint64_t page = addr & ~0xFFFUL;
    for (int i = 0; i < MAX_HIDE; i++)
        if (g_hide[i].mm == mm && g_hide[i].page == page) {
            apps(p, e, "ok: hidergn already present\n");
            return 0;
        }
    int slot = -1;
    for (int i = 0; i < MAX_HIDE; i++)
        if (g_hide[i].mm == 0) {
            slot = i;
            break;
        }
    if (slot < 0) {
        apps(p, e, "error: hide-set full\n");
        return -1;
    }
    g_hide[slot].mm = mm;
    g_hide[slot].page = page;
    g_nhide++;
    ensure_maps_hooked(); /* best-effort: arm show_map/show_smap so the hide takes effect */
    p = apps(p, e, "ok: hidergn page=");
    p = apphex(p, e, page);
    p = apps(p, e, " nhide=");
    p = appdec(p, e, g_nhide);
    apps(p, e, "\n");
    return 0;
}

static long do_hidetracer(char *p, char *e)
{
    resolve_syms();
    if (!g_addr_status) {
        apps(p, e, "error: proc_pid_status not resolved\n");
        return -1;
    }
    if (!g_tracer_hooked) {
        if (hook_wrap4(g_addr_status, (void *)before_status, (void *)after_status, 0) != HOOK_NO_ERR) {
            apps(p, e, "error: hook_wrap4(proc_pid_status) failed\n");
            return -1;
        }
        g_tracer_hooked = 1;
    }
    apps(p, e, "ok: TracerPid spoof on (all /proc/*/status show 0)\n");
    return 0;
}

static long do_unhidetracer(char *p, char *e)
{
    if (g_tracer_hooked && g_addr_status) {
        hook_unwrap(g_addr_status, (void *)before_status, (void *)after_status);
        g_tracer_hooked = 0;
    }
    p = apps(p, e, "ok: TracerPid spoof off, spoofed=");
    p = appdec(p, e, g_tracer_spoofed);
    apps(p, e, "\n");
    return 0;
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
    if (ensure_pf_hooked(p, e) != 0) {
        g_ptep = 0;
        return -1;
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
    } else if (mode == MODE_REDIRECT_FIXED) {
        p = apps(p, e, " mode=REDIRECT_FIXED replace=");
        p = apphex(p, e, g_redirect_fixed);
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

/* pagehook: whole-page UXN hook of ONE function that may share its page with
 * others. The whole page is recompiled into `clone` (offmap); we UXN-trap the
 * page and route every fault into the clone, EXCEPT the hooked function's entry
 * (page+target_off) which routes to `replace`. The faithful clone copy of the
 * target (clone + offmap[target_off/4]*4) is the `backup` for calling the original.
 * This is the process-wide, page-neighbor-safe inline hook for real libart funcs. */
static long do_pagehook(uint64_t pid, uint64_t page, uint64_t clone, uint64_t mapaddr, uint64_t ninsn,
                        uint64_t target_off, uint64_t replace, char *p, char *e)
{
    resolve_syms();
    if (!fn_access_process_vm || !fn_find_get_task_by_vpid) {
        apps(p, e, "error: symbols not resolved (run probe)\n");
        return -1;
    }
    if (ninsn == 0 || ninsn > OFFMAP_MAX || (target_off & 3) || target_off >= 0x1000) {
        apps(p, e, "error: bad ninsn/target_off\n");
        return -1;
    }
    void *task = fn_find_get_task_by_vpid((int)pid);
    if (is_err_or_null(task)) {
        apps(p, e, "error: task not found\n");
        return -1;
    }
    int want = (int)(ninsn * 4);
    if (fn_access_process_vm(task, mapaddr, g_offmap, want, 0) != want) {
        apps(p, e, "error: read offset_map failed\n");
        return -1;
    }
    g_nmap = (int)ninsn;
    g_hook_off = target_off;
    g_hook_replace = replace;
    long rc = arm_common(pid, page, MODE_REDIRECT_MAP, clone, p, e);
    /* append the backup pointer = clone copy of the target (offmap is now loaded) */
    char *q = p;
    while (*q) q++;
    q = apps(q, e, "backup=");
    q = apphex(q, e, (clone & ~0xFFFUL) + (uint64_t)g_offmap[target_off / 4] * 4);
    q = apps(q, e, " hook_off=");
    q = apphex(q, e, target_off);
    apps(q, e, "\n");
    return rc;
}

/* GC region slots whose owning process has exited (find_get_task_by_vpid -> NULL). Runs in
 * the serialized, sleepable supercall context (do_pghook / `pggc`), so it can vfree and never
 * races do_pghook. Safe vs before_pf: a dead slot's offmap is only ever dereferenced after the
 * `s->pid == current tgid` check, which a dead pid can't pass, and the dead process isn't
 * faulting -- so freeing it can't UAF a live reader. (Without this, processes that exit leak
 * their region slots until MAX_PG fills and new hooks fall back to DETECTABLE Dobby/in-place.)
 * Note: leaks one task ref per LIVE gated process scanned (put_task_struct is inline/unexposed);
 * negligible since this only runs when the table is full / on demand. */
static int gc_dead_slots_locked(void)
{
    int freed = 0;
    for (int i = 0; i < MAX_PG; i++) {
        struct pghook *s = &g_pg[i];
        if (!s->active) continue;
        void *task = fn_find_get_task_by_vpid ? fn_find_get_task_by_vpid(s->pid) : 0;
        if (!is_err_or_null(task)) continue; /* alive (ref leaked -- rare, acceptable) */
        void *dead_mm = s->mm;
        s->active = 0;                        /* publish inert before freeing (before_pf skips) */
        s->npages = 0;
        if (s->offmap && fn_vfree) fn_vfree(s->offmap);
        s->offmap = 0;
        s->mm = 0;
        if (g_npg > 0) g_npg--;
        freed++;
        /* drop this dead process's general hide-set entries (its mm is being freed; a stale
         * mm pointer could false-match a reused mm and hide a line in a new process) */
        if (dead_mm)
            for (int j = 0; j < MAX_HIDE; j++)
                if (g_hide[j].mm == dead_mm) {
                    g_hide[j].mm = 0;
                    g_hide[j].page = 0;
                    if (g_nhide > 0) g_nhide--;
                }
    }
    if (freed) {
        maybe_unhook_pf();
        maybe_unhook_maps();
    }
    return freed;
}

/* pghook: add ONE page to the multi-page hook table. Routing is identical to
 * pagehook (whole-page clone via per-slot offset_map + optional single-fn entry
 * override), but several pages can be armed simultaneously -- this is what an
 * LSPlant-style frontend needs, where multiple libart functions live on distinct
 * code pages and must all be trapped at once. Each call consumes one slot;
 * `replace` is optional (0 => whole page just runs from the clone, no override).
 * Tear the whole table down with `pgdisarm`. */
static long do_pghook(uint64_t pid, uint64_t page, uint64_t clone, uint64_t mapaddr, uint64_t ninsn,
                      uint64_t target_off, uint64_t replace, char *p, char *e)
{
    resolve_syms();
    if (!fn_access_process_vm || !fn_find_get_task_by_vpid || !fn_get_task_mm || !fn_mmput ||
        !fn_apply_existing || !g_addr_pf || !fn_task_pid_nr_ns) {
        apps(p, e, "error: symbols not resolved (run probe)\n");
        return -1;
    }
    /* ninsn is the REGION instruction count = npages*1024; target_off is region-relative */
    if (ninsn == 0 || (ninsn & 1023) || ninsn > (uint64_t)(MAX_RGN * 1024) || (target_off & 3) ||
        target_off >= ninsn * 4) {
        apps(p, e, "error: bad ninsn (must be Nx1024, <= MAX_RGN pages) / target_off\n");
        return -1;
    }
    int npages = (int)(ninsn / 1024);
    page &= ~0xFFFUL;
    clone &= ~0xFFFUL;

    /* LSPlant hooks one function at a time; several can land on the SAME page. If
     * this page is already armed for the process, just APPEND the (off -> replace)
     * override to its slot (no re-arm) -- the whole-page clone is already in place. */
    for (int i = 0; i < MAX_PG; i++) {
        struct pghook *s = &g_pg[i];
        if (!s->active || s->pid != (int)pid || s->page != page) continue;
        if (s->clone != clone) {
            apps(p, e, "error: page armed with a different clone (pgdisarm first)\n");
            return -1;
        }
        if (replace) {
            /* dedup: re-hooking the same offset updates its replacement in place */
            int k = -1, free = -1;
            for (int j = 0; j < MAX_OV; j++) {
                if (s->ov_off[j] == target_off) { k = j; break; }
                if (free < 0 && s->ov_off[j] == OV_NONE) free = j;
            }
            if (k < 0) k = free; /* claim an inert slot */
            if (k < 0) {
                apps(p, e, "error: page override table full\n");
                return -1;
            }
            int fresh = (s->ov_off[k] != target_off);
            pg_set_ov(s, k, target_off, replace); /* key-last publish (see pg_set_ov) */
            if (fresh) s->nlive++;
        }
        p = apps(p, e, "ok: pghook slot=");
        p = appdec(p, e, i);
        p = apps(p, e, " (appended) pid=");
        p = appdec(p, e, (long)pid);
        p = apps(p, e, " page=");
        p = apphex(p, e, page);
        p = apps(p, e, " backup=");
        p = apphex(p, e, clone + (uint64_t)s->offmap[target_off / 4] * 4);
        p = apps(p, e, " hook_off=");
        p = apphex(p, e, target_off);
        p = apps(p, e, " replace=");
        p = apphex(p, e, replace);
        p = apps(p, e, " nlive=");
        p = appdec(p, e, s->nlive);
        apps(p, e, "\n");
        return 0;
    }

    int si = -1;
    for (int i = 0; i < MAX_PG; i++)
        if (!g_pg[i].active) {
            si = i;
            break;
        }
    if (si < 0) {
        /* table full -- reap slots whose process exited, then retry (else this hook would fall
         * back to DETECTABLE Dobby/in-place, breaking tracelessness) */
        if (gc_dead_slots_locked() > 0)
            for (int i = 0; i < MAX_PG; i++)
                if (!g_pg[i].active) { si = i; break; }
    }
    if (si < 0) {
        apps(p, e, "error: hook table full (no dead slots to reap)\n");
        return -1;
    }
    struct pghook *s = &g_pg[si];

    void *task = fn_find_get_task_by_vpid((int)pid);
    if (is_err_or_null(task)) {
        apps(p, e, "error: task not found\n");
        return -1;
    }
    /* resolve + cache the leaf PTE of EVERY page in the region (all must be present) */
    uint64_t *ptep[MAX_RGN];
    uint64_t pte_orig[MAX_RGN];
    for (int j = 0; j < npages; j++) {
        struct pte_out o;
        int r = resolve_pte(pid, page + (uint64_t)j * 0x1000, &o);
        if (r || !(o.val & PTE_VALID)) {
            apps(p, e, "error: a region page is not present/valid (run it first)\n");
            return -1;
        }
        ptep[j] = (uint64_t *)o.ptep;
        pte_orig[j] = o.val;
    }
    /* vmalloc the region offmap (too big for BSS) and read it from the target */
    if (!fn_vmalloc || !fn_vfree) {
        apps(p, e, "error: vmalloc not resolved\n");
        return -1;
    }
    int want = (int)(ninsn * 4);
    uint32_t *offmap = fn_vmalloc((unsigned long)want);
    if (!offmap) {
        apps(p, e, "error: offmap vmalloc failed\n");
        return -1;
    }
    int got = (int)fn_access_process_vm(task, mapaddr, offmap, want, 0);
    if (got != want) {
        fn_vfree(offmap);
        p = apps(p, e, "error: read offset_map failed got=");
        p = appdec(p, e, got);
        p = apps(p, e, " want=");
        p = appdec(p, e, want);
        p = apps(p, e, " mapaddr=");
        p = apphex(p, e, mapaddr);
        apps(p, e, "\n");
        return -1;
    }
    /* ensure do_page_fault is hooked (shared, ref-counted with the single-page path) */
    if (ensure_pf_hooked(p, e) != 0) {
        fn_vfree(offmap);
        return -1;
    }

    s->pid = (int)pid;
    /* cache the target's mm* for the maps-hide owner gate (equality use only -- never
     * dereferenced). get_task_mm takes/drops a ref; we keep just the pointer value. */
    s->mm = 0;
    {
        void *tmm = fn_get_task_mm(task);
        if (!is_err_or_null(tmm)) {
            s->mm = tmm;
            fn_mmput(tmm);
        }
    }
    s->page = page;
    s->npages = npages;
    s->clone = clone;
    for (int k = 0; k < MAX_OV; k++) s->ov_off[k] = OV_NONE; /* all slots inert */
    s->nlive = 0;
    if (replace) {
        s->ov_replace[0] = replace;
        s->ov_off[0] = target_off; /* not yet active/UXN -> no fault can race this */
        s->nlive = 1;
    }
    s->nmap = (int)ninsn;
    s->offmap = offmap;
    for (int j = 0; j < npages; j++) {
        s->ptep[j] = ptep[j];
        s->pte_orig[j] = pte_orig[j];
    }
    s->redirects = 0;
    s->active = 1; /* publish the fully-populated slot before arming UXN */
    g_npg++;

    /* arm UXN on EVERY region page -> EL0 execute now faults into before_pf */
    for (int j = 0; j < npages; j++)
        *(volatile uint64_t *)s->ptep[j] = s->pte_orig[j] | PTE_UXN;
    flush_tlb_all();

    /* auto-hide: hide this clone from /proc/pid/maps the moment the region is armed
     * (best-effort -- the redirect still works if the maps hook can't install) */
    int maps_rc = ensure_maps_hooked();

    p = apps(p, e, "ok: pghook slot=");
    p = appdec(p, e, si);
    p = apps(p, e, " pid=");
    p = appdec(p, e, (long)pid);
    p = apps(p, e, " page=");
    p = apphex(p, e, page);
    p = apps(p, e, " npages=");
    p = appdec(p, e, npages);
    p = apps(p, e, " clone=");
    p = apphex(p, e, clone);
    p = apps(p, e, " backup=");
    p = apphex(p, e, clone + (uint64_t)s->offmap[target_off / 4] * 4);
    p = apps(p, e, " hook_off=");
    p = apphex(p, e, target_off);
    p = apps(p, e, " replace=");
    p = apphex(p, e, replace);
    p = apps(p, e, " maps_hide=");
    p = appdec(p, e, maps_rc == 0 ? 1 : 0);
    p = apps(p, e, " npg=");
    p = appdec(p, e, g_npg);
    apps(p, e, "\n");
    return 0;
}

/* pgdisarm: tear down the entire multi-page table -- restore every UXN'd page
 * and drop all slots. Unhooks do_page_fault only if the single-page path is also
 * inactive (maybe_unhook_pf). */
static long do_pgdisarm(char *p, char *e)
{
    long total = 0;
    int n = 0;
    /* clear UXN on every armed region's pages first, keeping the slots active so a
     * fault racing the teardown is still routed; then ONE flush; then drop the slots
     * (after the flush no page is trapped, so deactivation can't strand a fault) */
    for (int i = 0; i < MAX_PG; i++) {
        struct pghook *s = &g_pg[i];
        if (!s->active) continue;
        for (int j = 0; j < s->npages; j++)
            if (s->ptep[j]) *(volatile uint64_t *)s->ptep[j] = s->pte_orig[j]; /* clear UXN */
        n++;
    }
    if (n) flush_tlb_all();
    for (int i = 0; i < MAX_PG; i++) {
        struct pghook *s = &g_pg[i];
        if (!s->active) continue;
        total += s->redirects;
        s->active = 0;
        s->npages = 0;
        if (s->offmap && fn_vfree) fn_vfree(s->offmap);
        s->offmap = 0;
    }
    g_npg = 0;
    maybe_unhook_pf();
    maybe_unhook_maps(); /* last region gone -> reveal maps again (unless manual hidemaps) */
    p = apps(p, e, "ok: pgdisarm slots=");
    p = appdec(p, e, n);
    p = apps(p, e, " redirects=");
    p = appdec(p, e, total);
    apps(p, e, "\n");
    return 0;
}

/* pgunhook <pid> <page> <off>: remove ONE override from a page slot (mirrors
 * LSPlant inline_unhooker). The function reverts to running from its faithful
 * clone copy. When the slot's last override is removed, fully disarm that page
 * (restore the original PTE, flush, free the slot) -- same teardown as pgdisarm
 * but for a single page. Runs in the sleepable bridge/supercall context. */
static long do_pgunhook(uint64_t pid, uint64_t page, uint64_t off, char *p, char *e)
{
    page &= ~0xFFFUL;
    for (int i = 0; i < MAX_PG; i++) {
        struct pghook *s = &g_pg[i];
        if (!s->active || s->pid != (int)pid || s->page != page) continue;

        int k = -1;
        for (int j = 0; j < MAX_OV; j++)
            if (s->ov_off[j] == off) { k = j; break; }
        if (k < 0) {
            apps(p, e, "error: offset not hooked on this page\n");
            return -1;
        }
        /* retire key-first: a single store of OV_NONE makes the slot inert for the
         * racing before_pf scan (the offset then reverts to its faithful clone copy);
         * ov_replace is left as-is (stale-but-valid, never matched again) */
        s->ov_off[k] = OV_NONE;
        s->nlive--;

        if (s->nlive > 0) {
            p = apps(p, e, "ok: pgunhook slot=");
            p = appdec(p, e, i);
            p = apps(p, e, " off=");
            p = apphex(p, e, off);
            p = apps(p, e, " nlive=");
            p = appdec(p, e, s->nlive);
            p = apps(p, e, " (region still armed)\n");
            return 0;
        }

        /* last override gone -> disarm the whole region (restore every PTE, free slot) */
        long red = s->redirects;
        for (int j = 0; j < s->npages; j++)
            if (s->ptep[j]) *(volatile uint64_t *)s->ptep[j] = s->pte_orig[j]; /* clear UXN */
        flush_tlb_all();
        s->active = 0;
        s->npages = 0;
        if (s->offmap && fn_vfree) fn_vfree(s->offmap);
        s->offmap = 0;
        if (g_npg > 0) g_npg--;
        maybe_unhook_pf();
        maybe_unhook_maps(); /* last region gone -> reveal maps again (unless manual hidemaps) */
        p = apps(p, e, "ok: pgunhook slot=");
        p = appdec(p, e, i);
        p = apps(p, e, " disarmed region=");
        p = apphex(p, e, page);
        p = apps(p, e, " redirects=");
        p = appdec(p, e, red);
        p = apps(p, e, " npg=");
        p = appdec(p, e, g_npg);
        apps(p, e, "\n");
        return 0;
    }
    apps(p, e, "error: region not armed for this pid\n");
    return -1;
}

static long do_disarm(char *p, char *e)
{
    g_armed = 0;
    if (g_ptep) {
        *(volatile uint64_t *)g_ptep = g_pte_orig; /* clear UXN */
        flush_tlb_all();
    }
    maybe_unhook_pf(); /* keep do_page_fault hooked if pghook slots are still armed */
    p = apps(p, e, "ok: disarmed, faults=");
    p = appdec(p, e, g_faults);
    p = apps(p, e, " redirects=");
    p = appdec(p, e, g_redirects);
    apps(p, e, "\n");
    g_ptep = 0;
    g_mode = MODE_SELFHEAL;
    g_clone_page = 0;
    g_redirect_fixed = 0;
    g_hook_off = 0;
    g_hook_replace = 0;
    g_nmap = 0;
    return 0;
}

static long do_state(char *p, char *e)
{
    p = apps(p, e, "armed=");
    p = appdec(p, e, g_armed);
    p = apps(p, e, " mode=");
    p = apps(p, e, g_mode == MODE_REDIRECT_MAP ? "REDIRECT_MAP"
                   : g_mode == MODE_REDIRECT ? "REDIRECT"
                   : g_mode == MODE_REDIRECT_FIXED ? "REDIRECT_FIXED"
                   : "SELFHEAL");
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
    p = apps(p, e, " maps_hooked=");
    p = appdec(p, e, g_maps_hooked);
    p = apps(p, e, " hide_page=");
    p = apphex(p, e, g_hide_page);
    p = apps(p, e, " maps_hidden=");
    p = appdec(p, e, g_maps_hidden);
    p = apps(p, e, " smaps_hooked=");
    p = appdec(p, e, g_smaps_hooked);
    p = apps(p, e, " smaps_hidden=");
    p = appdec(p, e, g_smaps_hidden);
    p = apps(p, e, " tracer_spoof=");
    p = appdec(p, e, g_tracer_hooked);
    p = apps(p, e, " ghost_va=");
    p = apphex(p, e, g_ghost_va);
    p = apps(p, e, " hwbp_armed=");
    p = appdec(p, e, g_hwbp_armed);
    p = apps(p, e, " hw_redirects=");
    p = appdec(p, e, g_hw_redirects);
    p = apps(p, e, " npg=");
    p = appdec(p, e, g_npg);
    for (int i = 0; i < MAX_PG; i++) {
        struct pghook *s = &g_pg[i];
        if (!s->active) continue;
        p = apps(p, e, "\n pg[");
        p = appdec(p, e, i);
        p = apps(p, e, "] pid=");
        p = appdec(p, e, s->pid);
        p = apps(p, e, " page=");
        p = apphex(p, e, s->page);
        p = apps(p, e, " npages=");
        p = appdec(p, e, s->npages);
        p = apps(p, e, " clone=");
        p = apphex(p, e, s->clone);
        p = apps(p, e, " nlive=");
        p = appdec(p, e, s->nlive);
        p = apps(p, e, " redirects=");
        p = appdec(p, e, s->redirects);
        for (int k = 0; k < MAX_OV; k++) {
            if (s->ov_off[k] == OV_NONE) continue; /* skip inert slots */
            p = apps(p, e, "\n   ov[");
            p = appdec(p, e, k);
            p = apps(p, e, "] off=");
            p = apphex(p, e, s->ov_off[k]);
            p = apps(p, e, " -> ");
            p = apphex(p, e, s->ov_replace[k]);
        }
    }
    if (g_ptep) {
        p = apps(p, e, "\npte_now=");
        p = apphex(p, e, *(volatile uint64_t *)g_ptep);
        p = decode_pte(p, e, *(volatile uint64_t *)g_ptep);
    }
    apps(p, e, "\n");
    return 0;
}

/* inject a VMA-less executable scratch page at user VA `xol_va` in `mm`, exec attrs
 * copied from `template_va` (the region's .text). Keeps the kernel alias in *kaddr_out
 * so before_pf can write the copied insn PAN-free. Mirrors ghost_inject. */
static int ssol_inject_xol(void *mm, uint64_t xol_va, uint64_t template_va, uint64_t *kaddr_out)
{
    xol_va &= ~0xFFFUL;
    struct pte_out chk;
    chk.n = 0;
    chk.val = 0;
    fn_apply_existing(mm, xol_va, 0x1000, (void *)pte_cb, &chk);
    if (chk.n > 0 && (chk.val & PTE_VALID)) return -3; /* xol_va must be unmapped */
    struct pte_out tpl;
    tpl.n = 0;
    tpl.val = 0;
    fn_apply_existing(mm, template_va & ~0xFFFUL, 0x1000, (void *)pte_cb, &tpl);
    if (tpl.n == 0 || !(tpl.val & PTE_VALID)) return -4;
    uint64_t attrs = tpl.val & ~PFN_MASK; /* exec attrs from the .text page */
    void *kaddr = fn_vmalloc(0x1000);
    if (is_err_or_null(kaddr)) return -5;
    for (int i = 0; i < 0x1000; i++) ((volatile char *)kaddr)[i] = 0;
    sync_icache(kaddr, 0x1000);
    uint64_t pfn = fn_vmalloc_to_pfn(kaddr);
    uint64_t pte_val = ((pfn << 12) & PFN_MASK) | attrs;
    if (fn_apply(mm, xol_va, 0x1000, (void *)inject_cb, &pte_val)) {
        fn_vfree(kaddr);
        return -7;
    }
    flush_tlb_all();
    *kaddr_out = (uint64_t)kaddr;
    return 0;
}

/* Core SSOL region arm. entry/replace/bk_va=0 -> pure pass-through (ssoltest);
 * nonzero -> entry override (ssolhook): a real call to `entry` routes to `replace`
 * (the trampoline); the hook frontend runs the original by jumping to `bk_va` (an
 * unmapped VA = `backup`), which arms a one-shot bypass + runs the body via SSOL.
 * UXN-traps [func_page, +npages). Tear down with `ssoldisarm`. */
static long do_ssolarm(uint64_t pid, uint64_t base, uint64_t npages, uint64_t xol_va, uint64_t entry,
                       uint64_t replace, uint64_t bk_va, char *p, char *e)
{
    resolve_syms();
    if (!fn_access_process_vm || !fn_find_get_task_by_vpid || !fn_get_task_mm || !fn_mmput ||
        !fn_apply_existing || !fn_apply || !fn_vmalloc || !fn_vfree || !fn_vmalloc_to_pfn || !g_addr_pf ||
        !fn_task_pid_nr_ns || !fn_register_user_step_hook || !fn_user_enable_single_step) {
        apps(p, e, "error: symbols not resolved (run probe)\n");
        return -1;
    }
    if (npages == 0 || npages > (uint64_t)MAX_RGN) {
        apps(p, e, "error: bad npages (1..MAX_RGN)\n");
        return -1;
    }
    uint64_t page = base & ~0xFFFUL;
    uint64_t region_end = page + npages * 0x1000UL;
    /* an entry override (ssolhook) must land inside [page, region_end) and be aligned;
     * entry == 0 is a pure pass-through region (ssoltest, every insn just runs). */
    if (entry && (entry < page || entry >= region_end || (entry & 3))) {
        apps(p, e, "error: entry outside region / misaligned\n");
        return -1;
    }

    /* LSPlant hooks one qc at a time; several can share a region (same page range). If
     * this region is already armed for the process, just APPEND the {entry_off ->
     * replace, bk_va} override to its table -- no re-arm/re-snapshot, the whole-region
     * UXN trap + snapshot + xol scratch are already in place. Mirrors do_pghook. */
    for (int i = 0; i < MAX_SSOL_RGN; i++) {
        struct ssol_rgn *s = &g_ssol[i];
        if (!s->active || s->pid != (int)pid || s->page != page) continue;
        if (s->npages != (int)npages) {
            apps(p, e, "error: region armed with a different npages (ssoldisarm first)\n");
            return -1;
        }
        if (entry) {
            uint64_t off = entry - page;
            int k = -1, freek = -1;
            for (int j = 0; j < MAX_SSOL_OV; j++) {
                if (s->ov_off[j] == off) { k = j; break; }       /* re-hook same entry */
                if (freek < 0 && s->ov_off[j] == OV_NONE) freek = j;
            }
            if (k < 0) k = freek; /* claim an inert slot */
            if (k < 0) {
                apps(p, e, "error: ssol override table full\n");
                return -1;
            }
            int fresh = (s->ov_off[k] != off);
            ssol_set_ov(s, k, off, replace, bk_va); /* key-last publish (see ssol_set_ov) */
            if (fresh) s->nov++;
        }
        p = apps(p, e, "ok: ssolarm slot=");
        p = appdec(p, e, i);
        p = apps(p, e, " (appended) pid=");
        p = appdec(p, e, (long)pid);
        p = apps(p, e, " page=");
        p = apphex(p, e, page);
        p = apps(p, e, " entry=");
        p = apphex(p, e, entry);
        p = apps(p, e, " replace=");
        p = apphex(p, e, replace);
        p = apps(p, e, " bk_va=");
        p = apphex(p, e, bk_va);
        p = apps(p, e, " nov=");
        p = appdec(p, e, s->nov);
        apps(p, e, "\n");
        return 0;
    }

    int si = -1;
    for (int i = 0; i < MAX_SSOL_RGN; i++)
        if (!g_ssol[i].active) {
            si = i;
            break;
        }
    if (si < 0) {
        apps(p, e, "error: ssol region table full\n");
        return -1;
    }
    struct ssol_rgn *s = &g_ssol[si];

    void *task = fn_find_get_task_by_vpid((int)pid);
    if (is_err_or_null(task)) {
        apps(p, e, "error: task not found\n");
        return -1;
    }
    void *mm = fn_get_task_mm(task);
    if (is_err_or_null(mm)) {
        apps(p, e, "error: get_task_mm failed\n");
        return -1;
    }
    /* resolve + cache the leaf PTE of every region page (all must be present) */
    uint64_t *ptep[MAX_RGN];
    uint64_t pte_orig[MAX_RGN];
    int ok = 1;
    for (int j = 0; j < (int)npages; j++) {
        struct pte_out o;
        if (resolve_pte(pid, page + (uint64_t)j * 0x1000, &o) || !(o.val & PTE_VALID)) {
            ok = 0;
            break;
        }
        ptep[j] = (uint64_t *)o.ptep;
        pte_orig[j] = o.val;
    }
    if (!ok) {
        fn_mmput(mm);
        apps(p, e, "error: a region page not present (run it first)\n");
        return -1;
    }
    /* snapshot the region instructions into a kernel buffer (insn + literal pool) */
    int want = (int)(npages * 0x1000);
    uint32_t *insns = fn_vmalloc((unsigned long)want);
    if (!insns) {
        fn_mmput(mm);
        apps(p, e, "error: snapshot vmalloc failed\n");
        return -1;
    }
    if ((int)fn_access_process_vm(task, page, insns, want, 0) != want) {
        fn_vfree(insns);
        fn_mmput(mm);
        apps(p, e, "error: snapshot read failed\n");
        return -1;
    }
    /* inject the XOL scratch page (exec attrs from the region's .text) */
    uint64_t xol_kaddr = 0;
    int ir = ssol_inject_xol(mm, xol_va, page, &xol_kaddr);
    fn_mmput(mm);
    if (ir) {
        fn_vfree(insns);
        p = apps(p, e, "error: xol inject failed ir=");
        p = appdec(p, e, ir);
        apps(p, e, "\n");
        return -1;
    }
    if (ensure_pf_hooked(p, e) != 0) {
        fn_vfree(insns);
        return -1;
    }
    if (ssol_ensure_step_hook()) {
        fn_vfree(insns);
        apps(p, e, "error: step hook register failed\n");
        return -1;
    }

    s->pid = (int)pid;
    s->mm = 0;
    {
        void *tmm = fn_get_task_mm(task);
        if (!is_err_or_null(tmm)) {
            s->mm = tmm;
            fn_mmput(tmm);
        }
    }
    s->page = page;
    s->npages = (int)npages;
    for (int k = 0; k < MAX_SSOL_OV; k++) s->ov_off[k] = OV_NONE; /* all slots inert */
    s->nov = 0;
    if (entry) {
        /* not yet active/UXN-armed -> no fault can race; set ov[0] directly */
        s->ov_off[0] = entry - page;
        s->ov_replace[0] = replace;
        s->ov_bk[0] = bk_va;
        s->nov = 1;
    }
    s->insns = insns;
    s->xol_kaddr = xol_kaddr;
    s->xol_va = xol_va & ~0xFFFUL;
    for (int j = 0; j < (int)npages; j++) {
        s->ptep[j] = ptep[j];
        s->pte_orig[j] = pte_orig[j];
    }
    s->n_sim = 0;
    s->n_xol = 0;
    s->n_hook = 0;
    s->n_orig = 0;
    s->active = 1; /* publish before arming UXN */
    g_nssol++;

    for (int j = 0; j < (int)npages; j++)
        *(volatile uint64_t *)s->ptep[j] = s->pte_orig[j] | PTE_UXN;
    flush_tlb_all();

    p = apps(p, e, "ok: ssolarm slot=");
    p = appdec(p, e, si);
    p = apps(p, e, " pid=");
    p = appdec(p, e, (long)pid);
    p = apps(p, e, " page=");
    p = apphex(p, e, page);
    p = apps(p, e, " npages=");
    p = appdec(p, e, (long)npages);
    p = apps(p, e, " entry=");
    p = apphex(p, e, entry);
    p = apps(p, e, " replace=");
    p = apphex(p, e, replace);
    p = apps(p, e, " xol_va=");
    p = apphex(p, e, s->xol_va);
    p = apps(p, e, " nssol=");
    p = appdec(p, e, g_nssol);
    apps(p, e, "\n");
    return 0;
}

/* ssoldisarm: restore UXN on every SSOL region, free snapshots + scratch pages. */
static long do_ssoldisarm(char *p, char *e)
{
    int n = 0;
    for (int i = 0; i < MAX_SSOL_RGN; i++) {
        struct ssol_rgn *s = &g_ssol[i];
        if (!s->active) continue;
        for (int j = 0; j < s->npages; j++)
            if (s->ptep[j]) *(volatile uint64_t *)s->ptep[j] = s->pte_orig[j];
        n++;
    }
    if (n) flush_tlb_all();
    for (int i = 0; i < MAX_SSOL_RGN; i++) {
        struct ssol_rgn *s = &g_ssol[i];
        if (!s->active) continue;
        s->active = 0;
        if (s->insns && fn_vfree) fn_vfree(s->insns);
        s->insns = 0;
        if (s->xol_kaddr) {
            void *task = fn_find_get_task_by_vpid ? fn_find_get_task_by_vpid(s->pid) : 0;
            if (task && !is_err_or_null(task) && fn_get_task_mm) {
                void *mm = fn_get_task_mm(task);
                if (!is_err_or_null(mm)) {
                    uint64_t zero = 0;
                    fn_apply_existing(mm, s->xol_va, 0x1000, (void *)inject_cb, &zero);
                    flush_tlb_all();
                    fn_mmput(mm);
                }
            }
            if (fn_vfree) fn_vfree((void *)s->xol_kaddr);
            s->xol_kaddr = 0;
        }
    }
    g_nssol = 0;
    for (int i = 0; i < MAX_SSOL_CTX; i++) g_ctx[i].active = 0;
    p = apps(p, e, "ok: ssoldisarm regions=");
    p = appdec(p, e, n);
    apps(p, e, "\n");
    return 0;
}

/* ssolunhook <pid> <region_base> <entry>: remove ONE override from an SSOL region
 * (mirrors LSPlant inline_unhooker / do_pgunhook). The entry reverts to running its
 * body straight via SSOL (no trampoline redirect). When the region's last override is
 * removed, fully disarm it: restore every UXN'd PTE, free the snapshot + xol scratch.
 * Runs in the sleepable bridge/supercall context. */
static long do_ssolunhook(uint64_t pid, uint64_t base, uint64_t entry, char *p, char *e)
{
    uint64_t page = base & ~0xFFFUL;
    for (int i = 0; i < MAX_SSOL_RGN; i++) {
        struct ssol_rgn *s = &g_ssol[i];
        if (!s->active || s->pid != (int)pid || s->page != page) continue;
        uint64_t off = entry - page;
        int k = -1;
        for (int j = 0; j < MAX_SSOL_OV; j++)
            if (s->ov_off[j] == off) { k = j; break; }
        if (k < 0) {
            apps(p, e, "error: entry not hooked in this region\n");
            return -1;
        }
        /* retire key-first: one store of OV_NONE makes the slot inert for the racing
         * before_pf scan (the entry then runs its body straight via SSOL); the stale
         * ov_replace/ov_bk are left as-is, never matched again. */
        s->ov_off[k] = OV_NONE;
        s->nov--;
        if (s->nov > 0) {
            p = apps(p, e, "ok: ssolunhook slot=");
            p = appdec(p, e, i);
            p = apps(p, e, " entry=");
            p = apphex(p, e, entry);
            p = apps(p, e, " nov=");
            p = appdec(p, e, s->nov);
            p = apps(p, e, " (region still armed)\n");
            return 0;
        }
        /* last override gone -> disarm the whole region (restore every UXN'd PTE, then
         * free the snapshot + xol scratch). Same race-free order as do_ssoldisarm. */
        for (int j = 0; j < s->npages; j++)
            if (s->ptep[j]) *(volatile uint64_t *)s->ptep[j] = s->pte_orig[j];
        flush_tlb_all();
        s->active = 0;
        if (s->insns && fn_vfree) fn_vfree(s->insns);
        s->insns = 0;
        if (s->xol_kaddr) {
            void *task = fn_find_get_task_by_vpid ? fn_find_get_task_by_vpid(s->pid) : 0;
            if (task && !is_err_or_null(task) && fn_get_task_mm) {
                void *mm = fn_get_task_mm(task);
                if (!is_err_or_null(mm)) {
                    uint64_t zero = 0;
                    fn_apply_existing(mm, s->xol_va, 0x1000, (void *)inject_cb, &zero);
                    flush_tlb_all();
                    fn_mmput(mm);
                }
            }
            if (fn_vfree) fn_vfree((void *)s->xol_kaddr);
            s->xol_kaddr = 0;
        }
        if (g_nssol > 0) g_nssol--;
        /* leave do_page_fault + the step hook installed: other SSOL/pghook regions may
         * still be live, and the step hook is module-lifetime by design (teardown rule). */
        p = apps(p, e, "ok: ssolunhook slot=");
        p = appdec(p, e, i);
        p = apps(p, e, " disarmed region=");
        p = apphex(p, e, page);
        p = apps(p, e, " nssol=");
        p = appdec(p, e, g_nssol);
        apps(p, e, "\n");
        return 0;
    }
    apps(p, e, "error: region not armed for this pid\n");
    return -1;
}

/* P1b-1 self-test of the single-step primitive: arm ONE step on the CALLER (the
 * shctl/manager thread) via the exact uprobes flow. On return to EL0 the caller
 * single-steps one harmless instruction -> ssol_step_fn -> g_selfstep_fired++.
 * Read it back with `ssolstat` (or a 2nd `selfstep`). Validates register_user_step_hook
 * + user_enable_single_step + step delivery in isolation, with low blast radius. */
static long do_selfstep(char *p, char *e)
{
    resolve_syms();
    if (!fn_register_user_step_hook || !fn_user_enable_single_step || !fn_user_disable_single_step ||
        !fn_task_pid_nr_ns) {
        apps(p, e, "error: step symbols not resolved (run probe)\n");
        return -1;
    }
    if (ssol_ensure_step_hook()) {
        apps(p, e, "error: register_user_step_hook failed\n");
        return -1;
    }
    void *cur = (void *)get_current();
    int tid = fn_task_pid_nr_ns(cur, PIDTYPE_PID, 0);
    if (ctx_by_tid(tid)) {
        apps(p, e, "error: ctx busy for this tid\n");
        return -1;
    }
    struct ssol_ctx *c = ctx_free();
    if (!c) {
        apps(p, e, "error: no free ctx\n");
        return -1;
    }
    c->tid = tid;
    c->kind = SSOL_K_SELFSTEP;
    c->resume_pc = 0;
    c->xol_va = 0;
    c->active = 1; /* publish last: the step fires only after we return to EL0 */
    g_selfstep_armed++;
    fn_user_enable_single_step(cur); /* on return to EL0: 1 step -> ssol_step_fn */
    p = apps(p, e, "ok: armed selfstep tid=");
    p = appdec(p, e, tid);
    p = apps(p, e, " armed=");
    p = appdec(p, e, g_selfstep_armed);
    p = apps(p, e, " fired(prev)=");
    p = appdec(p, e, g_selfstep_fired);
    apps(p, e, "\n");
    return 0;
}

static long do_ssolstat(char *p, char *e)
{
    int nctx = 0;
    for (int i = 0; i < MAX_SSOL_CTX; i++)
        if (g_ctx[i].active) nctx++;
    p = apps(p, e, "step_registered=");
    p = appdec(p, e, g_step_registered);
    p = apps(p, e, " selfstep_armed=");
    p = appdec(p, e, g_selfstep_armed);
    p = apps(p, e, " selfstep_fired=");
    p = appdec(p, e, g_selfstep_fired);
    p = apps(p, e, " step_fires=");
    p = appdec(p, e, g_step_fires);
    p = apps(p, e, " ctx_active=");
    p = appdec(p, e, nctx);
    p = apps(p, e, " nssol=");
    p = appdec(p, e, g_nssol);
    for (int i = 0; i < MAX_SSOL_RGN; i++) {
        struct ssol_rgn *s = &g_ssol[i];
        if (!s->active) continue;
        p = apps(p, e, "\n ssol[");
        p = appdec(p, e, i);
        p = apps(p, e, "] pid=");
        p = appdec(p, e, s->pid);
        p = apps(p, e, " page=");
        p = apphex(p, e, s->page);
        p = apps(p, e, " npages=");
        p = appdec(p, e, s->npages);
        p = apps(p, e, " nov=");
        p = appdec(p, e, s->nov);
        p = apps(p, e, " n_sim=");
        p = appdec(p, e, s->n_sim);
        p = apps(p, e, " n_xol=");
        p = appdec(p, e, s->n_xol);
        p = apps(p, e, " n_hook=");
        p = appdec(p, e, s->n_hook);
        p = apps(p, e, " n_orig=");
        p = appdec(p, e, s->n_orig);
        for (int k = 0; k < MAX_SSOL_OV; k++) {
            if (s->ov_off[k] == OV_NONE) continue;
            p = apps(p, e, "\n   ov off=");
            p = apphex(p, e, s->ov_off[k]);
            p = apps(p, e, " replace=");
            p = apphex(p, e, s->ov_replace[k]);
            p = apps(p, e, " bk=");
            p = apphex(p, e, s->ov_bk[k]);
        }
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
    p = apps(p, e, "\nshow_map=");
    p = apphex(p, e, (uint64_t)g_addr_show_map);
    p = apps(p, e, "\napply_to_page_range=");
    p = apphex(p, e, (uint64_t)fn_apply);
    p = apps(p, e, "\nvmalloc=");
    p = apphex(p, e, (uint64_t)fn_vmalloc);
    p = apps(p, e, "\nvmalloc_to_pfn=");
    p = apphex(p, e, (uint64_t)fn_vmalloc_to_pfn);
    p = apps(p, e, "\nregister_user_step_hook=");
    p = apphex(p, e, (uint64_t)fn_register_user_step_hook);
    p = apps(p, e, "\nunregister_user_step_hook=");
    p = apphex(p, e, (uint64_t)fn_unregister_user_step_hook);
    p = apps(p, e, "\nuser_enable_single_step=");
    p = apphex(p, e, (uint64_t)fn_user_enable_single_step);
    p = apps(p, e, "\nuser_disable_single_step=");
    p = apphex(p, e, (uint64_t)fn_user_disable_single_step);
    apps(p, e, "\n");
    return 0;
}

static long shpte_init(const char *args, const char *event, void *__user reserved)
{
    logki("shpte: init event=%s\n", event ? event : "");
    resolve_syms();
    return 0;
}

static long shpte_run(const char *args, char *buf, int bufcap); /* fwd */

/* syscall bridge: an injected agent (no superkey) drives the KPM via
 *   syscall(BRIDGE_NR=sysinfo, BRIDGE_MAGIC, cmd_ptr, cmd_len, out_ptr, out_len)
 * It runs in the agent's own process context (sleepable), like a supercall.
 * Real sysinfo() calls (arg0 != magic) pass straight through. */
static void before_bridge(hook_fargs6_t *fargs, void *udata)
{
    (void)udata;
    if ((uint64_t)syscall_argn(fargs, 0) != BRIDGE_MAGIC) return; /* not ours -> passthrough */
    const char *ucmd = (const char *)syscall_argn(fargs, 1);
    void *uout = (void *)syscall_argn(fargs, 3);
    long outlen = (long)syscall_argn(fargs, 4);

    char cmd[256];
    char buf[1024];
    long n = compat_strncpy_from_user(cmd, ucmd, sizeof(cmd));
    if (n < 0) {
        fargs->ret = -1;
        fargs->skip_origin = 1;
        return;
    }
    cmd[sizeof(cmd) - 1] = 0;
    long rc = shpte_run(cmd, buf, (int)sizeof(buf));
    int len = 0;
    while (buf[len] && len < (int)sizeof(buf) - 1) len++;
    if (uout && outlen > 0) {
        if (len >= outlen) len = (int)outlen - 1;
        buf[len] = 0;
        compat_copy_to_user(uout, buf, len + 1);
    }
    fargs->ret = rc;
    fargs->skip_origin = 1; /* swallow the carrier syscall */
}

static long do_bridge(char *p, char *e)
{
    if (g_bridge_hooked) {
        apps(p, e, "ok: bridge already on\n");
        return 0;
    }
    hook_err_t err = fp_hook_syscalln(BRIDGE_NR, 6, (void *)before_bridge, 0, 0);
    if (err != HOOK_NO_ERR) {
        p = apps(p, e, "error: hook sysinfo failed err=");
        p = appdec(p, e, (int)err);
        apps(p, e, "\n");
        return -1;
    }
    g_bridge_hooked = 1;
    apps(p, e, "ok: syscall bridge on (sysinfo + magic)\n");
    return 0;
}

static long do_unbridge(char *p, char *e)
{
    if (g_bridge_hooked) {
        fp_unhook_syscalln(BRIDGE_NR, (void *)before_bridge, 0);
        g_bridge_hooked = 0;
    }
    apps(p, e, "ok: syscall bridge off\n");
    return 0;
}

/* dispatch a command string into `buf` (kernel buffer), returns rc. Shared by the
 * KPM_CTL0 entry (superkey path) and the syscall bridge (no-superkey agent path). */
static long shpte_run(const char *args, char *buf, int bufcap)
{
    for (int i = 0; i < bufcap; i++) buf[i] = 0;
    char *p = buf;
    char *e = buf + bufcap - 1;
    long rc = 0;
    const char *a = skipsp(args ? args : "");

    if (starts(a, "probe")) {
        rc = do_probe(p, e);
    } else if (starts(a, "selfstep")) {
        rc = do_selfstep(p, e);
    } else if (starts(a, "ssolstat")) {
        rc = do_ssolstat(p, e);
    } else if (starts(a, "ssoltest")) {
        uint64_t pid = 0, func = 0, n = 0, xol = 0;
        const char *s = parse_ull(a + 8, &pid);
        s = parse_ull(s, &func);
        s = parse_ull(s, &n);
        parse_ull(s, &xol);
        if (!pid || !func || !n || !xol)
            apps(p, e, "usage: ssoltest <pid> <func_va> <npages> <xol_va>\n"), rc = -1;
        else
            rc = do_ssolarm(pid, func, n, xol, 0, 0, 0, p, e);
    } else if (starts(a, "ssolunhook")) {
        uint64_t pid = 0, base = 0, entry = 0;
        const char *s = parse_ull(a + 10, &pid);
        s = parse_ull(s, &base);
        parse_ull(s, &entry);
        if (!pid || !base || !entry)
            apps(p, e, "usage: ssolunhook <pid> <region_base> <entry_va>\n"), rc = -1;
        else
            rc = do_ssolunhook(pid, base, entry, p, e);
    } else if (starts(a, "ssolhook")) {
        uint64_t pid = 0, base = 0, n = 0, xol = 0, entry = 0, rep = 0, bk = 0;
        const char *s = parse_ull(a + 8, &pid);
        s = parse_ull(s, &base);
        s = parse_ull(s, &n);
        s = parse_ull(s, &xol);
        s = parse_ull(s, &entry);
        s = parse_ull(s, &rep);
        parse_ull(s, &bk);
        if (!pid || !base || !n || !xol || !entry || !rep || !bk)
            apps(p, e,
                 "usage: ssolhook <pid> <region_base> <npages> <xol_va> <entry_va> <replace_va> "
                 "<backup_va>\n"),
                rc = -1;
        else
            rc = do_ssolarm(pid, base, n, xol, entry, rep, bk, p, e);
    } else if (starts(a, "ssoldisarm")) {
        rc = do_ssoldisarm(p, e);
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
    } else if (starts(a, "pagehook")) {
        uint64_t pid = 0, page = 0, clone = 0, map = 0, n = 0, toff = 0, rep = 0;
        const char *s = parse_ull(a + 8, &pid);
        s = parse_ull(s, &page);
        s = parse_ull(s, &clone);
        s = parse_ull(s, &map);
        s = parse_ull(s, &n);
        s = parse_ull(s, &toff);
        parse_ull(s, &rep);
        if (!pid || !page || !clone || !map || !n || !rep)
            apps(p, e,
                 "usage: pagehook <pid> <page> <clone> <map> <ninsn> <target_off> <replace>\n"),
                rc = -1;
        else
            rc = do_pagehook(pid, page, clone, map, n, toff, rep, p, e);
    } else if (starts(a, "pggc")) {
        int n = gc_dead_slots_locked();
        p = apps(p, e, "ok: pggc reaped ");
        p = appdec(p, e, n);
        p = apps(p, e, " dead slots, npg=");
        p = appdec(p, e, g_npg);
        apps(p, e, "\n");
    } else if (starts(a, "pgdisarm")) {
        rc = do_pgdisarm(p, e);
    } else if (starts(a, "pgunhook")) {
        uint64_t pid = 0, page = 0, off = 0;
        const char *s = parse_ull(a + 8, &pid);
        s = parse_ull(s, &page);
        parse_ull(s, &off);
        if (!pid || !page)
            apps(p, e, "usage: pgunhook <pid> <page> <off>\n"), rc = -1;
        else
            rc = do_pgunhook(pid, page, off, p, e);
    } else if (starts(a, "pghook")) {
        uint64_t pid = 0, page = 0, clone = 0, map = 0, n = 0, toff = 0, rep = 0;
        const char *s = parse_ull(a + 6, &pid);
        s = parse_ull(s, &page);
        s = parse_ull(s, &clone);
        s = parse_ull(s, &map);
        s = parse_ull(s, &n);
        s = parse_ull(s, &toff);
        parse_ull(s, &rep); /* target_off + replace optional (0 = no override) */
        if (!pid || !page || !clone || !map || !n)
            apps(p, e,
                 "usage: pghook <pid> <page> <clone> <map> <ninsn> [target_off] [replace]\n"),
                rc = -1;
        else
            rc = do_pghook(pid, page, clone, map, n, toff, rep, p, e);
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
    } else if (starts(a, "hidergn")) {
        uint64_t pid = 0, addr = 0;
        const char *s = parse_ull(a + 7, &pid);
        parse_ull(s, &addr);
        if (!pid || !addr)
            apps(p, e, "usage: hidergn <pid> <hexaddr>\n"), rc = -1;
        else
            rc = do_hidergn(pid, addr, p, e);
    } else if (starts(a, "hidemaps")) {
        uint64_t page = 0;
        parse_ull(a + 8, &page);
        rc = do_hidemaps(page, p, e); /* page optional: defaults to active clone */
    } else if (starts(a, "unhidemaps")) {
        rc = do_unhidemaps(p, e);
    } else if (starts(a, "hidetracer")) {
        rc = do_hidetracer(p, e);
    } else if (starts(a, "unhidetracer")) {
        rc = do_unhidetracer(p, e);
    } else if (starts(a, "ghostredirect")) {
        uint64_t pid = 0, fn = 0, gva = 0, cb = 0, nc = 0, mp = 0, ni = 0, tv = 0;
        const char *s = parse_ull(a + 13, &pid);
        s = parse_ull(s, &fn);
        s = parse_ull(s, &gva);
        s = parse_ull(s, &cb);
        s = parse_ull(s, &nc);
        s = parse_ull(s, &mp);
        s = parse_ull(s, &ni);
        parse_ull(s, &tv);
        if (!pid || !fn || !gva || !cb || !nc || !mp || !ni || !tv)
            apps(p, e,
                 "usage: ghostredirect <pid> <func> <ghost_va> <clonebytes> <nclone> <map> <ninsn> "
                 "<template_va>\n"),
                rc = -1;
        else
            rc = do_ghostredirect(pid, fn, gva, cb, nc, mp, ni, tv, p, e);
    } else if (starts(a, "ghosttest")) {
        uint64_t pid = 0, gva = 0, tva = 0;
        const char *s = parse_ull(a + 9, &pid);
        s = parse_ull(s, &gva);
        parse_ull(s, &tva);
        if (!pid || !gva || !tva)
            apps(p, e, "usage: ghosttest <pid> <ghost_va> <template_va>\n"), rc = -1;
        else
            rc = do_ghosttest(pid, gva, tva, p, e);
    } else if (starts(a, "ghostfree")) {
        rc = do_ghostfree(p, e);
    } else if (starts(a, "hookto")) {
        uint64_t pid = 0, tgt = 0, rep = 0, cb = 0, nc = 0, tv = 0, gv = 0;
        const char *s = parse_ull(a + 6, &pid);
        s = parse_ull(s, &tgt);
        s = parse_ull(s, &rep);
        s = parse_ull(s, &cb);
        s = parse_ull(s, &nc);
        s = parse_ull(s, &tv);
        parse_ull(s, &gv);
        if (!pid || !tgt || !rep || !cb || !nc || !tv || !gv)
            apps(p, e,
                 "usage: hookto <pid> <target> <replace> <clonebytes> <nclone> <template> <ghost_va>\n"),
                rc = -1;
        else
            rc = do_hookto(pid, tgt, rep, cb, nc, tv, gv, p, e);
    } else if (starts(a, "hwhookto")) {
        uint64_t pid = 0, tgt = 0, rep = 0, cb = 0, nc = 0, tv = 0, gv = 0;
        const char *s = parse_ull(a + 8, &pid);
        s = parse_ull(s, &tgt);
        s = parse_ull(s, &rep);
        s = parse_ull(s, &cb);
        s = parse_ull(s, &nc);
        s = parse_ull(s, &tv);
        parse_ull(s, &gv);
        if (!pid || !tgt || !rep || !cb || !nc || !tv || !gv)
            apps(p, e,
                 "usage: hwhookto <pid> <target> <replace> <clonebytes> <nclone> <template> <ghost_va>\n"),
                rc = -1;
        else
            rc = do_hwhookto(pid, tgt, rep, cb, nc, tv, gv, p, e);
    } else if (starts(a, "hwunhook")) {
        rc = do_hwunhook(p, e);
    } else if (starts(a, "unbridge")) {
        rc = do_unbridge(p, e);
    } else if (starts(a, "bridge")) {
        rc = do_bridge(p, e);
    } else if (starts(a, "dump")) {
        rc = do_state(p, e);
    } else {
        apps(p, e,
             "usage: probe | pte | arm | redirect | redirectmap | pagehook | "
             "pghook | pgunhook | pgdisarm | hookto | hwhookto | hidemaps | unhidemaps | "
             "ghosttest | ghostredirect | ghostfree | bridge | unbridge | disarm | dump\n");
        rc = -1;
    }
    return rc;
}

static long shpte_control0(const char *args, char *__user out_msg, int outlen)
{
    char buf[1024];
    long rc = shpte_run(args, buf, (int)sizeof(buf));
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
    /* restore every SSOL-trapped page + free its snapshot/scratch before unload */
    {
        int restored = 0;
        for (int i = 0; i < MAX_SSOL_RGN; i++) {
            struct ssol_rgn *s = &g_ssol[i];
            if (!s->active) continue;
            for (int j = 0; j < s->npages; j++)
                if (s->ptep[j]) *(volatile uint64_t *)s->ptep[j] = s->pte_orig[j];
            restored++;
        }
        if (restored) flush_tlb_all();
        for (int i = 0; i < MAX_SSOL_RGN; i++) {
            struct ssol_rgn *s = &g_ssol[i];
            s->active = 0;
            if (s->insns && fn_vfree) fn_vfree(s->insns);
            s->insns = 0;
            if (s->xol_kaddr && fn_vfree) fn_vfree((void *)s->xol_kaddr);
            s->xol_kaddr = 0;
        }
        g_nssol = 0;
    }
    ssol_remove_step_hook(); /* drop the user step-hook + clear SSOL ctxs */
    if (g_ptep) {
        *(volatile uint64_t *)g_ptep = g_pte_orig;
        flush_tlb_all();
        g_ptep = 0;
    }
    /* restore every multi-page UXN'd slot so unload can't leave a trapped page:
     * clear UXN on all slots, one flush, then deactivate (same race-free order
     * as do_pgdisarm) */
    {
        int restored = 0;
        for (int i = 0; i < MAX_PG; i++) {
            if (!g_pg[i].active) continue;
            for (int j = 0; j < g_pg[i].npages; j++)
                if (g_pg[i].ptep[j]) *(volatile uint64_t *)g_pg[i].ptep[j] = g_pg[i].pte_orig[j];
            restored++;
        }
        if (restored) flush_tlb_all();
        for (int i = 0; i < MAX_PG; i++) {
            g_pg[i].active = 0;
            g_pg[i].npages = 0;
            if (g_pg[i].offmap && fn_vfree) fn_vfree(g_pg[i].offmap);
            g_pg[i].offmap = 0;
        }
        g_npg = 0;
    }
    if (g_pf_hooked && g_addr_pf) {
        hook_unwrap(g_addr_pf, (void *)before_pf, 0);
        g_pf_hooked = 0;
    }
    if (g_smaps_hooked && g_addr_show_smap) {
        hook_unwrap(g_addr_show_smap, (void *)before_showmap, (void *)after_showsmap);
        g_smaps_hooked = 0;
    }
    if (g_maps_hooked && g_addr_show_map) {
        hook_unwrap(g_addr_show_map, (void *)before_showmap, (void *)after_showmap);
        g_maps_hooked = 0;
    }
    if (g_tracer_hooked && g_addr_status) {
        hook_unwrap(g_addr_status, (void *)before_status, (void *)after_status);
        g_tracer_hooked = 0;
    }
    if (g_bridge_hooked) {
        fp_unhook_syscalln(BRIDGE_NR, (void *)before_bridge, 0);
        g_bridge_hooked = 0;
    }
    g_hwbp_armed = 0;
    if (g_hwbp && fn_unreg_hwbp) {
        fn_unreg_hwbp(g_hwbp);
        g_hwbp = 0;
    }
    if (g_ghost_kaddr) {
        /* clear the injected PTE then free, so we don't leave a dangling map/leak */
        void *task = fn_find_get_task_by_vpid ? fn_find_get_task_by_vpid(g_ghost_pid) : 0;
        if (task && !is_err_or_null(task) && fn_get_task_mm) {
            void *mm = fn_get_task_mm(task);
            if (!is_err_or_null(mm)) {
                uint64_t zero = 0;
                fn_apply_existing(mm, g_ghost_va, 0x1000, (void *)inject_cb, &zero);
                flush_tlb_all();
                fn_mmput(mm);
            }
        }
        if (fn_vfree) fn_vfree(g_ghost_kaddr);
        g_ghost_kaddr = 0;
    }
    logki("shpte: exit faults=%ld maps_hidden=%ld\n", g_faults, g_maps_hidden);
    return 0;
}

KPM_INIT(shpte_init);
KPM_CTL0(shpte_control0);
KPM_EXIT(shpte_exit);
