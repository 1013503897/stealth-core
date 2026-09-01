// SPDX-License-Identifier: GPL-2.0-or-later
// demohook: the SMALLEST end-to-end example of our traceless inline-hook API.
// It self-hooks one page-isolated function via lib/kpmhook over the no-superkey
// bridge, proves the call is intercepted, calls the backup (= the original), then
// unhooks. The target function's .text is NEVER modified.
//
// Call path this demonstrates (same one Vector's HookInline funnels into):
//     kpm_inline_hooker(target, hooker)                       [lib/kpmhook.h]
//   -> syscall(179 /*sysinfo*/, "SHPTBRDG", "pghook ...")     [no-superkey bridge]
//   -> shpte KPM: UXN-trap target's page + DBI region clone + override entry
//   -> target() call faults, do_page_fault routes PC into the clone's `hooker`;
//      `backup` points at the clone's faithful copy of target (call it = original).
//
// Prereq (once per boot, privileged; THIS device already has it):
//     shctl <KEY> load shpte.kpm ; control shpte probe ; control shpte bridge
//   check with:  adb shell /data/local/tmp/bridgetool dump
// Build: powershell tools/build_demohook.ps1     (links lib/dbi.c + lib/kpmhook.c)
// Run:   adb push tools/demohook /data/local/tmp/ ; adb shell /data/local/tmp/demohook

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "../lib/kpmhook.h"

// ---- the hook TARGET ----------------------------------------------------------
// Page-aligned + straight-line so its whole 4 KiB code page clones as-is (the
// simplest Layer-1 case). Returns n + 100.
__attribute__((aligned(0x1000), noinline)) int target_add(int n) { return n + 100; }

// guard: keep target_add's page isolated (push whatever the linker lays down next
// onto a different page, so the whole-page clone contains only target_add).
__attribute__((aligned(0x1000), noinline)) void guard(void) { asm volatile("nop"); }

// backup = pointer INTO the clone: the faithful copy of target_add ("call original").
static int (*backup)(int) = 0;

// ---- the REPLACEMENT ----------------------------------------------------------
// Runs instead of target_add's entry. Calls backup() to get the original result,
// then changes the behavior (returns original + 1) to prove interception.
__attribute__((noinline)) int my_hook(int n)
{
    int orig = backup ? backup(n) : -1;
    printf("  [hook] target_add(%d) intercepted; original=%d -> returning %d\n", n, orig, orig + 1);
    return orig + 1;
}

int main(void)
{
    kpm_hook_force_enable(); // standalone tool: bypass the Vector-only process gate
    if (kpm_hook_init() != 0) {
        printf("FATAL: KPM bridge not armed. Run: shctl <KEY> control shpte bridge\n");
        return 1;
    }
    printf("target_add=%p  page=0x%lx  pid=%d\n", (void *)&target_add,
           (unsigned long)((uintptr_t)&target_add & ~0xfffUL), getpid());

    // Call target_add THROUGH A VOLATILE FUNCTION POINTER with a VOLATILE arg, so the
    // compiler can't constant-fold `target_add(5)` to 105 and skip the real call --
    // the actual EL0 execute of target_add's entry is what trips the UXN trap.
    int (*volatile tp)(int) = &target_add;
    volatile int five = 5;

    printf("before hook : target_add(5) = %d   (expect 105)\n", tp(five));

    // ===== THE CALL: hook target_add -> my_hook; get backup(=original) =====
    backup = (int (*)(int))kpm_inline_hooker((void *)&target_add, (void *)&my_hook);
    printf("kpm_inline_hooker -> backup=%p\n", (void *)backup);
    if (!backup) { printf("hook FAILED\n"); return 1; }

    printf("after hook  : target_add(5) = %d   (expect 106 = original 105, +1 in hook)\n", tp(five));

    printf("...holding hooked for 4s (run `bridgetool dump` now to see the slot)...\n");
    fflush(stdout);
    sleep(4); // window to observe the live slot from the host

    // ===== UNHOOK: drop the entry override; target reverts to its clone copy =====
    int ok = kpm_inline_unhooker((void *)&target_add);
    printf("kpm_inline_unhooker -> %d\n", ok);

    printf("after unhook: target_add(5) = %d   (expect 105 again)\n", tp(five));

    kpm_hook_shutdown();
    return 0;
}
