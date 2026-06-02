// SPDX-License-Identifier: GPL-2.0-or-later
//
// shctl: minimal KernelPatch KPM control CLI for the stealth-poc.
//
// Self-contained: issues the KernelPatch "supercall" directly via syscall(45,...)
// using the public ABI constants, so it needs nothing but bionic libc. (We avoid
// KernelPatch's supercall.h because that header at 0.13.1 has unrelated inline
// helpers that fail to compile under clang.)
//
//   shctl <superkey> ready
//   shctl <superkey> load   <path.kpm> [args]
//   shctl <superkey> unload <name>
//   shctl <superkey> list
//   shctl <superkey> info    <name>
//   shctl <superkey> control <name> [ctl_args]

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#define NR_SUPERCALL 45

#define SC_HELLO 0x1000
#define SC_HELLO_MAGIC 0x11581158L
#define SC_KPM_LOAD 0x1020
#define SC_KPM_UNLOAD 0x1021
#define SC_KPM_CONTROL 0x1022
#define SC_KPM_LIST 0x1031
#define SC_KPM_INFO 0x1032

// KernelPatch version code = (MAJOR<<16)|(MINOR<<8)|PATCH.
// Target device runs kpimg d01 == 0.13.1 -> 0x0d01.
#define KP_VER_CODE ((0 << 16) | (13 << 8) | 1)

static long vcmd(long cmd)
{
    return ((long)KP_VER_CODE << 32) | (0x1158L << 16) | (cmd & 0xFFFF);
}

static long sc_hello(const char *key)
{
    return syscall(NR_SUPERCALL, key, vcmd(SC_HELLO));
}
static long sc_load(const char *key, const char *path, const char *args)
{
    return syscall(NR_SUPERCALL, key, vcmd(SC_KPM_LOAD), path, args, (void *)0);
}
static long sc_unload(const char *key, const char *name)
{
    return syscall(NR_SUPERCALL, key, vcmd(SC_KPM_UNLOAD), name, (void *)0);
}
static long sc_list(const char *key, char *buf, long len)
{
    return syscall(NR_SUPERCALL, key, vcmd(SC_KPM_LIST), buf, len);
}
static long sc_info(const char *key, const char *name, char *buf, long len)
{
    return syscall(NR_SUPERCALL, key, vcmd(SC_KPM_INFO), name, buf, len);
}
static long sc_control(const char *key, const char *name, const char *ctl, char *out, long len)
{
    return syscall(NR_SUPERCALL, key, vcmd(SC_KPM_CONTROL), name, ctl, out, len);
}

static void usage(void)
{
    fprintf(stderr,
            "usage: shctl <superkey> <cmd> [...]\n"
            "  ready\n"
            "  load   <path.kpm> [args]\n"
            "  unload <name>\n"
            "  list\n"
            "  info    <name>\n"
            "  control <name> [ctl_args]\n");
}

static void print_buf(const char *buf, long n)
{
    if (n < 0) n = (long)strlen(buf);
    for (long i = 0; i < n; i++) putchar(buf[i] == '\0' ? '\n' : buf[i]);
    putchar('\n');
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        usage();
        return 2;
    }
    const char *key = argv[1];
    const char *cmd = argv[2];

    long hello = sc_hello(key);
    if (hello != SC_HELLO_MAGIC) {
        fprintf(stderr, "[!] KernelPatch not responding / bad superkey (sc_hello=0x%lx)\n", hello);
        return 1;
    }

    if (!strcmp(cmd, "ready")) {
        printf("[+] KernelPatch ready (magic ok)\n");
        return 0;
    }
    if (!strcmp(cmd, "load")) {
        if (argc < 4) { usage(); return 2; }
        const char *path = argv[3];
        const char *args = (argc > 4) ? argv[4] : "";
        long r = sc_load(key, path, args);
        printf("[*] kpm_load(\"%s\", \"%s\") = %ld\n", path, args, r);
        return r == 0 ? 0 : 1;
    }
    if (!strcmp(cmd, "unload")) {
        if (argc < 4) { usage(); return 2; }
        long r = sc_unload(key, argv[3]);
        printf("[*] kpm_unload(\"%s\") = %ld\n", argv[3], r);
        return r == 0 ? 0 : 1;
    }
    if (!strcmp(cmd, "list")) {
        char buf[2048] = { 0 };
        long r = sc_list(key, buf, sizeof(buf));
        printf("[*] kpm_list = %ld\n", r);
        print_buf(buf, r > 0 ? r : -1);
        return 0;
    }
    if (!strcmp(cmd, "info")) {
        if (argc < 4) { usage(); return 2; }
        char buf[2048] = { 0 };
        long r = sc_info(key, argv[3], buf, sizeof(buf));
        printf("[*] kpm_info(\"%s\") = %ld\n", argv[3], r);
        print_buf(buf, r > 0 ? r : -1);
        return 0;
    }
    if (!strcmp(cmd, "control")) {
        if (argc < 4) { usage(); return 2; }
        const char *ctl = (argc > 4) ? argv[4] : "";
        char out[2048] = { 0 };
        long r = sc_control(key, argv[3], ctl, out, sizeof(out));
        printf("[*] kpm_control(\"%s\", \"%s\") = %ld\n", argv[3], ctl, r);
        print_buf(out, -1);
        return 0;
    }

    usage();
    return 2;
}
