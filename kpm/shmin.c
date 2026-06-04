/* SPDX-License-Identifier: GPL-2.0-or-later */
/* shmin: minimal KPM_CTL0 isolation test -- init + ctl0(fixed string) + exit. */

#include <compiler.h>
#include <kpmodule.h>
#include <log.h>
#include <kputils.h>

KPM_NAME("shmin");
KPM_VERSION("0.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("wxy");
KPM_DESCRIPTION("minimal ctl0 isolation test");

static long m_init(const char *args, const char *event, void *__user reserved)
{
    logki("shmin: init event=%s\n", event ? event : "");
    return 0;
}

static long m_ctl0(const char *args, char *__user out_msg, int outlen)
{
    static const char msg[] = "shmin ctl0 ok\n";
    int n = (int)sizeof(msg);
    if (n > outlen) n = outlen;
    compat_copy_to_user(out_msg, msg, n);
    logki("shmin: ctl0 args=%s\n", args ? args : "");
    return 0;
}

static long m_exit(void *__user reserved)
{
    logki("shmin: exit\n");
    return 0;
}

KPM_INIT(m_init);
KPM_CTL0(m_ctl0);
KPM_EXIT(m_exit);
