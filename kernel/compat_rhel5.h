#ifndef COMPAT_RHEL5_H
#define COMPAT_RHEL5_H 1

#include "compat_kfifo.h"

static inline 
ktime_t skb_tstamp(const struct sk_buff *skb)
{
    return ktime_set(skb->tstamp.off_sec, skb->tstamp.off_usec*1000);
}

/*
 * Dummy printk for disabled debugging statements to use whilst maintaining
 * gcc's format and side-effect checking.
 */
static inline __attribute__ ((format (printf, 1, 2)))
int no_printk(const char *fmt, ...)
{
    return 0;
}

#ifdef DEBUG
#define pr_devel(fmt, ...) \
    printk(KERN_DEBUG fmt, ##__VA_ARGS__)
#else
#define pr_devel(fmt, ...) \
    no_printk(KERN_DEBUG fmt, ##__VA_ARGS__)
#endif


#define init_net__proc_net proc_net

#include "compat.h"

#define xt_match            xt_compat_match
#define xt_register_match   xt_compat_register_match
#define xt_unregister_match xt_compat_unregister_match

#endif

