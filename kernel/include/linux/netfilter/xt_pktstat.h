#ifndef _XT_PKTSTAT_H
#define _XT_PKTSTAT_H

#define PKTSTAT_PERIOD  0x01
#define PKTSTAT_SAMPLES 0x02
#define PKTSTAT_IP_SRC  0x04
#define PKTSTAT_IP_DST  0x08

#include <linux/netfilter.h>

struct xt_pktstat_ctx;

struct xt_pktstat_info {

    u_int32_t       flags;
    u_int32_t       samples;
    aligned_u64     period;

    /* Used internally by the kernel */
    struct xt_pktstat_ctx *ctx __attribute__((aligned(8)));
};


#endif  
