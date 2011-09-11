#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <linux/netfilter/xt_pktstat.h>

/* 
 * iptables -m pktstat -h 
 */
static void pktstat_mt_help(void)
{
   printf (
            "PKTSTAT v%s options:\n"
            "    --period  <msecs>\t\tSampling period.\n"
            "    --samples <number>\t\tNumber of samples to buffer.\n"
            "\n", XTABLES_VERSION
         );
}


static const struct option pktstat_mt_opts[] = {
    { .name = "samples", .has_arg = true, .val = 's' },
    { .name = "period",  .has_arg = true, .val = 'p' },
    { .name = NULL }
};

static void pktstat_mt_init(struct xt_entry_match *match)
{
    struct xt_pktstat_info* info = (struct xt_pktstat_info*)(match)->data;
    info->flags    = 0;
    info->samples  = 0;
    info->period   = 0;
}


static int pktstat_mt4_parse(int c, char **argv, int invert, unsigned int *flags,
                             const void *entry, struct xt_entry_match **match)
{
    printf("+++ pktstat_mt4_parse(c=%c,optarg=%s, argv=, value=)\n", c, optarg);
     //       c, optind, argv[optind], argv[optind+1]);
    struct xt_pktstat_info* info = (struct xt_pktstat_info*)(*match)->data;

    switch (c) {
        /* --period */
        case 'p':
            //xtables_param_act(XTF_ONLY_ONCE, "pktstat", "--period", *flags & PKTSTAT_PERIOD);
            info->period  = (uint64_t)atol(optarg) * 1000000L;
            *flags  |= PKTSTAT_PERIOD;
            break;
        /* --samples */
        case 's':
            //info->samples = atoi(argv[optind+1]);
            info->samples = atoi(optarg);
            *flags  |= PKTSTAT_SAMPLES;
            break;
        default:
            return false;
    }

    return true;
}

static void pktstat_mt_check(unsigned int flags)
{
    if (!(flags & PKTSTAT_PERIOD) || !(flags & PKTSTAT_SAMPLES)) {
      xtables_error(PARAMETER_PROBLEM, "xt_pktstat: Invalid parameters.");
    }

}


static void pktstat_mt4_print(const void *entry,
                             const struct xt_entry_match *match,
                             int numeric)
{
    const struct xt_pktstat_info *info = (const struct xt_pktstat_info *)match->data;

    if (info->flags & PKTSTAT_SAMPLES) {
        printf("samples %u ", info->samples);
    }

    if (info->flags & PKTSTAT_PERIOD) {
        printf("period %llu ", info->period);
    }

}

/* 
 * iptables-saves
 */
static void pktstat_mt4_save(const void *entry, const struct xt_entry_match *match)
{
    const struct xt_pktstat_info *info = (const struct xt_pktstat_info *)match->data;


    if (info->flags & PKTSTAT_PERIOD) {
        printf("--period %llu", info->period / 1000000);
    }

    if (info->flags & PKTSTAT_SAMPLES) {
        printf("--samples %u", info->samples);
    }

}

static struct xtables_match pktstat_mt4_reg
= {
    .version         = XTABLES_VERSION,
    .name            = "pktstat",
    .revision        = 0,
    .family          = NFPROTO_IPV4,
    .size            = XT_ALIGN(sizeof(struct xt_pktstat_info)),
    .userspacesize   = offsetof(struct xt_pktstat_info, ctx),
    .help            = pktstat_mt_help,
    .init            = pktstat_mt_init,
    .parse           = pktstat_mt4_parse,
    .final_check     = pktstat_mt_check,
    .print           = pktstat_mt4_print,
    .save            = pktstat_mt4_save,
    .extra_opts      = pktstat_mt_opts
};

static void _init(void)
{
    xtables_register_match(&pktstat_mt4_reg);
}
