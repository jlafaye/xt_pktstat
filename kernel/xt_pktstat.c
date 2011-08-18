#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/hrtimer.h>
#include <linux/proc_fs.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/version.h>
#include <net/net_namespace.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_pktstat.h>

struct xt_pktstat_sample {
    ktime_t     tstamp;
    u_int32_t   total_count;
    u_int32_t   total_bytes;
};

struct xt_pktstat_ctx {
    ktime_t period;
    ktime_t next;
    int     rule_idx;

    // statistics
    u_int32_t                 total_count;
    u_int32_t                 total_bytes; 
    u_int32_t                 curr_sample;
    spinlock_t                samples_lock;
    u_int32_t                 samples_len;
    struct xt_pktstat_sample* samples;

    // /proc export
    struct proc_dir_entry*    proc_dir;
    struct proc_dir_entry*    proc_entry_data;
    struct proc_dir_entry*    proc_entry_conf;
};

static atomic_t rule_idx = ATOMIC_INIT(-1);
static struct proc_dir_entry *proc_xt_pktstat;

static int pktstat_proc_read(char *page, char **start, off_t offset,
                             int count, int *eof, void* data)
{
    struct xt_pktstat_ctx* ctx = data;
    int i = 0;
    int pos = 0;
    int len = count;
    int ret;
    int curr_sample = ctx->curr_sample;

    spin_lock_bh(&ctx->samples_lock);
    while (len > 0 && i < ctx->samples_len) {
        ret = snprintf(page+pos, len, "%llu %u %u\n",
                       (unsigned long long)ctx->samples[curr_sample].tstamp.tv64,
                       ctx->samples[curr_sample].total_count, 
                       ctx->samples[curr_sample].total_bytes);
        ++curr_sample;
        if (curr_sample >= ctx->samples_len)
            curr_sample = 0;
        pos += ret;
        len -= ret;
        ++i;
    }
    spin_unlock_bh(&ctx->samples_lock);

    return pos;
}

static int pktstat_proc_read_conf(char *page, char **start, off_t offset,
                                  int count, int* eof, void* data)
{
    struct xt_pktstat_info* info = data;

    int pos = 0;
    int len = count;
    int ret;
   
    ret  = snprintf(page+pos, len-pos, "ipsrc\t\t: %pI4/%pI4\n",
                    &info->src.in, &info->smask.in); pos += ret;
    ret  = snprintf(page+pos, len-pos, "ipdst\t\t: %pI4/%pI4\n",
                    &info->dst.in, &info->dmask.in); pos += ret;
    ret  = snprintf(page+pos, len-pos, "period\t\t: %llu\n",
                    info->period); pos += ret;
    ret  = snprintf(page+pos, len-pos, "samples\t\t: %u\n",
                    info->samples); pos += ret;
    return pos;
}


static bool pktstat_mt4_match(const struct sk_buff *skb, 
                              struct xt_action_param *param)
{
    ktime_t ts;
    const struct xt_pktstat_info *info = param->matchinfo;
    struct xt_pktstat_ctx* ctx = info->ctx;
    
#ifdef DEBUG
    int throttle = 10;
#endif
    
    // check if the current rule applies to the packet
    const struct iphdr *iph = ip_hdr(skb);
    if (iph == NULL)
        return false;
    // printk(KERN_DEBUG "xt_pktstat: src:%pI4 rule:%pI4/%pI4\n",
    //        &iph->saddr, &info->src.in, &info->smask.in);
            
    if ((iph->saddr & info->smask.ip) != info->src.ip)
        return false;
    if ((iph->daddr & info->dmask.ip) != info->dst.ip)
        return false;
    
    // get timestamp if no timestamp
    ts = skb->tstamp;
    if (ts.tv64 == 0) {
        ts = ktime_get_real();
    }

    pr_devel("xt_pktstat[%d] skb:%p info:%p next:%llu@%p period:%llu\n", 
             ctx->rule_idx, skb, info, 
             ctx->next.tv64, &ctx->next, ctx->period.tv64); 

    while (ctx->next.tv64 < ts.tv64) {
        ktime_t curr = ctx->next;

#ifdef DEBUG
        --throttle;
        if (throttle == 0) {
            pr_devel("xt_pktstat[%d] weird clock\n",
                    ctx->rule_idx);
            pr_devel("xt_pktstat[%d] next:%llu\n", ctx->rule_idx, ctx->next.tv64);
            pr_devel("xt_pktstat[%d]   ts:%llu\n", ctx->rule_idx, ts.tv64);
            return true;
        }
#endif

        /*
        printk(KERN_DEBUG "xt_pktstat: ts: %llu total_count:%u total_bytes:%u\n",
               (unsigned long long)ctx->next.tv64, ctx->total_count, ctx->total_bytes);
        */

        // backup statistics
        spin_lock_bh(&ctx->samples_lock);
        ctx->samples[ctx->curr_sample].tstamp.tv64 = curr.tv64;
        ctx->samples[ctx->curr_sample].total_count = ctx->total_count;
        ctx->samples[ctx->curr_sample].total_bytes = ctx->total_bytes;

        // change sample
        ++ctx->curr_sample;
        if (ctx->curr_sample >= info->samples) {
            ctx->curr_sample = 0;
        }
        spin_unlock_bh(&ctx->samples_lock);

        ctx->next = ktime_add(ctx->next, ctx->period);
    }

    // update statistics
    ctx->total_count += 1;
    ctx->total_bytes += skb->len;

    return true; 
}

static int pktstat_mt4_checkentry(const struct xt_mtchk_param* param)
{

    ktime_t now;
    int i;
    struct xt_pktstat_info *info = param->matchinfo;
    struct xt_pktstat_ctx  *ctx  = 0;
    uint64_t now64;
    char buf[64];

    pr_devel("xt_pktstat: added a rule, period:%llunsecs, samples:%u flags:0x%04x"
             "%pI4/%pI4->%pI4/%pI4",
             info->period, info->samples, info->flags,
             &info->src.in, &info->smask.in, &info->dst.in, &info->dmask.in);

    // check parameters
    if (!info->period || !info->samples) {
        printk(KERN_ERR "xt_pkstat: invalid parameters\n");
        return -EINVAL;
    }

    // allocate and initialize context
    pr_devel(KERN_DEBUG "xt_pkstat: allocating a context of size %d\n", sizeof(*info->ctx));
    ctx = kmalloc(sizeof(*info->ctx), GFP_KERNEL);
    if (ctx == NULL)
        goto error;
    ctx->rule_idx = atomic_add_return(1, &rule_idx);
    spin_lock_init(&ctx->samples_lock);
    info->ctx = ctx;

    // create procfs directory & entries
    snprintf(buf, 64, "%d", ctx->rule_idx);
    ctx->proc_dir = proc_mkdir(buf, proc_xt_pktstat);
    if (ctx->proc_dir == NULL)
        goto error;

    // ... data
    ctx->proc_entry_data = 
        create_proc_entry("data", S_IRUGO | S_IWUSR, ctx->proc_dir);
    if (ctx->proc_entry_data == NULL)
        goto error;
    ctx->proc_entry_data->read_proc = pktstat_proc_read;
    ctx->proc_entry_data->data      = ctx;
    
    // ... conf
    ctx->proc_entry_conf = 
        create_proc_entry("config", S_IRUGO | S_IWUSR, ctx->proc_dir);
    if (ctx->proc_entry_conf == NULL) 
        goto error;
    ctx->proc_entry_conf->read_proc = pktstat_proc_read_conf;
    ctx->proc_entry_conf->data      = info;

    // allocate and initialize counters
    pr_devel("xt_pktstat: allocating %u bytes\n",
             info->samples*sizeof(struct xt_pktstat_sample));     
    ctx->samples = kmalloc(sizeof(struct xt_pktstat_sample)*info->samples, GFP_KERNEL);
    if (ctx->samples == NULL) 
        goto error;
    ctx->total_count = 0;
    ctx->total_bytes = 0;
    ctx->curr_sample = 0;
    ctx->samples_len = info->samples;
    for (i=0; i<ctx->samples_len; ++i) {
        ctx->samples[i].tstamp.tv64 = 0;
        ctx->samples[i].total_count = 0;
        ctx->samples[i].total_bytes = 0;
    }

    // round now to the closest inferior period multiple
    ctx->period.tv64 = info->period;
    now = ktime_get_real();
    // printk(KERN_DEBUG "xt_pktstat[%d]:  now: %llup\n", ctx->rule_idx, now.tv64);
    now64    = (uint64_t)now.tv64;
    do_div(now64, info->period);
    now64 = (now64)*info->period;
    now.tv64 = now64;

    // schedule next stat rotation
    ctx->next = ktime_add(now, ctx->period);
    /*
    printk(KERN_DEBUG "xt_pktstat[%d]: next: %llu@%p\n", 
           ctx->rule_idx, ctx->next.tv64, &ctx->next);*/

    // pktstat_dbg = (unsigned long long*)&ctx->next;
    // DEBUG_TS;
    printk(KERN_INFO "xt_pktstat[%02d]: added a rule, "
                     "period:%llunsecs, samples:%u flags:0x%04x\n", 
                     ctx->rule_idx, info->period, info->samples, info->flags);
    
    return 0;

  error:
    if (ctx) {
        if (ctx->proc_dir) {
            remove_proc_entry("data",   ctx->proc_dir);
            remove_proc_entry("config", ctx->proc_dir);
            snprintf(buf, sizeof(buf), "%d", ctx->rule_idx);
            remove_proc_entry(buf, proc_xt_pktstat);
        }
        kfree(ctx->samples);
    }
    kfree(info->ctx);
    return -ENOMEM;
}

static void pktstat_mt4_destroy(const struct xt_mtdtor_param* param)
{
    char buf[64];
    const struct xt_pktstat_info *info = param->matchinfo;
    const struct xt_pktstat_ctx  *ctx  = info->ctx;

    // release the context if necessary
    if (ctx) {
        if (ctx->proc_dir) {
            remove_proc_entry("data",   ctx->proc_dir);
            remove_proc_entry("config", ctx->proc_dir);
            snprintf(buf, sizeof(buf), "%d", ctx->rule_idx);
            remove_proc_entry(buf, proc_xt_pktstat);
        } 
        printk(KERN_INFO "xt_pkstat[%02d]: destroying rule\n", ctx->rule_idx);
    }
    kfree(info->ctx);


}


static struct xt_match pktstat_mt4_reg = {
    .name       = "pktstat",
    .revision   = 0,
    .family     = NFPROTO_IPV4,
    .match      = &pktstat_mt4_match,
    .checkentry = &pktstat_mt4_checkentry,
    .destroy    = &pktstat_mt4_destroy,
    .matchsize  = sizeof(struct xt_pktstat_info), // ??????
    .me         = THIS_MODULE
};

static int __init init(void)
{
    proc_xt_pktstat = proc_mkdir("xt_pktstat", init_net.proc_net);
    if (proc_xt_pktstat == NULL) {
        printk(KERN_ERR "xt_pkstat: unable to create procfs entry\n");
        return ENOENT;
    }

    printk(KERN_INFO "xt_pktstat: init!\n");
    return xt_register_match(&pktstat_mt4_reg); 
}

static void __exit fini(void)
{
    remove_proc_entry("xt_pktstat", init_net.proc_net);
    printk(KERN_INFO "xt_pktstat: exit!\n");
    return xt_unregister_match(&pktstat_mt4_reg);
}

module_init(init);
module_exit(fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Julien Lafaye");
MODULE_DESCRIPTION("netfilter module xt_pktstat");
