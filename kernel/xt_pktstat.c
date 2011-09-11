
#define DEBUG
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/hrtimer.h>
#include <linux/proc_fs.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/kfifo.h>
#include <linux/version.h>
#include <net/net_namespace.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_pktstat.h>

struct xt_pktstat_sample {
    ktime_t     tstamp;
    u_int32_t   total_count;
    u_int32_t   total_bytes;
};

// static DECLARE_KFIFO_PTR(kfifo_sample_ptr, struct xt_pktstat_sample);

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
    DECLARE_KFIFO_PTR(samples, struct xt_pktstat_sample);

    // /proc export
    struct proc_dir_entry*    proc_dir;
    struct proc_dir_entry*    proc_entry_data;
    struct proc_dir_entry*    proc_entry_conf;
};

static atomic_t rule_idx = ATOMIC_INIT(-1);
static struct proc_dir_entry *proc_xt_pktstat;

/* 1 64bits number and 2 32bits numbers */
/* 20 + 2*10 + 3 chars */
#define MAX_LINE_SIZE 64

static int pktstat_proc_read(char *page, char **start, off_t offset,
                             int count, int *eof, void* data)
{
    struct xt_pktstat_ctx* ctx = data;
    struct xt_pktstat_sample sample;
    int pos = 0;
    int len = count;
    int quota = ctx->samples_len;

    while (len>MAX_LINE_SIZE && quota--) {
        int ret;
        unsigned int res = kfifo_out(&ctx->samples, &sample, 1);
        // no more data
        if (res == 0)
            break; 
        // unable to pop
        if (res < 1) {
            printk(KERN_DEBUG "xt_pktstat[%d]: unable to pop item: %u\n", ctx->rule_idx, res);
            return pos; 
        }
        ret = snprintf(page+pos, len, "%llu %u %u\n",
                      (unsigned long long)sample.tstamp.tv64,
                      sample.total_count, 
                      sample.total_bytes);
        pos += ret;
        len -= ret;
    }

    return pos;
}

static int pktstat_proc_read_conf(char *page, char **start, off_t offset,
                                  int count, int* eof, void* data)
{
    struct xt_pktstat_info* info = data;

    int pos = 0;
    int len = count;
    int ret;
    ret  = snprintf(page+pos, len-pos, "period\t\t: %llu\n",
                    info->period); pos += ret;
    ret  = snprintf(page+pos, len-pos, "samples\t\t: %u\n",
                    info->samples); pos += ret;

    // TODO: to retrieve src and dst, we need to retrieve
    // corresponding xt_entry_target

    return pos;
}


static bool pktstat_mt4_match(const struct sk_buff *skb, 
                              struct xt_action_param *param)
{
    unsigned int ret;
    ktime_t ts;
    const struct xt_pktstat_info *info = param->matchinfo;
    struct xt_pktstat_ctx* ctx = info->ctx;
    struct xt_pktstat_sample sample;
    
#ifdef DEBUG
    int attempts = 0;
    int throttle = 10;
#endif
    
    // get timestamp if no timestamp
    // TODO: use kernel variable to automatically activate packet timestamping ?
    // no: because our rule might not apply to all packets
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
        sample.tstamp.tv64 = curr.tv64;
        sample.total_count = ctx->total_count;
        sample.total_bytes = ctx->total_bytes;

        // push sample in the fifo  
        ret = kfifo_put(&ctx->samples, &sample);
        if (ret < 1) {
            pr_devel("xt_pktstat[%d] unable to put sample onto the fifo: %u\n",
                     ctx->rule_idx, ret);
        }

        ctx->next = ktime_add(ctx->next, ctx->period);
    }

    // update statistics
    ctx->total_count += 1;
    ctx->total_bytes += skb->len;
    pr_devel("xt_pktstat[%d] total_count:%d total_bytes:%d\n", 
             ctx->rule_idx, ctx->total_count, ctx->total_bytes);

    return true; 
}

static int pktstat_mt4_checkentry(const struct xt_mtchk_param* param)
{

    ktime_t now;
    // int i;
    struct xt_pktstat_info *info = param->matchinfo;
    struct xt_pktstat_ctx  *ctx  = 0;
    uint64_t now64;
    char buf[64];

    pr_devel("xt_pktstat: added a rule, period:%llunsecs, samples:%u flags:0x%04x",
             info->period, info->samples, info->flags);

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

    if (kfifo_alloc(&ctx->samples, info->samples, GFP_KERNEL))
        goto error;

    ctx->total_count = 0;
    ctx->total_bytes = 0;
    ctx->curr_sample = 0;
    ctx->samples_len = info->samples;

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
        kfifo_free(&ctx->samples);
        // kfree(ctx->samples);
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

    printk(KERN_INFO "xt_pktstat: init! size:%d\n", sizeof(struct xt_pktstat_info));
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
