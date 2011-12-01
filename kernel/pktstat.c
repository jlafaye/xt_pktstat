/*
 * xt_pktstat - high frequency packet accounting
 * by Julien Lafaye <jlafaye@gmail.com>, 2011
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License; either
 *	version 2 of the License, as published by the Free Software Foundation.
 */
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
#include <linux/seq_file.h>
#include <linux/version.h>
#include <net/net_namespace.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_pktstat.h>

struct xt_pktstat_sample {
    ktime_t     tstamp;
    u_int32_t   total_count;
    u_int32_t   total_bytes;
};

struct iterator {
    u_int32_t   credit;
};

struct xt_pktstat_ctx {
    struct list_head list;
    atomic_t         ref;

    ktime_t     period;
    ktime_t     next;
    spinlock_t  lock;

    // statistics
    u_int32_t                 total_count;
    u_int32_t                 total_bytes; 
    u_int32_t                 curr_sample;
    u_int32_t                 samples_len;
    DECLARE_KFIFO_PTR(samples, struct xt_pktstat_sample);

    char name[sizeof(((struct xt_pktstat_info*)NULL)->name)];

    // /proc export
    struct proc_dir_entry*    proc_dir;
    struct proc_dir_entry*    proc_entry_data;
    struct proc_dir_entry*    proc_entry_conf;
};

static LIST_HEAD(xt_pktstat_ctx_list);
static DEFINE_SPINLOCK(xt_pktstat_ctx_list_lock);

// static atomic_t rule_idx = ATOMIC_INIT(-1);
static struct proc_dir_entry* proc_xt_pktstat;

/* 1 64bits number and 2 32bits numbers */
/* 20 + 2*10 + 3 chars */
#define MAX_LINE_SIZE 64

// seq file for /proc
static void* pktstat_proc_seq_start(struct seq_file* s, loff_t* pos)
{
    struct xt_pktstat_ctx* ctx = s->private;

    pr_devel("xt_pktstat[%s]: proc/start: pos=%d\n", ctx->name, (int)*pos);

    if (*pos >= ctx->samples_len)
        return NULL;

    return pos;
}

static void* pktstat_proc_seq_next(struct seq_file* s, void* v, loff_t* pos)
{
    struct xt_pktstat_ctx* ctx = s->private;

    pr_devel("xt_pktstat[%s]: proc/next: pos=%d\n", ctx->name, (int)*pos);

    // we've exhausted our quota
    if (*pos >= ctx->samples_len)
        return NULL;

    ++(*pos);

    return pos;
}

static void pktstat_proc_seq_stop(struct seq_file* s, void* v)
{
    pr_devel("xt_pktstat: proc/stop\n");
}

static int pktstat_proc_seq_show(struct seq_file* s, void* v)
{
    struct xt_pktstat_ctx* ctx = s->private;
    struct xt_pktstat_sample sample;
    unsigned int res;
    
    pr_devel("xt_pktstat[%s]: proc/show pos\n",
             ctx->name);

    // pop a statistics sample, if available
    spin_lock_bh(&ctx->lock); 
    res = kfifo_out(&ctx->samples, &sample, 1);
    spin_unlock_bh(&ctx->lock); 

    // empty fifo, stop iteration
    if (!res) {
        return 0;
    }

    // write single line
    seq_printf(s, "%llu %u %u\n",
              (unsigned long long)sample.tstamp.tv64,
              sample.total_count, 
              sample.total_bytes);
    return 0;
}

static struct seq_operations pktstat_proc_seq_ops = {
    .start = pktstat_proc_seq_start,
    .next  = pktstat_proc_seq_next,
    .stop  = pktstat_proc_seq_stop,
    .show  = pktstat_proc_seq_show
};

static int pktstat_proc_seq_open(struct inode* inode, struct file* file)
{
    struct seq_file* s; 
    int res = seq_open(file, &pktstat_proc_seq_ops);
    pr_devel("xt_pktstat: proc/open: seq_open)\n");
    if (res) 
        return res;

    // file->private_data was initialized by seq_open
    s = (struct seq_file*)file->private_data;

    if (s->private) {
        printk(KERN_DEBUG "xt_pktstat: proc/open: invalid initialization\n");
        return -EINVAL;
    }

    // use xt_pktstat_ctx as private data
    s->private = PROC_I(inode)->pde->data;
    return res;
}

static struct file_operations pktstat_proc_file_ops = {
    .owner   = THIS_MODULE,
    .open    = pktstat_proc_seq_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = seq_release
};

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


static bool pktstat_mt4_match(const struct sk_buff*         skb, 
                                    struct xt_action_param* param)
{
    unsigned int ret;
    ktime_t ts;
    const struct xt_pktstat_info* info = param->matchinfo;
    struct xt_pktstat_ctx* ctx = info->ctx;
    struct xt_pktstat_sample sample;
    
    // get timestamp if no timestamp
    ts = skb->tstamp;
    if (ts.tv64 == 0) {
        ts = ktime_get_real();
    }

    pr_devel("xt_pktstat[%s] skb:%p info:%p next:%llu@%p period:%llu\n", 
             ctx->name, skb, info, 
             ctx->next.tv64, &ctx->next, ctx->period.tv64); 
    
    spin_lock_bh(&ctx->lock);

    // if period has changed, we need to push statistics
    if (ctx->next.tv64 < ts.tv64) {
        ktime_t prevnext = ctx->next;

        // adjust next logging timestamp
        while (ctx->next.tv64 < ts.tv64) {
            prevnext  = ctx->next;
            ctx->next = ktime_add(ctx->next, ctx->period);
        }

        // build sample
        sample.tstamp.tv64 = prevnext.tv64;
        sample.total_count = ctx->total_count;
        sample.total_bytes = ctx->total_bytes;

        // push sample in the fifo  
        ret = kfifo_put(&ctx->samples, &sample);

#ifdef DEBUG
        if (ret < 1) {
            pr_devel("xt_pktstat[%s] unable to put sample onto the fifo: %u\n",
                     ctx->name, ret);
        } 
        else {
            pr_devel("xt_pkstat[%s] %d samples put into the fifo",
                     ctx->name, ret);
        }
#endif
    }

    // update statistics
    ctx->total_count += 1;
    ctx->total_bytes += skb->len;

    spin_unlock_bh(&ctx->lock);

    pr_devel("xt_pktstat[%s] total_count:%d total_bytes:%d\n", 
             ctx->name, ctx->total_count, ctx->total_bytes);

    return true; 
}

static struct xt_pktstat_ctx *
pktstat_create_xt_pktstat_ctx(const struct xt_pktstat_info* info)
{
    struct xt_pktstat_ctx *ctx;
    ktime_t now;
    uint64_t now64;

    // allocate and initialize xt_pktstat_ctx
    pr_devel(KERN_DEBUG "xt_pkstat: allocating a xt_pktstat_ctx of size %d\n", sizeof(*info->ctx));
    ctx = kmalloc(sizeof(*info->ctx), GFP_KERNEL);
    if (ctx == NULL)
        return NULL;
    
    // initialize
    atomic_set(&ctx->ref, 1);
    spin_lock_init(&ctx->lock);
    strcpy(ctx->name, info->name);
    INIT_LIST_HEAD(&ctx->list);

    // create procfs directory & entries
    ctx->proc_dir = proc_mkdir(ctx->name, proc_xt_pktstat);
    if (ctx->proc_dir == NULL)
        goto error;

    // ... data
    ctx->proc_entry_data = 
        create_proc_entry("data", S_IRUGO | S_IWUSR, ctx->proc_dir);
    if (ctx->proc_entry_data == NULL)
        goto error;

    // data read handled by seq_file API
    ctx->proc_entry_data->data      = ctx;
    ctx->proc_entry_data->proc_fops = &pktstat_proc_file_ops;

    // ... conf
    ctx->proc_entry_conf = 
            create_proc_entry("config", S_IRUGO | S_IWUSR, ctx->proc_dir);
    if (ctx->proc_entry_conf == NULL) 
        goto error;
    ctx->proc_entry_conf->read_proc = pktstat_proc_read_conf;
    ctx->proc_entry_conf->data      = (void*)info;

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
    now64    = (now64)*info->period;
    now.tv64 = now64;

    // schedule next stat rotation
    ctx->next = ktime_add(now, ctx->period);
        /*
           printk(KERN_DEBUG "xt_pktstat[%d]: next: %llu@%p\n", 
           ctx->rule_idx, ctx->next.tv64, &ctx->next);*/

        // pktstat_dbg = (unsigned long long*)&ctx->next;
        // DEBUG_TS;
    printk(KERN_INFO "xt_pktstat[%s]: added a rule, "
                    "period:%llunsecs, samples:%u flags:0x%04x\n", 
                    ctx->name, info->period, info->samples, info->flags);
    return ctx;

  error:
    if (ctx) {
        if (ctx->proc_dir) {
            remove_proc_entry("data",    ctx->proc_dir);
            remove_proc_entry("config",  ctx->proc_dir);
            remove_proc_entry(ctx->name, proc_xt_pktstat);
        }
        kfifo_free(&ctx->samples);
    }
    kfree(ctx);
    return NULL; 
}

static struct xt_pktstat_ctx *
pktstat_get_xt_pktstat_ctx(const struct xt_pktstat_info* info)
{
    struct xt_pktstat_ctx *ctx;

    spin_lock_bh(&xt_pktstat_ctx_list_lock);
    list_for_each_entry(ctx, &xt_pktstat_ctx_list, list)
        if (strcmp(ctx->name, info->name) == 0) {
            atomic_inc(&ctx->ref);
            spin_unlock_bh(&xt_pktstat_ctx_list_lock);
            return ctx;
        }

    ctx = pktstat_create_xt_pktstat_ctx(info);
    if (ctx == NULL)
        goto error;

    list_add_tail(&ctx->list, &xt_pktstat_ctx_list);
    spin_unlock_bh(&xt_pktstat_ctx_list_lock);
    return ctx;

  error:
    spin_unlock_bh(&xt_pktstat_ctx_list_lock);
    return NULL;
}

static int pktstat_mt4_checkentry(const struct xt_mtchk_param* param)
{
    struct xt_pktstat_info* info = param->matchinfo;
    struct xt_pktstat_ctx * ctx  = 0;

    info->name[sizeof(info->name)-1] = '\0';
    if (    *info->name == '\0' 
         || *info->name == '.' 
         || strchr(info->name, '/') != NULL) {
        printk(KERN_ERR "xt_pktstat: illegal name\n");
        return -EINVAL;
    }
    
    pr_devel("xt_pktstat: added a rule, period:%llunsecs, samples:%u flags:0x%04x",
             info->period, info->samples, info->flags);

    // check parameters
    if (!info->period || !info->samples) {
        printk(KERN_ERR "xt_pkstat: invalid parameters\n");
        return -EINVAL;
    }

    ctx = pktstat_get_xt_pktstat_ctx(info); 

    if (ctx == NULL) {
        printk(KERN_ERR "xt_pktstat: unable to acquire xt_pktstat_ctx\n");
        return -ENOMEM;
    }

    info->ctx = ctx;
    
    return 0;
}

static void pktstat_mt4_destroy(const struct xt_mtdtor_param* param)
{
    const struct xt_pktstat_info *info = param->matchinfo;
          struct xt_pktstat_ctx *ctx   = info->ctx;

    if (ctx == NULL)
        return;
    
    spin_lock_bh(&xt_pktstat_ctx_list_lock);
    if (!atomic_dec_and_test(&ctx->ref)) {
        spin_unlock_bh(&xt_pktstat_ctx_list_lock);
        return;
    }

    list_del(&ctx->list);

    // release the xt_pktstat_ctx if necessary
    if (ctx) {
        if (ctx->proc_dir) {
            remove_proc_entry("data",   ctx->proc_dir);
            remove_proc_entry("config", ctx->proc_dir);
            remove_proc_entry(ctx->name, proc_xt_pktstat);
        } 
        printk(KERN_INFO "xt_pkstat[%s]: destroying rule\n", ctx->name);
    }
    kfree(ctx);
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
