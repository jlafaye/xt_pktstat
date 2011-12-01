#include <linux/kernel.h>
#include <linux/netfilter/x_tables.h>

#include "compat.h"

static inline struct xt_compat_match *xtcompat_numatch(const struct xt_match *m)
{
    void *q;
    memcpy(&q, m->name + sizeof(m->name)-sizeof(void*), sizeof(void*));
    return q;
}

static int xt_compat_match(const struct sk_buff *skb,
                           const struct net_device *in,
                           const struct net_device *out,
                           const struct xt_match *match,
                           const void* matchinfo,
                           int offset,
                           unsigned int protoff,
                           int *hotdrop)
{
    bool ret;
    struct xt_compat_match *m = xtcompat_numatch(match);
    
    // prepare parameters
    // execute
    struct xt_action_param par;
    par.in        = in;
    par.out       = out;
    par.match     = match;
    par.matchinfo = matchinfo;
    par.fragoff   = offset;
    par.thoff     = protoff;
    par.hotdrop   = false;
    par.family    = NFPROTO_UNSPEC;

    ret = m->match(skb, &par);

    if (ret) return 0;

    return -1;
}

static int xt_compat_checkentry(const char* tablename,
                                const void* ip,
                                const struct xt_match* match,
                                void *matchinfo,
                                unsigned int matchinfosize,
                                unsigned int hook_mask) 
{
    struct xt_compat_match *m = xtcompat_numatch(match);

    struct xt_mtchk_param par;
    par.table     = tablename;
    par.entryinfo = NULL;
    par.match     = match;
    par.matchinfo = matchinfo;
    par.hook_mask = hook_mask;
    par.family    = NFPROTO_UNSPEC;
    
    // call wrapped method
    return m->checkentry(&par) == 0;
}

static void xt_compat_destroy(const struct xt_match* match, 
                              void *matchinfo,
                              unsigned int matchinfosize)
{
    struct xt_compat_match *m = xtcompat_numatch(match);

    struct xt_mtdtor_param par;
    par.match     = match;
    par.matchinfo = matchinfo;
    par.family    = NFPROTO_UNSPEC;

    // call wrapped method
    return m->destroy(&par);
}


int xt_compat_register_match(struct xt_compat_match *nt)
{
    struct xt_match *ct;
    char *tmp;
    int ret;

    ct = kzalloc(sizeof(struct xt_match), GFP_KERNEL);
    if (ct == NULL)
        return -ENOMEM;

    tmp = (char *)ct->name;
    memcpy(tmp, nt->name, sizeof(nt->name));
    tmp = (char *)(ct->name + sizeof(ct->name) - sizeof(void*));
    *(tmp-1) = '\0';
    memcpy(tmp, &nt, sizeof(void *));

    ct->revision = nt->revision;
    ct->family   = nt->family;
    ct->table    = (char *)nt->table;
    ct->hooks    = nt->hooks;
    ct->proto    = nt->proto;

    ct->match      = xt_compat_match;
    ct->checkentry = xt_compat_checkentry;
    ct->destroy    = xt_compat_destroy;
        
    ct->matchsize  = nt->matchsize;
    ct->me         = nt->me;
        
    nt->__compat_match = ct;
    ret = xt_register_match(ct);
    if (ret != 0)
        kfree(ct);
    return ret;
}

EXPORT_SYMBOL_GPL(xt_compat_register_match);

void xt_compat_unregister_match(struct xt_compat_match *nt)
{
    xt_unregister_match(nt->__compat_match);
    kfree(nt->__compat_match);
}
