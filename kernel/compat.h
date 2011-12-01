
enum {
	NFPROTO_UNSPEC =  0,
	NFPROTO_IPV4   =  2,
	NFPROTO_ARP    =  3,
	NFPROTO_BRIDGE =  7,
	NFPROTO_IPV6   = 10,
	NFPROTO_DECNET = 12,
	NFPROTO_NUMPROTO,
};

struct xt_mtchk_param {
	const char *table;
	const void *entryinfo;
	const struct xt_match *match;
	void *matchinfo;
	unsigned int hook_mask;
	u_int8_t family;
};

struct xt_mtdtor_param {
	const struct xt_match *match;
	void *matchinfo;
	u_int8_t family;
};

struct xt_action_param {
	union {
		const struct xt_match *match;
		const struct xt_target *target;
	};
	union {
		const void *matchinfo, *targinfo;
	};
	const struct net_device *in, *out;
	int fragoff;
	unsigned int thoff, hooknum;
	u_int8_t family;
	bool hotdrop;
};

struct xt_compat_match {
	/*
	 * Making it smaller by sizeof(void *) on purpose to catch
	 * lossy translation, if any.
	 */
	char name[sizeof(((struct xt_match *)NULL)->name) - 1 - sizeof(void *)];
	uint8_t revision;
	bool (*match)(const struct sk_buff *, struct xt_action_param *);
	int (*checkentry)(const struct xt_mtchk_param *);
	void (*destroy)(const struct xt_mtdtor_param *);
	struct module *me;
	const char *table;
	unsigned int matchsize, hooks;
	unsigned short proto, family;

	void *__compat_match;
};

int  xt_compat_register_match(struct xt_compat_match*);
void xt_compat_unregister_match(struct xt_compat_match*);
