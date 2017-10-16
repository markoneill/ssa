#include <net/netlink.h>
#include <net/genetlink.h>
#include "netlink.h"

int nl_fail(struct sk_buff* skb, struct genl_info* info);

static const struct nla_policy ssa_nl_policy[SSA_NL_A_MAX + 1] = {
        [SSA_NL_A_UNSPEC] = { .type = NLA_UNSPEC },
        [SSA_NL_A_SOCKADDR_INTERNAL] = { .type = NLA_UNSPEC },
        [SSA_NL_A_SOCKADDR_EXTERNAL] = { .type = NLA_UNSPEC },
};

static struct genl_ops ssa_nl_ops[] = {
        {
                .cmd = SSA_NL_C_NOTIFY,
                .flags = GENL_ADMIN_PERM,
                .policy = ssa_nl_policy,
                .doit = nl_fail,
                .dumpit = NULL,
        },
};

static const struct genl_multicast_group ssa_nl_grps[] = {
        [SSA_NL_NOTIFY] = { .name = "notify", },
};

static struct genl_family ssa_nl_family = {
        .module = THIS_MODULE,
        .ops = ssa_nl_ops,
        .n_ops = ARRAY_SIZE(ssa_nl_ops),
        .mcgrps = ssa_nl_grps,
        .n_mcgrps = ARRAY_SIZE(ssa_nl_grps),
        .hdrsize = 0,
        .name = "SSA",
        .version = 1,
        .maxattr = SSA_NL_A_MAX,
};

int nl_fail(struct sk_buff* skb, struct genl_info* info) {
        printk(KERN_ALERT "Kernel receieved an SSA netlink notificatio. This should never happen.\n");
        return -1;
}
 
int register_netlink() {
	return genl_register_family(&ssa_nl_family);
}

void unregister_netlink() {
	genl_unregister_family(&ssa_nl_family);
	return;
}

int send_listen_notify(struct sockaddr* internal, struct sockaddr* external) {
	struct sk_buff* skb;
	int ret;
	void* msg_head;

	skb = genlmsg_new(sizeof(struct sockaddr) * 2, GFP_ATOMIC);
	if (skb == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_new\n");
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, SSA_NL_C_NOTIFY);
	if (msg_head == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_put\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_SOCKADDR_INTERNAL, sizeof(struct sockaddr), internal);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (internal)\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_SOCKADDR_EXTERNAL, sizeof(struct sockaddr), external);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (external)\n");
		nlmsg_free(skb);
		return -1;
	}
	genlmsg_end(skb, msg_head);
	ret = genlmsg_multicast(&ssa_nl_family, skb, 0, SSA_NL_NOTIFY, GFP_ATOMIC);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in genlmsg_multicast\n");
		return -1;
	}
	return 0;
}

