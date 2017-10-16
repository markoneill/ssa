#ifndef NETLINK_H
#define NETLINK_H

#include <linux/socket.h>

// Attributes
enum {
        SSA_NL_A_UNSPEC,
	SSA_NL_A_SOCKADDR_INTERNAL,
	SSA_NL_A_SOCKADDR_EXTERNAL,
        SSA_NL_A_PAD,
        __SSA_NL_A_MAX,
};

#define SSA_NL_A_MAX (__SSA_NL_A_MAX - 1)

// Operations
enum {
        SSA_NL_C_UNSPEC,
        SSA_NL_C_NOTIFY,
        __SSA_NL_C_MAX,
};

#define SSA_NL_C_MAX (__SSA_NL_C_MAX - 1)

// Multicast group
enum ssa_nl_groups {
        SSA_NL_NOTIFY,
};


int register_netlink(void);
int send_listen_notify(struct sockaddr* internal, struct sockaddr* external);
void unregister_netlink(void);

#endif
