#ifndef _TLS_PROTO_H
#define _TLS_PROTO_H

#include <linux/socket.h>
#include <net/sock.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h> // for current (pointer to task)
#include <linux/hashtable.h>

/* Holds all variables for socket options */
typedef struct tls_sock_ops {
        unsigned long key;
        struct hlist_node hash;
        pid_t pid;
        char *host_name;
        struct sock* sk;
} tls_sock_ops;

/* Corresponding TLS override functions */
int tls_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int tls_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int tls_disconnect(struct sock *sk, int flags);
void tls_shutdown(struct sock *sk, int how);
int tls_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len);
int tls_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);
int tls_v4_init_sock(struct sock *sk);

/* Hash Helper functions */
tls_sock_ops* tls_sock_ops_get(pid_t pid, struct sock* sk);
void tls_prot_init(void);

#endif
