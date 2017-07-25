#ifndef _TLS_PROTO_H
#define _TLS_PROTO_H

#include <linux/socket.h>
#include <net/sock.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h> // for current (pointer to task)
#include <linux/hashtable.h>
#include <linux/uio.h>

/* Holds all variables for socket options */
typedef struct tls_sock_ops {
        unsigned long key;
        struct hlist_node hash;
        pid_t pid;
        char *host_name;
        struct sock* sk;
} tls_sock_ops;

int do_sock_handshake(struct sock *sk, struct sockaddr *uaddr, int addr_len, unsigned char ip_type);
int is_ancestor(struct task_struct* parent);

/* Corresponding TLS override functions */
int tls_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int tls_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);

#endif
