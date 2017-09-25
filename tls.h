#ifndef TLS_H
#define TLS_H

#include <linux/socket.h>
#include <net/sock.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h> // for current (pointer to task)
#include <linux/hashtable.h>
#include "socktls.h"

/* Holds additional data needed by our TLS sockets */
typedef struct tls_sock_ext_data {
        unsigned long key;
        struct hlist_node hash;
	unsigned long remote_key; /* for orig dest lookup */
	struct hlist_node remote_hash; /* for orig dest lookup */
	struct sockaddr orig_dst_addr;
	int orig_dst_addrlen;
        pid_t pid;
        char *hostname;
        struct sock* sk;
} tls_sock_ext_data_t;

/* Corresponding TLS override functions */
int tls_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int tls_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int tls_disconnect(struct sock *sk, int flags);
void tls_shutdown(struct sock *sk, int how);
int tls_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len);
int tls_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);
int tls_v4_init_sock(struct sock *sk);
void tls_v4_destroy_sock(struct sock* sk);
void tls_close(struct sock *sk, long timeout);
int tls_setsockopt(struct sock *sk, int level, int optname, char __user *optval, unsigned int len);
int tls_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen);

int tls_inet_listen(struct socket *sock, int backlog);
int tls_inet_accept(struct socket *sock, struct socket *newsock, int flags, bool kern);
int tls_inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len);

/* Hash Helper functions */
tls_sock_ext_data_t* tls_sock_ext_get_data(struct sock* sk);
void tls_setup(void);
void tls_cleanup(void);

#endif
