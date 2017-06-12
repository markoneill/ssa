#ifndef _TLS_PROTO_H
#define _TLS_PROTO_H

#include <linux/socket.h>
#include <net/sock.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/kernel.h>

int tls_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int tls_disconnect(struct sock *sk, int flags);
void tls_shutdown(struct sock *sk, int how);
int tls_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len);
int tls_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);

#endif
