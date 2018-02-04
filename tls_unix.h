#ifndef TLS_UNIX_H
#define TLS_UNIX_H

#include <linux/net.h>

/* TLS override functions for Unix domain sockets */
int tls_unix_init_sock(struct sock *sk);
int tls_unix_release(struct socket* sock);
int tls_unix_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len);
int tls_unix_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags);
int tls_unix_listen(struct socket *sock, int backlog);
int tls_unix_accept(struct socket *sock, struct socket *newsock, int flags, bool kern);
int tls_unix_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen);
int tls_unix_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen);

#endif /* TLS_UNIX_H */
