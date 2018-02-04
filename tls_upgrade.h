#ifndef TLS_UPGRADE_H
#define TLS_UPGRADE_H

int hook_tcp_setsockopt(struct sock* sk, int level, int optname, char __user* optval, unsigned int optlen);

#endif /* TLS_UPGRADE_H */
