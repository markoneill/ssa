#ifndef TLS_H
#define TLS_H

#include <linux/hashtable.h>
#include <linux/completion.h>

/* Holds additional data needed by our TLS sockets */
typedef struct tls_sock_ext_data {
        unsigned long key;
        struct hlist_node hash;
	struct sockaddr ext_addr;
	int ext_addrlen;
	struct sockaddr int_addr;
	int int_addrlen;
	struct sockaddr rem_addr;
	int rem_addrlen;
	int has_bound; /* zero if no bind explicitly called  by app */
        pid_t pid;
        char *hostname;
	int is_connected;
        struct sock* sk;
	struct completion sock_event;
	int response;
	char* data;
	unsigned int data_len;
	int daemon_id;
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
void report_return(unsigned long key, int ret);
void report_data_return(unsigned long key, char* data, unsigned int len);

#endif
