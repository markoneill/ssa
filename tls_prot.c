#include "tls_prot.h"

/* Original TCP reference functions */
int (*ref_tcp_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int (*ref_tcp_disconnect)(struct sock *sk, int flags);
void (*ref_tcp_shutdown)(struct sock *sk, int how);
int (*ref_tcp_recvmsg)(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
                        int flags, int *addr_len);
int (*ref_tcp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t size);

int tls_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len){
	printk(KERN_ALERT "Attempting tls connect");
	return (*ref_tcp_connect)(sk, uaddr, addr_len);
}

int tls_disconnect(struct sock *sk, int flags){
	return (*ref_tcp_disconnect)(sk, flags);
}

void tls_shutdown(struct sock *sk, int how){
	(*ref_tcp_shutdown)(sk, how);
	// Will need to free host_name from sock
}

int tls_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len){
	return (*ref_tcp_recvmsg)(sk, msg, len, nonblock, flags, addr_len);
}

int tls_sendmsg(struct sock *sk, struct msghdr *msg, size_t size){
	return (*ref_tcp_sendmsg)(sk, msg, size);
}
