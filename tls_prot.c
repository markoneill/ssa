#include "tls_prot.h"

int tls_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len){
	return 36;
}
EXPORT_SYMBOL(tls_v4_connect);

int tls_disconnect(struct sock *sk, int flags){
	return 0;
}
EXPORT_SYMBOL(tls_disconnect);

void tls_shutdown(struct sock *sk, int how){
	return;
}
EXPORT_SYMBOL(tls_shutdown);

int tls_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len){
	return 0;
}
EXPORT_SYMBOL(tls_recvmsg);

int tls_sendmsg(struct sock *sk, struct msghdr *msg, size_t size){
	return 0;
}
EXPORT_SYMBOL(tls_sendmsg);
