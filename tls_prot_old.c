#ifndef _TLS_PROTO_
#define _TLS_PROTO_

void tls_close(struct sock *sk, long timeout);
int tls_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int tls_disconnect(struct sock *sk, int flags);
struct sock *tls_accept(struct wsock *sk, int flags, int *err, bool kern);
int tls_ioctl(struct sock *sk, int cmd, unsigned long arg);
int tls_init_sock(struct sock *sk);
void tls_destroy_sock(struct sock *sk);
void tls_shutdown(struct sock *sk, int how);
int tls_setsockopt(struct sock *sk, int level, int optname,
		char __user *optval, unsigned int optlen);
int tls_getsockopt(struct sock *sk, int level, int optname,
		char__user *optval, int __user *optlen);
void tls_set_keepalive(struct sock *sk, int val);
int tls_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, 
		int nonblock, int flags, int *addr_len);
int tls_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);
int tls_sendpage(struct sock *sk, struct page *page, int offset, size_t size, int flags);
int tls_do_rcv(struct sock *sk, struct sk_buff *skb);
void tls_release_cb(struct sock *sk);
void tls_enter_memory_pressure(struct sock *sk);
inline bool tls_stream_memory_free(const struct sock *sk);
int compat_tls_set_sockopt(struct sock *sk, int level, int optname,
		char __user *optval, unsigned int optlen);
int compat_tls_get_sockopt(struct sock *sk, int level, int optname,
		char__user *optval, int __user *optlen);
int tls_abort(struct sock *sk, int err);

struct proto tls_prot = {
	.name 		= "TLS",
	.owner 		= THIS_MODULE,
	.close		= tls_close,
	.connect	= tls_connect, // may need to differenctiate v4 from v6
	.disconnect	= tls_disconnect,
	.accept		= tls_accept,
	.ioctl		= tls_ioctl,
	.init		= tls_init_sock, // may need to differentiate v4 from v6
	.destroy	= tls_destroy_sock, // may need to differentiate v4 from v6
	.shutdown	= tls_shutdown,
	.setsockopt	= tls_setsockopt,
	.getsockopt	= tls_getsockopt,
	.keepalive	= tls_set_keepalive,
	.recvmsg	= tls_recvmsg,
	.sendmsg	= tls_sendmsg,
	.sendpage	= tls_sendpage,
	.backlog_rcv	= tls_do_rcv
	.release_cb	= tls_release_cb,
	.hash		= 
	.unhash		=
	.get_port	=
	.enter_memory_pressure	= tls_enter_memory_pressure,
	.stream_memory_free	= tls_stream_memory_free,
	.sockets_allocated	= // still need the tcp variables or different for tls? 
	.orphan_count		= // still need the tcp variables or different for tls? 
	.memory_allocated	= // still need the tcp variables or different for tls? 
	.memory_pressure	= // still need the tcp variables or different for tls? 
	.sysctl_mem	= 
	.sysctl_wmem	=
	.sysct_rmem	=
	.max_header	=
	.obj_size	=
	.slab_flags	=
	.twsk_prot	= 
	.rsk_prot	=
	.h.hashinfo	=
	.no_autobind	=
#ifdef CONFIG_COMPAT
	.compat_setsockopt	= compat_tls_setsockopt,
	.compat_getsockopt	= compat_tls_getsockopt,
#endif
	.diag_destroy	= tls_abort,
};
EXPORT_SYMBOL(tls_prot);

#endif /*_TLS_PROTO_*/
