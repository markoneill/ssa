/*
 * Overrides the TCP functions to give the TLS functionality. Also contains functions manage
 * the hash table where TLS socket options are stored.
 */

#include <linux/slab.h>
#include "tls_prot_tor.h"

#define REROUTE_PORT		9050

/* Original TCP reference functions */
int (*ref_tcp_v4_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int (*ref_tcp_v6_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int (*ref_tcp_disconnect)(struct sock *sk, int flags);
void (*ref_tcp_shutdown)(struct sock *sk, int how);
int (*ref_tcp_recvmsg)(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
                        int flags, int *addr_len);
int (*ref_tcp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t size);
int (*ref_tcp_v4_init_sock)(struct sock *sk);

struct sockaddr_in reroute_addr = {
	.sin_family = AF_INET,
	.sin_port = htons(REROUTE_PORT),
	.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
};

/* Sock5 handshake for TOR */
int do_sock_handshake(struct sock *sk, struct sockaddr *uaddr, int addr_len){
	char ver;
	char nmethods;
	char method;
	int buf_len;
	struct msghdr hdr_out;	
	struct msghdr hdr_in;
	char *in_buf;
	char outgoing[3];
	struct kvec iov_out;
	struct kvec iov_in;
	int addr_len_in;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	buf_len = 3;	

	ver = 0x05; // Socks version 5
	nmethods = 0x01; // only one method supported
	method = 0x00; // no authentication

	outgoing[0] = ver;
	outgoing[1] = nmethods;
	outgoing[2] = method;

	iov_out.iov_base = outgoing;
	iov_out.iov_len = buf_len;
	iov_iter_kvec(&hdr_out.msg_iter, WRITE | ITER_KVEC, &iov_out, 1, buf_len);
	hdr_out.msg_namelen = 0;
	hdr_out.msg_flags = 0;
	hdr_out.msg_control = NULL;
	hdr_out.msg_controllen = 0;
	hdr_out.msg_iocb = NULL;

	(*ref_tcp_sendmsg)(sk, &hdr_out, buf_len);

	/* --------------- Recieve message from TOR ---------------------- */

	in_buf = kmalloc(2, GFP_KERNEL);
	if (!in_buf){
		set_fs(old_fs);
		return -ENOMEM;
	}
	
	iov_in.iov_base = in_buf;
	iov_in.iov_len = 2;
	iov_iter_kvec(&hdr_in.msg_iter, READ | ITER_KVEC, &iov_in, 1, 2);
	
	addr_len_in = 0;
	ref_tcp_recvmsg(sk, &hdr_in, 2, 0, 0, &addr_len_in);
	set_fs(old_fs);

	if (in_buf[0] == 0x05 && in_buf[1] == 0x00){
		printk(KERN_ALERT "Initial Socks5 Handshake successful");
	} else {
		printk(KERN_ALERT "Initial Socks5 Handshake failed");
		return -1;
	}

	return 0;
}

/* Overriden TLS .connect for v4 function */
int tls_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len){
	int err;
	
	if (strstr(current->comm, "tor") != NULL){
		return (*ref_tcp_v4_connect)(sk, uaddr, addr_len);
	}

	err = (*ref_tcp_v4_connect)(sk, ((struct sockaddr*)&reroute_addr), addr_len);
	if (err != 0){
		return err;
	}

	err = do_sock_handshake(sk, uaddr, addr_len);

	return err;
}

/* Overriden TLS .connect for v6 function */
int tls_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len){
	return (*ref_tcp_v6_connect)(sk, uaddr, addr_len);
}

/* Overriden TLS .disconnect function */
int tls_disconnect(struct sock *sk, int flags){
	return (*ref_tcp_disconnect)(sk, flags);
}

/* Overriden TLS .shutdown function */
void tls_shutdown(struct sock *sk, int how){
	(*ref_tcp_shutdown)(sk, how);
}

/* Overriden TLS .recvmsg function */
int tls_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len){
	return (*ref_tcp_recvmsg)(sk, msg, len, nonblock, flags, addr_len);
}

/* Overriden TLS .sendmsg function */
int tls_sendmsg(struct sock *sk, struct msghdr *msg, size_t size){
	return (*ref_tcp_sendmsg)(sk, msg, size);
}

/* Overriden TLS .init function */
int tls_v4_init_sock(struct sock *sk){
	return (*ref_tcp_v4_init_sock)(sk);
}
