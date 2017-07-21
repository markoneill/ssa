/*
 * Overrides the TCP functions to give the TLS functionality. Also contains functions manage
 * the hash table where TLS socket options are stored.
 */

#include <linux/slab.h>
#include "tls_prot_tor.h"

#define REROUTE_PORT		9050

struct task_struct *tor_engine_task;

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

/* 
 * Sock5 handshake for TOR 
 * @param version	Same as ATYP in RFC1928. 0x01 for IPv4, 0x03 for domain names, and 0x04 for IPv6
 */
int do_sock_handshake(struct sock *sk, struct sockaddr *uaddr, int addr_len, unsigned char ip_type){
	int err;
	int bytes_rcvd;
	int bytes_rcvd_host;
	char ver;
	char nmethods;
	char method;
	int buf_len;
	struct msghdr hdr_out;	
	struct msghdr hdr_in;
	struct msghdr hdr_out_host;
	struct msghdr hdr_in_host;
	int buf_len_host;
	char *in_buf;
	char *in_buf_host;
	char outgoing[3];
	struct kvec iov_out;
	struct kvec iov_in;
	struct kvec iov_out_host;
	struct kvec iov_in_host;
	int addr_len_in;
	int addr_len_in_host;
	mm_segment_t old_fs;

	unsigned char host_out[10];
	unsigned char CMD;
	unsigned char RSV;
	unsigned char ATYP;

	unsigned int remote_addr;
	unsigned short remote_port;
	
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	err = 0;
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
	hdr_out.msg_name = NULL;
	hdr_out.msg_namelen = 0;
	hdr_out.msg_flags = 0;
	hdr_out.msg_control = NULL;
	hdr_out.msg_controllen = 0;
	hdr_out.msg_iocb = NULL;

	release_sock(sk);
	(*ref_tcp_sendmsg)(sk, &hdr_out, buf_len);
	lock_sock(sk);
	/* --------------- Recieve message from TOR ---------------------- */

	in_buf = kmalloc(2, GFP_KERNEL);
	if (!in_buf){
		err = -ENOMEM;
		goto Out_first_send;
	}
	
	iov_in.iov_base = in_buf;
	iov_in.iov_len = 2;
	iov_iter_kvec(&hdr_in.msg_iter, READ | ITER_KVEC, &iov_in, 1, 2);
	
	addr_len_in = 0;
	release_sock(sk);
	bytes_rcvd = ref_tcp_recvmsg(sk, &hdr_in, 2, 0, 0, &addr_len_in);
	if (bytes_rcvd < 0){
		printk(KERN_ALERT "first receive failed");
		goto Out_first_send;
	}
	lock_sock(sk);

	if (in_buf[0] != 0x05 || in_buf[1] != 0x00){
		printk(KERN_ALERT "Initial Socks5 Handshake failed");
		err = -1;
		goto Out_first_send;
	}

	/* ------------------ Send URL to TOR -------------------- */

	CMD = 0x01;
	RSV = 0x00;
	ATYP = ip_type;	
	
	host_out[0] = ver;
	host_out[1] = CMD;
	host_out[2] = RSV;
	host_out[3] = ATYP;  
	remote_addr = ((struct sockaddr_in *)uaddr)->sin_addr.s_addr;
	memcpy(&host_out[4], &remote_addr, sizeof(remote_addr));
	remote_port = ((struct sockaddr_in *)uaddr)->sin_port;
	memcpy(&host_out[8], &remote_port, sizeof(remote_port));

	buf_len_host = 10;
	iov_out_host.iov_base = host_out;
	iov_out_host.iov_len = buf_len_host;
	iov_iter_kvec(&hdr_out_host.msg_iter, WRITE | ITER_KVEC, &iov_out_host, 1, buf_len_host);
	hdr_out_host.msg_name = NULL;
	hdr_out_host.msg_namelen = 0;
	hdr_out_host.msg_flags = 0;
 	hdr_out_host.msg_control = NULL;
 	hdr_out_host.msg_controllen = 0;
 	hdr_out_host.msg_iocb = NULL;

	release_sock(sk);
	(*ref_tcp_sendmsg)(sk, &hdr_out_host, buf_len_host);
	lock_sock(sk);

	/* ----------------- Verify Host Recieved by TOR --------------*/

	in_buf_host = kmalloc(buf_len_host, GFP_KERNEL);
	if (!in_buf_host) {
		err = -ENOMEM;
		goto Out_second_send;
	}

	iov_in_host.iov_base = in_buf_host;
	iov_in_host.iov_len = buf_len_host;
	iov_iter_kvec(&hdr_in_host.msg_iter, READ | ITER_KVEC, &iov_in_host, 1, buf_len_host);

	addr_len_in_host = 0;
	release_sock(sk);
	bytes_rcvd_host = ref_tcp_recvmsg(sk, &hdr_in_host, buf_len_host, 0, 0, &addr_len_in_host);
	if(bytes_rcvd_host < 0){
		printk(KERN_ALERT "second receive failed");
		goto Out_second_send;
	}
	lock_sock(sk);

	set_fs(old_fs);

	if (in_buf_host[0] == 0x05 && in_buf_host[1] == 0x00){
		 printk(KERN_ALERT "Initial Socks5 Handshake successful");
	} else {
		printk(KERN_ALERT "Initial Socks5 Handshake failed");
		err = -1;
		goto Out_second_send;
	}

Out_second_send:
	kfree(in_buf_host);
Out_first_send:
	kfree(in_buf);
	set_fs(old_fs);
	return err;
}

int is_ancestor(struct task_struct* parent) {
        struct task_struct* cur_task = current;
        while (cur_task->pid != 0) {
                if (cur_task == parent) return 1;
                cur_task = cur_task->parent;
        }
        return 0;
}

/* Overriden TLS .connect for v4 function */
int tls_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len){
	int err;
	
	if (current->tgid == tor_engine_task->tgid || is_ancestor(tor_engine_task)){
		return (*ref_tcp_v4_connect)(sk, uaddr, addr_len);
	}

	err = (*ref_tcp_v4_connect)(sk, ((struct sockaddr*)&reroute_addr), addr_len);
	if (err != 0){
		return err;
	}

	err = do_sock_handshake(sk, uaddr, addr_len, 0x01);

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
