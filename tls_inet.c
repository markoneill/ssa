#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/completion.h>
#include <linux/string.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/limits.h>
#include <linux/cpumask.h>
#include "tls_inet.h"
#include "tls_common.h"
#include "netlink.h"

static atomic_long_t tls_memory_allocated;
static struct percpu_counter tls_orphan_count;
static struct percpu_counter tls_sockets_allocated;

unsigned int balancer = 0;

static struct proto_ops ref_inet_stream_ops;
static struct proto ref_tcp_prot;

/* TLS functions for INET ops */
int tls_inet_init_sock(struct sock *sk);
int tls_inet_release(struct socket* sock);
int tls_inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len);
int tls_inet_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags);
int tls_inet_listen(struct socket *sock, int backlog);
int tls_inet_accept(struct socket *sock, struct socket *newsock, int flags, bool kern);
int tls_inet_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen);
int tls_inet_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen);
/* We don't need sendmsg, recvmsg, poll, etc here because we're using the native socket functions */

int set_tls_prot_inet_stream(struct proto* tls_prot, struct proto_ops* tls_proto_ops) {
	/* We share operations with TCP for transport to daemon */
	*tls_prot = tcp_prot;
	ref_tcp_prot = tcp_prot;

	/* Guessing what the TLS-unique things should be here */
	strcpy(tls_prot->name, "TLS");
	tls_prot->owner = THIS_MODULE;
	tls_prot->inuse_idx = 0;
	tls_prot->memory_allocated = &tls_memory_allocated;
	tls_prot->orphan_count = &tls_orphan_count;
	tls_prot->sockets_allocated = &tls_sockets_allocated;
	percpu_counter_init(&tls_orphan_count, 0, GFP_KERNEL);
	percpu_counter_init(&tls_sockets_allocated, 0, GFP_KERNEL);

	/* Keep all tcp_prot functions except the following */
	tls_prot->init = tls_inet_init_sock;

	*tls_proto_ops = inet_stream_ops;
	ref_inet_stream_ops = inet_stream_ops;
	
	tls_proto_ops->owner = THIS_MODULE;

	/* Keep all inet_stream_ops except the following */
	tls_proto_ops->release = tls_inet_release;
	tls_proto_ops->bind = tls_inet_bind;
	tls_proto_ops->connect = tls_inet_connect;
	tls_proto_ops->listen = tls_inet_listen;
	tls_proto_ops->accept = tls_inet_accept;
	tls_proto_ops->setsockopt = tls_inet_setsockopt;
	tls_proto_ops->getsockopt = tls_inet_getsockopt;

	return 0;
}

void inet_stream_cleanup(void) {
	percpu_counter_destroy(&tls_orphan_count);
	percpu_counter_destroy(&tls_sockets_allocated);
	return;
}

int tls_inet_init_sock(struct sock *sk) {
	int ret;
	tls_sock_data_t* sock_data;
	char comm[NAME_MAX];
	char* comm_ptr;

	if ((sock_data = kmalloc(sizeof(tls_sock_data_t), GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "kmalloc failed in tls_inet_init_sock\n");
		return -1;
	}

	memset(sock_data, 0, sizeof(tls_sock_data_t));

	((struct sockaddr_in*)&sock_data->int_addr)->sin_family = AF_INET;
	((struct sockaddr_in*)&sock_data->int_addr)->sin_port = 0;
	((struct sockaddr_in*)&sock_data->int_addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	sock_data->pid = current->pid;
	sock_data->sk = sk;
	sock_data->key = (unsigned long)sk->sk_socket;
	sock_data->daemon_id = DAEMON_START_PORT;
	//sock_data->daemon_id = DAEMON_START_PORT + (balancer % nr_cpu_ids);
	//printk(KERN_INFO "Assigning new socket to daemon %d\n", sock_data->daemon_id);
	balancer = (balancer+1) % nr_cpu_ids;
	init_completion(&sock_data->sock_event);
	put_tls_sock_data(sock_data->key, &sock_data->hash);
	ret = ref_tcp_prot.init(sk);

	comm_ptr = get_full_comm(comm, NAME_MAX);

	send_socket_notification((unsigned long)sk->sk_socket, comm_ptr, sock_data->daemon_id);
	wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT);
	/* We're not checking return values here because init_sock always returns 0 */
	return ret;
}

int tls_inet_release(struct socket* sock) {
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	if (sock_data == NULL) {
		/* We're not treating this particular socket.*/
		return ref_inet_stream_ops.release(sock);
	}
	send_close_notification((unsigned long)sock, sock_data->daemon_id);
	//wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT);
	if (sock_data->hostname != NULL) {
		kfree(sock_data->hostname);
	}
	rem_tls_sock_data(&sock_data->hash);
	kfree(sock_data);
	return ref_inet_stream_ops.release(sock);
}

int tls_inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len) {
	int ret;
	tls_sock_data_t* sock_data;
	/* We disregard the address the application wants to bind to in favor
	 * of one assigned by the system (using sin_port = 0 on localhost),
	 * so that we can have the TLS wrapper daemon bind to the actual one */

	sock_data = get_tls_sock_data((unsigned long)sock);
	ret = ref_inet_stream_ops.bind(sock, &sock_data->int_addr, addr_len);
	/* We only want to continue if the internal socket bind succeeds */
	if (ret != 0) {
		printk(KERN_ALERT "INET bind failed\n");
		return ret;
	}

	/* We can use the port number now because inet_bind will have set
	 * it for us */
	((struct sockaddr_in*)&sock_data->int_addr)->sin_port = inet_sk(sock->sk)->inet_sport;

	send_bind_notification((unsigned long)sock, &sock_data->int_addr,
			(struct sockaddr*)uaddr, sock_data->daemon_id);
	if (wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -EADDRINUSE;
	}
	if (sock_data->response != 0) {
		return sock_data->response;
	}
	sock_data->has_bound = 1;
	sock_data->int_addrlen = addr_len;
	sock_data->ext_addr = *uaddr;
	sock_data->ext_addrlen = addr_len;
	return 0;
}

int tls_inet_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags) {
	int ret;
	/*struct sockaddr_in* uaddr_in;*/
	struct sockaddr_in reroute_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};

	struct sockaddr_in int_addr = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};

	/* Save original destination address information */
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	sock_data->rem_addr = (struct sockaddr)(*uaddr);
	sock_data->rem_addrlen = addr_len;

	/* Pre-emptively bind the source port so we can register it before remote
	 * connection. We only do this if the application hasn't explicitly called
	 * bind already */
	if (sock_data->has_bound == 0) {
		ref_inet_stream_ops.bind(sock, (struct sockaddr*)&int_addr, sizeof(int_addr));
		int_addr.sin_port = inet_sk(sock->sk)->inet_sport;
		memcpy(&sock_data->int_addr, &int_addr, sizeof(int_addr));
		sock_data->has_bound = 1;
		sock_data->int_addrlen = sizeof(int_addr);
	}

	send_connect_notification((unsigned long)sock, &sock_data->int_addr, uaddr, sock_data->daemon_id);
	if (wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -EHOSTUNREACH;
	}
	if (sock_data->response != 0) {
		return sock_data->response;
	}

	reroute_addr.sin_port = htons(sock_data->daemon_id);
	ret = ref_inet_stream_ops.connect(sock, ((struct sockaddr*)&reroute_addr), sizeof(reroute_addr), flags);
	if (ret != 0) {
		return ret;
	}
	sock_data->is_connected = 1;
	return 0;
}

int tls_inet_listen(struct socket *sock, int backlog) {
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
        struct sockaddr_in int_addr = {
                .sin_family = AF_INET,
                .sin_port = 0,
                .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        };

	if (sock_data->has_bound == 0) {
		ref_inet_stream_ops.bind(sock, (struct sockaddr*)&int_addr, sizeof(int_addr));
		int_addr.sin_port = inet_sk(sock->sk)->inet_sport;
		memcpy(&sock_data->int_addr, &int_addr, sizeof(int_addr));
		sock_data->int_addrlen = sizeof(int_addr);
		sock_data->has_bound = 1;
	}
	send_listen_notification((unsigned long)sock, 
			(struct sockaddr*)&sock_data->int_addr,
		        (struct sockaddr*)&sock_data->ext_addr,
			sock_data->daemon_id);

	if (wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -EADDRINUSE;
	}
	if (sock_data->response != 0) {
		return sock_data->response;
	}

	return ref_inet_stream_ops.listen(sock, backlog);
}

int tls_inet_accept(struct socket *sock, struct socket *newsock, int flags, bool kern) {
	tls_sock_data_t* sock_data;
	char comm[NAME_MAX];
	char* comm_ptr;

	//printk(KERN_ALERT "Accept called\n");
	if ((sock_data = kmalloc(sizeof(tls_sock_data_t), GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "kmalloc failed in tls_inet_init_sock\n");
		return -1;
	}

	memset(sock_data, 0, sizeof(tls_sock_data_t));

	sock_data->pid = current->pid;
	sock_data->sk = newsock->sk;
	sock_data->daemon_id = 8443; /* XXX FIX */
	sock_data->key = (unsigned long)newsock;
	init_completion(&sock_data->sock_event);
	put_tls_sock_data(sock_data->key, &sock_data->hash);

	comm_ptr = get_full_comm(comm, NAME_MAX);

	//((struct sockaddr_in*)&sock_data->int_addr)->sin_port = inet_sk(sock->sk)->inet_sport;
	send_accept_notification((unsigned long)newsock, comm_ptr, sock_data->daemon_id);
	wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT);
	/* We're not checking return values here because init_sock always returns 0 */
	return ref_inet_stream_ops.accept(sock, newsock, flags, kern);
}

int tls_inet_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen) {
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	if (sock_data == NULL) {
		return -EBADF;
	}
	return tls_common_setsockopt(sock_data, sock, level, optname, optval, optlen, ref_inet_stream_ops.setsockopt);
}

int tls_inet_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen) {
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	if (sock_data == NULL) {
		return -EBADF;
	}
	return tls_common_getsockopt(sock_data, sock, level, optname, optval, optlen, ref_inet_stream_ops.getsockopt);
}

