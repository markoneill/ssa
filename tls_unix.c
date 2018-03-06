#include <net/af_unix.h>
#include <linux/un.h>
#include <net/inet_common.h>
#include "tls_unix.h"
#include "tls_common.h"
#include "netlink.h"

/* TLS functions for Unix domain sockets */
int tls_unix_init_sock(struct sock *sk);
int tls_unix_release(struct socket* sock);
int tls_unix_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len);
int tls_unix_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags);
int tls_unix_listen(struct socket *sock, int backlog);
int tls_unix_accept(struct socket *sock, struct socket *newsock, int flags, bool kern);
int tls_unix_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen);
int tls_unix_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen);
int tls_unix_getname(struct socket *sock, struct sockaddr *uaddr, int *uaddr_len, int peer);
unsigned int tls_unix_poll(struct file *file, struct socket *sock, struct poll_table_struct *wait);
int tls_unix_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg);
int tls_unix_shutdown(struct socket *sock, int how);
int tls_unix_sendmsg(struct socket *sock, struct msghdr *msg, size_t size);
int tls_unix_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags);
ssize_t tls_unix_sendpage(struct socket *sock, struct page *page, int offset, size_t size, int flags);
ssize_t tls_unix_splice_read(struct socket *sk, loff_t *ppos, struct pipe_inode_info *pipe, size_t len, unsigned int flags);

static struct proto_ops ref_unix_stream_ops;
static struct proto ref_unix_prot;

int set_tls_prot_unix_stream(struct proto* tls_prot, struct proto_ops* tls_proto_ops) {
	struct socket* sock;
	if (sock_create(PF_UNIX, SOCK_STREAM, 0, &sock) != 0) {
		printk(KERN_ALERT "Could not create dummy Unix socket in kernel\n");
		return -1;
	}
	*tls_prot = *(sock->sk->sk_prot);
	ref_unix_prot = *(sock->sk->sk_prot);

	strcpy(tls_prot->name, "TLS");
	tls_prot->owner = THIS_MODULE;
	tls_prot->init = tls_unix_init_sock;

	*tls_proto_ops = *(sock->ops);
	ref_unix_stream_ops = *(sock->ops);


	tls_proto_ops->owner = THIS_MODULE;

	/* Keep all unix_stream_ops except the following */
	tls_proto_ops->release = tls_unix_release;
	tls_proto_ops->bind = tls_unix_bind;
	tls_proto_ops->connect = tls_unix_connect;
	tls_proto_ops->listen = tls_unix_listen;
	tls_proto_ops->accept = tls_unix_accept;
	tls_proto_ops->setsockopt = tls_unix_setsockopt;
	tls_proto_ops->getsockopt = tls_unix_getsockopt;
	/* INET ops have no socketpair, so we're emulating that */
	tls_proto_ops->socketpair = sock_no_socketpair;
	tls_proto_ops->getname = tls_unix_getname;
	tls_proto_ops->poll = tls_unix_poll;
	tls_proto_ops->ioctl = tls_unix_ioctl;
	tls_proto_ops->shutdown = tls_unix_shutdown;
	tls_proto_ops->sendmsg = tls_unix_sendmsg;
	tls_proto_ops->recvmsg = tls_unix_recvmsg;
	tls_proto_ops->sendpage = tls_unix_sendpage;
	tls_proto_ops->splice_read = tls_unix_splice_read;

	sock_release(sock);
	return 0;
}


/* TLS override functions for Unix */
int tls_unix_init_sock(struct sock *sk) {
	tls_sock_data_t* sock_data;
	struct socket* unix_sock;
	int ret;
	char comm[NAME_MAX];
	char* comm_ptr;

	ret = sock_create(PF_UNIX, SOCK_STREAM, 0, &unix_sock);
	if (ret != 0) {
		printk(KERN_ALERT "Could not create unix sock\n");
		return -1;
	}

	if ((sock_data = kmalloc(sizeof(tls_sock_data_t), GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "kmalloc failed in tls_unix_init_sock\n");
		return -1;
	}
	
	memset(sock_data, 0, sizeof(tls_sock_data_t));


	((struct sockaddr_un*)&sock_data->int_addr)->sun_family = AF_UNIX;
	
	sock_data->key = (unsigned long)sk->sk_socket;
	sock_data->unix_sock = unix_sock;
	sock_data->daemon_id = DAEMON_START_PORT;
	//sock_data->daemon_id = DAEMON_START_PORT + (balancer % nr_cpu_ids);
	//printk(KERN_INFO "Assigning new socket to daemon %d\n", sock_data->daemon_id);
	//balancer = (balancer+1) % nr_cpu_ids;
	init_completion(&sock_data->sock_event);
	put_tls_sock_data(sock_data->key, &sock_data->hash);
	
	comm_ptr = get_full_comm(comm, NAME_MAX);

	send_socket_notification(sock_data->key, comm_ptr, sock_data->daemon_id);
	wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT);
	/* We're not checking daemon return values here because init_sock needs to return
	 * at this point anyway 0 */
	return 0;
}

int tls_unix_release(struct socket* sock) {
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	if (sock_data == NULL) {
		/* Since inet_create creates our sockets, we use inet_release
		 * to free them */
		//return inet_release(sock);
		return 0;
	}
	send_close_notification(sock_data->key, sock_data->daemon_id);
	//wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT);
	if (sock_data->hostname != NULL) {
		kfree(sock_data->hostname);
	}
	rem_tls_sock_data(&sock_data->hash);
	kfree(sock_data);
	ref_unix_stream_ops.release(sock_data->unix_sock);
	//return inet_release(sock);
	return 0;
}

int tls_unix_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len) {
	int ret;
	tls_sock_data_t* sock_data;
	struct socket* unix_sock;
	/* We disregard the address the application wants to bind to in favor
	 * of one assigned by the system (using sin_port = 0 on localhost),
	 * so that we can have the TLS wrapper daemon bind to the actual one */

	sock_data = get_tls_sock_data((unsigned long)sock);
	unix_sock = sock_data->unix_sock;
	ret = ref_unix_stream_ops.bind(unix_sock, &sock_data->int_addr, sizeof(sa_family_t));

	/* We only want to continue if the internal socket bind succeeds */
	if (ret != 0) {
		printk(KERN_ALERT "Internal bind failed\n");
		return ret;
	}

	/* We can use the abstract name now because unix_bind will have set
	 * it for us */
	memcpy(&sock_data->int_addr, unix_sk(unix_sock->sk)->addr->name, sizeof(sa_family_t) + 6);

	send_bind_notification((unsigned long)sock, &sock_data->int_addr, (struct sockaddr*)uaddr, sock_data->daemon_id);
	if (wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -EADDRINUSE;
	}
	if (sock_data->response != 0) {
		return sock_data->response;
	}
	sock_data->is_bound = 1;
	sock_data->int_addrlen = sizeof(sa_family_t) + 6;
	sock_data->ext_addr = *uaddr;
	sock_data->ext_addrlen = addr_len;
	return 0;
}

int tls_unix_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags) {
	int ret;
	int reroute_addrlen;
	struct socket* unix_sock;
	struct sockaddr_un reroute_addr = {
		.sun_family = AF_UNIX,
	};

	struct sockaddr_un int_addr = {
		.sun_family = AF_UNIX
	};

	/* Save original destination address information */
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	unix_sock = sock_data->unix_sock;
	sock_data->rem_addr = (struct sockaddr)(*uaddr);
	sock_data->rem_addrlen = addr_len;

	/* Pre-emptively bind the source port so we can register it before remote
	 * connection. We only do this if the application hasn't explicitly called
	 * bind already */
	if (sock_data->is_bound == 0) {
		ref_unix_stream_ops.bind(unix_sock, (struct sockaddr*)&int_addr, sizeof(sa_family_t));
		sock_data->int_addrlen = sizeof(sa_family_t) + 6;
		memcpy(&sock_data->int_addr, unix_sk(unix_sock->sk)->addr->name, sock_data->int_addrlen);
		sock_data->is_bound = 1;
	}

	send_connect_notification((unsigned long)sock, &sock_data->int_addr, uaddr, sock_data->daemon_id,1);
	if (wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -EHOSTUNREACH;
	}
	if (sock_data->response != 0) {
		return sock_data->response;
	}

	reroute_addrlen = sprintf(reroute_addr.sun_path+1, "%d", sock_data->daemon_id) + 1 + sizeof(sa_family_t);
	printk(KERN_INFO "sock is redirected to %s\n", reroute_addr.sun_path+1);
	ret = ref_unix_stream_ops.connect(unix_sock, ((struct sockaddr*)&reroute_addr), reroute_addrlen, flags);
	if (ret != 0) {
		return ret;
	}
	sock_data->is_connected = 1;
	return 0;
}

int tls_unix_listen(struct socket *sock, int backlog) {
	struct socket* unix_sock;
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
        struct sockaddr_un int_addr = {
                .sun_family = AF_INET,
        };

	unix_sock = sock_data->unix_sock;

	if (sock_data->is_bound == 0) {
		/* Invoke autobind */
		ref_unix_stream_ops.bind(unix_sock, (struct sockaddr*)&int_addr, sizeof(sa_family_t));
		sock_data->int_addrlen = sizeof(sa_family_t) + 6;
		memcpy(&sock_data->int_addr, unix_sk(unix_sock->sk)->addr->name, sock_data->int_addrlen);
		sock_data->is_bound = 1;
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
	return ref_unix_stream_ops.listen(unix_sock, backlog);
}

/* XXX Unix development has essentially halted since it didn't
 * seem to enhance performance. the accept method, and maybe some
 * others, will need to be updated to reflect current inet practices
 * if it is to be used again */
int tls_unix_accept(struct socket *sock, struct socket *newsock, int flags, bool kern) {
	struct socket* unix_sock;
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	unix_sock = sock_data->unix_sock;
	return ref_unix_stream_ops.accept(unix_sock, newsock, flags, kern);
}

int tls_unix_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen) {
	struct socket* unix_sock;
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	unix_sock = sock_data->unix_sock;
	return tls_common_setsockopt(sock_data, unix_sock, level, optname, optval, optlen, NULL);
}

int tls_unix_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen) {
	struct socket* unix_sock;
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	unix_sock = sock_data->unix_sock;
	return tls_common_getsockopt(sock_data, unix_sock, level, optname, optval, optlen, NULL);
}

int tls_unix_getname(struct socket *sock, struct sockaddr *uaddr, int *uaddr_len, int peer) {
	struct socket* unix_sock;
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	unix_sock = sock_data->unix_sock;
	return ref_unix_stream_ops.getname(unix_sock, uaddr, uaddr_len, peer);
}

unsigned int tls_unix_poll(struct file *file, struct socket *sock, struct poll_table_struct *wait) {
	struct socket* unix_sock;
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	unix_sock = sock_data->unix_sock;
	/* Uh oh. File XXX?*/
	return ref_unix_stream_ops.poll(file, unix_sock, wait);
}

int tls_unix_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg) {
	struct socket* unix_sock;
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	unix_sock = sock_data->unix_sock;
	return ref_unix_stream_ops.ioctl(unix_sock, cmd, arg);
}

int tls_unix_shutdown(struct socket *sock, int how) {
	struct socket* unix_sock;
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	unix_sock = sock_data->unix_sock;
	return ref_unix_stream_ops.shutdown(unix_sock, how);
}

int tls_unix_sendmsg(struct socket *sock, struct msghdr *msg, size_t size) {
	struct socket* unix_sock;
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	unix_sock = sock_data->unix_sock;
	return ref_unix_stream_ops.sendmsg(unix_sock, msg, size);
}

int tls_unix_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags) {
	struct socket* unix_sock;
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	unix_sock = sock_data->unix_sock;
	return ref_unix_stream_ops.recvmsg(unix_sock, msg, size, flags);
}

ssize_t tls_unix_sendpage(struct socket *sock, struct page *page, int offset, size_t size, int flags) {
	struct socket* unix_sock;
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sock);
	unix_sock = sock_data->unix_sock;
	return ref_unix_stream_ops.sendpage(unix_sock, page, offset, size, flags);
}

ssize_t tls_unix_splice_read(struct socket *sk, loff_t *ppos, struct pipe_inode_info *pipe, size_t len, unsigned int flags) {
	struct socket* unix_sock;
	tls_sock_data_t* sock_data = get_tls_sock_data((unsigned long)sk);
	unix_sock = sock_data->unix_sock;
	return ref_unix_stream_ops.splice_read(unix_sock, ppos, pipe, len, flags);
}


