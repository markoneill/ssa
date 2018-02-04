#include <net/af_unix.h>
#include <linux/un.h>
#include "tls_unix.h"
#include "tls_common.h"

/* Original Unix domain reference functions */
extern int (*ref_unix_release)(struct socket* sock);
extern int (*ref_unix_bind)(struct socket *sock, struct sockaddr *uaddr, int addr_len);
extern int (*ref_unix_connect)(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags);
extern int (*ref_unix_listen)(struct socket *sock, int backlog);
extern int (*ref_unix_accept)(struct socket *sock, struct socket *newsock, int flags, bool kern);
extern int (*ref_unix_setsockopt)(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen);
extern int (*ref_unix_getsockopt)(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen);

/* Original Unix domain reference functions */
int (*ref_unix_init_sock)(struct sock *sk);
int (*ref_unix_release)(struct socket* sock);
int (*ref_unix_bind)(struct socket *sock, struct sockaddr *uaddr, int addr_len);
int (*ref_unix_connect)(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags);
int (*ref_unix_listen)(struct socket *sock, int backlog);
int (*ref_unix_accept)(struct socket *sock, struct socket *newsock, int flags, bool kern);
int (*ref_unix_setsockopt)(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen);
int (*ref_unix_getsockopt)(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen);

int set_tls_prot_unix(void) {
	struct socket* sock;
	if (sock_create(PF_UNIX, SOCK_STREAM, 0, &sock) != 0) {
		printk(KERN_ALERT "Could not create dummy Unix socket in kernel\n");
		return -1;
	}
	tls_prot = *(sock->sk->sk_prot);

	strcpy(tls_prot.name, "TLS");
	tls_prot.owner = THIS_MODULE;
	/*tls_prot.inuse_idx = 0;
	tls_prot.memory_allocated = &tls_memory_allocated;
	tls_prot.orphan_count = &tls_orphan_count;
	tls_prot.sockets_allocated = &tls_sockets_allocated;
	percpu_counter_init(&tls_orphan_count, 0, GFP_KERNEL);
	percpu_counter_init(&tls_sockets_allocated, 0, GFP_KERNEL);*/

	tls_proto_ops = *(sock->ops);
	tls_proto_ops.owner = THIS_MODULE;

	tls_prot.init = tls_unix_init_sock;

	/* Save reference functions */
	ref_unix_release = tls_proto_ops.release;
	ref_unix_bind = tls_proto_ops.bind;
	ref_unix_connect = tls_proto_ops.connect;
	ref_unix_listen = tls_proto_ops.listen;
	ref_unix_accept = tls_proto_ops.accept;
	ref_unix_setsockopt = tls_proto_ops.setsockopt;
	ref_unix_getsockopt = tls_proto_ops.getsockopt;

	/* Assign TLS functions */
	tls_proto_ops.release = tls_unix_release;
	tls_proto_ops.bind = tls_unix_bind;
	tls_proto_ops.connect = tls_unix_connect;
	tls_proto_ops.listen = tls_unix_listen;
	tls_proto_ops.accept = tls_unix_accept;
	tls_proto_ops.setsockopt = tls_unix_setsockopt;
	tls_proto_ops.getsockopt = tls_unix_getsockopt;

	sock_release(sock);

	printk(KERN_INFO "TLS protocol initialized\n");
	return 0;
}


/* TLS override functions for Unix */
int tls_unix_init_sock(struct sock *sk) {
	tls_sock_ext_data_t* sock_ext_data;
	struct socket* unix_sock;
	int ret;

	ret = sock_create_kern(current->nsproxy->net_ns, PF_UNIX, SOCK_STREAM, 0, &unix_sock);
	if (ret != 0) {
		printk(KERN_ALERT "Could not create unix sock\n");
		return -1;
	}

	if ((sock_ext_data = kmalloc(sizeof(tls_sock_ext_data_t),GFP_ATOMIC)) == NULL) {
		printk(KERN_ALERT "kmalloc failed in tls_unix_init_sock\n");
		return -1;
	}
	
	memset(sock_ext_data, 0, sizeof(tls_sock_ext_data_t));


	((struct sockaddr_un*)&sock_ext_data->int_addr)->sun_family = AF_UNIX;
	
	sock_ext_data->pid = current->pid;
	sock_ext_data->key = (unsigned long)sk->sk_socket;
	sock_ext_data->unix_sock = unix_sock;
	sock_ext_data->daemon_id = DAEMON_START_PORT;
	//sock_ext_data->daemon_id = DAEMON_START_PORT + (balancer % nr_cpu_ids);
	//printk(KERN_INFO "Assigning new socket to daemon %d\n", sock_ext_data->daemon_id);
	balancer = (balancer+1) % nr_cpu_ids;
	init_completion(&sock_ext_data->sock_event);
	spin_lock(&tls_sock_ext_lock);
	hash_add(tls_sock_ext_data_table, &sock_ext_data->hash, sock_ext_data->key);
	spin_unlock(&tls_sock_ext_lock);
	
	send_socket_notification(sock_ext_data->key, sock_ext_data->daemon_id);
	wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT);
	/* We're not checking daemon return values here because init_sock needs to return
	 * at this point anyway 0 */
	return 0;
}

int tls_unix_release(struct socket* sock) {
	tls_sock_ext_data_t* sock_ext_data = tls_sock_ext_get_data(sock);
	if (sock_ext_data == NULL) {
		return 0;
	}
	send_close_notification(sock_ext_data->key, sock_ext_data->daemon_id);
	//wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT);
	if (sock_ext_data->hostname != NULL) {
		kfree(sock_ext_data->hostname);
	}
	spin_lock(&tls_sock_ext_lock);
	hash_del(&sock_ext_data->hash); /* remove from ext_data_Table */
	spin_unlock(&tls_sock_ext_lock);
	kfree(sock_ext_data);
	(*ref_unix_release)(sock_ext_data->unix_sock);
	return inet_release(sock);
}

int tls_unix_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len) {
	int ret;
	tls_sock_ext_data_t* sock_ext_data;
	struct socket* unix_sock;
	/* We disregard the address the application wants to bind to in favor
	 * of one assigned by the system (using sin_port = 0 on localhost),
	 * so that we can have the TLS wrapper daemon bind to the actual one */

	sock_ext_data = tls_sock_ext_get_data(sock);
	unix_sock = sock_ext_data->unix_sock;
	ret = (*ref_unix_bind)(unix_sock, &sock_ext_data->int_addr, sizeof(sa_family_t));

	/* We only want to continue if the internal socket bind succeeds */
	if (ret != 0) {
		printk(KERN_ALERT "Internal bind failed\n");
		return ret;
	}

	/* We can use the abstract name now because unix_bind will have set
	 * it for us */
	memcpy(&sock_ext_data->int_addr, unix_sk(unix_sock)->addr->name, sizeof(sa_family_t) + 6);

	send_bind_notification((unsigned long)sock, &sock_ext_data->int_addr, (struct sockaddr*)uaddr, sock_ext_data->daemon_id);
	if (wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -EADDRINUSE;
	}
	if (sock_ext_data->response != 0) {
		return sock_ext_data->response;
	}
	sock_ext_data->has_bound = 1;
	sock_ext_data->int_addrlen = sizeof(sa_family_t) + 6;
	sock_ext_data->ext_addr = *uaddr;
	sock_ext_data->ext_addrlen = addr_len;
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
	tls_sock_ext_data_t* sock_ext_data = tls_sock_ext_get_data(sock);
	unix_sock = sock_ext_data->unix_sock;
	sock_ext_data->rem_addr = (struct sockaddr)(*uaddr);
	sock_ext_data->rem_addrlen = addr_len;

	/* Pre-emptively bind the source port so we can register it before remote
	 * connection. We only do this if the application hasn't explicitly called
	 * bind already */
	if (sock_ext_data->has_bound == 0) {
		(*ref_unix_bind)(unix_sock, (struct sockaddr*)&int_addr, sizeof(sa_family_t));
		sock_ext_data->int_addrlen = sizeof(sa_family_t) + 6;
		memcpy(&sock_ext_data->int_addr, unix_sk(unix_sock->sk)->addr->name, sock_ext_data->int_addrlen);
		sock_ext_data->has_bound = 1;
	}

	send_connect_notification((unsigned long)sock, &sock_ext_data->int_addr, uaddr, sock_ext_data->daemon_id);
	if (wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -EHOSTUNREACH;
	}
	if (sock_ext_data->response != 0) {
		return sock_ext_data->response;
	}

	reroute_addrlen = sprintf(reroute_addr.sun_path+1, "%d", sock_ext_data->daemon_id) + 1 + sizeof(sa_family_t);
	printk(KERN_INFO "sock is redirected to %s\n", reroute_addr.sun_path+1);
	ret = (*ref_unix_connect)(unix_sock, ((struct sockaddr*)&reroute_addr), reroute_addrlen, flags);
	if (ret != 0) {
		return ret;
	}
	sock_ext_data->is_connected = 1;
	return 0;
}

int tls_unix_listen(struct socket *sock, int backlog) {
	struct socket* unix_sock;
	tls_sock_ext_data_t* sock_ext_data = tls_sock_ext_get_data(sock);
        struct sockaddr_un int_addr = {
                .sun_family = AF_INET,
        };

	unix_sock = sock_ext_data->unix_sock;

	if (sock_ext_data->has_bound == 0) {
		/* Invoke autobind */
		(*ref_unix_bind)(unix_sock, (struct sockaddr*)&int_addr, sizeof(sa_family_t));
		sock_ext_data->int_addrlen = sizeof(sa_family_t) + 6;
		memcpy(&sock_ext_data->int_addr, unix_sk(unix_sock->sk)->addr->name, sock_ext_data->int_addrlen);
		sock_ext_data->has_bound = 1;
	}
	send_listen_notification((unsigned long)sock, 
			(struct sockaddr*)&sock_ext_data->int_addr,
		        (struct sockaddr*)&sock_ext_data->ext_addr,
			sock_ext_data->daemon_id);

	if (wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -EADDRINUSE;
	}
	if (sock_ext_data->response != 0) {
		return sock_ext_data->response;
	}
	return (*ref_unix_listen)(unix_sock, backlog);
}

int tls_unix_accept(struct socket *sock, struct socket *newsock, int flags, bool kern) {
	struct socket* unix_sock;
	tls_sock_ext_data_t* sock_ext_data = tls_sock_ext_get_data(sock);
	unix_sock = sock_ext_data->unix_sock;
	return (*ref_unix_accept)(unix_sock, newsock, flags, kern);
}

int tls_unix_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen) {
	struct socket* unix_sock;
	tls_sock_ext_data_t* sock_ext_data = tls_sock_ext_get_data(sock);
	unix_sock = sock_ext_data->unix_sock;
	return common_setsockopt(unix_sock->sk, level, optname, optval, optlen, NULL);
}

int tls_unix_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen) {
	struct socket* unix_sock;
	tls_sock_ext_data_t* sock_ext_data = tls_sock_ext_get_data(sock);
	unix_sock = sock_ext_data->unix_sock;
	return common_getsockopt(unix_sock->sk, level, optname, optval, optlen, NULL);
}

