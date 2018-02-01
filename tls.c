/*
 * Overrides the TCP functions to give the TLS functionality. Also contains functions manage
 * the hash table where TLS socket options are stored.
 */

#include <net/inet_sock.h>
#include <net/af_unix.h>
#include <linux/un.h>
#include <linux/net.h>
#include <linux/ctype.h>
#include <linux/completion.h>
#include <linux/cpumask.h>

#include <net/sock.h>
#include <linux/un.h>
#include <linux/string.h>
#include <uapi/linux/uio.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/spinlock.h>

#include "socktls.h"
#include "netlink.h"
#include "tls.h"

#define RESPONSE_TIMEOUT	HZ*100
#define HASH_TABLE_BITSIZE	9
#define DAEMON_START_PORT	8443

#define MAX_HOST_LEN		255

#define TCP_UPGRADE_TLS	33

#define TLS_UPGRADE_PATH	"\0tls_upgrade" 
#define TLS_UPGRADE_PATH_LEN	sizeof(TLS_UPGRADE_PATH)

#define MAX_CON_INFO_SIZE	64

static DEFINE_HASHTABLE(tls_sock_ext_data_table, HASH_TABLE_BITSIZE);
static DEFINE_SPINLOCK(tls_sock_ext_lock);

/* Original TCP reference functions */
extern int (*ref_tcp_v4_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
extern int (*ref_tcp_v6_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
extern int (*ref_tcp_disconnect)(struct sock *sk, int flags);
extern void (*ref_tcp_shutdown)(struct sock *sk, int how);
extern int (*ref_tcp_recvmsg)(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
                        int flags, int *addr_len);
extern int (*ref_tcp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t size);
extern int (*ref_tcp_v4_init_sock)(struct sock *sk);
extern void (*ref_tcp_v4_destroy_sock)(struct sock *sk);
extern void (*ref_tcp_close)(struct sock *sk, long timeout);
extern int (*ref_tcp_setsockopt)(struct sock *sk, int level, int optname, char __user *optval, unsigned int len);
extern int (*ref_tcp_getsockopt)(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen);

/* Original Unix domain reference functions */
extern int (*ref_unix_init_sock)(struct sock *sk);
extern int (*ref_unix_release)(struct socket* sock);
extern int (*ref_unix_bind)(struct socket *sock, struct sockaddr *uaddr, int addr_len);
extern int (*ref_unix_connect)(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags);
extern int (*ref_unix_listen)(struct socket *sock, int backlog);
extern int (*ref_unix_accept)(struct socket *sock, struct socket *newsock, int flags, bool kern);
extern int (*ref_unix_setsockopt)(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen);
extern int (*ref_unix_getsockopt)(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen);

/* inet stream reference functions */
extern int (*ref_inet_listen)(struct socket *sock, int backlog);
extern int (*ref_inet_accept)(struct socket *sock, struct socket *newsock, int flags, bool kern);
extern int (*ref_inet_bind)(struct socket *sock, struct sockaddr *uaddr, int addr_len);

/* Auxillary support reference functions */
extern int (*orig_tcp_setsockopt)(struct sock*, int, int, char __user*, unsigned int);

int get_hostname(struct sock* sk, char __user *optval, int* __user len);
int get_id(struct sock* sk, char __user *optval, int* __user optlen);
int set_hostname(tls_sock_ext_data_t* sock_ext_data, char* optval, unsigned int len);
int is_valid_host_string(char* str, int len);

unsigned int balancer = 0;

static int common_setsockopt(struct sock *sk, int level, int optname, char __user *optval, unsigned int len, typeof(ref_tcp_setsockopt) orig_func);
static int common_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen, typeof(ref_tcp_getsockopt) orig_func);

/* Original AF Inet reference functions */
int tls_inet_listen(struct socket *sock, int backlog) {
	tls_sock_ext_data_t* sock_ext_data = tls_sock_ext_get_data(sock->sk);
        struct sockaddr_in int_addr = {
                .sin_family = AF_INET,
                .sin_port = 0,
                .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        };
	/*struct sockaddr_in ext_addr = {
                .sin_family = AF_INET,
                .sin_port = 0,
                .sin_addr.s_addr = htonl(INADDR_ANY),
        };*/

	if (sock_ext_data->has_bound == 0) {
		(*ref_inet_bind)(sock, (struct sockaddr*)&int_addr, sizeof(int_addr));
        	//kernel_bind(sock, (struct sockaddr*)&int_addr, sizeof(int_addr));
		int_addr.sin_port = inet_sk(sock->sk)->inet_sport;
		memcpy(&sock_ext_data->int_addr, &int_addr, sizeof(int_addr));
		sock_ext_data->int_addrlen = sizeof(int_addr);
		//memcpy(&sock_ext_data->ext_addr, &ext_addr, sizeof(ext_addr));
		//sock_ext_data->ext_addrlen = sizeof(ext_addr);
		sock_ext_data->has_bound = 1;
	}
	send_listen_notification((unsigned long)sock->sk, 
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
	return (*ref_inet_listen)(sock, backlog);
}

int tls_inet_accept(struct socket *sock, struct socket *newsock, int flags, bool kern) {
	return (*ref_inet_accept)(sock, newsock, flags, kern);
}

int tls_inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len) {
	int ret;
	tls_sock_ext_data_t* sock_ext_data;
	/* We disregard the address the application wants to bind to in favor
	 * of one assigned by the system (using sin_port = 0 on localhost),
	 * so that we can have the TLS wrapper daemon bind to the actual one */

	sock_ext_data = tls_sock_ext_get_data(sock->sk);
	ret = (*ref_inet_bind)(sock, &sock_ext_data->int_addr, addr_len);

	/* We can use the port number now because inet_bind will have set
	 * it for us */
	((struct sockaddr_in*)&sock_ext_data->int_addr)->sin_port = inet_sk(sock->sk)->inet_sport;

	/* We only want to continue if the internal socket bind succeeds */
	if (ret != 0) {
		printk(KERN_ALERT "Internal bind failed\n");
		return ret;
	}

	send_bind_notification((unsigned long)sock->sk, &sock_ext_data->int_addr, (struct sockaddr*)uaddr,
			sock_ext_data->daemon_id);
	if (wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -EADDRINUSE;
	}
	if (sock_ext_data->response != 0) {
		return sock_ext_data->response;
	}
	sock_ext_data->has_bound = 1;
	sock_ext_data->int_addrlen = addr_len;
	sock_ext_data->ext_addr = *uaddr;
	sock_ext_data->ext_addrlen = addr_len;
	return 0;
}

/* Overriden TLS connect for v4 function */
int tls_tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) {
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
	tls_sock_ext_data_t* sock_ext_data = tls_sock_ext_get_data(sk);
	sock_ext_data->rem_addr = (struct sockaddr)(*uaddr);
	sock_ext_data->rem_addrlen = addr_len;

	/* Pre-emptively bind the source port so we can register it before remote
	 * connection. We only do this if the application hasn't explicitly called
	 * bind already */
	if (sock_ext_data->has_bound == 0) {
		release_sock(sk);
		(*ref_inet_bind)(sk->sk_socket, (struct sockaddr*)&int_addr, sizeof(int_addr));
		//kernel_bind(sk->sk_socket, (struct sockaddr*)&int_addr, sizeof(int_addr));
		lock_sock(sk);
		int_addr.sin_port = inet_sk(sk)->inet_sport;
		memcpy(&sock_ext_data->int_addr, &int_addr, sizeof(int_addr));
		sock_ext_data->int_addrlen = sizeof(int_addr);
		sock_ext_data->has_bound = 1;
	}

	/* Handle case wherein a socket is connecting directly to the daemon */
	/*uaddr_in = (struct sockaddr_in*)uaddr;
	if (uaddr_in->sin_port == htons(8443) && uaddr_in->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
		ret = (*ref_tcp_v4_connect)(sk, uaddr, addr_len);
		if (ret != 0) {
			return ret;
		}
		sock_ext_data->is_connected = 1;
		return 0;
	}*/

	send_connect_notification((unsigned long)sk, &sock_ext_data->int_addr, uaddr, sock_ext_data->daemon_id);
	if (wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -EHOSTUNREACH;
	}
	if (sock_ext_data->response != 0) {
		return sock_ext_data->response;
	}
	reroute_addr.sin_port = htons(sock_ext_data->daemon_id);
	ret = (*ref_tcp_v4_connect)(sk, ((struct sockaddr*)&reroute_addr), sizeof(reroute_addr));
	if (ret != 0) {
		return ret;
	}
	sock_ext_data->is_connected = 1;
	return 0;
}

/* Overriden TLS connect for v6 function */
int tls_tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) {
	return (*ref_tcp_v6_connect)(sk, uaddr, addr_len);
}

/* Overriden TLS disconnect function */
int tls_tcp_disconnect(struct sock *sk, int flags) {
	return (*ref_tcp_disconnect)(sk, flags);
}

/* Overriden TLS shutdown function */
void tls_tcp_close(struct sock *sk, long timeout) {
	(*ref_tcp_close)(sk, timeout);
	return;
}

/* Overriden TLS recvmsg function */
int tls_tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len){
	return (*ref_tcp_recvmsg)(sk, msg, len, nonblock, flags, addr_len);
}

/* Overriden TLS sendmsg function */
int tls_tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size){
	return (*ref_tcp_sendmsg)(sk, msg, size);
}

/* Overriden TLS shutodwn function */
void tls_tcp_shutdown(struct sock *sk, int how){
	return (*ref_tcp_shutdown)(sk, how);
}

/* Overriden TLS init function */
int tls_tcp_v4_init_sock(struct sock *sk) {
	int ret;
	tls_sock_ext_data_t* sock_ext_data;
	if ((sock_ext_data = kmalloc(sizeof(tls_sock_ext_data_t),GFP_ATOMIC)) == NULL) {
		printk(KERN_ALERT "kmalloc failed in tls_v4_init_sock\n");
		return -1;
	}

	memset(sock_ext_data, 0, sizeof(tls_sock_ext_data_t));

	((struct sockaddr_in*)&sock_ext_data->int_addr)->sin_family = AF_INET;
	((struct sockaddr_in*)&sock_ext_data->int_addr)->sin_port = 0;
	((struct sockaddr_in*)&sock_ext_data->int_addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	sock_ext_data->pid = current->pid;
	sock_ext_data->sk = sk;
	sock_ext_data->key = (unsigned long)sk;
	//sock_ext_data->daemon_id = DAEMON_START_PORT;
	sock_ext_data->daemon_id = DAEMON_START_PORT + (balancer % nr_cpu_ids);
	//printk(KERN_INFO "Assigning new socket to daemon %d\n", sock_ext_data->daemon_id);
	balancer = (balancer+1) % nr_cpu_ids;
	init_completion(&sock_ext_data->sock_event);
	spin_lock(&tls_sock_ext_lock);
	hash_add(tls_sock_ext_data_table, &sock_ext_data->hash, sock_ext_data->key);
	spin_unlock(&tls_sock_ext_lock);
	ret = (*ref_tcp_v4_init_sock)(sk);

	send_socket_notification((unsigned long)sk, sock_ext_data->daemon_id);
	wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT);
	/* We're not checking return values here because init_sock always returns 0 */
	return ret;
}

void tls_tcp_v4_destroy_sock(struct sock* sk) {
	tls_sock_ext_data_t* sock_ext_data = tls_sock_ext_get_data(sk);
	if (sock_ext_data == NULL) {
		return;
	}
	//send_close_notification((unsigned long)sk, sock_ext_data->daemon_id);
	//wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT);
	if (sock_ext_data->hostname != NULL) {
		kfree(sock_ext_data->hostname);
	}
	spin_lock(&tls_sock_ext_lock);
	hash_del(&sock_ext_data->hash); /* remove from ext_data_Table */
	spin_unlock(&tls_sock_ext_lock);
	kfree(sock_ext_data);
	(*ref_tcp_v4_destroy_sock)(sk);
	return;
}

/**
 * Finds a socket option in the hash table
 * @param	sk - A pointer to the sock struct related to the socket option
 * @return	The desired socket options if found. If not found, returns NULL
 */
tls_sock_ext_data_t* tls_sock_ext_get_data(struct sock* sk) {
	tls_sock_ext_data_t* it;
	hash_for_each_possible(tls_sock_ext_data_table, it, hash, (unsigned long)sk) {
		if (it->sk == sk) {
			return it;
		}
	}
	return NULL;
}

void tls_setup() {
	register_netlink();
	hash_init(tls_sock_ext_data_table);
	return;
}

void tls_cleanup() {
        int bkt;
        tls_sock_ext_data_t* it;
        struct hlist_node tmp;
        struct hlist_node* tmpptr = &tmp;

        spin_lock(&tls_sock_ext_lock);
        hash_for_each_safe(tls_sock_ext_data_table, bkt, tmpptr, it, hash) {
		//(*ref_tcp_close)(it->sk, 0);
		if (it->int_addr.sa_family == AF_INET) {
			(*ref_tcp_v4_destroy_sock)(it->sk);
		}
		else {
			(*ref_unix_release)((it->sk)->sk_socket);
		}
                hash_del(&it->hash);
                kfree(it->hostname);
		kfree(it);
        }
        spin_unlock(&tls_sock_ext_lock);

	unregister_netlink();

	return;
}

int tls_tcp_setsockopt(struct sock *sk, int level, int optname, char __user *optval, unsigned int len) {
	return common_setsockopt(sk, level, optname, optval, len, ref_tcp_setsockopt);
}

int common_setsockopt(struct sock *sk, int level, int optname, char __user *optval, unsigned int len, typeof(ref_tcp_setsockopt) orig_func) {
	int ret;
	char* koptval;
	tls_sock_ext_data_t* sock_ext_data;
	sock_ext_data = tls_sock_ext_get_data(sk);

	if (sock_ext_data == NULL) {
		return -EBADF;
	}
	if (optval == NULL) {
		return -EINVAL;	
	}
	if (len == 0) {
		return -EINVAL;
	}
	koptval = kmalloc(len, GFP_ATOMIC);
	if (koptval == NULL) {
		return -ENOMEM;
	}
	if (copy_from_user(koptval, optval, len) != 0) {
		kfree(koptval);
		return -EFAULT;
	}

	/* Here we save all TLS-specific sockopt values so that
	 * we can retrieve them directly from the kernel when
	 * the application uses getsockopt */
	switch (optname) {
		case SO_HOSTNAME:
			ret = set_hostname(sock_ext_data, koptval, len);
			break;
		case SO_CERTIFICATE_CHAIN:
		case SO_PRIVATE_KEY:
		default:
			ret = 0;
			break;
	}

	/* We return early if preliminary checks during our
	 * kernel-side saving of sockopts failed. No sense
	 * in telling the daemon about it. */
	if (ret != 0) {
		kfree(koptval);
		return ret;
	}

	send_setsockopt_notification((unsigned long)sk, level, optname, koptval, len, sock_ext_data->daemon_id);
	kfree(koptval);
	if (wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -ENOBUFS;
	}
	if (sock_ext_data->response != 0) {
		return sock_ext_data->response;
	}

	/* We only get here if the daemonside setsockopt succeeded */

	switch (optname) {
		case SO_HOSTNAME:
		case SO_CERTIFICATE_CHAIN:
		case SO_PRIVATE_KEY:
			break;
		default:
			/* Now we do the same thing to the application socket, if applicable */
			if (orig_func) {
				return orig_func(sk, level, optname, optval, len);
			}
			return -EOPNOTSUPP;
			break;
	}
	return 0;
}

int tls_tcp_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen) {
	return common_getsockopt(sk, level, optname, optval, optlen, ref_tcp_getsockopt);
}

int common_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen, typeof(ref_tcp_getsockopt) orig_func) {
	int len;
	tls_sock_ext_data_t* sock_ext_data;
	sock_ext_data = tls_sock_ext_get_data(sk);
	if (get_user(len, optlen)) {
		return -EFAULT;
	}
	switch (optname) {
		case SO_HOSTNAME:
			return get_hostname(sk, optval, optlen);
		case SO_ID:
			return get_id(sk, optval, optlen);
		case SO_PEER_CERTIFICATE:
		/* We'll probably add all other daemon-required getsockopt options here
		 * as fall-through cases. The following implementation is fairly generic.
		 */
			send_getsockopt_notification((unsigned long)sk, level, optname, sock_ext_data->daemon_id);
			if (wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT) == 0) {
				/* Let's lie to the application if the daemon isn't responding */
				return -ENOBUFS;
			}
			if (sock_ext_data->response != 0) {
				return sock_ext_data->response;
			}


			/* We set this to the minimum of actual data length and size
			 * of user's buffer rather than aborting if the user one is 
			 * smaller because POSIX says to silently truncate in this
			 * case */
			len = min_t(unsigned int, len, sock_ext_data->data_len);
			if (unlikely(put_user(len, optlen))) {
				kfree(sock_ext_data->data);
				sock_ext_data->data = NULL;
				sock_ext_data->data_len = 0;
				return -EFAULT;
			}
			if (copy_to_user(optval, sock_ext_data->data, len)) {
				kfree(sock_ext_data->data);
				sock_ext_data->data = NULL;
				sock_ext_data->data_len = 0;
				return -EFAULT;
			}
			break;
		default:
			if (orig_func) {
				return orig_func(sk, level, optname, optval, optlen);
			}
			return -EOPNOTSUPP;
	}
	return 0;
}

int set_hostname(tls_sock_ext_data_t* sock_ext_data, char* optval, unsigned int len) {
	if (sock_ext_data->is_connected == 1) {
		return -EISCONN;
	}
	if (len > MAX_HOST_LEN) {
		return -EINVAL;
	}
	sock_ext_data->hostname = krealloc(sock_ext_data->hostname, len, GFP_ATOMIC);
	if (sock_ext_data->hostname == NULL) {
		return -ENOMEM;
	}
	if (!is_valid_host_string(optval, len)) {
		return -EINVAL;
	}
	memcpy(sock_ext_data->hostname, optval, len);
	return  0;
}

int get_hostname(struct sock* sk, char __user *optval, int* __user len) {
	int hostname_len;
	tls_sock_ext_data_t* data;
	char* hostname = NULL;
	if ((data = tls_sock_ext_get_data(sk)) == NULL) {
		return -EBADF;
	}
	hostname = data->hostname;
	if (hostname == NULL) {
		return -EFAULT;
	}
	hostname_len = strnlen(hostname, MAX_HOST_LEN) + 1;
	if (*len < hostname_len) {
		return -EINVAL;	
	}
	if (copy_to_user(optval, hostname, hostname_len) != 0 ) {
		return -EFAULT;
	}
	*len = hostname_len;
	return 0;
}

/* The ID is just the pointer value sk */
int get_id(struct sock* sk, char __user *optval, int* __user optlen) {
	int len;
	if (get_user(len, optlen)) {
		return -EFAULT;
	}
	len = min_t(unsigned int, len, sizeof(sk));
	if (put_user(len, optlen)) {
		return -EFAULT;
	}
	if (copy_to_user(optval, &sk, len)) {
		return -EFAULT;
	}
	return 0;
}

/* 
 * Tests whether a socket option input contains only valid host name characters
 * as defined by RFC 952 and RFC 1123.
 * @param	str - A pointer to a string to be checked
 * @param	len - The length of str, including null terminator 
 * @return	1 if string is valid and 0 otherwise
 */
int is_valid_host_string(char* str, int len) {
	int i;
	char c;
	for (i = 0; i < len-1; i++) {
		c = str[i];
                if (!isalnum(c) && c != '-' && c != '.') {
			return 0;
                }
        }
	if (str[len-1] != '\0') {
		return 0;
	}
        return 1;
}

void report_return(unsigned long key, int ret) {
	tls_sock_ext_data_t* sock_ext_data;
	sock_ext_data = tls_sock_ext_get_data((struct sock*)key);
	//BUG_ON(sock_ext_data == NULL);
	if (sock_ext_data == NULL) {
		return;
	}
	sock_ext_data->response = ret;
	complete(&sock_ext_data->sock_event);
	return;
}

void report_data_return(unsigned long key, char* data, unsigned int len) {
	tls_sock_ext_data_t* sock_ext_data;
	sock_ext_data = tls_sock_ext_get_data((struct sock*)key);
	//BUG_ON(sock_ext_data == NULL);
	if (sock_ext_data == NULL) {
		return;
	}
	sock_ext_data->data = kmalloc(len, GFP_ATOMIC);
	if (sock_ext_data->data == NULL) {
		printk(KERN_ALERT "failed to create memory for getsockopt return\n");
	}
	memcpy(sock_ext_data->data, data, len);
	sock_ext_data->data_len = len;
	/* set success if this callback is used.
	 * The report_return case is for errors
	 * and simple statuses */
	sock_ext_data->response = 0;
	complete(&sock_ext_data->sock_event);
	return;
}

/* File Descriptor Passing Functions */

// recieves a message back from the daemon as confirmation of file descriptor reciept
int recv_con(struct socket* sock) {
	char buf[1014];
	struct kvec iov;
	struct msghdr msg = {0};
	int err;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	printk(KERN_ERR "1\n");
	err = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, 0);
	printk(KERN_ERR "2\n");

	if (err == -1) {
		printk(KERN_ERR "recvmsg error\n");
	} else {
		printk(KERN_INFO "Got msg(%d) \"%s\"\n", err, buf);
	}

	return err;
}

int sockdup2(int oldfd, struct socket* sock) {
	struct files_struct* files;
	struct file* filp;

	files = current->files;

	// lock the files
	spin_lock(&files->file_lock);

	// grab the old filp
	filp = files->fdt->fd[oldfd];
	
	// NULL out oldfd
	files->fdt->fd[oldfd] = NULL;
	
	// replace it with the new
	fd_install(oldfd, sock->file); 

	// unlock
	spin_unlock(&files->file_lock);

	// close the old file
	filp_close(filp, files);

	return 0;
}

// finds the associated file descriptor for a struct sock*
int getsk_fd(struct sock* sk) {
	int i;
	struct fdtable* fdt;
	struct file* sk_fp;

	if (sk == NULL) {
		return -1;
	}

	sk_fp = sk->sk_socket->file;

	fdt = files_fdtable(current->files);

	for (i=0; i<fdt->max_fds; i++) {
		if (fdt->fd[i] == sk_fp) {
			return i;
		}
	}
	return -1;
}

// takes the fd you want to gift to the daemon
// the buf and buf size are the message
ssize_t write_fd(int fd_gift, char* buf, int buf_sz) {
	int error;
	struct socket* sock;
	struct sockaddr_un addr;
    	struct sockaddr_un self;

	struct msghdr msg = {0};
	struct kvec iov;

	//TODO remove printfs from this call

	union {
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr* cmptr;

	error = sock_create(PF_UNIX, SOCK_DGRAM, 0, &sock); 
	if (error < 0) {
		printk(KERN_ERR "sock_create error\n");
		return -1;
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, TLS_UPGRADE_PATH, TLS_UPGRADE_PATH_LEN);
	
	error = kernel_connect(sock, (struct sockaddr*)&addr, sizeof(addr), 0);
	if (error < 0) {
		printk(KERN_ERR "connect error\n");
		sock_release(sock);
		return -1;
	}

	// make and send the message

	msg.msg_control = control_un.control;
	msg.msg_controllen = sizeof(control_un.control);

	cmptr = CMSG_FIRSTHDR(&msg);
	cmptr->cmsg_len = CMSG_LEN(sizeof(int));
	cmptr->cmsg_level = SOL_SOCKET;
	cmptr->cmsg_type = SCM_RIGHTS;

	*((int*) CMSG_DATA(cmptr)) = fd_gift;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	iov.iov_base = buf;
	iov.iov_len = buf_sz;

	iov_iter_kvec(&msg.msg_iter, READ | ITER_KVEC, &iov, 1, iov.iov_len);
	
	// before we send the message, we need to bind so they can send back something as a confirmation
	self.sun_family = AF_UNIX;

	// autobind only is invoked if bind size == 2 == sizeof(sa_family_t)
	if (kernel_bind(sock, (struct sockaddr*)&self, sizeof(sa_family_t)) == -1) {
		printk(KERN_ERR "bind error\n");
		sock_release(sock);
		return -1;
	}

	error = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
	if (error == -1) {
		printk(KERN_ERR "sendmsg error\n");
	}

	// revc confirmation
	printk(KERN_INFO "recving confirmation\n");
	recv_con(sock);

	printk(KERN_INFO "got confirmation\n");

	// clean up
	sock_release(sock);
	return 0;
}

// hooks tcp's setsockopt so that we can find our special options
int hook_tcp_setsockopt(struct sock* sk, int level, int optname, char __user* optval, unsigned int optlen) {
	int fd;
	char con_info[MAX_CON_INFO_SIZE];
	int con_info_size;
	int is_accepting;
	int error;
	struct socket* new_sock;
	
	//TODO get rid of printfs
	printk(KERN_INFO "Hook called\n");
	// first check if it is our special opt
	// otherwise pass it on
	if (level == SOL_TCP && optname == TCP_UPGRADE_TLS) {
		if (optlen < sizeof(int)) {
			printk(KERN_ERR "optlen for TCP_UPGRADE_TLS was not\n");
			is_accepting = 0;
		} else {
			is_accepting = *((int*)optval);
		}
		
		printk(KERN_INFO "Got TCP_UPGRADE_TLS %d\n", is_accepting);
		// try to send some info to the server with a unix domain socket
		// find the fd associated with this sk
		fd = getsk_fd(sk);
		if (fd == -1) {
			printk(KERN_ERR "BadBadNotGood Couldn't find sk in fd\n");
			return -1;
		}
		//TODO
		// on this tcp sock we need to know if this is a connection, unconnected, listening, accepted
		// make tls sock
		
		error = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TLS, &new_sock);
		if (error < 0) {
			printk(KERN_ERR "Could not create TLS socket :(\n");
			return -1;
		}
		
		// get tls sock id
		
		// create the correct message to send
		con_info_size = snprintf(con_info, MAX_CON_INFO_SIZE, "%d:%lu", is_accepting, (long unsigned int)(void*)new_sock);
		// gift the original connection
		// and recv for a completion
		write_fd(fd, con_info, con_info_size);
		printk(KERN_INFO "Sent fd\n");
		
		// dup2 tls over fd
		// so we can't acutally use dup_2, so we null out the fd and install it quickly, haha.
		sockdup2(fd, new_sock);
		
		return 0;
	}	

	return orig_tcp_setsockopt(sk, level, optname, optval, optlen);
}

/* TLS override functions for Unix */
int tls_unix_init_sock(struct sock *sk) {
	tls_sock_ext_data_t* sock_ext_data;
	if ((sock_ext_data = kmalloc(sizeof(tls_sock_ext_data_t),GFP_ATOMIC)) == NULL) {
		printk(KERN_ALERT "kmalloc failed in tls_unix_init_sock\n");
		return -1;
	}

	memset(sock_ext_data, 0, sizeof(tls_sock_ext_data_t));

	((struct sockaddr_un*)&sock_ext_data->int_addr)->sun_family = AF_UNIX;

	sock_ext_data->pid = current->pid;
	sock_ext_data->sk = sk;
	sock_ext_data->key = (unsigned long)sk;
	sock_ext_data->daemon_id = DAEMON_START_PORT;
	//sock_ext_data->daemon_id = DAEMON_START_PORT + (balancer % nr_cpu_ids);
	//printk(KERN_INFO "Assigning new socket to daemon %d\n", sock_ext_data->daemon_id);
	balancer = (balancer+1) % nr_cpu_ids;
	init_completion(&sock_ext_data->sock_event);
	spin_lock(&tls_sock_ext_lock);
	hash_add(tls_sock_ext_data_table, &sock_ext_data->hash, sock_ext_data->key);
	spin_unlock(&tls_sock_ext_lock);
	/*if (ref_unix_init_sock != NULL) {
		(*ref_unix_init_sock)(sk);
	}*/

	send_socket_notification((unsigned long)sk, sock_ext_data->daemon_id);
	wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT);
	/* We're not checking return values here because init_sock always returns 0 */
	return 0;
}

int tls_unix_release(struct socket* sock) {
	struct sock* sk = sock->sk;
	tls_sock_ext_data_t* sock_ext_data = tls_sock_ext_get_data(sk);
	if (sock_ext_data == NULL) {
		return 0;
	}
	//send_close_notification((unsigned long)sk, sock_ext_data->daemon_id);
	//wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT);
	if (sock_ext_data->hostname != NULL) {
		kfree(sock_ext_data->hostname);
	}
	spin_lock(&tls_sock_ext_lock);
	hash_del(&sock_ext_data->hash); /* remove from ext_data_Table */
	spin_unlock(&tls_sock_ext_lock);
	kfree(sock_ext_data);
	return (*ref_unix_release)(sock);
}

int tls_unix_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len) {
	int ret;
	tls_sock_ext_data_t* sock_ext_data;
	/* We disregard the address the application wants to bind to in favor
	 * of one assigned by the system (using sin_port = 0 on localhost),
	 * so that we can have the TLS wrapper daemon bind to the actual one */

	sock_ext_data = tls_sock_ext_get_data(sock->sk);
	ret = (*ref_unix_bind)(sock, &sock_ext_data->int_addr, sizeof(sa_family_t));

	/* We only want to continue if the internal socket bind succeeds */
	if (ret != 0) {
		printk(KERN_ALERT "Internal bind failed\n");
		return ret;
	}

	/* We can use the abstract name now because unix_bind will have set
	 * it for us */
	memcpy(&sock_ext_data->int_addr, unix_sk(sock->sk)->addr->name,
		       	sizeof(sa_family_t) + 6);

	send_bind_notification((unsigned long)sock->sk, &sock_ext_data->int_addr, (struct sockaddr*)uaddr, sock_ext_data->daemon_id);
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
	struct sockaddr_un reroute_addr = {
		.sun_family = AF_UNIX,
	};

	struct sockaddr_un int_addr = {
		.sun_family = AF_UNIX
	};

	struct sock* sk = sock->sk;
	/* Save original destination address information */
	tls_sock_ext_data_t* sock_ext_data = tls_sock_ext_get_data(sk);
	sock_ext_data->rem_addr = (struct sockaddr)(*uaddr);
	sock_ext_data->rem_addrlen = addr_len;

	/* Pre-emptively bind the source port so we can register it before remote
	 * connection. We only do this if the application hasn't explicitly called
	 * bind already */
	if (sock_ext_data->has_bound == 0) {
		(*ref_unix_bind)(sock, (struct sockaddr*)&int_addr, sizeof(sa_family_t));
		sock_ext_data->int_addrlen = sizeof(sa_family_t) + 6;
		memcpy(&sock_ext_data->int_addr, unix_sk(sk)->addr->name, 
				sock_ext_data->int_addrlen);
		sock_ext_data->has_bound = 1;
	}

	send_connect_notification((unsigned long)sk, &sock_ext_data->int_addr, uaddr, sock_ext_data->daemon_id);
	if (wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -EHOSTUNREACH;
	}
	if (sock_ext_data->response != 0) {
		return sock_ext_data->response;
	}

	reroute_addrlen = sprintf(reroute_addr.sun_path+1, "%d", sock_ext_data->daemon_id) + 1 + sizeof(sa_family_t);
	printk(KERN_INFO "sock is redirected to %s\n", reroute_addr.sun_path+1);
	ret = (*ref_unix_connect)(sock, ((struct sockaddr*)&reroute_addr), reroute_addrlen, flags);
	if (ret != 0) {
		return ret;
	}
	sock_ext_data->is_connected = 1;
	return 0;
}

int tls_unix_listen(struct socket *sock, int backlog) {
	tls_sock_ext_data_t* sock_ext_data = tls_sock_ext_get_data(sock->sk);
        struct sockaddr_un int_addr = {
                .sun_family = AF_INET,
        };

	if (sock_ext_data->has_bound == 0) {
		/* Invoke autobind */
		(*ref_unix_bind)(sock, (struct sockaddr*)&int_addr, sizeof(sa_family_t));
		sock_ext_data->int_addrlen = sizeof(sa_family_t) + 6;
		memcpy(&sock_ext_data->int_addr, unix_sk(sock->sk)->addr->name, 
				sock_ext_data->int_addrlen);
		sock_ext_data->has_bound = 1;
	}
	send_listen_notification((unsigned long)sock->sk, 
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
	return (*ref_unix_listen)(sock, backlog);
}

int tls_unix_accept(struct socket *sock, struct socket *newsock, int flags, bool kern) {
	return (*ref_unix_accept)(sock, newsock, flags, kern);
}

int tls_unix_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen) {
	return common_setsockopt(sock->sk, level, optname, optval, optlen, NULL);
}

int tls_unix_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen) {
	return common_getsockopt(sock->sk, level, optname, optval, optlen, NULL);
}

