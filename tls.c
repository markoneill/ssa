/*
 * Overrides the TCP functions to give the TLS functionality. Also contains functions manage
 * the hash table where TLS socket options are stored.
 */

#include <net/inet_sock.h>
#include <linux/net.h>
#include <linux/completion.h>
#include "socktls.h"
#include "netlink.h"
#include "tls.h"

#define RESPONSE_TIMEOUT	HZ
#define HASH_TABLE_BITSIZE	9
#define REROUTE_PORT		8443

#define MAX_HOST_LEN		255

static DEFINE_HASHTABLE(tls_sock_ext_data_table, HASH_TABLE_BITSIZE);
static DEFINE_SPINLOCK(tls_sock_ext_lock);

static DEFINE_HASHTABLE(dst_map, HASH_TABLE_BITSIZE);
static DEFINE_SPINLOCK(dst_map_lock);

/* Original TCP reference functions */
extern int (*ref_tcp_v4_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
extern int (*ref_tcp_v6_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
extern struct sock* (*ref_inet_csk_accept)(struct sock *sk, int flags, int *err);
extern int (*ref_tcp_disconnect)(struct sock *sk, int flags);
extern void (*ref_tcp_shutdown)(struct sock *sk, int how);
extern int (*ref_tcp_recvmsg)(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
                        int flags, int *addr_len);
extern int (*ref_tcp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t size);
extern void (*ref_tcp_close)(struct sock *sk, long timeout);
extern int (*ref_tcp_v4_init_sock)(struct sock *sk);
extern void (*ref_tcp_v4_destroy_sock)(struct sock *sk);
extern int (*ref_tcp_setsockopt)(struct sock *sk, int level, int optname, char __user *optval, unsigned int len);
extern int (*ref_tcp_getsockopt)(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen);

/* inet reference functions */
extern int (*ref_inet_listen)(struct socket *sock, int backlog);
extern int (*ref_inet_accept)(struct socket *sock, struct socket *newsock, int flags, bool kern);
extern int (*ref_inet_bind)(struct socket *sock, struct sockaddr *uaddr, int addr_len);

tls_sock_ext_data_t* get_tls_sock_data_using_local_endpoint(struct sock *sk);

int get_hostname(struct sock* sk, char __user *optval, int* __user len);
int set_hostname(struct sock* sk, char __user *optval, unsigned int len);
int is_valid_host_string(void *input);
int get_orig_dst(struct sock *sk, void __user *optval, int __user *len);

struct sockaddr_in reroute_addr = {
	.sin_family = AF_INET,
	.sin_port = htons(REROUTE_PORT),
	.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
};

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
		        (struct sockaddr*)&sock_ext_data->ext_addr);

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
        struct sockaddr_in int_addr = {
                .sin_family = AF_INET,
                .sin_port = 0,
                .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        };

	/* We disregard the address the application wants to bind to in favor
	 * of one assigned by the system (using sin_port = 0 on localhost),
	 * so that we can have the TLS wrapper daemon bind to the actual one */
	tls_sock_ext_data_t* sock_ext_data = tls_sock_ext_get_data(sock->sk);
	BUG_ON(sock_ext_data == NULL);
	printk(KERN_ALERT "bind was called");
	ret = (*ref_inet_bind)(sock, (struct sockaddr*)&int_addr, sizeof(int_addr));

	/* We can use the port number now because inet_bind will have set
	 * it for us */
	int_addr.sin_port = inet_sk(sock->sk)->inet_sport;
	sock_ext_data->remote_key = int_addr.sin_port;
	printk(KERN_ALERT "Adding source port %lu to map\n", (unsigned long)sock_ext_data->remote_key);

	/* We only want to continue if the internal socket bind succeeds */
	if (ret != 0) {
		return ret;
	}

	send_bind_notification((unsigned long)sock->sk, (struct sockaddr*)&int_addr, (struct sockaddr*)uaddr);
	if (wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -EADDRINUSE;
	}
	if (sock_ext_data->response != 0) {
		return sock_ext_data->response;
	}
	sock_ext_data->has_bound = 1;
	memcpy(&sock_ext_data->int_addr, &int_addr, sizeof(int_addr));
	sock_ext_data->int_addrlen = sizeof(int_addr);
	sock_ext_data->ext_addr = *uaddr;
	sock_ext_data->ext_addrlen = addr_len;
	return 0;
}

/* Overriden TLS connect for v4 function */
int tls_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) {
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
		sock_ext_data->remote_key = int_addr.sin_port;
		memcpy(&sock_ext_data->int_addr, &int_addr, sizeof(int_addr));
		sock_ext_data->int_addrlen = sizeof(int_addr);
		sock_ext_data->has_bound = 1;
		printk(KERN_ALERT "Adding source port %lu to map\n", (unsigned long)int_addr.sin_port);
	}

	/* Use bound source port as the key for rem_addr hash lookup */
	spin_lock(&dst_map_lock);
	hash_add(dst_map, &sock_ext_data->remote_hash, sock_ext_data->remote_key);
	spin_unlock(&dst_map_lock);

	
	send_connect_notification((unsigned long)sk, &sock_ext_data->int_addr, uaddr);
	if (wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -EHOSTUNREACH;
	}
	if (sock_ext_data->response != 0) {
		return sock_ext_data->response;
	}
	return (*ref_tcp_v4_connect)(sk, ((struct sockaddr*)&reroute_addr), sizeof(reroute_addr));
}

/* Overriden TLS connect for v6 function */
int tls_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) {
	return (*ref_tcp_v6_connect)(sk, uaddr, addr_len);
}

/* Overriden TLS disconnect function */
int tls_disconnect(struct sock *sk, int flags) {
	return (*ref_tcp_disconnect)(sk, flags);
}

/* Overriden TLS shutdown function */
void tls_close(struct sock *sk, long timeout) {
	printk(KERN_ALERT "Close called on socket %p from PID %d\n", sk, current->pid);
	printk(KERN_ALERT "timeout is %ld and state is %d\n", timeout, sk->sk_state == TCP_CLOSE ? 1 : 0);
	(*ref_tcp_close)(sk, timeout);
	return;
}

/* Overriden TLS recvmsg function */
int tls_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len){
	return (*ref_tcp_recvmsg)(sk, msg, len, nonblock, flags, addr_len);
}

/* Overriden TLS sendmsg function */
int tls_sendmsg(struct sock *sk, struct msghdr *msg, size_t size){
	return (*ref_tcp_sendmsg)(sk, msg, size);
}

/* Overriden TLS shutodwn function */
void tls_shutdown(struct sock *sk, int how){
	return (*ref_tcp_shutdown)(sk, how);
}

/* Overriden TLS init function */
int tls_v4_init_sock(struct sock *sk) {
	int ret;
	tls_sock_ext_data_t* sock_ext_data;
	if ((sock_ext_data = kmalloc(sizeof(tls_sock_ext_data_t), GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "kmalloc failed in tls_v4_init_sock\n");
		return -1;
	}
	memset(sock_ext_data, 0, sizeof(tls_sock_ext_data_t));
	sock_ext_data->pid = current->pid;
	sock_ext_data->sk = sk;
	sock_ext_data->key = (unsigned long)sk;
	init_completion(&sock_ext_data->sock_event);
	spin_lock(&tls_sock_ext_lock);
	hash_add(tls_sock_ext_data_table, &sock_ext_data->hash, sock_ext_data->key);
	spin_unlock(&tls_sock_ext_lock);
	ret = (*ref_tcp_v4_init_sock)(sk);

	send_socket_notification((unsigned long)sk);
	wait_for_completion_timeout(&sock_ext_data->sock_event, RESPONSE_TIMEOUT);
	/* We're not checking return values here because init_sock always returns 0 */
	return ret;
}

void tls_v4_destroy_sock(struct sock* sk) {
	tls_sock_ext_data_t* sock_ext_data = tls_sock_ext_get_data(sk);
	printk(KERN_ALERT "Destroy called on socket %p from PID %d\n", sk, current->pid);
	if (sock_ext_data != NULL) {
		hash_del(&sock_ext_data->remote_hash); /* remove from dst_map */
		hash_del(&sock_ext_data->hash); /* remove from ext_data_Table */
		if (sock_ext_data->hostname) {
			kfree(sock_ext_data->hostname);
		}
		kfree(sock_ext_data);
	}
	printk(KERN_ALERT "state is %d, socks reminaing: %d, memoryallocated: %ld\n", sk->sk_state == TCP_CLOSE ? 1 : 0, sk_sockets_allocated_read_positive(sk), sk_memory_allocated(sk));
	return (*ref_tcp_v4_destroy_sock)(sk);
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
	hash_init(dst_map);
	return;
}

void tls_cleanup() {
        int bkt;
        tls_sock_ext_data_t* it;
        struct hlist_node tmp;
        struct hlist_node* tmpptr = &tmp;

	spin_lock(&dst_map_lock);
	hash_for_each_safe(dst_map, bkt, tmpptr, it, remote_hash) {
		printk(KERN_ALERT "Deleting socket %p from dst_map\n", it->sk);
		hash_del(&it->remote_hash);
	}
	spin_unlock(&dst_map_lock);

        spin_lock(&tls_sock_ext_lock);
        hash_for_each_safe(tls_sock_ext_data_table, bkt, tmpptr, it, hash) {
		printk(KERN_ALERT "Calling close manually on socket %p\n", it->sk);
		//(*ref_tcp_close)(it->sk, 0);
		(*ref_tcp_v4_destroy_sock)(it->sk);
		printk(KERN_ALERT "Deleting socket %p from ext_data\n", it->sk);
		hash_del(&it->remote_hash);
                hash_del(&it->hash);
		printk(KERN_ALERT "Freeing ext data for socket %p\n", it->sk);
                kfree(it->hostname);
		kfree(it);
        }
        spin_unlock(&tls_sock_ext_lock);

	unregister_netlink();

	return;
}

int tls_setsockopt(struct sock *sk, int level, int optname, char __user *optval, unsigned int len) {
	switch (optname) {
		case SO_HOSTNAME:
			return set_hostname(sk, optval, len);
		case SO_ORIG_DST:
			return 0; /* Unimplemented */
		default:
			return ref_tcp_setsockopt(sk, level, optname, optval, len);
	}
	return 0;
}

int tls_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen) {
	switch (optname) {
		case SO_HOSTNAME:
			return get_hostname(sk, optval, optlen);
		case SO_ORIG_DST:
			return get_orig_dst(sk, optval, optlen);
		default:
			return ref_tcp_getsockopt(sk, level, optname, optval, optlen);
	}
	return 0;
}


int set_hostname(struct sock* sk, char __user *optval, unsigned int len) {
	tls_sock_ext_data_t* sock_ext_data;
	sock_ext_data = tls_sock_ext_get_data(sk);

	if (optval == NULL){
		printk(KERN_ALERT "user input is NULL\n");
		goto einval_out;
	}

	if (len > MAX_HOST_LEN){
		printk(KERN_ALERT "user input hostname too long, cutting to 255\n");
		len = MAX_HOST_LEN;
	}	

	sock_ext_data->hostname = krealloc(sock_ext_data->hostname, len + 1, GFP_KERNEL);

	if (copy_from_user(sock_ext_data->hostname, optval, len) != 0){
		return EFAULT;
	}
 
	sock_ext_data->hostname[len] = '\0';

	if (!is_valid_host_string(optval)) {
		kfree(sock_ext_data->hostname);
		printk(KERN_ALERT "user input is invalid hostname\n");
		goto einval_out;
	}

	printk(KERN_ALERT "hostname registered with socket: %s\n", sock_ext_data->hostname);
	return  0;

einval_out:
	printk(KERN_ERR "ABORTING SET HOST NAME SOCKOPT. HOST NAME HAS NOT BEEN SET\n");
	return EINVAL;	
}

int get_hostname(struct sock* sk, char __user *optval, int* __user len) {
	char *m_hostname;
	size_t hostname_len;
	tls_sock_ext_data_t* data;

	/* If this test succeeds, we're actually calling get_hostname from the TLS wrapper daemon */
	if ((data = get_tls_sock_data_using_local_endpoint(sk)) != NULL) {
		m_hostname = data->hostname;
	}
	else { /* otherwise, we're calling this on a socket the calling process owns */
		m_hostname = tls_sock_ext_get_data(sk)->hostname;
	}
	
	printk(KERN_ALERT "Host Name: %s\t%d\n", m_hostname, (int)strlen(m_hostname));
	if (m_hostname == NULL){
		printk(KERN_ALERT "Host name requested was NULL\n");
		return EFAULT;
	}
	hostname_len = strnlen(m_hostname, MAX_HOST_LEN) + 1;
	if ((unsigned int) *len < hostname_len){
		printk(KERN_ALERT "len smaller than requested hostname\n");
		return EINVAL;	
	} 
	/* Check ownership of pointer and FS thingy */
	if (copy_to_user(optval, m_hostname, hostname_len) != 0 ){
		printk(KERN_ALERT "hostname copy to user failed\n");
		return EFAULT;
	}
	
	*len = (int)hostname_len - 1;
	return 0;
}

/* 
 * Tests whether a socket option input contains only valid host name characters
 * @param	input - The void *user that was passed to setsockops
 * @return	1 if string is valid. Otherwise 0.
 */
int is_valid_host_string(void *input) {
        int str_len;
	unsigned int i;
        str_len = strnlen((char *)input, 255);
        for (i = 0; i < str_len; i++){
                int c = (int)(*((char*)input));
                if ( (c >= 48 && c <=57) || c == 45 || c == 46 || (c >= 65 && c <= 90) || (c >= 97 && c <= 122)){
			input++;
                        continue;
                }
		return 0;
        }
        return 1;
}

tls_sock_ext_data_t* get_tls_sock_data_using_local_endpoint(struct sock *sk) {
	unsigned long key;
	tls_sock_ext_data_t* it;
	printk(KERN_ALERT "Looking up client tls_sock_ext_data from local endpoint\n");
	key = inet_sk(sk)->inet_dport; /* we use dport because dport of tls daemon's client fd is sport of the app's fd */
	hash_for_each_possible(dst_map, it, remote_hash, key) {
		if (key == it->remote_key) {
			printk(KERN_ALERT "Found client tls_sock_ext_data\n");
			return it;
		}
	}
        return NULL;
}

int get_orig_dst(struct sock *sk, void __user *optval, int __user *len) {
	unsigned long copied;
	tls_sock_ext_data_t* data;
	printk(KERN_ALERT "Someone called get_orig_dst\n");
	if ((data = get_tls_sock_data_using_local_endpoint(sk)) != NULL) {
		*len = data->rem_addrlen;
		copied = copy_to_user(optval, &data->rem_addr, data->rem_addrlen);
		printk(KERN_ALERT "Found orig dst using key\n");
		if (copied != data->rem_addrlen) return 1;
		else return 0;
	}
        return 0;
}

void report_return(unsigned long key, int ret) {
	tls_sock_ext_data_t* sock_ext_data;
	sock_ext_data = tls_sock_ext_get_data((struct sock*)key);
	BUG_ON(sock_ext_data == NULL);
	sock_ext_data->response = ret;
	complete(&sock_ext_data->sock_event);
	return;
}

