/*
 * Overrides the TCP functions to give the TLS functionality. Also contains functions manage
 * the hash table where TLS socket options are stored.
 */

#include "tls_prot.h"

#define HASH_TABLE_BITSIZE	9
static DEFINE_HASHTABLE(sock_ops_table, HASH_TABLE_BITSIZE);
static DEFINE_SPINLOCK(sock_ops_lock);

/* Original TCP reference functions */
int (*ref_tcp_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int (*ref_tcp_disconnect)(struct sock *sk, int flags);
void (*ref_tcp_shutdown)(struct sock *sk, int how);
int (*ref_tcp_recvmsg)(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
                        int flags, int *addr_len);
int (*ref_tcp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t size);
int (*ref_tcp_v4_init_sock)(struct sock *sk);

/* Overriden TLS .connect function */
int tls_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len){
	return (*ref_tcp_connect)(sk, uaddr, addr_len);
}

/* Overriden TLS .disconnect function */
int tls_disconnect(struct sock *sk, int flags){
	return (*ref_tcp_disconnect)(sk, flags);
}

/* Overriden TLS .shutdown function */
void tls_shutdown(struct sock *sk, int how){
	tls_sock_ops* to_free = tls_sock_ops_get(current->pid, sk);
	if (to_free != NULL){
		kfree(to_free);
	}	
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
	tls_sock_ops* new_sock_op;
	if ((new_sock_op = kmalloc(sizeof(struct tls_sock_ops), GFP_KERNEL)) == NULL){
		printk(KERN_ALERT "kmalloc failed when creating tls_sock_ops");
		return -1;
	}
	new_sock_op->host_name = NULL;
	new_sock_op->pid = current->pid;
	new_sock_op->sk = sk;
	new_sock_op->key = new_sock_op->pid ^ (unsigned long)sk;
	spin_lock(&sock_ops_lock);
	hash_add(sock_ops_table, &new_sock_op->hash, new_sock_op->key);
	spin_unlock(&sock_ops_lock);
	return (*ref_tcp_v4_init_sock)(sk);
}

/**
 * Finds a socket option in the hash table
 * @param	pid - The desired socket options Process ID
 * @param	sk - A pointer to the sock struct related to the socket option
 * @return	The desired socket options if found. If not found, returns NULL
 */
tls_sock_ops* tls_sock_ops_get(pid_t pid, struct sock* sk){
	tls_sock_ops* sock_op = NULL;
	tls_sock_ops* sock_op_it;
	hash_for_each_possible(sock_ops_table, sock_op_it, hash, pid ^ (unsigned long)sk){
		if (sock_op_it->pid == pid && sock_op_it->sk == sk){
			sock_op = sock_op_it;
			break;
		}
	}
	return sock_op;
}

void tls_prot_init(){
	hash_init(sock_ops_table);
}
