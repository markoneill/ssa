/*
 * Overrides the TCP functions to give the TLS functionality. Also contains functions manage
 * the hash table where TLS socket options are stored.
 */

#include "tls.h"

#define HASH_TABLE_BITSIZE	9
#define REROUTE_PORT		8443

#define MAX_HOST_LEN	255
#define HOSTNAME	85
#define ORIG_DEST_ADDR 	86


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
extern int (*ref_tcp_setsockopt)(struct sock *sk, int level, int optname, char __user *optval, unsigned int len);
extern int (*ref_tcp_getsockopt)(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen);

int get_hostname(struct sock* sk, char __user *optval, int* __user len);
int set_hostname(struct sock* sk, char __user *optval, unsigned int len);
int is_valid_host_string(void *input);
int get_orig_dst(struct sock *sk, void __user *optval, int __user *len);

struct sockaddr_in reroute_addr = {
	.sin_family = AF_INET,
	.sin_port = htons(REROUTE_PORT),
	.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
};

/* Overriden TLS .connect for v4 function */
int tls_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len){
	printk(KERN_ALERT "Address: %s", uaddr->sa_data);
	
	return (*ref_tcp_v4_connect)(sk, ((struct sockaddr*)&reroute_addr), sizeof(reroute_addr));
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
	tls_sock_ext_data_t* sock_ext_data = tls_sock_ext_get_data(current->pid, sk);
	if (sock_ext_data != NULL){
		kfree(sock_ext_data);
	}	
	(*ref_tcp_shutdown)(sk, how);
	return;
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
	tls_sock_ext_data_t* sock_ext_data;
	if ((sock_ext_data = kmalloc(sizeof(tls_sock_ext_data_t), GFP_KERNEL)) == NULL){
		printk(KERN_ALERT "kmalloc failed in tls_v4_init_sock");
		return -1;
	}
	sock_ext_data->hostname = NULL;
	sock_ext_data->pid = current->pid;
	sock_ext_data->sk = sk;
	sock_ext_data->key = sock_ext_data->pid ^ (unsigned long)sk;
	spin_lock(&tls_sock_ext_lock);
	hash_add(tls_sock_ext_data_table, &sock_ext_data->hash, sock_ext_data->key);
	spin_unlock(&tls_sock_ext_lock);
	return (*ref_tcp_v4_init_sock)(sk);
}

/**
 * Finds a socket option in the hash table
 * @param	pid - The desired socket options Process ID
 * @param	sk - A pointer to the sock struct related to the socket option
 * @return	The desired socket options if found. If not found, returns NULL
 */
tls_sock_ext_data_t* tls_sock_ext_get_data(pid_t pid, struct sock* sk) {
	tls_sock_ext_data_t* it;
	hash_for_each_possible(tls_sock_ext_data_table, it, hash, pid ^ (unsigned long)sk) {
		if (it->pid == pid && it->sk == sk) {
			return it;
		}
	}
	return NULL;
}

void tls_setup() {
	hash_init(tls_sock_ext_data_table);
	return;
}

void tls_cleanup() {
	/* Delete all entries in the hash table */
        int bkt;
        tls_sock_ext_data_t* it;
        struct hlist_node tmp;
        struct hlist_node* tmpptr = &tmp;
        spin_lock(&tls_sock_ext_lock);
        hash_for_each_safe(tls_sock_ext_data_table, bkt, tmpptr, it, hash) {
                printk(KERN_INFO "Deleting data from bucket [%d] with pid %d and socket %p", bkt, it->pid, it->sk);
                hash_del(&it->hash);
                kfree(it->hostname);
        }
        spin_unlock(&tls_sock_ext_lock);
	return;
}

int tls_setsockopt(struct sock *sk, int level, int optname, char __user *optval, unsigned int len) {
	switch (optname) {
		case HOSTNAME:
			return set_hostname(sk, optval, len);
		case ORIG_DEST_ADDR:
			return 0; /* Unimplemented */
		default:
			return ref_tcp_setsockopt(sk, level, optname, optval, len);
	}
	return 0;
}

int tls_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen) {
	switch (optname) {
		case HOSTNAME:
			return get_hostname(sk, optval, optlen);
		case ORIG_DEST_ADDR:
			return get_orig_dst(sk, optval, optlen);
		default:
			return ref_tcp_getsockopt(sk, level, optname, optval, optlen);
	}
	return 0;
}


int set_hostname(struct sock* sk, char __user *optval, unsigned int len) {
	tls_sock_ext_data_t* sock_ext_data;
	sock_ext_data = tls_sock_ext_get_data(current->pid, sk);

	if (optval == NULL){
		printk(KERN_ALERT "user input is NULL");
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
	
	m_hostname = tls_sock_ext_get_data(current->pid, sk)->hostname;
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

int get_orig_dst(struct sock *sk, void __user *optval, int __user *len) {
        return 0;
}

