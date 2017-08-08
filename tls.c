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


static DEFINE_HASHTABLE(sock_ops_table, HASH_TABLE_BITSIZE);
static DEFINE_SPINLOCK(sock_ops_lock);

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
int is_valid_test_string(void *input);

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

int tls_setsockopt(struct sock *sk, int level, int optname, char __user *optval, unsigned int len) {
	switch (optname) {
		case HOSTNAME:
			return set_hostname(sk, optval, len);
		case ORIG_DEST_ADDR:
			break;
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
			break;
		default:
			return ref_tcp_getsockopt(sk, level, optname, optval, optlen);
	}
	return 0;
}


int set_hostname(struct sock* sk, char __user *optval, unsigned int len) {
	char *loc_host_name;

	if (optval == NULL){
		printk(KERN_ALERT "user input is NULL");
		goto einval_out;
	}

	loc_host_name = ((tls_sock_ops*)tls_sock_ops_get(current->pid, sk))->host_name;

	if (len > MAX_HOST_LEN){
		printk(KERN_ALERT "user input host_name too long, cutting to 255\n");
		len = MAX_HOST_LEN;
	}	

	loc_host_name = krealloc(loc_host_name, len + 1, GFP_KERNEL);

	if (copy_from_user(loc_host_name, optval, len) != 0){
		return EFAULT;
	}
 
	loc_host_name[len] = '\0';	

	if (!is_valid_test_string(optval)){
		kfree(loc_host_name);
		printk(KERN_ALERT "user input is invalid hostname\n");
		goto einval_out;
	}

	tls_sock_ops_get(current->pid, sk)->host_name = loc_host_name;
	printk(KERN_ALERT "host_name registered with socket: %s\n", loc_host_name);
	return  0;

einval_out:
	printk(KERN_ERR "ABORTING SET HOST NAME SOCKOPT. HOST NAME HAS NOT BEEN SET\n");
	return EINVAL;	
}

int get_hostname(struct sock* sk, char __user *optval, int* __user len) {
	char *m_host_name;
	size_t host_name_len;
	
	m_host_name = tls_sock_ops_get(current->pid, sk)->host_name;
	printk(KERN_ALERT "Host Name: %s\t%d\n", m_host_name, (int)strlen(m_host_name));
	if (m_host_name == NULL){
		printk(KERN_ALERT "Host name requested was NULL\n");
		return EFAULT;
	}
	host_name_len = strnlen(m_host_name, MAX_HOST_LEN) + 1;
	if ((unsigned int) *len < host_name_len){
		printk(KERN_ALERT "len smaller than requested host_name\n");
		return EINVAL;	
	} 
	/* Check ownership of pointer and FS thingy */
	if (copy_to_user(optval, m_host_name, host_name_len) != 0 ){
		printk(KERN_ALERT "host_name copy to user failed\n");
		return EFAULT;
	}
	
	*len = (int)host_name_len - 1;
	return 0;
}

/* 
 * Tests whether a socket option input contains only valid host name characters
 * @param	input - The void *user that was passed to setsockops
 * @return	1 if string is valid. Otherwise 0.
 */
int is_valid_test_string(void *input) {
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

