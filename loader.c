/*
 * A loadable kernel module that completes all registrations necessary to give TLS functionality
 * to the POSIX socket API call. Also registers the socket option functions to set and get the
 * host name for TLS to use.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <net/sock.h>
#include <linux/netfilter.h>
#include <linux/hashtable.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/capability.h>
#include <linux/cpumask.h>
#include "tls.h"
#include "socktls.h"

#define DRIVER_AUTHOR 	"Mark O'Neill <mark@markoneill.name> and Nick Bonner <j.nick.bonner@gmail.com>"
#define DRIVER_DESC	"A loadable TLS module to give TLS functionality to the POSIX socket API"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

static struct proto tls_prot;
static struct proto_ops tls_proto_ops;
static struct proto tcpv6_prot;
static struct net_protocol ipprot;

/* Original TCP reference functions */
int (*ref_tcp_v4_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int (*ref_tcp_v6_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int (*ref_tcp_disconnect)(struct sock *sk, int flags);
void (*ref_tcp_shutdown)(struct sock *sk, int how);
int (*ref_tcp_recvmsg)(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
                        int flags, int *addr_len);
int (*ref_tcp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t size);
int (*ref_tcp_v4_init_sock)(struct sock *sk);
void (*ref_tcp_v4_destroy_sock)(struct sock *sk);
void (*ref_tcp_close)(struct sock *sk, long timeout);
int (*ref_tcp_setsockopt)(struct sock *sk, int level, int optname, char __user *optval, unsigned int len);
int (*ref_tcp_getsockopt)(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen);


/* inet stream reference functions */
int (*ref_inet_listen)(struct socket *sock, int backlog);
int (*ref_inet_accept)(struct socket *sock, struct socket *newsock, int flags, bool kern);
int (*ref_inet_bind)(struct socket *sock, struct sockaddr *uaddr, int addr_len);

/* Original Unix domain reference functions */
int (*ref_unix_init_sock)(struct sock *sk);
int (*ref_unix_release)(struct socket* sock);
int (*ref_unix_bind)(struct socket *sock, struct sockaddr *uaddr, int addr_len);
int (*ref_unix_connect)(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags);
int (*ref_unix_listen)(struct socket *sock, int backlog);
int (*ref_unix_accept)(struct socket *sock, struct socket *newsock, int flags, bool kern);
int (*ref_unix_setsockopt)(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen);
int (*ref_unix_getsockopt)(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen);

/* Auxillary support reference functions */
int (*orig_tcp_setsockopt)(struct sock*, int, int, char __user*, unsigned int) = NULL;

/* The TLS protocol structure to be registered */
static struct inet_protosw tls_stream_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_TLS,
	.prot		= &tls_prot,
	.ops		= &tls_proto_ops,
	.flags 		= INET_PROTOSW_ICSK
};

static atomic_long_t tls_memory_allocated;
struct percpu_counter tls_orphan_count;
struct percpu_counter tls_sockets_allocated;


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

int set_tls_prot_tcp(void) {

	unsigned long kallsyms_err;

	kallsyms_err = kallsyms_lookup_name("tcpv6_prot");
	if (kallsyms_err == 0){
        	printk(KERN_ALERT "kallsyms_lookup_name failed to retrieve tcpv6_prot address\n");
		return -1;
        }

	tls_prot = tcp_prot;

	/* Guessing what the TLS-unique things should be here */
	strcpy(tls_prot.name, "TLS");
	tls_prot.owner = THIS_MODULE;
	tls_prot.inuse_idx = 0;
	tls_prot.memory_allocated = &tls_memory_allocated;
	tls_prot.orphan_count = &tls_orphan_count;
	tls_prot.sockets_allocated = &tls_sockets_allocated;
	percpu_counter_init(&tls_orphan_count, 0, GFP_KERNEL);
	percpu_counter_init(&tls_sockets_allocated, 0, GFP_KERNEL);


	tcpv6_prot = *(struct proto *)kallsyms_err;

	ref_tcp_v4_connect = tls_prot.connect;
	tls_prot.connect = tls_tcp_v4_connect;

	ref_tcp_v6_connect = tcpv6_prot.connect;
	//tcpv6_prot.connect = tls_v6_connect; /* wtf is this here? */

	ref_tcp_disconnect = tls_prot.disconnect;
	tls_prot.disconnect = tls_tcp_disconnect;

	ref_tcp_shutdown = tls_prot.shutdown;
	tls_prot.shutdown = tls_tcp_shutdown;

	ref_tcp_recvmsg = tls_prot.recvmsg;
	tls_prot.recvmsg = tls_tcp_recvmsg;

	ref_tcp_sendmsg = tls_prot.sendmsg;
	tls_prot.sendmsg = tls_tcp_sendmsg;

	ref_tcp_close = tls_prot.close;
	tls_prot.close = tls_tcp_close;

	ref_tcp_v4_init_sock = tls_prot.init;
	tls_prot.init = tls_tcp_v4_init_sock;

	ref_tcp_v4_destroy_sock = tls_prot.destroy;
	tls_prot.destroy = tls_tcp_v4_destroy_sock;

	tls_proto_ops = inet_stream_ops;
	
	ref_inet_listen = tls_proto_ops.listen;
	ref_inet_bind = tls_proto_ops.bind;
	ref_inet_accept = tls_proto_ops.accept;
	tls_proto_ops.listen = tls_inet_listen;
	tls_proto_ops.bind = tls_inet_bind;
	tls_proto_ops.accept = tls_inet_accept;
	tls_proto_ops.owner = THIS_MODULE;

	ref_tcp_setsockopt = tcp_prot.setsockopt;
	ref_tcp_getsockopt = tcp_prot.getsockopt;

	tls_prot.setsockopt = tls_tcp_setsockopt;
	tls_prot.getsockopt = tls_tcp_getsockopt;
	printk(KERN_INFO "TLS protocol initialized\n");
	return 0;
}

static int __init tls_init(void) {
	int err;	
	static const struct net_protocol *ipprot_lookup;
	unsigned long kallsyms_err;

	printk(KERN_INFO "Initializing TLS module\n");
	printk(KERN_INFO "Found %u CPUs\n", nr_cpu_ids);
	
	/* initialize our global data structures for TLS handling */
	tls_setup();

	/* Establish and register the tls_prot structure */
	//err = set_tls_prot_tcp();
	err = set_tls_prot_unix();
	if (err != 0){
		goto out;
	}

	err = proto_register(&tls_prot, 0);

	if (err == 0){
		printk(KERN_INFO "Protocol registration was successful\n");
	}
	else {
		printk(KERN_ALERT "Protocol registration failed\n");
		goto out;
	}

	/*
	 * Retrieve the non-exported tcp_protocol struct address location 
	 * and verify that it was found. If it fails, unregister the protocol
	 * and exit the module initialization.
	 */
	kallsyms_err = kallsyms_lookup_name("tcp_protocol");
	if (kallsyms_err == 0){
		printk(KERN_ALERT "kallsyms_lookup_name failed to retrieve tcp_protocol address\n");
		goto out_proto_unregister;
	}

	/* Create a copy of the tcp net_protocol and register it to the IPPROTO_TLS macro */
	ipprot_lookup = (struct net_protocol*)kallsyms_err;
	ipprot = *ipprot_lookup;
	

	err = inet_add_protocol(&ipprot, IPPROTO_TLS);
	inet_register_protosw(&tls_stream_protosw);
	
	if (err == 0){
		printk(KERN_INFO "Protocol insertion in inet_protos[] was successful\n");
	}
	else {
		printk(KERN_ALERT "Protocol insertion in inet_protos[] failed\n");
		goto out_proto_unregister;
	}

	/* Register the tls_stream_protosw */

	/* Register the setsockopt hook */
	orig_tcp_setsockopt = tcp_prot.setsockopt;
	tcp_prot.setsockopt = hook_tcp_setsockopt;

	printk(KERN_INFO "TLS Module loaded and tls_prot registered\n");
	return 0;

out:
	return err;
out_proto_unregister:
	proto_unregister(&tls_prot);
	goto out;
}

static void __exit tls_exit(void) {
	percpu_counter_destroy(&tls_orphan_count);
	percpu_counter_destroy(&tls_sockets_allocated);

	/* Unregister the tcp hook */
	if (orig_tcp_setsockopt != NULL) {
		tcp_prot.setsockopt = orig_tcp_setsockopt;
	}

	/* Unregister the protocols and structs in the reverse order they were registered */
	inet_del_protocol(&ipprot, IPPROTO_TLS);
	inet_unregister_protosw(&tls_stream_protosw);
	
	//tcp_prot.setsockopt = ref_tcp_setsockopt;
	//tcp_prot.getsockopt = ref_tcp_getsockopt;

	/* Set these pointers to NULL to avoid deleting tcp_prot's copied memory */
	tls_prot.slab = NULL;
	tls_prot.rsk_prot = NULL;
	tls_prot.twsk_prot = NULL;

	proto_unregister(&tls_prot);
	printk(KERN_INFO "TLS Module removed and tls_prot unregistered\n");
	/* Free TLS socket handling data */
	tls_cleanup();
}

module_init(tls_init);
module_exit(tls_exit);
