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


/*
 *	Creates a copy of the tcp_prot structure and overrides
 *	posix method's functionality.
 */
int set_tls_prot(void) {

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
	tls_prot.connect = tls_v4_connect;

	ref_tcp_v6_connect = tcpv6_prot.connect;
	//tcpv6_prot.connect = tls_v6_connect; /* wtf is this here? */

	ref_tcp_disconnect = tls_prot.disconnect;
	tls_prot.disconnect = tls_disconnect;

	ref_tcp_shutdown = tls_prot.shutdown;
	tls_prot.shutdown = tls_shutdown;

	ref_tcp_recvmsg = tls_prot.recvmsg;
	tls_prot.recvmsg = tls_recvmsg;

	ref_tcp_sendmsg = tls_prot.sendmsg;
	tls_prot.sendmsg = tls_sendmsg;

	ref_tcp_close = tls_prot.close;
	tls_prot.close = tls_close;

	ref_tcp_v4_init_sock = tls_prot.init;
	tls_prot.init = tls_v4_init_sock;

	ref_tcp_v4_destroy_sock = tls_prot.destroy;
	tls_prot.destroy = tls_v4_destroy_sock;

	tls_proto_ops = inet_stream_ops;
	ref_inet_listen = tls_proto_ops.listen;
	ref_inet_bind = tls_proto_ops.bind;
	ref_inet_accept = tls_proto_ops.accept;
	tls_proto_ops.listen = tls_inet_listen;
	tls_proto_ops.bind = tls_inet_bind;
	tls_proto_ops.accept = tls_inet_accept;
	tls_proto_ops.owner = THIS_MODULE;
	/* We're saving and overriding the tcp_prot set/getsockopt
	 * so that we can define a "set/get original destination"
	 * option for stream socket types */
	ref_tcp_setsockopt = tcp_prot.setsockopt;
	ref_tcp_getsockopt = tcp_prot.getsockopt;
	tls_prot.setsockopt = tls_setsockopt;
	tls_prot.getsockopt = tls_getsockopt;
	tcp_prot.setsockopt = tls_setsockopt;
	tcp_prot.getsockopt = tls_getsockopt;


	printk(KERN_ALERT "TLS protocol set");
	return 0;
}

static int __init tls_init(void) {
	int err;	
	static const struct net_protocol *ipprot_lookup;
	unsigned long kallsyms_err;

	printk(KERN_ALERT "Initializing TLS module\n");
	
	/* initialize our global data structures for TLS handling */
	tls_setup();

	/* Establish and register the tls_prot structure */
	err = set_tls_prot();
	if (err != 0){
		goto out;
	}

	err = proto_register(&tls_prot, 0);

	if (err == 0){
		printk(KERN_INFO "Protocol registration was successful\n");
	}
	else {
		printk(KERN_INFO "Protocol registration failed\n");
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
		printk(KERN_INFO "Protocol insertion in inet_protos[] failed\n");
		goto out_proto_unregister;
	}

	/* Register the tls_stream_protosw */

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

	/* Unregister the protocols and structs in the reverse order they were registered */
	inet_del_protocol(&ipprot, IPPROTO_TLS);
	inet_unregister_protosw(&tls_stream_protosw);
	
	tcp_prot.setsockopt = ref_tcp_setsockopt;
	tcp_prot.getsockopt = ref_tcp_getsockopt;

	/* Set these pointers to NULL to avoid deleting tcp_prot's copied memory */
	tls_prot.slab = NULL;
	tls_prot.rsk_prot = NULL;
	tls_prot.twsk_prot = NULL;

	proto_unregister(&tls_prot);
	printk(KERN_INFO "TLS Module removed and tls_prot unregistered\n");
	/* Free TLS socket handling data */
	tls_cleanup();
	printk(KERN_ALERT "memallocated: %ld\n", proto_memory_allocated(&tls_prot));
}

module_init(tls_init);
module_exit(tls_exit);
