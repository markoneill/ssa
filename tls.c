#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <net/sock.h>
#include "tls_prot.h"


#define DRIVER_AUTHOR 	"Mark O'Neill <phoenixteam1@gmail.com> and Nick Bonner <j.nick.bonner@gmail.com>"
#define DRIVER_DESC	"A loadable TLS module to give TLS functionality to the POSIX socket API"
#define IPPROTO_TLS 	(715 % 255)	

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

static struct proto tls_prot;

/* Original TCP reference functions */
extern int (*ref_tcp_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
extern int (*ref_tcp_disconnect)(struct sock *sk, int flags);
extern void (*ref_tcp_shutdown)(struct sock *sk, int how);
extern int (*ref_tcp_recvmsg)(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
                        int flags, int *addr_len);
extern int (*ref_tcp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t size);

static struct inet_protosw tls_stream_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_TLS,
	.prot		= &tls_prot,
	.ops		= &inet_stream_ops,
	.flags 		= INET_PROTOSW_PERMANENT | INET_PROTOSW_ICSK
};

static struct net_protocol ipprot;

/*
 *	Creates a copy of the tcp_prot structure and overrides
 *	posix method's functionality.
 */
void set_tls_prot(void){
	tls_prot = tcp_prot;

	ref_tcp_connect = tls_prot.connect;
	tls_prot.connect = tls_v4_connect;

	ref_tcp_disconnect = tls_prot.disconnect;
	tls_prot.disconnect = tls_disconnect;

	ref_tcp_shutdown = tls_prot.shutdown;
	tls_prot.shutdown = tls_shutdown;

	ref_tcp_recvmsg = tls_prot.recvmsg;
	tls_prot.recvmsg = tls_recvmsg;

	ref_tcp_sendmsg = tls_prot.sendmsg;
	tls_prot.sendmsg = tls_sendmsg;

	printk(KERN_ALERT "TLS protocols set");
}

static int __init tls_init(void)
{
	int err;	
	static const struct net_protocol *ipprot_lookup;
	unsigned long kallsyms_err;

	printk(KERN_ALERT "Initializing TLS module\n");
	
	/* Establish and register the tls_prot structure */
	set_tls_prot();
	err = proto_register(&tls_prot, 1);

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
	
	if (err == 0){
		printk(KERN_INFO "Protocol insertion in inet_protos[] was successful\n");
	}
	else {
		printk(KERN_INFO "Protocol insertion in inet_protos[] failed\n");
		goto out_proto_unregister;
	}

//	tls_stream_protosw.ops = &inet_stream_ops;

	/* Register the tls_stream_protosw */
	inet_register_protosw(&tls_stream_protosw);

	printk(KERN_INFO "TLS Module loaded and tls_prot registered\n");
	return 0;

out:
	return err;
out_proto_unregister:
	proto_unregister(&tls_prot);
	goto out;
}

static void __exit tls_exit(void)
{
	/* Unregister the protocols and structs in the reverse order they were registered */
	inet_unregister_protosw(&tls_stream_protosw);
	inet_del_protocol(&ipprot, IPPROTO_TLS);
	
	/* Set these pointers to NULL to avoid deleting tcp_prot's copied memory */
	tls_prot.slab = NULL;
	tls_prot.rsk_prot = NULL;
	tls_prot.twsk_prot = NULL;

	proto_unregister(&tls_prot);
	printk(KERN_INFO "TLS Module removed and tls_prot unregistered\n");
}

module_init(tls_init);
module_exit(tls_exit);
