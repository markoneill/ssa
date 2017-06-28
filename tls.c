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
#include "tls_prot.h"


#define DRIVER_AUTHOR 	"Mark O'Neill <phoenixteam1@gmail.com> and Nick Bonner <j.nick.bonner@gmail.com>"
#define DRIVER_DESC	"A loadable TLS module to give TLS functionality to the POSIX socket API"
#define IPPROTO_TLS 	(715 % 255)	
#define TLS_SOCKOPT_BASE	85
#define MAX_HOST_LEN		255
#define TLS_SOCKOPT_SET		(TLS_SOCKOPT_BASE)
#define TLS_SOCKOPT_GET		(TLS_SOCKOPT_BASE)
#define TLS_SOCKOPT_MAX		(TLS_SOCKOPT_BASE + 1)

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

static struct proto tls_prot;
static struct net_protocol ipprot;

/* Original TCP reference functions */
extern int (*ref_tcp_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
extern int (*ref_tcp_disconnect)(struct sock *sk, int flags);
extern void (*ref_tcp_shutdown)(struct sock *sk, int how);
extern int (*ref_tcp_recvmsg)(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
                        int flags, int *addr_len);
extern int (*ref_tcp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t size);
extern int (*ref_tcp_v4_init_sock)(struct sock *sk);

/* The TLS protocol structure to be registered */
static struct inet_protosw tls_stream_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_TLS,
	.prot		= &tls_prot,
	.ops		= &inet_stream_ops,
	.flags 		= INET_PROTOSW_PERMANENT | INET_PROTOSW_ICSK
};


/* Defines the socket options to specify a URL for TLS protocol */
int set_host_name(struct sock *sk, int cmd, void __user *user, unsigned int len);
int get_host_name(struct sock *sk, int cmd, void __user *user, int *len);
static struct nf_sockopt_ops tls_sockopts = {
	.pf		= PF_INET,
	.set_optmin	= TLS_SOCKOPT_SET,
	.set_optmax	= TLS_SOCKOPT_MAX,
	.set		= set_host_name,
	.get_optmin	= TLS_SOCKOPT_GET,
	.get_optmax	= TLS_SOCKOPT_MAX,
	.get		= get_host_name,
	.owner		= THIS_MODULE
};

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

	ref_tcp_v4_init_sock = tls_prot.init;
	tls_prot.init = tls_v4_init_sock;

	printk(KERN_ALERT "TLS protocols set");
}

void register_sockopts(void){
	int err;
	
	err = nf_register_sockopt(&tls_sockopts);
	if (err != 0){
		printk(KERN_ALERT "Failed to register new sock opts with the kernel. TLS host_name specification will fail\n");
	}
}

static int __init tls_init(void)
{
	int err;	
	static const struct net_protocol *ipprot_lookup;
	unsigned long kallsyms_err;

	printk(KERN_ALERT "Initializing TLS module\n");

	/* register the tls socket options */
	register_sockopts();
	
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


int set_host_name(struct sock *sk, int cmd, void __user *user, unsigned int len)
{
	char *loc_host_name;

	printk(KERN_ALERT "host_name registered with socket");

	loc_host_name = tls_sock_ops_get(current->pid, sk)->host_name;
	if (cmd != TLS_SOCKOPT_SET){
		return EINVAL;
	}
	if (strnlen((char *)user, MAX_HOST_LEN + 1) > MAX_HOST_LEN){
		return EINVAL;
	}
	loc_host_name = krealloc(loc_host_name, len, GFP_KERNEL);
	tls_sock_ops_get(current->pid, sk)->host_name = loc_host_name;
	if (copy_from_user(loc_host_name, user, len) != 0){
		return EFAULT;
	} 
	else {
		return  0;
	}
	
}

int get_host_name(struct sock *sk, int cmd, void __user *user, int *len)
{
	char *m_host_name;
	size_t host_name_len;
	
	if (cmd != TLS_SOCKOPT_GET){
		return EINVAL;
	}
		
	m_host_name = tls_sock_ops_get(current->pid, sk)->host_name;
	host_name_len = strnlen(m_host_name, MAX_HOST_LEN);
	if ((unsigned int) *len < host_name_len){
		printk(KERN_ALERT "len smaller than requested host_name");
		return EINVAL;	
	} 
	if (copy_to_user(user, m_host_name, host_name_len) != 0 ){
		printk(KERN_ALERT "host_name copy to user failed");
		return EFAULT;
	}
	else {
		return 0;
	}
}

module_init(tls_init);
module_exit(tls_exit);
