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
#include "tls_prot_tor.h"


#define DRIVER_AUTHOR 	"Mark O'Neill <phoenixteam1@gmail.com> and Nick Bonner <j.nick.bonner@gmail.com>"
#define DRIVER_DESC	"A loadable TLS module to give TLS functionality to the POSIX socket API"
#define MAX_HOST_LEN		255

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

static struct proto tcpv6_prot;

/* Original TCP reference functions */
extern int (*ref_tcp_v4_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
extern int (*ref_tcp_v6_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
extern int (*ref_tcp_disconnect)(struct sock *sk, int flags);
extern void (*ref_tcp_shutdown)(struct sock *sk, int how);
extern int (*ref_tcp_recvmsg)(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
                        int flags, int *addr_len);
extern int (*ref_tcp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t size);
extern int (*ref_tcp_v4_init_sock)(struct sock *sk);

/*
 *	Save off tcp_prot original functionality and replace them with custom
 *	posix methods.
 */
int set_tcp_prot(void){

	unsigned long kallsyms_err;

	kallsyms_err = kallsyms_lookup_name("tcpv6_prot");
	if (kallsyms_err == 0){
        	printk(KERN_ALERT "kallsyms_lookup_name failed to retrieve tcpv6_prot address\n");
		return -1;
        }

	tcpv6_prot = *(struct proto *)kallsyms_err;

	ref_tcp_v4_connect = tcp_prot.connect;
	tcp_prot.connect = tls_v4_connect;

	ref_tcp_v6_connect = tcpv6_prot.connect;
	tcpv6_prot.connect = tls_v6_connect;

	ref_tcp_disconnect = tcp_prot.disconnect;
	tcp_prot.disconnect = tls_disconnect;

	ref_tcp_shutdown = tcp_prot.shutdown;
	tcp_prot.shutdown = tls_shutdown;

	ref_tcp_recvmsg = tcp_prot.recvmsg;
	tcp_prot.recvmsg = tls_recvmsg;

	ref_tcp_sendmsg = tcp_prot.sendmsg;
	tcp_prot.sendmsg = tls_sendmsg;

	ref_tcp_v4_init_sock = tcp_prot.init;
	tcp_prot.init = tls_v4_init_sock;

	printk(KERN_ALERT "TLS protocols set");
	return 0;
}

/*
 * Reset the tcp_prot to have its original functions
 */
void reset_tcp_prot(void){
	tcp_prot.connect = ref_tcp_v4_connect;
	tcpv6_prot.connect = ref_tcp_v6_connect;
	tcp_prot.disconnect = ref_tcp_disconnect;
	tcp_prot.shutdown = ref_tcp_shutdown;
	tcp_prot.recvmsg = ref_tcp_recvmsg;
	tcp_prot.sendmsg = ref_tcp_sendmsg;
	tcp_prot.init = ref_tcp_v4_init_sock;
}

static int __init tor_reroute_init(void)
{
	int err;	

	printk(KERN_ALERT "Initializing TLS module\n");
	
	/* initialize tls_prot hash table */
	tls_prot_init();

	/* Override functionality in the tcp_prot structure */
	err = set_tcp_prot();
	if (err != 0){
		goto out;
	}

	printk(KERN_INFO "TCP TOR redirect Module loaded. All traffic now sent through TOR\n");
	return 0;

out:
	return err;
}

static void __exit tor_reroute_exit(void)
{
	reset_tcp_prot();
	printk(KERN_INFO "TLS Module removed and tls_prot unregistered\n");
}

module_init(tor_reroute_init);
module_exit(tor_reroute_exit);
