#include <linux/module.h>
#include <linux/kernel.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <net/sock.h>
#include "tls_prot.h"


#define DRIVER_AUTHOR 	"Mark O'Neill <phoenixteam1@gmail.com> and Nick Bonner <j.nick.bonner@gmail.com>"
#define DRIVER_DESC	"A loadable TLS module to give TLS functionality to the POSIX socket API"
#define IPPROTO_TLS 	5	

//extern struct proto tcp_prot;
//extern struct proto_ops inet_stream_ops;
//extern void inet_register_protosw(struct inet_protosw);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

static struct proto tls_prot;

static struct inet_protosw tls_stream_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_TLS,
	.prot		= &tls_prot,
	.ops		= &inet_stream_ops,
	.flags 		= INET_PROTOSW_PERMANENT | INET_PROTOSW_ICSK
};

void set_tls_prot(void){
	tls_prot = tcp_prot;
	tls_prot.connect = tls_v4_connect;
	tls_prot.disconnect = tls_disconnect;
	tls_prot.shutdown = tls_shutdown;
	tls_prot.recvmsg = tls_recvmsg;
	tls_prot.sendmsg = tls_sendmsg;
	printk(KERN_ALERT "TLS protocols set");
}

static int __init tls_init(void)
{
	printk(KERN_ALERT "Initializing TLS module");
	set_tls_prot();
	inet_register_protosw(&tls_stream_protosw);
	printk(KERN_INFO "TLS Module loaded and tls_prot registered\n");
	return 0;
}

static void __exit tls_exit(void)
{
	inet_unregister_protosw(&tls_stream_protosw);
	printk(KERN_INFO "TLS Module removed and tls_prot unregistered\n");
}

module_init(tls_init);
module_exit(tls_exit);
