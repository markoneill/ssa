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
#define IPPROTO_TLS 	143	

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

static const struct net_protocol tcp_protocol = {
	.early_demux	= tcp_v4_early_demux,
	.handler	= tcp_v4_rcv,
	.err_handler	= tcp_v4_err,
	.no_policy	= 1,
	.netns_ok	= 1,
	.icmp_strict_tag_validation = 1,
};

void set_tls_prot(void){
	tls_prot = tcp_prot;
//	tls_prot.connect = tls_v4_connect;
//	tls_prot.disconnect = tls_disconnect;
//	tls_prot.shutdown = tls_shutdown;
//	tls_prot.recvmsg = tls_recvmsg;
//	tls_prot.sendmsg = tls_sendmsg;
	printk(KERN_ALERT "TLS protocols set");
}

static int __init tls_init(void)
{
	int err;	

	printk(KERN_ALERT "Initializing TLS module");
	set_tls_prot();
	
	err = proto_register(&tls_prot, 1);

	if (err != 0){
		goto out;
	}

	err = inet_add_protocol(&tcp_protocol, IPPROTO_TLS);
	if (err != 0){
		goto out_proto_unregister;
	}

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
	inet_unregister_protosw(&tls_stream_protosw);
	inet_del_protocol(&tcp_protocol, IPPROTO_TLS);
	proto_unregister(&tls_prot);
	printk(KERN_INFO "TLS Module removed and tls_prot unregistered\n");
}

module_init(tls_init);
module_exit(tls_exit);
