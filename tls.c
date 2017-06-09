#ifndef _TLS_H
#define _TLS_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <net/sock.h>
#include "tls_prot.h"


#define DRIVER_AUTHOR 	"Mark O'Neill <phoenixteam1@gmail.com> and Nick Bonner <j.nick.bonner@gmail.com>"
#define DRIVER_DESC	"A loadable TLS module to give TLS functionality to the POSIX socket API"
#define IPPROTO_TLS 	715	

//extern struct proto tcp_prot;
//extern struct proto_ops inet_stream_ops;
//extern void inet_register_protosw(struct inet_protosw);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

struct inet_protosw *p;

struct proto* set_tls_prot(void){
	struct proto *prot = &tcp_prot;
	prot->connect = tls_v4_connect;
	prot->disconnect = tls_disconnect;
	prot->shutdown = tls_shutdown;
	prot->recvmsg = tls_recvmsg;
	prot->sendmsg = tls_sendmsg;
	return prot;
}

void init_proto_info(void){
	//p->list = 0;
	p->type = SOCK_STREAM;
	p->protocol = IPPROTO_TLS; 
	p->prot = set_tls_prot();
	p->ops = &inet_stream_ops; 
	p->flags = INET_PROTOSW_PERMANENT | INET_PROTOSW_ICSK; // same as TCP?
}

static int __init tls_init(void)
{
	struct inet_protosw *p = kmalloc(GFP_KERNEL, sizeof(struct inet_protosw));
	init_proto_info();
	inet_register_protosw(p);

	printk(KERN_INFO "TLS Module loaded and tls_prot registered\n");
	return 0;
}

static void __exit tls_exit(void)
{
	inet_unregister_protosw(p);
	kfree(p);
	printk(KERN_INFO "TLS Module removed and tls_prot unregistered\n");
}

module_init(tls_init);
module_exit(tls_exit);

#endif /*_TLS_H */
