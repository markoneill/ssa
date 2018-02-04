/*
 * Secure Socket API - transparent TLS wrapping of plaintext connections
 * Copyright (C) 2017-2018, Mark O'Neill <mark@markoneill.name>
 * All rights reserved.
 * https://owntrust.org
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <net/sock.h>
#include <linux/netfilter.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/capability.h>
#include <linux/cpumask.h>
#include "tls_common.h"
#include "tls_inet.h"
#include "tls_upgrade.h"
#include "socktls.h"

#define DRIVER_AUTHOR 	"Mark O'Neill <mark@markoneill.name> and Nick Bonner <j.nick.bonner@gmail.com>"
#define DRIVER_DESC	"A loadable TLS module to give TLS functionality to the POSIX socket API"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

/* The TLS protocol structures to be filled and registered */
static struct proto tls_prot;
static struct proto_ops tls_proto_ops;
static struct net_protocol tls_protocol;
static struct inet_protosw tls_stream_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_TLS,
	.prot		= &tls_prot,
	.ops		= &tls_proto_ops,
	.flags 		= INET_PROTOSW_ICSK
};


/* Auxillary support reference functions */
int (*orig_tcp_setsockopt)(struct sock*, int, int, char __user*, unsigned int);

static int __init ssa_init(void) {
	int err;	
	unsigned long kallsyms_err;
	static const struct net_protocol *tcp_protocol_lookup;

	printk(KERN_INFO "Initializing Secure Socket API module\n");
	printk(KERN_INFO "Found %u CPUs\n", nr_cpu_ids);
	
	/* initialize our global data structures for TLS handling */
	tls_setup();

	/* Obtain referencess to desired TLS handling functions */
	err = set_tls_prot_inet_stream(&tls_prot, &tls_proto_ops);
	//err = set_tls_prot_unix();
	if (err != 0) {
		goto out;
	}

	/* Initialize the TLS protocol */
	/* XXX Do we really NOT want to allocate cache space here? Why is 2nd param 0? */
	err = proto_register(&tls_prot, 0);
	if (err == 0) {
		printk(KERN_INFO "TLS protocol registration was successful\n");
	} else {
		printk(KERN_ALERT "TLS Protocol registration failed\n");
		goto out;
	}

	/*
	 * Retrieve the non-exported tcp_protocol struct address location 
	 * and verify that it was found. If it fails, unregister the protocol
	 * and exit the module initialization.
	 */
	kallsyms_err = kallsyms_lookup_name("tcp_protocol");
	if (kallsyms_err == 0) {
		printk(KERN_ALERT "kallsyms_lookup_name failed to retrieve tcp_protocol address\n");
		goto out_proto_unregister;
	}

	/* Create a copy of the tcp_protocol net_protocol and register it with IPPROTO_TLS.
	   We borrow these operations because they suit our needs. Modify them later if
	   necessary through our local copy. */
	tcp_protocol_lookup = (struct net_protocol*)kallsyms_err;
	tls_protocol = *tcp_protocol_lookup;
	err = inet_add_protocol(&tls_protocol, IPPROTO_TLS);
	if (err == 0) {
		printk(KERN_INFO "Protocol insertion in inet_protos[] was successful\n");
	} else {
		printk(KERN_ALERT "Protocol insertion in inet_protos[] failed\n");
		goto out_proto_unregister;
	}
	inet_register_protosw(&tls_stream_protosw);
	

	/* Register the setsockopt hooks for TLS upgrades */
	orig_tcp_setsockopt = tcp_prot.setsockopt;
	tcp_prot.setsockopt = hook_tcp_setsockopt;

	printk(KERN_INFO "Initialized Secure Socket API module successfully\n");
	return 0;

out:
	return err;
out_proto_unregister:
	proto_unregister(&tls_prot);
	goto out;
}

static void __exit ssa_exit(void) {

	inet_stream_cleanup();

	/* Unregister the tcp hook */
	if (orig_tcp_setsockopt != NULL) {
		tcp_prot.setsockopt = orig_tcp_setsockopt;
	}

	/* Unregister the protocols and structs in the reverse order they were registered */
	inet_del_protocol(&tls_protocol, IPPROTO_TLS);
	inet_unregister_protosw(&tls_stream_protosw);
	
	/* Set these pointers to NULL to avoid deleting tcp_prot's shared memory */
	tls_prot.slab = NULL;
	tls_prot.rsk_prot = NULL;
	tls_prot.twsk_prot = NULL;

	proto_unregister(&tls_prot);
	printk(KERN_INFO "TLS Module removed and tls_prot unregistered\n");
	/* Free TLS socket handling data */
	tls_cleanup();
}

module_init(ssa_init);
module_exit(ssa_exit);
