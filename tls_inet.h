#ifndef TLS_INET_H
#define TLS_INET_H

#include <net/sock.h>
#include <linux/net.h>

int set_tls_prot_inet_stream(struct proto* tls_prot, struct proto_ops* tls_proto_ops);
void inet_stream_cleanup(void);
void report_handshake_finished(unsigned long key, int response, int blocking);

#endif /* TLS_INET_H */
