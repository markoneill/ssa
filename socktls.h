#ifndef SOCKTLS_H
#define SOCKTLS_H

#define SO_HOSTNAME	85
#define IPPROTO_TLS 	(715 % 255)

#define AF_HOSTNAME	43

struct host_addr { 
        unsigned char name[255]; 
}; 
 
struct sockaddr_host { 
        sa_family_t sin_family; 
        unsigned short sin_port; 
        struct host_addr sin_addr; 
}; 

#endif
