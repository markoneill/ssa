#ifndef IN_TLS
#define IN_TLS

/* Protocol */
#define IPPROTO_TLS     (715 % 255)

/* Options */
#define TLS_REMOTE_HOSTNAME               85
#define TLS_HOSTNAME                      86
#define TLS_TRUSTED_PEER_CERTIFICATES     87
#define TLS_CERTIFICATE_CHAIN             88
#define TLS_PRIVATE_KEY                   89
#define TLS_ALPN                          90
#define TLS_SESSION_TTL                   91
#define TLS_DISABLE_CIPHER                92
#define TLS_PEER_IDENTITY		  93
#define TLS_REQUEST_PEER_AUTH		  94

/* Internal use only */
#define TLS_PEER_CERTIFICATE_CHAIN        95
#define TLS_ID                            96

/* TCP options */
#define TCP_UPGRADE_TLS         33

/* Address types */
#define AF_HOSTNAME     43

struct host_addr {
        unsigned char name[255];
};

struct sockaddr_host {
        sa_family_t sin_family;
        unsigned short sin_port;
        struct host_addr sin_addr;
};


#endif

