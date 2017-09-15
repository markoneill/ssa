#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "../../socktls.h"

#define MAX_HOSTNAME	255

void run_sockops_tests(void);
void run_connect_tests(void);
void run_hostname_tests(void);
int connect_to_host(char* host, char* service);
int connect_to_host_new(char* host, char* service);

int main(int argc, char* argv[]) {
	run_sockops_tests();
	run_hostname_tests();
	run_connect_tests();
	printf("All tests succeeded!\n");
	return 0;
}

void run_sockops_tests(void) {
	int sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
	if (sock_fd == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	const char hostname[] = "www.google.com";
        if (setsockopt(sock_fd, IPPROTO_IP, SO_HOSTNAME, hostname, sizeof(hostname)) == -1) {
		perror("setsockopt: SO_HOSTNAME");
		exit(EXIT_FAILURE);
	}

	char hostname_retrieved[MAX_HOSTNAME];
	int hostname_length = MAX_HOSTNAME;
	if (getsockopt(sock_fd, IPPROTO_IP, SO_HOSTNAME, hostname_retrieved, &hostname_length) == -1) {
		perror("getsockopt: SO_HOSTNAME");
		exit(EXIT_FAILURE);
	}

	if (hostname_length != strlen(hostname)) {
		fprintf(stderr, "Hostname is length %d but retrieved length is %d!\n", strlen(hostname), hostname_length);
		exit(EXIT_FAILURE);
	}

	if (strncmp(hostname, hostname_retrieved, strlen(hostname)) != 0) {
		fprintf(stderr, "Hostname mismatch: expected %s but got %s\n", hostname, hostname_retrieved);
		exit(EXIT_FAILURE);
	}
        struct sockaddr_in dst_addr = {
                .sin_family = AF_INET,
                .sin_port = htons(8888),
                .sin_addr.s_addr = htonl(INADDR_LOOPBACK), // 127.0.0.1
        };
	if (connect(sock_fd, (struct sockaddr*)&dst_addr, sizeof(dst_addr)) == -1) {
		perror("connect");
		exit(EXIT_FAILURE);
	}
	return;
}

void run_connect_tests(void) {
	int sock_fd = connect_to_host("www.google.com", "443");
	char http_request[] = "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
	char http_response[1024*1024];
	memset(http_response, 0, 4096);
	send(sock_fd, http_request, sizeof(http_request), 0);
	recv(sock_fd, http_response, 4096, 0);
	printf("%s", http_response);
	close(sock_fd);
}

void run_hostname_tests(void) {
	int sock_fd = connect_to_host_new("www.google.com", "443");
	printf("ugh\n");
	char http_request[] = "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
	char http_response[1024*1024];
	memset(http_response, 0, 4096);
	send(sock_fd, http_request, sizeof(http_request), 0);
	recv(sock_fd, http_response, 4096, 0);
	printf("%s", http_response);
	close(sock_fd);
}

int connect_to_host(char* host, char* service) {
	int sock;
	int ret;
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	ret = getaddrinfo(host, service, &hints, &addr_list);
	if (ret != 0) {
		fprintf(stderr, "Failed in getaddrinfo: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, IPPROTO_TLS);
		if (sock == -1) {
			perror("socket");
			continue;
		}
	        if (setsockopt(sock, IPPROTO_IP, SO_HOSTNAME, host, strlen(host)+1) == -1) {
			perror("setsockopt: SO_HOSTNAME");
			close(sock);
			continue;
		}

		if (connect(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == -1) {
			perror("connect");
			close(sock);
			continue;
		}
		break;
	}
	freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		fprintf(stderr, "failed to find a suitable address for connection\n");
		exit(EXIT_FAILURE);
	}
	return sock;
}

int connect_to_host_new(char* host, char* service) {
	int sock;
	int ret;
	struct sockaddr_host addr;
       	addr.sin_family = AF_HOSTNAME;
	addr.sin_port = htons(atoi(service));
	strcpy(addr.sin_addr.name, host);
	printf("Connecting to %s:%u\n", host, ntohs(addr.sin_port));

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TLS);
	if (sock == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("connect");
		close(sock);
		exit(EXIT_FAILURE);
	}
	return sock;
}

