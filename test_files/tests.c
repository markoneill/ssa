#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "../socktls.h"

#define MAX_HOSTNAME	255
#define BUFFER_MAX	1024

void run_sockops_tests(void);
void run_connect_tests(void);
void run_listen_tests(void);
void run_hostname_tests(void);

void handle_client(int sock, struct sockaddr_storage client_addr, socklen_t addr_len);
int connect_to_host(char* host, char* service);
int connect_to_host_new(char* host, char* service);
int create_server_socket(char* port, int protocol);
int create_server_socket_new(int port);

void run_socket_baseline(void);
void run_socket_benchmark(void);
void run_connect_baseline(void);
void run_connect_benchmark(void);
void run_listen_baseline(void);
void run_listen_benchmark(void);
void run_bind_baseline(void);
void run_bind_benchmark(void);

int timeval_subtract(struct timeval* result, struct timeval* x, struct timeval* y);

int counter;

int main(int argc, char* argv[]) {
	// Default counter value set. Separate starting value can be set
	// at beginning of each function if necessary
	counter = 0;
	for (int i = 0; i < 100; i++) {
		//run_sockops_tests();
		//run_hostname_tests();
		//run_listen_tests();
		//run_connect_tests();
		//run_connect_baseline();
		//run_connect_benchmark();
		//run_listen_baseline();
		//run_listen_benchmark();
		//run_bind_baseline();
		run_bind_benchmark();
		counter++;
	}
	printf("All tests succeeded!\n");
	return 0;
}


void run_sockops_tests(void) {
	int flag = 1;
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

        if (setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) == -1) {
		perror("setsockopt: TCP_NODELAY");
		exit(EXIT_FAILURE);
	}

	char hostname_retrieved[MAX_HOSTNAME];
	int hostname_length = MAX_HOSTNAME;
	if (getsockopt(sock_fd, IPPROTO_IP, SO_HOSTNAME, hostname_retrieved, &hostname_length) == -1) {
		perror("getsockopt: SO_HOSTNAME");
		exit(EXIT_FAILURE);
	}

	if (hostname_length != sizeof(hostname)) {
		fprintf(stderr, "Hostname is length %d but retrieved length is %d!\n", sizeof(hostname), hostname_length);
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
	close(sock_fd);
	return;
}

void run_listen_tests(void) {
	int sock_fd = create_server_socket_new(3333);
	struct sockaddr_storage client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	int client = accept(sock_fd, (struct sockaddr*)&client_addr, &client_addr_len);
	if (client == -1) {
		perror("accept");
		return;
	}
	handle_client(client, client_addr, client_addr_len);
	close(sock_fd);
	return;
}

void run_socket_baseline(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	printf("%i [Vanilla] Before socket: %ld.%06ld\n", counter, tv.tv_sec, tv.tv_usec);

	int sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	gettimeofday(&tv, NULL);
	printf("%i [Vanilla] After socket: %ld.%06ld\n", counter, tv.tv_sec, tv.tv_usec);

	close(sock_fd);
}

void run_socket_benchmark(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	printf("%i Before socket: %ld.%06ld\n", counter, tv.tv_sec, tv.tv_usec);

	int sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	gettimeofday(&tv, NULL);
	printf("%i After socket: %ld.%06ld\n", counter, tv.tv_sec, tv.tv_usec);

	close(sock_fd);
}

void run_connect_baseline(void) {
	counter = 0;
	int sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock_fd == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

        struct sockaddr_in dst_addr = {
                .sin_family = AF_INET,
                .sin_port = htons(8888),
                .sin_addr.s_addr = htonl(INADDR_LOOPBACK), // 127.0.0.1
        };
	struct timeval tv;
	gettimeofday(&tv, NULL);
	printf("%i [Vanilla] Before connect: %ld.%06ld\n", counter, tv.tv_sec, tv.tv_usec);
	if (connect(sock_fd, (struct sockaddr*)&dst_addr, sizeof(dst_addr)) == -1) {
		perror("connect");
		exit(EXIT_FAILURE);
	}
	gettimeofday(&tv, NULL);
	printf("%i [Vanilla] After connect: %ld.%06ld\n", counter, tv.tv_sec, tv.tv_usec);
	close(sock_fd);
	return;
}

void run_connect_benchmark(void) {
	counter = 3000;
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
        struct sockaddr_in dst_addr = {
                .sin_family = AF_INET,
                .sin_port = htons(8888),
                .sin_addr.s_addr = htonl(INADDR_LOOPBACK), // 127.0.0.1
        };
	struct timeval tv;
	gettimeofday(&tv, NULL);
	printf("Before connect: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
	if (connect(sock_fd, (struct sockaddr*)&dst_addr, sizeof(dst_addr)) == -1) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	gettimeofday(&tv, NULL);
	printf("After Connect: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);

	close(sock_fd);
	return;
}

void run_bind_baseline(void){
	struct sockaddr_storage their_addr;
	socklen_t addr_size;
	struct addrinfo hints, *res;
	int sockfd, new_fd;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	getaddrinfo(NULL, "0", &hints, &res);

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	struct timeval tv;
	gettimeofday(&tv, NULL);
	printf("[vanilla] Before bind: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);

	if (bind(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
		perror("Bind Failure:");
		exit(0);
	}

	gettimeofday(&tv, NULL);
	printf("[Vanilla] After bind: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);

}

void run_bind_benchmark(void){
	struct sockaddr_storage their_addr;
	socklen_t addr_size;
	struct addrinfo hints, *res;
	int sockfd, new_fd;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	getaddrinfo(NULL, "0", &hints, &res);

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
	if (sockfd == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	struct timeval tv;
	gettimeofday(&tv, NULL);
	printf("Before bind: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);

	if (bind(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
		perror("Bind Failure");
	}

	gettimeofday(&tv, NULL);
	printf("After bind: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);


}

void run_listen_baseline(void){
	struct sockaddr_storage their_addr;
	socklen_t addr_size;
	struct addrinfo hints, *res;
	int sockfd, new_fd;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	getaddrinfo(NULL, "0", &hints, &res);

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	bind(sockfd, res->ai_addr, res->ai_addrlen);

	struct timeval tv;
	gettimeofday(&tv, NULL);
	printf("[vanilla] Before listen: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);

	listen(sockfd, 10);
	
	gettimeofday(&tv, NULL);
	printf("[Vanilla] After listen: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);

	close(sockfd);
}

void run_listen_benchmark(void){
	struct sockaddr_storage their_addr;
        socklen_t addr_size;
        struct addrinfo hints, *res;
        int sockfd, new_fd;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        getaddrinfo(NULL, "0", &hints, &res);

        sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
        if (sockfd == -1) {
                perror("socket");
                exit(EXIT_FAILURE);
        }

        bind(sockfd, res->ai_addr, res->ai_addrlen);

        struct timeval tv; 
        gettimeofday(&tv, NULL);
        printf("Before listen: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);

        listen(sockfd, 10);

        gettimeofday(&tv, NULL);
        printf("After listen: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);

	close(sockfd);
}

void handle_client(int sock, struct sockaddr_storage client_addr, socklen_t addr_len) {
	unsigned char buffer[BUFFER_MAX];
	char client_hostname[NI_MAXHOST];
	char client_port[NI_MAXSERV];
	int ret = getnameinfo((struct sockaddr*)&client_addr, addr_len, client_hostname,
		       NI_MAXHOST, client_port, NI_MAXSERV, 0);
	if (ret != 0) {
		fprintf(stderr, "Failed in getnameinfo: %s\n", gai_strerror(ret));
	}
	printf("Got a connection from %s:%s\n", client_hostname, client_port);
	while (1) {
		int bytes_read = recv(sock, buffer, BUFFER_MAX-1, 0);
		if (bytes_read == 0) {
			printf("Peer disconnected\n");
			close(sock);
			return;
		}
		if (bytes_read < 0) {
			perror("recv");
			continue;
		}
		buffer[bytes_read] = '\0';
		printf("received: %s\n", buffer);
		send(sock, buffer, strlen(buffer)+1, 0);
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

int create_server_socket(char* port, int protocol) {
	int sock;
	int ret;
	int optval = 1;
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = protocol;
	/* AI_PASSIVE for filtering out addresses on which we
	 * can't use for servers
	 *
	 * AI_ADDRCONFIG to filter out address types the system
	 * does not support
	 *
	 * AI_NUMERICSERV to indicate port parameter is a number
	 * and not a string
	 *
	 * */
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_NUMERICSERV;
	/*
	 *  On Linux binding to :: also binds to 0.0.0.0
	 *  Null is fine for TCP, but UDP needs both
	 *  See https://blog.powerdns.com/2012/10/08/on-binding-datagram-udp-sockets-to-the-any-addresses/
	 */
	ret = getaddrinfo(protocol == SOCK_DGRAM ? "::" : NULL, port, &hints, &addr_list);
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

		// Allow us to quickly reuse the address if we shut down (avoiding timeout)
		ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
		if (ret == -1) {
			perror("setsockopt");
			close(sock);
			continue;
		}

		ret = bind(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen);
		if (ret == -1) {
			perror("bind");
			close(sock);
			continue;
		}
		break;
	}
	freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		fprintf(stderr, "Failed to find a suitable address for binding\n");
		exit(EXIT_FAILURE);
	}

	if (protocol == SOCK_DGRAM) {
		return sock;
	}
	// Turn the socket into a listening socket if TCP
	ret = listen(sock, SOMAXCONN);
	if (ret == -1) {
		perror("listen");
		close(sock);
		exit(EXIT_FAILURE);
	}

	return sock;
}

int create_server_socket_new(int port) {
	int ret;
	int sock;
	struct sockaddr_in addr;
	int optval = 1;
       	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
	if (sock == -1) {
		perror("socket");
		return -1;
	}
	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (ret == -1) {
		perror("setsockopt");
		close(sock);
		return -1;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	ret = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
	if (ret == -1) {
		perror("bind");
		close(sock);
		return -1;
	}

	ret = listen(sock, SOMAXCONN);
	if (ret == -1) {
		perror("listen");
		close(sock);
		return -1;
	}
	return sock;
}

int timeval_subtract(struct timeval* result, struct timeval* x, struct timeval* y) {
	struct timeval y_cpy = *y;
	/* Perform the carry for the later subtraction by updating y_cpy. */
	if (x->tv_usec < y_cpy.tv_usec) {
		int nsec = (y_cpy.tv_usec - x->tv_usec) / 1000000 + 1;
		y_cpy.tv_usec -= 1000000 * nsec;
		y_cpy.tv_sec += nsec;
	}
	if (x->tv_usec - y_cpy.tv_usec > 1000000) {
		int nsec = (x->tv_usec - y_cpy.tv_usec) / 1000000;
		y_cpy.tv_usec += 1000000 * nsec;
		y_cpy.tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 * tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y_cpy.tv_sec;
	result->tv_usec = x->tv_usec - y_cpy.tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y_cpy.tv_sec;
}
