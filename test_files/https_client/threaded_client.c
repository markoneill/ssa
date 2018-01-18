#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <sys/signal.h>
#include <netdb.h>
#include <pthread.h>
#include "../../socktls.h"

int connect_to_host(char* host, char* service);
void * threaded_connection();
void recv_func(int sock_fd,char* http_response);
void send_func(int sock_fd, char* http_request,int len);
int const CALLS_PER_THREAD = 2;
int const NUM_THREADS = 10;
int main() {
	signal(SIGPIPE, SIG_IGN);
    pthread_t t[NUM_THREADS];
	for(int i = 0; i < NUM_THREADS ; i++){
        pthread_create(&t[i], NULL, threaded_connection,NULL);
    }
    for(int i = 0; i < NUM_THREADS; i++){
        pthread_join(t[i],NULL);
    }
    return 0;
}
void * threaded_connection(){
    int sock_fd = connect_to_host("www.phoenixteam.net", "443");
	char http_request[] = "GET / HTTP/1.1\r\nHost: www.phoenixteam.net\r\n\r\n";
	
	char http_response[2048];
	memset(http_response, 0, 2048);
    for(int i = 0; i < CALLS_PER_THREAD; i++){
	    send_func(sock_fd, http_request,sizeof(http_request)-1);
	    recv_func(sock_fd, http_response);
	    printf("Iteration %d completed for thread ID %ld\n", i, pthread_self());
	//printf("Received:\n%s", http_response);
    }
	close(sock_fd);
    return NULL;
}
void send_func(int sock_fd, char* http_request,int len) {
	send(sock_fd, http_request, len, 0);
}
void recv_func(int sock_fd,char* http_response){
    recv(sock_fd, http_response, 750, 0); /* Just grab up to the first 750 bytes from the host (for now) */
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
	        if (setsockopt(sock, IPPROTO_TLS, SO_HOSTNAME, host, strlen(host)+1) == -1) {
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
