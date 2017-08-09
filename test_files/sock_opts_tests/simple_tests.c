#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../../constants.h"

#define MAX_HOSTNAME	255

void run_sockops_tests(void);

int main(int argc, char* argv[]) {
	run_sockops_tests();
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


	return;
}
