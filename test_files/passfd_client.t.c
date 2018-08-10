#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>

#include "../socktls.h"
#define ADDR	"localhost"
#define PORT	8080

#define MSG	"Hey from the client!\n"


int main(int argc, char** argv) {
	struct sockaddr_in addr;
	struct hostent* server;
	int con;
	int error = 0;

	int optval;
	socklen_t optlen = sizeof(optval);
	// Open a connection to the server

	server = gethostbyname(ADDR);
	if (server == NULL) {
		printf("Bad Host\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = *((unsigned long*)server->h_addr);

	con = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (con == -1) {
		printf("Socket error\n");
		return -1;
	}

	if (connect(con, (struct sockaddr*)&addr, sizeof(addr))) {
		printf("Connect error\n");
		return -1;
	}
	
	optval = 0;
	printf("Setsockopt %d\n", setsockopt(con, SOL_TCP, TCP_UPGRADE_TLS, &optval, optlen));

	// set hostname
	setsockopt(con, IPPROTO_TLS, TLS_REMOTE_HOSTNAME, "google.com", sizeof("google.com"));


	error = send(con, MSG, sizeof(MSG), 0);
	printf("Send msg (%s) = %d\n", MSG, error);
	if (error == -1) {
		printf("Errno = (%d) %s\n", errno, strerror(errno));
	}

	getchar();

	close(con);

	return 0;
}
