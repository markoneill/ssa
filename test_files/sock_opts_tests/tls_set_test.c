/*
client.c -- a stream socket client demo

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#define PORT "3490" // the port client will be connecting to 

#define MAXDATASIZE 100 // max number of bytes we can get at once 

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
    int sockfd, numbytes;  
    char buf[MAXDATASIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    int optlen;
    char host_name[] = "google.com";
    char host_name2[255];
    int err;

    if (argc != 4) {
        fprintf(stderr,"usage: client hostname host_name len(host_name)\n");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
	fprintf(stderr,"Attempting socket creation with socket(%s, %s, %s)\n",
		p->ai_family == AF_INET ? "AF_INET" : "AF_INET6",
		p->ai_socktype == SOCK_STREAM ? "SOCK_STREAM" : "SOCK_DGRAM",
		"715 % 255" );
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                (715 % 255))) == -1) {
            perror("client: socket");
            continue;
        }
	
	//Set socket options testing
        err = setsockopt(sockfd, IPPROTO_IP, 85, argv[2], atoi(argv[3]));
	printf("len = %i: ", atoi(argv[3]));
        if (err != 0){
            printf("%i\n", err);
        }
	else {
		printf("0\n");
	}
//        else {
//            //Get socket options testing
//            //optval2 = malloc(255);
//            optlen = 255;
//            err = getsockopt(sockfd, IPPROTO_IP, 85, host_name2, &optlen);
//            if (err != 0){
//                printf("getsockopt failed with error code %i\n", errno);
//            }
//            else {
//                printf("%i\t%s\n", optlen, host_name2);
//            }
//        }

	// Attempt connection to server with socket
	int conRet = connect(sockfd, p->ai_addr, p->ai_addrlen); 
        if (conRet == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    freeaddrinfo(servinfo); // all done with this structure

    if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
        perror("recv");
        exit(1);
    }

    buf[numbytes] = '\0';

    close(sockfd);

    return 0;
}
