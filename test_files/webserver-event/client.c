#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <unistd.h>
#include <search.h>
#include <time.h>
#include <sys/time.h>
#include "client.h"
#include "http_server.h"
#include "utils.h"

client_t* first;
client_t* last;

void timeval_add(struct timeval* result, struct timeval* x, struct timeval* y);
int timeval_subtract(struct timeval* result, struct timeval* x, struct timeval* y);
int timeval_cmp(struct timeval* x, struct timeval* y);

client_t* create_client(int server_sock) {
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(struct sockaddr_storage);
	int new_fd = accept(server_sock, (struct sockaddr*)&addr, &addr_len);
	if (new_fd == -1) {
		perror("accept");
		return NULL;
	}
	client_t* client = (client_t*)malloc(sizeof(client_t));
	if (client == NULL) {
		return NULL;
	}
	client->fd = new_fd;
	int ret = getnameinfo((struct sockaddr*)&addr, addr_len, client->hostname, NI_MAXHOST, client->port, NI_MAXSERV, 0);
	if (ret != 0) {
		client->hostname[0] = '\0';
		client->port[0] = '\0';
		fprintf(stderr, "Failed in getnameinfo: %s\n", gai_strerror(ret));
	}
	client->send_buf.length = 0;
	client->send_buf.position = 0;
	client->send_buf.max_length = MAX_HEADER_LENGTH;
	client->send_buf.data = (unsigned char*)calloc(1, MAX_HEADER_LENGTH);
	client->recv_buf.length = 0;
	client->recv_buf.position = 0;
	client->recv_buf.max_length = BUFFER_MAX;
	client->recv_buf.data = (unsigned char*)calloc(1, BUFFER_MAX);
	client->state = PARSING_HEADERS;
	client->sentinel_pos = NULL;
	client->current_request = NULL;
	client->current_resource.fd = -1;
	client->current_resource.size = 0;
	client->current_resource.position = 0;
	gettimeofday(&client->last_event, NULL);
	if (first != NULL) {
		insque(client, last);
		last = client;
	}
	else {
		insque(client, NULL);
		first = client;
		last = client;
	}
	client->request_list = NULL;

	//printfv("[client from %s:%s connected]\n", client->hostname, client->port);
	return client;
}

void reset_client(client_t* client) {
	client->send_buf.position = 0;
	client->send_buf.length = 0;
	client->sentinel_pos = NULL;
	client->current_request = NULL;
	client->current_resource.position = 0;
	client->current_resource.size = 0;
	if (client->current_resource.fd != -1) {
		close(client->current_resource.fd);
		client->current_resource.fd = -1;
	}
	return;
}

void free_client(client_t* client) {
	if (!client) return;
	if (client->recv_buf.data) free(client->recv_buf.data);
	if (client->send_buf.data) free(client->send_buf.data);
	if (client->current_request) free_http_request(client->current_request);
	if (client->current_resource.fd != -1) {
		close(client->current_resource.fd);
	}
	if (client == first) {
		first = client->next;
	}
	if (client == last) {
		last = client->prev;
	}
	remque(client);
	free(client);
}

void sweep_clients(time_t timeout_secs) {
	client_t* current = first;
	client_t* next;
	struct timeval limit;
	gettimeofday(&limit, NULL);
	limit.tv_sec -= timeout_secs;
	while (current != NULL) {
		next = current->next;
		if (timeval_cmp(&limit, &current->last_event) == 0) {
			close(current->fd);
			//printfv("[client from %s:%s disconnected (idle)]\n", current->hostname, current->port);
			//printfv("closing and freeing client\n");
			free_client(current);
		}
		current = next;
	}
	return;
}

void timeval_add(struct timeval* result, struct timeval* x, struct timeval* y) {
	suseconds_t usecs = x->tv_usec + y->tv_usec;
	time_t secs = x->tv_sec + y->tv_sec;
	while (usecs >= 1000000) {
		usecs -= 1000000;
		secs++;
	}
	result->tv_usec = usecs;
	result->tv_sec = secs;
	return;
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

int timeval_cmp(struct timeval* x, struct timeval* y) {
	struct timeval y_cpy = *y;
	/* Perform the carry for the later subtraction. */
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

	/* Return 1 if y is more recent than x. */
	return x->tv_sec < y_cpy.tv_sec;
}

