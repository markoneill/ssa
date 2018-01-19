#ifndef CLIENT_H
#define CLIENT_H

#include <linux/limits.h>
#include <netdb.h>
#include <time.h>
#include "http_server.h"

typedef struct buffer {
	unsigned char* data;
	int length;
	int max_length;
	int position;
} buffer_t;

typedef struct resource {
	int fd;
	long int size;
	long int position;
} resource_t;

typedef enum state {
	PARSING_HEADERS,
	PARSING_BODY,
	RECEIVED_REQUEST,
	CREATING_RESPONSE,
	SENDING_HEADERS,
	SENDING_BODY,
	DISCONNECTED
} state_t;

typedef struct client {
	struct client* next;
	struct client* prev;
	int fd;
	state_t state;
	buffer_t send_buf;
	buffer_t recv_buf;
	char* sentinel_pos;
	http_request_t* current_request;
	http_request_t* request_list;
	resource_t current_resource;
	struct timeval last_event;
	char hostname[NI_MAXHOST];
	char port[NI_MAXSERV];
} client_t;

client_t* create_client(int server_sock);
void sweep_clients(time_t timeout_secs);
void reset_client(client_t* client);
void free_client(client_t* client);


#endif
