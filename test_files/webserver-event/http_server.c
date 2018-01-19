#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <search.h>
#include <sys/time.h>

#include "http_server.h"
#include "client.h"
#include "config.h"
#include "utils.h"
#include "../../socktls.h"

#define MAX_EVENTS	1000
#define MAX_ERROR_BODY				1024
#define MAX_CONTENT_LENGTH_LENGTH		16
#define MAX_DATE_LENGTH				128

char http_version[] = "HTTP/1.1";
char default_path[] = "/index.html";
char server_name[]  = "Simple Web Server";

typedef struct server {
	int fd;
} server_t;

/* Helpers */
void format_date(char* date_str, time_t raw_time);
char* first_non_space(char* str);
char* strnstr(char* haystack, char* needle, int length);
char* resolve_path(char* root_dir, char* path);
int handle_cgi(int sock, char* root, char* resolved_path, http_request_t* request);

/* HTTP functions */
int parse_request_line(char* request_header, http_request_t* request);
int parse_headers(char* headers, int length, http_request_t* request);
void free_headers(http_header_t* headers);
char* get_header_value(http_header_t* headers, char* field);
int recv_http_requests(client_t* client);
int send_http_responses(client_t* client);
int create_http_error_response(client_t* client, char* status, char* phrase, char* desc);
int create_http_response(client_t* client, http_request_t* request);
int create_http_response_header(client_t* client, char* status, char* phrase, char* mime_type, time_t m_time, long int content_length);

/* Printing */
void print_config(config_t* config);
void print_request(http_request_t* request);
void print_headers(http_header_t* headers);

/* Network functions */
int send_data(client_t* client);
int send_content(client_t* client);
int recv_data(client_t* client);
int create_server_socket(char* port, int protocol);
int set_blocking(int sock, int blocking);

void handle_client(client_t* client);
void signal_handler(int signum);

time_t g_timeout_secs = 5;
config_t g_config;
int g_running;

void signal_handler(int signum) {
	if (signum == SIGINT) {
		g_running = 0;
	}
	return;
}

void http_server_run(char* config_path, char* port) {
	int n;
	int nfds;
	struct epoll_event ev;
	struct epoll_event events[MAX_EVENTS];
	g_running = 1;

	struct sigaction sigact;
	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = signal_handler;
	sigaction(SIGINT, &sigact, NULL);

	/* Ignore SIGPIPE so we don't die if a browser stops */
	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sigact, NULL);

	g_config = parse_config(config_path);
	printfv("Temporary buffer sizes are %d bytes\n", BUFFER_MAX);

	int listen_sock = create_server_socket(port, SOCK_STREAM);
	
	int epoll_fd = epoll_create1(0);
	if (epoll_fd == -1) {
		perror("epoll_create1");
		exit(EXIT_FAILURE);
	}

	set_blocking(listen_sock, 0);
	server_t server = { .fd = listen_sock };
	ev.events = EPOLLIN;
	ev.data.ptr = (void*)&server;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_sock, &ev) == -1) {
		perror("epoll_ctl: listen_sock");
		exit(EXIT_FAILURE);
	}

	/* Always check at at least 2x the max frequency you want to detect
	 * Nyquist rate, baby */
	int wait_milliseconds = (g_timeout_secs * 1000) / 2;

	while (1) {
		/* Wait for events, indefinitely */
		nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, wait_milliseconds);
		if (nfds == -1) {
			if (errno == EINTR) {
				if (g_running == 0) break;
			}
			perror("epoll_wait");
			exit(EXIT_FAILURE);
		}
		for (n = 0; n < nfds; n++) {
			if (events[n].data.ptr == &server) {
				/* Incoming event for server listening socket */
				client_t* new_client = create_client(server.fd);
				set_blocking(new_client->fd, 0);
				if (new_client == NULL) continue;

				/* Add new client to epoll */
				ev.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
				ev.data.ptr = (void*)new_client;
				if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_client->fd, &ev) == -1) {
					perror("epoll_ctl: new_client");
					exit(EXIT_FAILURE);
				}
				printfv("Client connected\n");
				continue;
			}

			client_t* client = (client_t*)events[n].data.ptr;
			gettimeofday(&client->last_event, NULL); /* mark client's latest event*/
			/* We got an event on a client socket */
			if (events[n].events & EPOLLIN) {
				/* Switch to sending events if we got any full requests */
				if (recv_http_requests(client) > 0) {
					printfv("Received and parsed some requests for client. Switching client events to EPOLLOUT\n");
					ev.events = EPOLLOUT | EPOLLRDHUP | EPOLLET;
					ev.data.ptr = (void*)client;
					if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &ev) == -1) {
						perror("epoll_ctl: move to send state");
						exit(EXIT_FAILURE);
					}
				}
			}
			if (events[n].events & EPOLLOUT) {
				if (send_http_responses(client) > 0) {
					/* free request and response and register for receiving */
					printfv("Satisfied all requests for client. Switching client events to EPOLLIN\n");
					ev.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
					ev.data.ptr = (void*)client;
					if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &ev) == -1) {
						perror("epoll_ctl: move to send state");
						exit(EXIT_FAILURE);
					}
				}
				//else { printfv("went twice\n");}
			}
			if (events[n].events & EPOLLRDHUP && client->request_list == NULL) {
				/* If client closes its writing side and ther are no outstanding requests, end it */
				client->state = DISCONNECTED;
			}
			if (client->state == DISCONNECTED) {
				if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client->fd, NULL) == -1) {
					perror("epoll_ctl: removing client");
					exit(EXIT_FAILURE);
				}
				printfv("Client disconnected\n");
				close(client->fd);
				free_http_request(client->current_request);
				free_client(client);
			}
		}
		sweep_clients(g_timeout_secs);
	}

	/* Free all clients */
	sweep_clients(0);
	free_config(&g_config);
	return;
}

/**
 * Drain the OS recv buffer and parse all requests found.
 * Requests are placed into the client's request list.
 *
 * Side effect: clears existing client request list.
 * Side effect: modifies client recv buffer internals
 *
 * @returns Returns the number of requests parsed
 */
int recv_http_requests(client_t* client) {
	int requests_parsed = 0;
	int bytes_parsed = 0;
	if (recv_data(client) == 1) {
		/* return early if the client disconnected */
		return requests_parsed;
	}
	char* request_beg = (char*)client->recv_buf.data;
	while ((client->sentinel_pos = strnstr(request_beg, "\r\n\r\n", client->recv_buf.length-bytes_parsed)) != NULL) {
		//printfv("sentinel is found at %d\n", client->sentinel_pos - (char*)client->recv_buf.data);
		if (client->state == PARSING_HEADERS) {
			/* Create and init request structure */
			http_request_t* request = (http_request_t*)calloc(1, sizeof(http_request_t));
			client->current_request = request;

			/* If we're here then we got the end of some headers for a request */
			char* body_pos = client->sentinel_pos + strlen("\r\n\r\n");
			request->header_length = body_pos - request_beg;
			printfv("Request Received. Headers:\n%.*s", request->header_length, request_beg);

			/* Parse headers */		
			char* token = strstr(request_beg, "\r\n");
			*token = '\0'; token += strlen("\r\n");
			request->is_valid = 1;
			if (parse_request_line(request_beg, request) != 0) {
				request->is_valid = 0;
			}
			if (parse_headers(token, request->header_length - (token - request_beg), request) != 0) {
				request->is_valid = 0;
			}

			if (request->is_valid) {
				/* Check to see  if we need to read a body */
				char* content_length = get_header_value(request->headers, "Content-Length");
				if (content_length == NULL) {
					char* transfer_encoding = get_header_value(request->headers, "Transfer-Encoding");
					if (transfer_encoding && strstr(transfer_encoding, "chunked") != NULL) {
						fprintf(stderr, "We don't yet support chunked encoding!\n");
						request->is_valid = 0;
					}
					/* There is no request body */
					request->body = NULL;
					request->body_length = 0;
					/* stay in receiving header state, we just finished a request */
					client->state = RECEIVED_REQUEST;
				}
				else {
					request->body_length = atoi(content_length);
					request->body = (unsigned char*)malloc(request->body_length);
					/* move to receiving body state, we're not done yet */
					client->state = PARSING_BODY;
				}
			}
			else {
				/* Don't try to parse anything else from bad requests */
				request->body = NULL;
				request->body_length = 0;
				client->state = RECEIVED_REQUEST;
			}
		}
		if (client->state == PARSING_BODY) {
			http_request_t* request = client->current_request;
			int excess_bytes_read = client->recv_buf.length - request->header_length;
			int bytes_to_read = request->body_length - excess_bytes_read;
			if (bytes_to_read > 0) {
				return requests_parsed;
			}
			/* We got all the body content. Copy it to request*/
			memcpy(request->body, request_beg + request->header_length, request->body_length);
			client->state = RECEIVED_REQUEST;

		}
		if (client->state == RECEIVED_REQUEST) {
			http_request_t* request = client->current_request;
			/* add current request to full request list */
			http_request_t* last_request = client->request_list;
			if (last_request == NULL) {
				client->request_list = client->current_request;
			}
			else {
				while (last_request->next != NULL) {
					last_request = last_request->next;
				}
				last_request->next = client->current_request;
			}
			client->current_request = NULL;
			requests_parsed++;
			client->state = PARSING_HEADERS;

			/* Shift buffer down */
			//char* request_end = (char*)client->recv_buf.data + request->header_length + request->body_length;
			//int new_buf_length = client->recv_buf.length - (request->header_length + request->body_length);
			//memmove(client->recv_buf.data, request_end, new_buf_length);
			//client->recv_buf.length = new_buf_length;
			/* reset recvieve state */
			
			/* Move to next request */
			bytes_parsed += request->header_length + request->body_length;
			request_beg = (char*)client->recv_buf.data + bytes_parsed;
			//printfv("start of next request is %c\n", *request_beg);
			//printfv("would have been %c\n", *request_end);
		}
	}
	/* We're here because we have nothing left to parse */
	if (requests_parsed > 0) {
		int new_buf_length = client->recv_buf.length - bytes_parsed;
		memmove(client->recv_buf.data, request_beg, new_buf_length);
		client->recv_buf.length = new_buf_length;

		client->state = CREATING_RESPONSE;
	}
	return requests_parsed;
}

int send_http_responses(client_t* client) {
	/* create response and register for sending */
	http_request_t* last_request = NULL;
	while (client->request_list != NULL) {
		if (client->state == CREATING_RESPONSE) {
			create_http_response(client, client->request_list);
			client->state = SENDING_HEADERS;
		}
		if (client->state == SENDING_HEADERS) {
			if (send_data(client) != 0) {
				/* errors or full buffer */
				return 0;
			}
			/* We sent all our header info */
			client->state = SENDING_BODY;
		}
		if (client->state == SENDING_BODY) {
			/* if there's no content to send don't bother */
			if (client->current_resource.fd == -1) {
				client->state = CREATING_RESPONSE;
			}
			if (send_content(client) != 0) {
				/* errors or full buffer */
				return 0;
			}
			/* We sent the body content */
			client->state = CREATING_RESPONSE;
		}
		last_request = client->request_list;
		client->request_list = client->request_list->next;
		free_http_request(last_request);
		reset_client(client);
	}
	/* We finished sending everything */
	client->state = PARSING_HEADERS;
	return 1;
}

int create_http_response(client_t* client, http_request_t* request) {
	/* Deal with bad requests now */
	if (request->is_valid == 0) {
		create_http_error_response(client, "400", "Bad Request", "Could not parse request");
		return 1;
	}
	/* Make sure indicated host is valid, if existent */
	char* host = get_header_value(request->headers, "Host");
	char* port_pos;
	if (host == NULL) {
		/* If no host is specified, select first one from config */
		host = g_config.hosts[0].host;
	}
	if ((port_pos = strchr(host, ':')) != NULL) *port_pos = '\0';
	char* path;
	if ((path = get_host_path(&g_config, host)) == NULL) {
		create_http_error_response(client, "400", "Bad Request", "Invalid host header specified");
		return 1;
	}

	/* Resolve path */
	char* resolved_path = resolve_path(path, request->path);
	struct stat file_info;
	if (stat(resolved_path, &file_info) != 0) {
		create_http_error_response(client, "404", "Not Found", "Could not find the file specified");
		free(resolved_path);
		return 1;
	}
	if ((file_info.st_mode & S_IRUSR) == 0) {
		create_http_error_response(client, "403", "Forbidden", "Insufficient permissions to read requested file");
		free(resolved_path);
		return 1;
	}

	char* mime_type = get_mime_type(&g_config, resolved_path);

	/* We're ready to handle CGI now */
	/*if (strstr(resolved_path, ".php") != NULL) {
		handle_cgi(client->fd, path, resolved_path, request);
		free(resolved_path);
		return 1;
	}*/


	/* Everything seems okay.  Let's actually do what the client requested */
	if (strcmp(request->method, "GET") == 0 || strcmp(request->method, "POST") == 0 || strcmp(request->method, "HEAD") == 0) {
		create_http_response_header(client, "200", "OK", mime_type, file_info.st_mtime, file_info.st_size);
		if (strcmp(request->method, "GET") == 0 || strcmp(request->method, "POST") == 0) {
			client->current_resource.fd = open(resolved_path, O_RDONLY);
			client->current_resource.size = file_info.st_size;
			client->current_resource.position  = 0;
		}
	}
	else {
		create_http_error_response(client, "501", "Not Implemented", "This server does not implement that HTTP Method");
	}
	free(resolved_path);
	return 1;
}

int create_http_error_response(client_t* client, char* status, char* phrase, char* desc) {
	char body[MAX_ERROR_BODY];
	int length = snprintf(body, MAX_ERROR_BODY,
			"<html><head><title>%s - %s</title></head><body><h1>%s - %s</h1><p>%s</p></body></html>",
			status, phrase, status, phrase, desc);
	if (length > MAX_ERROR_BODY) {
		fprintf(stderr, "MAX_ERROR_BODY needs to be increased");
		exit(EXIT_FAILURE);
	}
	time_t m_time;
	time(&m_time);

	create_http_response_header(client, status, phrase, "text/html", m_time , length);
	int new_length = client->send_buf.length + length;
	if (new_length > client->send_buf.max_length) {
		client->send_buf.data = (unsigned char*)realloc(client->send_buf.data, new_length);
		client->send_buf.max_length = new_length;
	}
	memcpy(&(client->send_buf.data)[client->send_buf.length], body, length);
	client->send_buf.length = new_length;
	return 0;
}

int create_http_response_header(client_t* client, char* status, char* phrase, char* mime_type, time_t m_time, long int content_length) {
	/* format date */
	char date_str[MAX_DATE_LENGTH];
	time_t raw_time;
	time(&raw_time);
	format_date(date_str, raw_time);

	/* format date */
	char last_modified_date_str[MAX_DATE_LENGTH];
	format_date(last_modified_date_str, m_time);

	/* format content length value */
	char length_str[MAX_CONTENT_LENGTH_LENGTH];
	if (snprintf(length_str, MAX_CONTENT_LENGTH_LENGTH, "%ld", content_length) > MAX_CONTENT_LENGTH_LENGTH) {
		fprintf(stderr, "MAX_CONTENT_LENGTH_LENGTH needs to be increased");
		exit(EXIT_FAILURE);
	}

	/* Complete Headers */
	http_header_t headers[] = {
			{ .field = "Date", .value = date_str },
			//{ .field = "Connection", "close" },
			{ .field = "Server", .value = server_name },
			{ .field = "Content-Type", .value = mime_type },
			{ .field = "Content-Length", .value = length_str },
			{ .field = "Last-Modified", .value = last_modified_date_str },
			{ .field = NULL, .value = NULL}
	};

	char* header = (char*)client->send_buf.data;
	int header_length = snprintf(header, MAX_HEADER_LENGTH, "%s %s %s\r\n", http_version, status, phrase);

	int i;
	size_t remaining_length;
	for (i = 0; headers[i].field != NULL; i++) {
		if (header_length > MAX_HEADER_LENGTH) break;
		remaining_length = MAX_HEADER_LENGTH - header_length;
		header_length += snprintf(header + header_length, remaining_length, "%s: %s\r\n",
			headers[i].field, headers[i].value);
	}
	remaining_length = MAX_HEADER_LENGTH - header_length;
	header_length += snprintf(header + header_length, remaining_length, "\r\n");
	if (header_length > MAX_HEADER_LENGTH) {
		fprintf(stderr, "MAX_HEADER_LENGTH needs to be increased\n");
		exit(EXIT_FAILURE);
	}
	printfv("Response created. Headers:\n%s", header);
	client->send_buf.length = header_length;
	return 0;
};


void free_http_request(http_request_t* request) {
	if (!request) return;
	if (request->headers) free_headers(request->headers);
	if (request->method) free(request->method);
	if (request->path) free(request->path);
	if (request->version) free(request->version);
	if (request->body) free(request->body);
	free(request);
	return;
}

void free_headers(http_header_t* headers) {
	int i;
	for (i = 0; headers[i].field != NULL; i++) {
		if (headers[i].field) free(headers[i].field);
		if (headers[i].value) free(headers[i].value);
	}
	free(headers);
	return;
}


int parse_request_line(char* request_header, http_request_t* request) {
	char* token = strchr(request_header, ' ');
	if (token == NULL) {
		printfv("No method found in request\n");
		return -1;
	}
	*token = '\0'; token++;
	request->method = (char*)malloc(strlen(request_header)+1);
	strcpy(request->method, request_header);
	request_header = token;

	token = strchr(request_header, ' ');
	if (token == NULL) {
		printfv("No path found in request\n");
		return -1;
	}
	*token = '\0'; token++;
	request->path = (char*)malloc(strlen(request_header)+1);
	strcpy(request->path, request_header);

	if (strlen(token) == 0) {
		printfv("No version found in request\n");
		return -1;
	}
	request->version = (char*)malloc(strlen(token)+1);
	strcpy(request->version, token);
	if (strcmp(http_version, request->version) != 0) {
		printfv("Unsupported HTTP Version\n");
		return -1;
	}
	return 0;
}

int parse_headers(char* headers, int length, http_request_t* request) {
	char* token;
	int count = 0;
	token = headers;
	while (token < (headers + length) && (token = strstr(token, "\r\n")) != NULL) {
		token += strlen("\r\n");
		count++;
	}
	http_header_t* parsed_headers = malloc(sizeof(http_header_t) * count);
	int i;
	/* Why so much verbosity? strtok is deprecated! */
	for (i = 0; i < (count - 1); i++) {
	       	token = strchr(headers, ':');
		if (token == NULL) {
			free(parsed_headers);
			fprintf(stderr, "Syntax error in headers\n");
			return -1;
		}
		*token = '\0'; token += 1;
		parsed_headers[i].field = malloc(strlen(headers)+1);
		strcpy(parsed_headers[i].field, headers);
		headers = token;
		token = strstr(headers, "\r\n");
		*token = '\0'; token += strlen("\r\n");
		parsed_headers[i].value = malloc(strlen(headers)+1);
		strcpy(parsed_headers[i].value, first_non_space(headers));
		headers = token;
	}
	if (count > 0) {
		parsed_headers[i].field = NULL;
		parsed_headers[i].value = NULL;
		request->headers = parsed_headers;
	}
	return 0;
}

char* get_header_value(http_header_t* headers, char* field) {
	char* value = NULL;
	int i;
	int match = 0;
	for (i = 0; headers[i].field != NULL; i++) {
		int j;
		for (j = 0; j < strlen(headers[i].field); j++) {
			if (tolower(field[j]) != tolower(headers[i].field[j])) {
				match = 0;
				break;
			}
			match = 1;
		}
		if (match) {
			value = headers[i].value;
			break;
		}

	}
	return value;
}

void print_headers(http_header_t* headers) {
	int i;
	printf("\tHeaders:\n");
	for (i = 0; headers[i].field != NULL; i++) {
		printf("\t\t%s: %s\n", headers[i].field, headers[i].value);
	}
	return;
}

void print_request(http_request_t* request) {
	printf("Request:\n");
	printf("\tMethod: %s\n\tPath: %s\n\tVersion: %s\n", 
		request->method, request->path, request->version);
	print_headers(request->headers);
	return;
}

int send_data(client_t* client) {
	char* buffer = (char*)client->send_buf.data;
	int bytes_sent;
	int bytes_left = client->send_buf.length - client->send_buf.position;
	while (bytes_left > 0) {
		bytes_sent = send(client->fd, &buffer[client->send_buf.position], bytes_left, 0);
		if (bytes_sent == -1) {
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				return 1; /* We've sent all we can for the moment */
			}
			else if (errno == EINTR) {
				continue; /* continue upon interrupt */
			}
			else if (errno == EPIPE) {
				client->state = DISCONNECTED;
				return 1; /* fail on broken pipe */
			}
			else if (errno == ECONNRESET) {
				client->state = DISCONNECTED;
				return 1;
			}
			else {
				perror("send");
				client->state = DISCONNECTED;
				return 1;
			}
		}
		bytes_left -= bytes_sent;
		client->send_buf.position += bytes_sent;
	}
	return 0;
}

int send_content(client_t* client) {
	int fd = client->current_resource.fd;
	int bytes_left = client->current_resource.size - client->current_resource.position;
	int bytes_sent;
	while (bytes_left > 0) {
		bytes_sent = sendfile(client->fd, fd, &client->current_resource.position, bytes_left);
		if (bytes_sent == -1) {
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				return 1; /* We've sent all we can for the moment */
			}
			perror("sendfile");
			client->state = DISCONNECTED;
			return 1;
		}
		bytes_left -= bytes_sent;
	}
	return 0;
}

int recv_data(client_t* client) {
	char temp_buffer[BUFFER_MAX];
	int bytes_read;
	while (1) {
		bytes_read = recv(client->fd, temp_buffer, BUFFER_MAX, 0);
		if (bytes_read == -1) {
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				return 0; /* We've read all we can for the moment */
			}
			else if (errno == EINTR) {
				continue; /* continue upon interrupt */
			}
			else if (errno == EPIPE) {
				perror("recv");
				client->state = DISCONNECTED;
				return 1; /* fail on broken pipe */
			}
			else {
				perror("recv");
				client->state = DISCONNECTED;
				return 1; /* pretend all other errors mean close */
			}
		}
		else if (bytes_read == 0) {
			//client->state = DISCONNECTED;
			//return 1;
			return 0;
		}

		/* Realloc if needed */
		int new_length = client->recv_buf.length + bytes_read;
		if (client->recv_buf.max_length < new_length) {
			client->recv_buf.data = realloc(client->recv_buf.data, new_length * 2);
			client->recv_buf.max_length = new_length * 2;
		}
		memcpy(&(client->recv_buf.data)[client->recv_buf.length], temp_buffer, bytes_read);
		client->recv_buf.length += bytes_read;
	}
	return 0;
}

int set_blocking(int sock, int blocking) {
	int flags;
	/* Get flags for socket */
	if ((flags = fcntl(sock, F_GETFL)) == -1) {
		perror("fcntl get");
		exit(EXIT_FAILURE);
	}
	/* Only change flags if they're not what we want */
	if (blocking && (flags & O_NONBLOCK)) {
		if (fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) == -1) {
			perror("fcntl set block");
			exit(EXIT_FAILURE);
		}
		return 0;
	}
	/* Only change flags if they're not what we want */
	if (!blocking && !(flags & O_NONBLOCK)) {
		if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
			perror("fcntl set nonblock");
			exit(EXIT_FAILURE);
		}
		return 0;
	}
	return 0;
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

char* first_non_space(char* str) {
	for (; *str == ' '; str++);
	return str;
}

char* resolve_path(char* root_dir, char* path) {
	char* end;
	int path_length = strlen(path);
	/* Don't count the query string in the path length */
	if ((end = strchr(path, '?')) != NULL) {
		path_length -= strlen(end);
	}
	/* Set default path if this is just slash (/) */
	if (strncmp("/", path, path_length) == 0) {
		path = default_path;
		path_length = strlen(default_path);
	}
	path_length += strlen(root_dir)+1;
	char* full_path = (char*)malloc(path_length);
	snprintf(full_path, path_length, "%s%s", root_dir, path);
	return full_path;
}

void format_date(char* date_str, time_t raw_time) {
	struct tm time_info;
	gmtime_r(&raw_time, &time_info);
	if (strftime(date_str, MAX_DATE_LENGTH, "%a, %d %b %Y %H:%M:%S %Z", &time_info) == 0) {
		fprintf(stderr, "Couldn't formate Date field");
		exit(EXIT_FAILURE);
	}
	return;
}

int handle_cgi(int sock, char* root, char* resolved_path, http_request_t* request) {
	pid_t pid;
	int err;
	int p[2];
	pipe(p);
	if ((pid = fork()) != 0) {
		if (pid < 0) {
			perror("fork");
			exit(EXIT_FAILURE);
		}
		close(p[0]);
		if (request->body) {
			write(p[1], request->body, request->body_length);
		}
		if ((err = waitpid(pid, NULL, 0)) == -1) {
			perror("cgi waitpid");
		}
		return 0;
	}
	close(p[1]);
	dup2(p[0], STDIN_FILENO);
	dup2(sock, STDOUT_FILENO);

	char* value;
	if ((value = get_header_value(request->headers, "Content-Length")) == NULL) {
		setenv("CONTENT_LENGTH", "0" , 1);
	}
	else {
		setenv("CONTENT_LENGTH", value , 1);
	}
	if ((value = get_header_value(request->headers, "Content-Type")) != NULL) {
		setenv("CONTENT_TYPE", value , 1);
	}
	setenv("DOCUMENT_ROOT", root, 1);
	if ((value = get_header_value(request->headers, "Cookie")) != NULL) {
		setenv("HTTP_COOKIE", value, 1);
	}
	setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
	if ((value = strchr(request->path, '?')) != NULL) {
		setenv("QUERY_STRING", value+1, 1);
		*value = '\0';
		setenv("PATH_INFO", request->path, 1);
	}
	else {
		setenv("QUERY_STRING", "", 1);
		setenv("PATH_INFO", resolved_path, 1);
	}
	setenv("PATH_TRANSLATED", resolved_path, 1);
	setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
	setenv("REMOTE_ADDR", "", 1); // XXX 
	setenv("REMOTE_HOST", "", 1); // XXX 
	setenv("REMOTE_IDENT", "", 1);
	setenv("REMOTE_USER", "", 1);
	setenv("REQUEST_METHOD", request->method, 1);
	setenv("SCRIPT_NAME", getenv("PATH_INFO"), 1);
	setenv("SERVER_NAME", "", 1); // XXX
	setenv("SERVER_PORT", "", 1); // XXX
	setenv("SERVER_PROTOCOL", http_version, 1);
	setenv("SERVER_SOFTWARE", server_name, 1);
	char* args[] = { "/usr/bin/php-cgi", NULL };
	//char cgi_header[] = "HTTP/1.1 200 OK\r\nConnection: close\r\n";
	//send_data(sock, (unsigned char*)cgi_header, strlen(cgi_header));
	execv(args[0], args);
	perror("php cgi: execv");
	exit(EXIT_FAILURE);
	return 0;
}

char* strnstr(char* haystack, char* needle, int length) {
	int i;
	int j;
	int needle_length = strlen(needle);
	int max_iterations = length - (needle_length -1);
	if (length < needle_length) return NULL;
	for (i = 0; i < max_iterations; i++) {
		for (j = 0; j < needle_length; j++) {
			if (haystack[i+j] != needle[j]) break;
		}
		if (j == needle_length)	return &haystack[i];
	}
	return NULL;
}

