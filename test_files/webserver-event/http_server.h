#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#define BUFFER_MAX				2048
#define MAX_HEADER_LENGTH			1024

typedef struct http_header {
	char* field;
	char* value;
} http_header_t;

typedef struct http_request {
	struct http_request* next;
	int is_valid;
	char* method;
	char* path;
	char* version;
	http_header_t* headers;
	unsigned char* body;
	int header_length;
	int body_length;
} http_request_t;

typedef struct http_response {
	char* version;
	char* status;
	char* phrase;
	http_header_t* headers;
	unsigned char* body;
	int resource_fd;
} http_response_t;

void http_server_run(char* config_path, char* port);
void free_http_request(http_request_t* request);

#endif
