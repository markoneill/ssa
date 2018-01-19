#ifndef CONFIG_H
#define CONFIG_H

#include <linux/limits.h>
#include <netdb.h>

#define MIME_MAX	256 /* RFC 6838 */
#define EXT_MAX		256 /* Likely */


typedef struct host_path {
	char host[NI_MAXHOST];
	char path[PATH_MAX];
} host_path_t;

typedef struct extension_mime {
	char extension[EXT_MAX];
	char mime_type[MIME_MAX];
} extension_mime_t;

typedef struct config {
	extension_mime_t* mimes;
	int mime_count;
	host_path_t* hosts;
	int host_count;
} config_t;

config_t parse_config(char* config_path);
void free_config(config_t* config);
char* get_host_path(config_t* config, char* host);
char* get_mime_type(config_t* config, char* extension);
void print_config(config_t* config);

#endif
