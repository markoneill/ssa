#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "http_server.h"
#include "utils.h"

#define DEFAULT_PORT	"8080"
#define DEFAULT_CONFIG	"http.conf"

void usage(char* name);

/* globals */
extern int verbose_flag;

int main(int argc, char* argv[]) {
	char* port = NULL;
	char* config_path = NULL;

	port = DEFAULT_PORT;
	config_path = DEFAULT_CONFIG;

	int c;
	while ((c = getopt(argc, argv, "vp:c:")) != -1) {
		switch (c) {
			case 'v':
				verbose_flag = 1;
		 		break;
			case 'p':
				port = optarg;
				break;
			case 'c':
				config_path = optarg;
				break;
			case '?':
				if (optopt == 'p' || optopt == 'c') {
					fprintf(stderr, "Option -%c requires an argument\n", optopt);
					usage(argv[0]);
					exit(EXIT_FAILURE);
				}
			default:
				fprintf(stderr, "Unknown option encountered\n");
				usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	printfv("Verbose mode set to %s\n", verbose_flag ? "true" : "false");
	printfv("Config path set to %s\n", config_path);
	printfv("Port set to %s\n", port);
	http_server_run(config_path, port);
	return 0;
}

void usage(char* name) {
	printf("Usage: %s [-v] [-p port] [-c config-file]\n", name);
	printf("Example:\n");
        printf("\t%s -v -p 8080 -c http.conf \n", name);
	return;
}

