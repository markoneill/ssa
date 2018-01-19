#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "config.h"

#define CONFIG_LINE_MAX				2048

char default_mime[] = "text/plain";

config_t parse_config(char* config_path) {
	// XXX better error handling in this function
	config_t cfg = {
		.hosts = NULL, .host_count = 0,
		.mimes = NULL, .mime_count = 0,
	};
	char buffer[CONFIG_LINE_MAX];
	FILE* config_file = fopen(config_path, "r");
	if (config_file == NULL) {
		perror("Configuration file error");
		exit(EXIT_FAILURE);
	}
	while (fgets(buffer, CONFIG_LINE_MAX, config_file) != NULL) {
		if (strncmp(buffer, "host", strlen("host")) == 0) {
			cfg.host_count++;
		}
		else if (strncmp(buffer, "media", strlen("media")) == 0) {
			cfg.mime_count++;
		}
	}
	if (cfg.host_count == 0) {
		fprintf(stderr, "No hosts found in config file. Aborting\n");
		fclose(config_file);
		exit(EXIT_FAILURE);
	}

	fseek(config_file, 0, SEEK_SET);
	cfg.hosts = (host_path_t*)malloc(sizeof(host_path_t) * cfg.host_count);
	if (cfg.mime_count) {
		cfg.mimes = (extension_mime_t*)malloc(sizeof(extension_mime_t) * cfg.mime_count);
	}
	int host_i = 0;
	int mime_i = 0;
	while (fgets(buffer, CONFIG_LINE_MAX, config_file) != NULL) {
		if (strncmp(buffer, "host", strlen("host")) == 0) {
			sscanf(buffer, "%*s %s %s[^\n]", cfg.hosts[host_i].host, cfg.hosts[host_i].path);
			host_i++;
		}
		else if (strncmp(buffer, "media", strlen("media")) == 0) {
			sscanf(buffer, "%*s %s %s[^\n]", cfg.mimes[mime_i].extension, cfg.mimes[mime_i].mime_type);
			mime_i++;
		}
	}
	fclose(config_file);
	return cfg;
}

void free_config(config_t* config) {
	if (config->host_count) free(config->hosts);
	if (config->mime_count) free(config->mimes);
	return;
}

char* get_host_path(config_t* config, char* host) {
	int i;
	for (i = 0; i < config->host_count; i++) {
		if (strcmp(config->hosts[i].host, host) == 0) {
			return config->hosts[i].path;
		}
	}
	return NULL;
}

char* get_mime_type(config_t* config, char* path) {
	char* type = default_mime;
	char* extension = strrchr(path, '.') + 1;
	if (extension == NULL) {
		return type;
	}
	int i;
	for(i = 0; i < config->mime_count; i++) {
		if (strcmp(config->mimes[i].extension, extension) == 0) {
			type = config->mimes[i].mime_type;
			return type;
		}
	}
	return type;
}

void print_config(config_t* config) {
	int i;
	printf("Config:\n");
	for (i = 0; i < config->host_count; i++) {
		printf("\tHost: %s --> %s\n", config->hosts[i].host, config->hosts[i].path);
	}
	printf("\n");
	for (i = 0; i < config->mime_count; i++) {
		printf("\tMedia: %s --> %s\n", config->mimes[i].extension, config->mimes[i].mime_type);
	}
	return;
}

