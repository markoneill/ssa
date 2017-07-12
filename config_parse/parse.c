#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct options {
	char *name;
	char **value;
	unsigned int val_count;
} options;

int main()
{
	char *line;
	FILE *fp;
	ssize_t read;
	size_t len;
	char *first;
	char *tmp;
	int line_count;
	unsigned int i;
	options *opt_arr;

	line = NULL;
	len = 0;
	first = NULL;
	tmp = NULL;
	fp = fopen("test.config", "r");
	line_count = 0;

	while((read = getline(&line, &len, fp)) != -1){
		line_count++;
	}

	fseek(fp, 0, SEEK_SET);
	opt_arr = malloc(line_count * sizeof(options));

	for (i = 0; i < line_count; i++){		
		char *hold;
		int cur_len;
		int print_me;	
		int len_tmp;
		unsigned int opt_count;
		unsigned int j;

		if ((read = getline(&line, &len, fp)) == -1){
			break;
		}

		cur_len = 0;
		opt_count = 0; 

		tmp = malloc (read);

		while(sscanf(line + cur_len, "%[^: \n]%n", tmp, &len_tmp) != EOF){
			opt_count++;
			cur_len += (len_tmp + 1);
		}

		cur_len = 0;
		opt_arr[i].value = malloc(opt_count * sizeof(char *));
		
		for (j = 0; j < opt_count; j++){

			if (sscanf(line + cur_len, "%[^: \n]%n", tmp, &len_tmp) == EOF){
				break;
			}

			cur_len += (len_tmp + 1);

			if (j == 0){
				opt_arr[i].name = malloc(len_tmp + 1);
				strcpy(opt_arr[i].name, tmp);
				opt_arr[i].val_count = opt_count;
				continue;
			}

			opt_arr[i].value[j - 1] = malloc(len_tmp + 1);
			strcpy(opt_arr[i].value[j - 1], tmp);		
		}
		  
	}      

	fclose(fp);

	if(tmp){
		free(tmp);
	}

	if(line){
		free(line);
	}

	unsigned int n;
	unsigned int m;
	for (n = 0; n < line_count; n++){
		printf("%s", opt_arr[n].name);
		for (m = 0; m < opt_arr[n].val_count - 1; m++){
			printf("\t%s", opt_arr[n].value[m]);
		} 	
		printf("\n");
	}

	return 0;
}
