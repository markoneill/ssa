#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main(){
	static char *tor_argv[]={"--RunAsDaemon 1", "--quiet", "--ignore-missing-torrc", NULL};
	int err;
//	int fp;

//	fp = open("/home/kerneldev/Documents/tls_kernel/tor_reroute/tor_out.log", O_RDWR | O_APPEND | O_CREAT, 0777);
//	if (fp < 0)	return 1;

//	close(0);
//	if (dup2(fp, 1) < 0)	return 1;
//	if (dup2(fp, 2) < 0)	return 1;
	err = execv("/usr/bin/tor", tor_argv);
//	err = execv("/home/kerneldev/Documents/tls_kernel/tor_reroute/looper", tor_argv);
}
