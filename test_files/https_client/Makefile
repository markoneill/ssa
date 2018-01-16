
normal:
	gcc -o https_client https_client.c

threaded:
	gcc -Wall -pthread -pg -o threaded_https_client threaded_client.c

clean_gprof:
	rm gmon.out
	rm analysis.txt