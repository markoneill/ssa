CC=gcc
CFLAGS=-I.

all: tls_set_fuzz

clientmake: client.o
	$(CC) -o clientmake client.o $(CFLAGS)

servermake: server.o
	$(CC) -o servermake server.o $(CFLAGS)

tls_set_fuzz: tls_set_test.o
	$(CC) -o tls_set_fuzz tls_set_test.o $(CFLAGS)
