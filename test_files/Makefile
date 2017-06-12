CC=gcc
CFLAGS=-I.

all: clientmake servermake tlsmake

clientmake: client.o
	$(CC) -o clientmake client.o $(CFLAGS)

servermake: server.o
	$(CC) -o servermake server.o $(CFLAGS)

tlsmake: tls.o
	$(CC) -o tlsmake tls.o $(CFLAGS)
