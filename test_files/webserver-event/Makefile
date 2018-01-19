CC = gcc
CCFLAGS = -Wall -g

HTTP_SERVER_SRC = main.c \
		http_server.c \
		client.c \
		config.c \
		utils.c

HTTP_SERVER_OBJ = $(HTTP_SERVER_SRC:%.c=%.o)
HTTP_SERVER_EXE = server

all: $(HTTP_SERVER_EXE)

$(HTTP_SERVER_EXE) : $(HTTP_SERVER_OBJ)
	$(CC) $(CCFLAGS) $^ -o $@ $(LIBS)

%.o : %.c %.h
	$(CC) $(CCFLAGS) -c $< -o $@

clean:
	rm -rf *.o $(HTTP_SERVER_EXE)
