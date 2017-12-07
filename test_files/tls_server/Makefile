CC = gcc
CC_FLAGS = -w -g -Wall -O3
 
EXEC = test_server
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
INCLUDES = 
LIBS = -lcrypto -lssl  
 
# Main target
$(EXEC): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(EXEC) $(LIBS)
 
# To obtain object files
%.o: %.c
	$(CC) -c $(CC_FLAGS) $< $(INCLUDES) -o $@
 
# To remove generated files
clean:
	rm -f $(EXEC) $(OBJECTS)
