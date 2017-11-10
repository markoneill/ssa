CC = gcc
CC_FLAGS = -w -g -Wall
 
EXEC = tests
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
INCLUDES = 
LIBS = 
 
# Main target
$(EXEC): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(EXEC) $(LIBS)
 
# To obtain object files
%.o: %.c
	$(CC) -c $(CC_FLAGS) $< $(INCLUDES) -o $@
 
# To remove generated files
clean:
	rm -f $(EXEC) $(OBJECTS)
