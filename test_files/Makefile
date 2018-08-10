CC = gcc
CC_FLAGS = -w -g -Wall -O3
 
EXEC = all
PASS_TEST = passfd_client
PASS_TEST_SRC = passfd_client.c
PASS_TEST_OBJ = $(PASS_TEST_SRC:.c=.o)

TESTS = tests
TESTS_SRC = tests.c
TESTS_OBJ = $(TESTS_SRC:.c=.o)

SOURCES_ALL = $(wildcard *.c)
SOURCES_GEN = $(filter-out $(wildcard *.t.c),$(SOURCES_ALL))
OBJECTS_ALL = $(SOURCES_ALL:.c=.o)
OBJECTS_GEN = $(SOURCES_GEN:.c=.o)
INCLUDES = 
LIBS = -lcrypto -lssl  
 
# Main target
$(EXEC): $(TESTS) $(PASS_TEST)

$(TESTS) : $(TESTS_OBJ)	$(OBJECTS_GEN)
	$(CC) $(OBJECTS_GEN) $(TESTS_OBJ) -o $(TESTS) $(LIBS)

$(PASS_TEST) : $(PASS_TEST_OBJ) $(OBJECTS_GEN)
	$(CC) $(OBJECTS_GEN) $(PASS_TEST_OBJ) -o $(PASS_TEST) $(LIBS)
 
# To obtain object files
%.o: %.c
	$(CC) -c $(CC_FLAGS) $< $(INCLUDES) -o $@
 
# To remove generated files
clean:
	rm -f $(EXEC) $(OBJECTS)
