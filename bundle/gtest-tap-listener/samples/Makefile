# This is a sample file for running Google Test with TAP Listener

GTEST_DIR=/opt/googletest

NAME=gtest-tap-listener-samples
LIBS=/usr/local/lib/libgtest.a
CC=g++
CFLAGS=-I$(GTEST_DIR) -I$(GTEST_DIR)/include -fprofile-arcs -ftest-coverage

debug: all
run-debug: 
	./${NAME}
	
all: clean ${NAME}.o
	
compile: $(NAME).o

clean:
	rm -rf *.o $(NAME) *.tap *.gcno *.gcda *.xml
	
$(NAME).o: src/gtest_main.cc src/gtest_testHelloWorld.cc
	$(CC) $(CFLAGS) src/gtest_main.cc src/gtest_testHelloWorld.cc $(LIBS) -lpthread -lgcov -o $(NAME)
	
run: clean compile
	./$(NAME); ls -la *.tap
