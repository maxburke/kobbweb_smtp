CC = gcc
CFLAGS = -g -Wextra -Wall -pedantic -Werror
LIBS = -lssl -lcurl
LDFLAGS = -g 
OBJ = kobbweb_smtp.o
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

kobbweb_smtp: $(OBJ)
	gcc -o $@ $^ $(LDFLAGS) $(LIBS)

.PHONY: clean
clean:
	rm -rf *.o kobbweb_smtp
