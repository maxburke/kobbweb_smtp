CC = clang
CFLAGS = -g -Wextra -Wall -pedantic -Werror
LIBS = -lssl -lcrypto -lcurl
LDFLAGS = -g 
OBJ = kobbweb_smtp.o
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

kobbweb_smtp: $(OBJ)
	clang -o $@ $^ $(LDFLAGS) $(LIBS)

.PHONY: clean
clean:
	rm -rf *.o kobbweb_smtp
