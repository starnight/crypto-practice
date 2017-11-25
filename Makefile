PROJ=crypto_test
CC=cc
DEF=-D_EVP_AES_MODE_
CFLAGS=-O0 -Wall -lcrypto $(DEF)
SRCS=$(PROJ).c

all:
	$(CC) $(SRCS) $(CFLAGS) -o $(PROJ)

test:
	./$(PROJ)

clean:
	rm -rf *.o $(PROJ)
