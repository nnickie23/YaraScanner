NAME = yaraScanner
CC = gcc

all:
	$(CC) main.c lib/cJSON.c lib/libyara.a -pthread -lssl -lcrypto -lm -o $(NAME)

clean:
	rm $(NAME)
