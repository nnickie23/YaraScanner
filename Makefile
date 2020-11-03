NAME = yaraScanner
CC = gcc

all:
	$(CC) dir_yara_scanner.c cJSON.c libyara.a -pthread -lssl -lcrypto -lm -o $(NAME)

clean:
	rm $(NAME)
