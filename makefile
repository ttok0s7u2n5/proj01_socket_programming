all: make1 make2

make1: client.c
	gcc -g -Wall -o client client.c

make2: server.c
	gcc -g -Wall -o server server.c

clean:
	rm client
	rm server

