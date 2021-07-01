/* 
 * 2021 Spring EE323 Computer Network
 * Project #1 Socket Programming
 * Author: Heewon Yang
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define BUF_SIZE 10000000
#define OP_SIZE 1
#define SHIFT_SIZE 1
#define CHECKSUM_SIZE 2
#define LENGTH_SIZE 4
#define STRING_SIZE 8

int verbose = 0; /* Verbose flag */
char host[30] = "\0"; /* IP address */
int port = -1; /* Port number */
int type = -1; /* Type of Operation */
int shift = -1; /* Shift */

int parse_cmd(int argc, char **argv)
{
	char opt;
	while ((opt = getopt(argc, argv, "h:p:o:s:v")) != -1) {
		switch (opt) {
			case 'h':
            			strcpy(host, optarg);
            			break;
        		case 'p':
            			port = atoi(optarg);
            			if ((port < 0) || (port > 65535)) {
                			fprintf(stderr,"Invalid port number: %d\n", port);
                			return -1;
            			}
            			break;
        		case 'o':
				type = atoi(optarg);
				if ((type != 0) && (type != 1)) {
					fprintf(stderr, "Invalid operation type: %d\n", type);
					return -1;
				}
				break;
        		case 's':
            			shift = atoi(optarg);
				if (shift < 0) {
					fprintf(stderr, "Invalid shift number: %d\n", shift);
					return -1;
				}
            			break;
			case 'v':
	    			verbose = 1;
	    			break;
        		default:
            			fprintf(stderr, "usage: -%c [-h host] [-p port] [-o operation] [-s shift]\n", optopt);
            			return -1;
		}
	}
	return 0;
}

/* Retrieved from "https://locklessinc.com/articles/tcp_checksum/" */
unsigned short checksum2(const char *buf, unsigned size)
{
	unsigned long long sum = 0;
	const unsigned long long *b = (unsigned long long *) buf;

	unsigned t1, t2;
	unsigned short t3, t4;

	/* Main loop - 8 bytes at a time */
	while (size >= sizeof(unsigned long long)) {
		unsigned long long s = *b++;
		sum += s;
		if (sum < s) sum++;
		size -= 8;
	}

	/* Handle tail less than 8-bytes long */
	buf = (const char *) b;
	if (size & 4) {
		unsigned s = *(unsigned *) buf;
		sum += s;
		if (sum < s) sum++;
		buf += 4;
	}
	
	if (size & 2) {
		unsigned short s = *(unsigned short *) buf;
		sum += s;
		if (sum < s) sum++;
		buf += 2;
	}

	if (size) {
		unsigned char s = *(unsigned char*) buf;
		sum += s;
		if (sum < s) sum++;
	}

	/* Fold down to 16 bits */
	t1 = sum;
	t2 = sum >> 32;
	t1 += t2;
	if (t1 < t2) t1++;
	t3 = t1;
	t4 = t1 >> 16;
	t3 += t4;
	if (t3 < t4) t3++;

	return ~t3;
}

/*
 * Adapted Robust I/O functions
 * from Computer Systems: A Programmer's Perspective (3rd ed) on chapter 10
 * "http://csapp.cs.cmu.edu/3e/ics3/code/src/csapp.c"
 * and sendall function from Beej's Guide to Network Programming on chapter 7
 * "https://beej.us/guide/bgnet/html//index.html#byte-order"
 */
/* Robustly read maximum n bytes */
ssize_t read_packet(int sockfd, void *buf, size_t n)
{
    	size_t nleft = n;
    	ssize_t nread;
    	char *bufp = buf;

    	while (nleft > 0) {
		if ((nread = read(sockfd, bufp, nleft)) < 0) {
			if (errno == EINTR) { /* interrupted by sig handler return */
	    			nread = 0;        /* and call read() again */
			}
			else {
				return -1;        /* errno set by read() */
			}
	   	}
	    	else if (nread == 0) {
			break;                /* EOF */
	    	}
	    	nleft -= nread;
	    	bufp += nread;
    	}
    	return (n - nleft);
}

/* Robustly write maximum n bytes */
ssize_t write_packet(int sockfd, void *buf, size_t n)
{
	if (n == 0) { return 0; }
    
   	size_t nleft = n;
    	ssize_t nwritten;
    	char *bufp = buf;

    	while (nleft > 0) {
        	if ((nwritten = write(sockfd, bufp, nleft)) <= 0) {
            		if (errno == EINTR) { /* interrupted by sig handler return */
                		nwritten = 0;     /* and call write() again */
            		}
            		else {
                		return -1;        /* errno set by write() */
            		}
        	}
        	nleft -= nwritten;
        	bufp += nwritten;
    	}
    	return nwritten;
}

int hosttoip(char *host, char *ip)
{
	struct hostent *h;
	struct in_addr **addr_list;
	int i;

	if ((h = gethostbyname(host)) == NULL) {
		herror("gethostbyname");
		return 1;
	}
	
	addr_list = (struct in_addr **) h->h_addr_list;

	for (i = 0; addr_list[i] != NULL; i++) {
		strcpy(ip, inet_ntoa(*addr_list[i]));
		return 0;
	}
	return 1;
}

int main(int argc, char **argv)
{
	uint8_t op; // operation type variable
	uint8_t sh; // shift number variable
	uint16_t cs, rcs; // checksum variable
	uint32_t l; // length variable
	int sockfd;
	char ip[16];
	struct sockaddr_in sa;
	unsigned char *msg;
	unsigned char *buf;
	unsigned char *rec;
	int buf_len = 0;
	int cnt = 0;

	parse_cmd(argc, argv);

	if ((host[0] == '\0') || (port == -1) || (type == -1) || (shift == -1)) {
		fprintf(stderr, "Missing arguments\n");
		return -1;
	}

	op = (uint8_t) type;
	sh = (uint8_t) shift;

	msg = (unsigned char *)calloc(BUF_SIZE, sizeof(unsigned char)); // whole message sending to the server
	buf = (unsigned char *)calloc(BUF_SIZE - 8, sizeof(unsigned char)); // only 'string' field
	rec = (unsigned char *)calloc(BUF_SIZE, sizeof(unsigned char)); // whole message received from the server

	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Socket creation error\n");
        	exit(1);
	}

	// if host is not IP address, convert it to IP adress by hosttoip function
	if (isalpha(host[0]) != 0) {
		hosttoip(host, ip);
	}
	else {
		strcpy(ip, host);
	}
	fprintf(stderr, "host: %s, port: %d, operation type: %d, shift number: %d\n", ip, port, type, shift);

	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = inet_addr(ip);

	if (connect(sockfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		fprintf(stderr, "Connection error\n");
        	return -1;
	}
	else { fprintf(stderr, "Connection success\n"); }

	while (1) {
		cnt++;
		fprintf(stderr, "---Stage %d---\n", cnt);

		if (fread(buf, 1, BUF_SIZE - 8, stdin) <= 0) { // EOF
		//	fprintf(stderr, "EOF\n");
			break; 
		}
		buf_len = strlen((const char*) buf);
		l = htonl((uint32_t)(buf_len + 8));

		memcpy(msg, &op, OP_SIZE);
		memcpy(msg + SHIFT_SIZE, &sh, SHIFT_SIZE);
		memcpy(msg + LENGTH_SIZE, &l, LENGTH_SIZE);
		memcpy(msg + STRING_SIZE, buf, buf_len);

		cs = checksum2((const char*) msg, ntohl(l));
		memcpy(msg + CHECKSUM_SIZE, &cs, CHECKSUM_SIZE);
		fprintf(stderr, "message 4byte : %x\n", *(uint32_t *)msg);
	        fprintf(stderr, "message 8byte : %x\n", *(uint32_t *)(msg + 4));
		//fprintf(stderr, "message 12byte : %s\n", msg + 8);

		write_packet(sockfd, msg, ntohl(l)); // sends a protocol message to the server
		fprintf(stderr, "Sending a message to server...\n");

		memset(msg, 0, BUF_SIZE); // initialize message
        	read_packet(sockfd, rec, ntohl(l)); // receives a reply from the server
		fprintf(stderr, "Receiving a reply from the server...\n");
		fprintf(stderr, "message 4byte : %x\n", *(uint32_t *)rec);
		fprintf(stderr, "message 8byte : %x\n", *(uint32_t *)rec + 4);
		//fprintf(stderr, "message 12byte : %s\n", rec + 8);

		rcs = checksum2((const char*) rec, ntohl(l));
		if (rcs != 0) {
			fprintf(stderr, "Invalid checksum: %u\n", rcs);
			break;
		}
		fprintf(stdout, "%s", rec + 8); // only print resulting string to stdout
		fprintf(stderr, "Printing out the result on stdout...\n");

		memset(msg, 0, BUF_SIZE);
		memset(buf, 0, BUF_SIZE - 8);
        	memset(rec, 0, BUF_SIZE);
	}

	close(sockfd);
	return 0;
}
