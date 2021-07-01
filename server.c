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
#include <assert.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define BUF_SIZE 10000000
#define BACKLOG 10
#define ENCRYPT 0
#define DECRYPT 1
#define OP_SIZE 1
#define SHIFT_SIZE 1
#define CHECKSUM_SIZE 2
#define LENGTH_SIZE 4
#define STRING_SIZE 8

int verbose = 0; /* Verbose flag */
int port = -1; /* Port number */

int parse_cmd(int argc, char **argv)
{
	char opt;
	while ((opt = getopt(argc, argv, "p:v")) != -1) {
		switch (opt) {
        		case 'p':
            			port = atoi(optarg);
            			if ((port < 0) || (port > 65535)) {
                			fprintf(stderr,"Invalid port number: %d\n", port);
                			return -1;
            			}
            			break;
			case 'v':
	    			verbose = 1;
	    			break;
        		default:
            			fprintf(stderr, "usage: -%c [-p port]\n", optopt);
            			return -1;
		}
	}
	return 0;
}
/*
unsigned short checksum(uint8_t op, uint8_t shift, uint32_t length, const char *buf)
{
	int buf_len = ntohl(length) - 8;
	uint32_t i = 0;
	uint8_t sum = 0;

	sum += ((op & 0xff) << 8) + (shift &0xff);
	sum += (((length >> 24) & 0xff) << 8) + ((length >> 16) & 0xff);
	sum += (((length >> 8) & 0xff) << 8) +
*/

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
int read_packet(int sockfd, unsigned char *buf, size_t n)
{
	if (n == 0) { return n; }

	size_t nleft = n;
	size_t nread;
	size_t totalread = 0;
	//char *bufp = buf;

    	while (nleft > 0) {
		if ((nread = (size_t) read(sockfd, buf + totalread, nleft)) < 0) {
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
	    	totalread += nread;
    	}
    	return totalread;
}

/* Robustly write maximum n bytes */
int write_packet(int sockfd, unsigned char *buf, size_t n)
{
	if (n == 0) { return n;}

   	size_t nleft = n;
    	size_t nwritten;
    	size_t totalwrote = 0;
	//char *bufp = buf;

    	while (nleft > 0) {
        	if ((nwritten = (size_t) write(sockfd, buf + totalwrote, nleft)) <= 0) {
            		if (errno == EINTR) { /* interrupted by sig handler return */
                		nwritten = 0;     /* and call write() again */
            		}
            		else {
                		return -1;        /* errno set by write() */
            		}
        	}
        	nleft -= nwritten;
        	totalwrote += nwritten;
    	}
    	return totalwrote;
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

/* Adapted the code to handle SIGCHLD from "https://stackoverflow.com/questions/7171722/how-can-i-handle-sigchld" */
/* Handler for SIGCHLD that calls waitpid for reap all the zombie processes */
static void sigchld_handler(int sig)
{
	pid_t pid;
	int status;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {}
}
/* Register the SIGCHLD handler */
static void register_handler(void)
{
	struct sigaction sa;
	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &sa, 0) == -1) {
		perror(0);
		exit(1);
	}
}

static void caesar_cipher(unsigned char *new, unsigned char *buf, uint8_t op, uint8_t sh, uint32_t l)
{
	int shift;
	int len, i;
	len = ntohl(l);

	shift = sh % ('z' - 'a' + 1);

	for (i = 0; i < len; i++) {
		//j = i + 8;
		unsigned char prev = buf[i];
		if (isalpha(prev)) {
			int curr; // modified character
			if (op == ENCRYPT) {
				curr = tolower(prev) + shift;
				if (curr > 'z') {
					curr -= 26;
				}
				memcpy(new + i, &curr, 1);
			}
			else if (op == DECRYPT) {
				//shift = 26 - shift;
				curr = tolower(prev) - shift;
				if (curr < 'a') {
				       curr += 26;
				}	       
				memcpy(new + i, &curr, 1);
			}
			else {
				fprintf(stderr, "Invalid operation type: %d\n", op);
				exit(1);
			}
		}
		else {
			memcpy(new + i, &prev, 1);
		}
	}
}

int main(int argc, char **argv)
{
	uint8_t op; // operation type variable
	uint8_t sh; // shift number variable
	uint16_t cs, rcs; // checksum variable
	uint32_t l; // length variable
	int sockfd, connfd; // listen on sockfd, new connection on connfd 
	struct sockaddr_in sa; // server address
	struct sockaddr_in ca; // client address
	socklen_t sin_size;
	unsigned char *msg;
	//unsigned char *snd;
	unsigned char *buf;
	unsigned char *new;
	int msg_len;
	int buf_len = 0;
	int new_len = 0;
	int pid;
	int cnt = 0;
	int ccnt = 0;

	parse_cmd(argc, argv);
	
	if (port == -1) {
		fprintf(stderr, "Missing argument\n");
		return -1;
	}

	register_handler();

	msg = (unsigned char *)calloc(BUF_SIZE, sizeof(unsigned char)); // whole message received from the client
	//snd = (unsigned char *)calloc(BUF_SIZE, sizeof(unsigned char)); // whole message sending to the client
	buf = (unsigned char *)calloc(BUF_SIZE - 8, sizeof(unsigned char)); // original string
	new = (unsigned char *)calloc(BUF_SIZE - 8, sizeof(unsigned char)); // modified string

	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Socket creation error\n");
        	exit(1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	sin_size = sizeof(ca);

	if (bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		fprintf(stderr, "Bind error\n");
        	return -1;
	}
	
	if (listen(sockfd, BACKLOG) < 0) {
		fprintf(stderr, "Listen error\n");
		return -1;
	}

	while (1) {
		if ((connfd = accept(sockfd, (struct sockaddr *)&ca, &sin_size)) < 0) {
			fprintf(stderr, "Accept error\n");
			return -1;
		}

		if ((pid = fork()) == 0) { // child process
			cnt++;
			while (1) {
				ccnt++;
				fprintf(stderr, "---Stage %d in %dth child process---\n", ccnt, cnt);
				msg_len = read_packet(connfd, msg, 8); // read header first
				fprintf(stderr, "Receiving a header from client...\n");
				if (msg_len == 0) {
					fprintf(stderr, "End of File\n");
					//close(connfd);
					return -1;
				}
				else if (msg_len < 0) {
					fprintf(stderr, "Socket read failed\n");
					exit(-1);
				}
				else if (msg_len < 8) {
					fprintf(stderr, "Malformed header\n");
					close(connfd);
					exit(-1);
				}
				fprintf(stderr, "message 4byte: %x\n", *(uint32_t *)msg);
				fprintf(stderr, "message 8byte: %x\n", *(uint32_t *)(msg + 4));

				memcpy(&op, msg, OP_SIZE);
				memcpy(&sh, msg + SHIFT_SIZE, SHIFT_SIZE);
				memcpy(&cs, msg + CHECKSUM_SIZE, CHECKSUM_SIZE);
				memcpy(&l, msg + LENGTH_SIZE, LENGTH_SIZE);

				buf_len = read_packet(connfd, buf, ntohl(l) - 8); // read buf next
				fprintf(stderr, "Receiving a string from client...\n");
				if (buf_len < (ntohl(l) - 8)) {
					fprintf(stderr, "Wrong message length: %d bytes expected but %d bytes received\n", ntohl(l) - 8, msg_len);
exit(-1);
				}
				memcpy(msg + STRING_SIZE, buf, buf_len);

				cs = checksum2((const char*) msg, ntohl(l));
				if (cs != 0) {
					fprintf(stderr, "Invalid checksum\n");
					exit(-1);
				}
				
				caesar_cipher(new, buf, op, sh, l);
				fprintf(stderr, "Doing caesar cipher shift...\n");
				new_len = strlen((const char*) new);
				
				memset(msg, 0, BUF_SIZE); // initialize message
				l = htonl(new_len + 8);
				memcpy(msg, &op, OP_SIZE);
				memcpy(msg + SHIFT_SIZE, &sh, SHIFT_SIZE);
				memset(msg + CHECKSUM_SIZE, 0, CHECKSUM_SIZE);
				memcpy(msg + LENGTH_SIZE, &l, LENGTH_SIZE);
				memcpy(msg + STRING_SIZE, new, new_len);
				
				rcs = checksum2((const char*) msg, ntohl(l));
				memcpy(msg + CHECKSUM_SIZE, &rcs, CHECKSUM_SIZE);

				fprintf(stderr, "message 4byte: %x\n", *(uint32_t *)msg);
				fprintf(stderr, "message 8byte: %x\n", *(uint32_t *)(msg + 4));
			
				write(connfd, msg, ntohl(l));
				fprintf(stderr, "Sending new message to client...\n");

				memset(msg, 0, BUF_SIZE);
				memset(buf, 0, BUF_SIZE - 8);
				memset(new, 0, BUF_SIZE - 8);
			}
		}
		else if (pid > 0) { // parent process - do nothing 
		}
		else { // fork error
			fprintf(stderr, "Fork error\n");
			close(connfd);
			return -1;
		}
		close(connfd);
	}
	close(sockfd);
	return 0;
}
