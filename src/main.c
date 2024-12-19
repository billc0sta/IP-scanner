#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#define CLOSE_SOCKET(s) closesocket(s)
#define SIN_ADDR sin_addr.S_un.S_addr 
#define GET_ERROR() WSAGetLastError()
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#define SOCKET int
#define CLOSE_SOCKET(s) close(s)
#define SIN_ADDR sin_addr.s_addr 
#define GET_ERROR() errno
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#define INET_ADDR(o1, o2, o3, o4) (htonl(o1 << 24 | o2 << 16 | o3 << 8 | o4))
#define TARGETS_LEN 100
#define TARGETS_TOTAL 100
#define TIMEOUT_SEC 5
#define TIMEOUT_USEC 0
#define ADDR_LEN 20
#define USAGE "Usage: scanner port [per-scan] [total-scan] [timeout-msec]\n" \
		      "port         - target port (1 - 65'535)\n" \
		      "per-scan     - how many IPs to ping per scan (1 - 10'000)\n" \
		      "total-scan   - how many IPs to scan in total (min 1)\n" \
		      "timeout-msec - ping timeout in milliseconds (min 1)"
#define MIN(a,b) ((a) < (b) ? a : b)

typedef uint32_t ipv4_t;
ipv4_t get_random_ip();
void rand_init(void);
uint32_t rand_next(void);
int scanner(uint16_t, int, int, long, long);

struct conn_info {
	SOCKET client_sockfd;
	struct sockaddr_in server_sockaddr;
	char address[ADDR_LEN];
	char connected;
};

int main(int argc, char** argv) {
	if (argc < 2) {
		printf(USAGE);
		return 1;
	}

	uint16_t port = 0;
	int      per_scan = TARGETS_LEN;
	int      total_scan = TARGETS_TOTAL;
	long     timeout_sec = TIMEOUT_SEC;
	long     timeout_usec = TIMEOUT_USEC;

	int p = strtol(argv[1], NULL, 10);
	if (p > 65535 || p < 1) {
		printf("invalid port\n");
		printf(USAGE);
		return 1;
	}
	port = p;

	if (argc >= 3) {
		p = strtol(argv[2], NULL, 10);
		if (p > 10000 || p < 1) {
			printf("invalid per-scan\n");
			printf(USAGE);
			return 1;
		}
		per_scan = p;
	}
	if (argc >= 4) {
		p = strtol(argv[3], NULL, 10);
		if (p < 1) {
			printf("invalid total-scan\n");
			printf(USAGE);
			return 1;
		}
		total_scan = p;
	}
	if (argc >= 5) {
		p = strtol(argv[4], NULL, 10);
		if (p < 1) {
			printf("invalid timeout-msec\n");
			printf(USAGE);
			return 1;
		}
		timeout_sec = 0;
		timeout_usec = p % 1000 * 1000;
		if (p >= 1000)
			timeout_sec = (p - timeout_usec / 1000) / 1000;
	}

	rand_init();

#ifdef _WIN32
	WSADATA data;
	int res;
	if ((res = WSAStartup(MAKEWORD(2, 2), &data)) != 0) {
		fprintf(stderr, "[main] WSAStartup() failed - %d\n", res);
		exit(1);
	}
#endif

	printf("port                    - %hu\n"
		"IPs per scan            - %d\n"
		"total to scan           - %d\n"
		"timeout in milliseconds - %ld\n--\n",
		port, per_scan, total_scan, timeout_sec * 1000 + timeout_usec / 1000);
	clock_t t0 = clock();
	int connected = scanner(port, per_scan, total_scan, timeout_sec, timeout_usec);
	clock_t t1 = clock() - t0;
	printf("total/replied - %d/%d\n"
		"time taken    - %.2fs", total_scan, connected, (float)t1 / CLOCKS_PER_SEC);

#ifdef _WIN32
	WSACleanup();
#endif
	return 0;
}

int scanner(uint16_t port, int per, int total, long timeout_sec, long timeout_usec) {
	int scanned = 0, connected = 0;
	struct conn_info* targets = calloc(per, sizeof(struct conn_info));
	if (!targets) {
		fprintf(stderr, "[scanner] calloc() failed\n");
		return -1;
	}
	while (scanned < total) {
		struct timeval timeout;
		timeout.tv_sec = timeout_sec;
		timeout.tv_usec = timeout_usec;
		size_t i;
		fd_set write;
		FD_ZERO(&write);
		const int count = MIN(per, total - scanned);
		scanned += count;
		for (i = 0; i < count; ++i) {
			struct conn_info* target = &targets[i];
			SOCKET sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#ifdef _WIN32
			int arg = 1;
			if (ioctlsocket(sockfd, FIONBIO, &arg) != 0) {
				fprintf(stderr, "[scanner] ioctlsocket() failed - %d\n", GET_ERROR());
				for (int i = 0; i < per; ++i)
					CLOSE_SOCKET(targets[i].client_sockfd);
				free(targets);
				return -1;
			}
#else
			if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK) != 0) {
				fprintf(stderr, "[scanner] fcntl() failed - %d\n", GET_ERROR());
				for (int i = 0; i < per; ++i)
					CLOSE_SOCKET(targets[i].client_sockfd);
				free(targets);
				return -1;
			}
#endif
			uint32_t random_ip = get_random_ip();
			struct sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			addr.SIN_ADDR = random_ip;
			target->server_sockaddr = addr;
			target->client_sockfd = sockfd;
			getnameinfo((struct sockaddr*)&addr, sizeof(addr), target->address, ADDR_LEN, NULL, 0, NI_NUMERICHOST);
			connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
		}
		FD_SET(targets[0].client_sockfd, &write);
		select((int)targets[0].client_sockfd + 1, NULL, &write, NULL, &timeout);
		timeout.tv_sec = 0;
		timeout.tv_usec = 0;
		for (i = 0; i < count; ++i) {
			struct conn_info* target = &targets[i];
			SOCKET sockfd = target->client_sockfd;
			FD_ZERO(&write);
			FD_SET(sockfd, &write);
			select((int)sockfd + 1, NULL, &write, NULL, &timeout);
			if (FD_ISSET(sockfd, &write)) {
				++connected;
				printf("%s\n", target->address);
			}
			CLOSE_SOCKET(sockfd);
		}
	}
	free(targets);
	return connected;
}

static uint32_t x, y, z, w;
void rand_init(void)
{
	x = (uint32_t)time(NULL);
	y = (uint32_t)time(NULL) ^ (uint32_t)time(NULL);
	z = clock();
	w = z ^ y;
}

uint32_t rand_next(void) //period 2^96-1
{
	uint32_t t = x;
	t ^= t << 11;
	t ^= t >> 8;
	x = y; y = z; z = w;
	w ^= w >> 19;
	w ^= t;
	return w;
}

ipv4_t get_random_ip() {
	uint32_t ip;
	uint8_t o1, o2, o3, o4;
	do {
		ip = rand_next();
		o1 = ip & 0xff;
		o2 = (ip >> 8) & 0xff;
		o3 = (ip >> 16) & 0xff;
		o4 = (ip >> 24) & 0xff;
	} while
		(o1 == 127                             // loop-back 
			|| o1 == 0                             // invalid address space
			|| o1 == 10				               // internal network
			|| o1 == 192 || o2 == 162              // internal network
			|| o1 == 172 || o2 >= 16 && o2 < 32    // internal network
			|| o1 == 100 || o2 >= 64 && o2 < 127   // IANA reserved
			|| o1 == 192 || o2 >= 254			   // IANA reserved
			|| o1 == 198 || o2 >= 18 && o2 < 20    // IANA special use
			);

	return INET_ADDR(o1, o2, o3, o4);
}

