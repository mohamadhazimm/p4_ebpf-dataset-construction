/* Benign micro-benchmark for the socket-ownership check: COUNT datagrams of 64 B on one
 * unconnected UDP socket (sendto, so the closed port's ICMP errors are not returned) to DST:PORT (the
 * isolated Sink), timed with CLOCK_MONOTONIC. Every datagram has the same 5-tuple. Prints one JSON line.
 *   udp_send_bench DST PORT COUNT LABEL */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static long long now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
	struct sockaddr_in dst;
	char payload[64];
	long count, i, failed = 0;
	long long start, end;
	int s;

	if (argc != 5) {
		fprintf(stderr, "usage: udp_send_bench DST PORT COUNT LABEL\n");
		return 2;
	}
	count = atol(argv[3]);
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port = htons((unsigned short)atoi(argv[2]));
	if (inet_pton(AF_INET, argv[1], &dst.sin_addr) != 1 || count <= 0)
		return 2;
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return 1;
	memset(payload, 'b', sizeof(payload));
	start = now_ns();
	for (i = 0; i < count; i++)
		if (sendto(s, payload, sizeof(payload), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
			failed++;
	end = now_ns();
	close(s);
	printf("{\"label\": \"%s\", \"count\": %ld, \"failed\": %ld, \"ns_total\": %lld, \"ns_per_send\": %.1f}\n",
	       argv[4], count, failed, end - start, (double)(end - start) / (double)count);
	return 0;
}
