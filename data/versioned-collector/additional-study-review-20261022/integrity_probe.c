/* Benign known-answer workload for the .19 collector integrity tests.
 *
 * Every mode does an exact, countable amount of work and prints one JSON receipt on stdout, so the validator can
 * compare what the program did against what the collector recorded:
 *   null    MARKER          nothing; no output (ambient-leak control)
 *   syscall MARKER N        N raw getppid calls (raw syscall id 110)
 *   threads MARKER T N      T threads, N raw getppid calls each
 *   udp     MARKER N        N sequence-marked UDP datagrams to isolated multicast 239.255.42.198:65003 on 10.0.0.10
 *   mixed   MARKER N K      N marked datagrams, K raw getppid calls after each
 *   http    MARKER N        N sequential HTTP/1.0 GETs to the internal Sink 10.0.0.1:80, one connection each
 * Destinations are numeric and limited to the isolated internal network; no name resolution is performed.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define GUEST "10.0.0.10"
#define SINK "10.0.0.1"
#define GROUP "239.255.42.198"
#define GROUP_PORT 65003
#define MAGIC "HZSEQ1"
#define MARKER_BYTES 16
#define MAX_THREADS 8

static long long monotonic_ns(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000000000LL + now.tv_nsec;
}

static long parse_count(const char *text, long low, long high) {
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno || !end || *end || value < low || value > high)
        exit(2);
    return value;
}

static void burst(long count) {
    for (long index = 0; index < count; index++)
        syscall(SYS_getppid);
}

struct worker {
    pthread_t thread;
    long count;
    long tid;
};

static void *work(void *argument) {
    struct worker *worker = argument;
    worker->tid = syscall(SYS_gettid);
    burst(worker->count);
    return NULL;
}

static int multicast_socket(struct sockaddr_in *group) {
    int descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct in_addr interface;
    unsigned char ttl = 1;
    memset(group, 0, sizeof(*group));
    group->sin_family = AF_INET;
    group->sin_port = htons(GROUP_PORT);
    if (descriptor < 0 || inet_pton(AF_INET, GROUP, &group->sin_addr) != 1
        || inet_pton(AF_INET, GUEST, &interface) != 1
        || setsockopt(descriptor, IPPROTO_IP, IP_MULTICAST_IF, &interface, sizeof(interface))
        || setsockopt(descriptor, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)))
        exit(1);
    return descriptor;
}

static long send_marked(int descriptor, struct sockaddr_in *group, const char *marker, uint64_t sequence) {
    unsigned char payload[sizeof(MAGIC) - 1 + MARKER_BYTES + 8];
    memset(payload, 0, sizeof(payload));
    memcpy(payload, MAGIC, sizeof(MAGIC) - 1);
    memcpy(payload + sizeof(MAGIC) - 1, marker, strlen(marker));
    for (int byte = 0; byte < 8; byte++)
        payload[sizeof(MAGIC) - 1 + MARKER_BYTES + byte] = (unsigned char)(sequence >> (56 - 8 * byte));
    return sendto(descriptor, payload, sizeof(payload), 0, (struct sockaddr *)group, sizeof(*group))
           == (ssize_t)sizeof(payload);
}

static int http_get(const char *marker, long index) {
    struct sockaddr_in sink = {.sin_family = AF_INET, .sin_port = htons(80)};
    struct timeval timeout = {.tv_sec = 3, .tv_usec = 0};
    char request[160], response[4096];
    size_t received = 0;
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (descriptor < 0 || inet_pton(AF_INET, SINK, &sink.sin_addr) != 1
        || setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))
        || setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))
        || connect(descriptor, (struct sockaddr *)&sink, sizeof(sink))) {
        if (descriptor >= 0)
            close(descriptor);
        return 0;
    }
    int length = snprintf(request, sizeof(request), "GET /hzint/%s/%ld HTTP/1.0\r\nHost: " SINK "\r\n\r\n",
                          marker, index);
    if (send(descriptor, request, (size_t)length, 0) != length) {
        close(descriptor);
        return 0;
    }
    for (;;) {
        ssize_t chunk = recv(descriptor, response + received, sizeof(response) - 1 - received, 0);
        if (chunk <= 0)
            break;
        received += (size_t)chunk;
        if (received == sizeof(response) - 1)
            break;
    }
    close(descriptor);
    response[received] = 0;
    return received > 12 && !strncmp(response, "HTTP/1.", 7) && !strncmp(response + 8, " 200", 4);
}

int main(int argc, char **argv) {
    if (argc < 3 || strlen(argv[2]) < 4 || strlen(argv[2]) > MARKER_BYTES
        || strspn(argv[2], "abcdefghijklmnopqrstuvwxyz0123456789") != strlen(argv[2]))
        return 2;
    const char *mode = argv[1], *marker = argv[2];
    long requested = 0, completed = 0, per_item = 0, threads = 0, tids[MAX_THREADS] = {0};
    long long started = monotonic_ns();
    if (!strcmp(mode, "null") && argc == 3) {
        return 0;
    } else if (!strcmp(mode, "syscall") && argc == 4) {
        requested = parse_count(argv[3], 1, 10000000);
        burst(requested);
        completed = requested;
    } else if (!strcmp(mode, "threads") && argc == 5) {
        threads = parse_count(argv[3], 1, MAX_THREADS);
        per_item = parse_count(argv[4], 1, 5000000);
        struct worker workers[MAX_THREADS];
        for (long index = 0; index < threads; index++) {
            workers[index].count = per_item;
            if (pthread_create(&workers[index].thread, NULL, work, &workers[index]))
                return 1;
        }
        for (long index = 0; index < threads; index++) {
            pthread_join(workers[index].thread, NULL);
            tids[index] = workers[index].tid;
        }
        requested = completed = threads * per_item;
    } else if ((!strcmp(mode, "udp") && argc == 4) || (!strcmp(mode, "mixed") && argc == 5)) {
        struct sockaddr_in group;
        int descriptor = multicast_socket(&group);
        requested = parse_count(argv[3], 1, 1000000);
        per_item = argc == 5 ? parse_count(argv[4], 0, 1000) : 0;
        for (long index = 0; index < requested; index++) {
            completed += send_marked(descriptor, &group, marker, (uint64_t)index);
            burst(per_item);
        }
        close(descriptor);
    } else if (!strcmp(mode, "http") && argc == 4) {
        requested = parse_count(argv[3], 1, 1000);
        for (long index = 0; index < requested; index++)
            completed += http_get(marker, index);
    } else {
        return 2;
    }
    long long ended = monotonic_ns();
    printf("{\"mode\":\"%s\",\"marker\":\"%s\",\"pid\":%ld,\"requested\":%ld,\"completed\":%ld,"
           "\"per_item_getppid\":%ld,\"threads\":%ld,\"tids\":[", mode, marker, (long)getpid(), requested,
           completed, per_item, threads);
    for (long index = 0; index < threads; index++)
        printf("%s%ld", index ? "," : "", tids[index]);
    printf("],\"started_monotonic_ns\":%lld,\"ended_monotonic_ns\":%lld}\n", started, ended);
    return completed == requested ? 0 : 1;
}
