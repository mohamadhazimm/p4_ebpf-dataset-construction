#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static void fail(const char *operation) {
    perror(operation);
    exit(1);
}

static void record(const char *event, const char *protocol, int source_port,
                   int destination_port, const char *value) {
    struct timespec realtime, monotonic;
    if (clock_gettime(CLOCK_REALTIME, &realtime) || clock_gettime(CLOCK_MONOTONIC, &monotonic))
        fail("clock");
    printf("%s,%ld,%s,10.0.0.10,%d,10.0.0.1,%d,%s,%lld,%lld\n", event,
           (long)getpid(), protocol, source_port, destination_port, value,
           (long long)realtime.tv_sec * 1000000000 + realtime.tv_nsec,
           (long long)monotonic.tv_sec * 1000000000 + monotonic.tv_nsec);
    fflush(stdout);
}

static int bound_socket(int type, int port) {
    int descriptor = socket(AF_INET, type, 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
    struct timeval timeout = {.tv_sec = 4, .tv_usec = 0};
    if (descriptor < 0 || inet_pton(AF_INET, "10.0.0.10", &address.sin_addr) != 1)
        fail("socket/address");
    if (setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
        bind(descriptor, (struct sockaddr *)&address, sizeof(address)))
        fail("socket setup");
    return descriptor;
}

int main(int argc, char **argv) {
    if (argc != 4 || strspn(argv[2], "abcdefghijklmnopqrstuvwxyz0123456789_") != strlen(argv[2]))
        return 2;
    int repeat = atoi(argv[3]);
    if (repeat < 1 || repeat > 2)
        return 2;
    printf("event,pid,protocol,source_ip,source_port,destination_ip,destination_port,value,realtime_ns,monotonic_ns\n");
    record("start", "none", 0, 0, argv[2]);
    if (!strcmp(argv[1], "null"))
        return 0;
    if (!strcmp(argv[1], "file")) {
        FILE *stream = fopen("pilot-file.bin", "wb");
        if (!stream)
            fail("file create");
        for (int iteration = 0; iteration < 128; iteration++)
            if (fprintf(stream, "%s\n", argv[2]) < 0)
                fail("file write");
        if (fclose(stream))
            fail("file close");
        record("file_written", "none", 0, 0, argv[2]);
        return 0;
    }
    if (strcmp(argv[1], "net"))
        return 2;
    int tcp_port = 65100 + repeat;
    int udp_port = 65200 + repeat;
    struct sockaddr_in destination = {.sin_family = AF_INET, .sin_port = htons(80)};
    if (inet_pton(AF_INET, "10.0.0.1", &destination.sin_addr) != 1)
        fail("destination");
    int descriptor = bound_socket(SOCK_STREAM, tcp_port);
    if (connect(descriptor, (struct sockaddr *)&destination, sizeof(destination)))
        fail("internal connect");
    struct sockaddr_in actual;
    socklen_t actual_size = sizeof(actual);
    if (getsockname(descriptor, (struct sockaddr *)&actual, &actual_size) ||
        actual.sin_port != htons(tcp_port) || actual.sin_addr.s_addr != inet_addr("10.0.0.10"))
        fail("actual endpoint");
    record("tcp_connected", "tcp", tcp_port, 80, argv[2]);
    char request[512];
    int length = snprintf(request, sizeof(request),
        "GET /attribution-%s HTTP/1.1\r\nHost: attribution.invalid\r\nConnection: close\r\n\r\n", argv[2]);
    if (length < 0 || (size_t)length >= sizeof(request))
        return 2;
    for (int written = 0; written < length;) {
        ssize_t count = send(descriptor, request + written, length - written, 0);
        if (count <= 0)
            fail("HTTP send");
        written += (int)count;
    }
    FILE *response = fopen("pilot-http-response.bin", "wb");
    if (!response)
        fail("response create");
    char buffer[4096];
    ssize_t received;
    size_t response_size = 0;
    while ((received = recv(descriptor, buffer, sizeof(buffer), 0)) > 0) {
        response_size += (size_t)received;
        if (response_size > 65536 || fwrite(buffer, 1, received, response) != (size_t)received)
            fail("bounded response write");
    }
    if (received < 0 || fclose(response) || close(descriptor) || response_size == 0)
        fail("HTTP receive/close");
    descriptor = bound_socket(SOCK_DGRAM, udp_port);
    destination.sin_port = htons(65003);
    record("udp_bound", "udp", udp_port, 65003, argv[2]);
    for (int sequence = 0; sequence < 6; sequence++) {
        length = snprintf(buffer, sizeof(buffer), "HAZIM_ATTR_%s_%03d", argv[2], sequence);
        if (sendto(descriptor, buffer, length, 0, (struct sockaddr *)&destination,
                   sizeof(destination)) != length)
            fail("internal UDP send");
        record("udp_sent", "udp", udp_port, 65003, buffer);
    }
    if (close(descriptor))
        fail("UDP close");
    record("done", "none", 0, 0, argv[2]);
    return 0;
}