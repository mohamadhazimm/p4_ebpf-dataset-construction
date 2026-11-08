#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

struct socket_identity {
    int descriptor;
    uint64_t inode;
    uint64_t cookie;
    unsigned int port;
};

static void require(int accepted, const char *operation)
{
    if (!accepted) {
        fprintf(stderr, "%s: %s\n", operation, strerror(errno));
        exit(1);
    }
}

static uint64_t monotonic_ns(void)
{
    struct timespec observed;
    require(clock_gettime(CLOCK_MONOTONIC, &observed) == 0, "clock_gettime");
    return (uint64_t)observed.tv_sec * UINT64_C(1000000000) + observed.tv_nsec;
}

static struct socket_identity create_socket(void)
{
    struct socket_identity identity = {0};
    struct sockaddr_in address = {.sin_family = AF_INET,
                                 .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct stat metadata;
    struct timeval timeout = {.tv_sec = 2};
    socklen_t address_size = sizeof(address);
    socklen_t cookie_size = sizeof(identity.cookie);
    identity.descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(identity.descriptor >= 0, "socket");
    require(bind(identity.descriptor, (struct sockaddr *)&address, sizeof(address)) == 0, "bind");
    require(setsockopt(identity.descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "receive timeout");
    require(setsockopt(identity.descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0, "send timeout");
    require(getsockname(identity.descriptor, (struct sockaddr *)&address, &address_size) == 0, "getsockname");
    require(address_size == sizeof(address) && address.sin_family == AF_INET &&
            address.sin_addr.s_addr == htonl(INADDR_LOOPBACK), "actual loopback endpoint");
    require(fstat(identity.descriptor, &metadata) == 0 && S_ISSOCK(metadata.st_mode), "socket inode");
    require(getsockopt(identity.descriptor, SOL_SOCKET, SO_COOKIE, &identity.cookie, &cookie_size) == 0 &&
            cookie_size == sizeof(identity.cookie) && identity.cookie != 0, "socket cookie");
    require(fcntl(identity.descriptor, F_GETFD) == FD_CLOEXEC, "actual descriptor flags");
    identity.inode = metadata.st_ino;
    identity.port = ntohs(address.sin_port);
    return identity;
}

static void exchange(struct socket_identity sender, struct socket_identity receiver, const char *marker)
{
    struct sockaddr_in target = {.sin_family = AF_INET,
                                .sin_port = htons(receiver.port),
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct sockaddr_in source = {0};
    socklen_t source_size = sizeof(source);
    char observed[64];
    size_t length = strlen(marker);
    require(syscall(SYS_sendto, sender.descriptor, marker, length, 0, (struct sockaddr *)&target, sizeof(target)) == (ssize_t)length, "sendto");
    require(syscall(SYS_recvfrom, receiver.descriptor, observed, sizeof(observed), 0, (struct sockaddr *)&source, &source_size) == (ssize_t)length &&
            memcmp(observed, marker, length) == 0, "exact received marker");
    require(source_size == sizeof(source) && source.sin_family == AF_INET &&
            source.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && ntohs(source.sin_port) == sender.port,
            "actual receive peer");
}

static void write_identity(FILE *output, const char *name, struct socket_identity identity)
{
    require(fprintf(output, "\"%s\":{\"fd\":%d,\"inode\":%" PRIu64
                    ",\"cookie\":%" PRIu64 ",\"local_endpoint\":[\"127.0.0.1\",%u]}",
                    name, identity.descriptor, identity.inode, identity.cookie, identity.port) > 0,
            "write socket identity");
}

int main(int argument_count, char **arguments)
{
    require(argument_count == 2 && sizeof(void *) == 4, "native 32-bit invocation");
    int descriptor = open(arguments[1], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    require(descriptor >= 0, "exclusive receipt");
    FILE *output = fdopen(descriptor, "w");
    require(output != NULL, "receipt stream");
    uint64_t beginning = monotonic_ns();
    struct socket_identity server = create_socket();
    struct socket_identity client = create_socket();
    const char *markers[] = {"HAZIM_I386_A", "HAZIM_I386_B"};
    for (size_t index = 0; index < sizeof(markers) / sizeof(markers[0]); index++) {
        exchange(client, server, markers[index]);
        exchange(server, client, markers[index]);
    }
    require(close(client.descriptor) == 0, "client close");
    require(close(server.descriptor) == 0, "server close");
    uint64_t ending = monotonic_ns();
    require(fprintf(output, "{\"transport\":\"i386-exec\",\"status\":\"accepted\",\"pid\":%ld,"
                    "\"pointer_bits\":32,\"begin_monotonic_ns\":%" PRIu64
                    ",\"end_monotonic_ns\":%" PRIu64 ",", (long)getpid(), beginning, ending) > 0,
            "write receipt");
    write_identity(output, "server_identity", server);
    require(fputc(',', output) != EOF, "receipt separator");
    write_identity(output, "client_identity", client);
    require(fputs(",\"messages_received_and_echoed\":[\"HAZIM_I386_A\",\"HAZIM_I386_B\"]}\n", output) >= 0,
            "write application echoes");
    require(fclose(output) == 0, "close receipt");
    return 0;
}