#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void require(int valid, const char *operation)
{
    if (!valid) {
        fprintf(stderr, "%s: %s\n", operation, strerror(errno));
        exit(1);
    }
}

static void file_task(void)
{
    unsigned char expected[65536], observed[65536];
    for (size_t offset = 0; offset < sizeof(expected); offset++)
        expected[offset] = (unsigned char)((offset * 37 + 11) % 251);
    FILE *stream = fopen("roundtrip.bin", "wbx");
    require(stream != NULL, "exclusive owned file");
    for (int block = 0; block < 256; block++)
        require(fwrite(expected, 1, sizeof(expected), stream) == sizeof(expected), "owned data write");
    require(fclose(stream) == 0, "writer close");
    stream = fopen("roundtrip.bin", "rb");
    require(stream != NULL, "owned file read");
    for (int block = 0; block < 256; block++)
        require(fread(observed, 1, sizeof(observed), stream) == sizeof(observed) &&
                memcmp(observed, expected, sizeof(observed)) == 0, "exact roundtrip bytes");
    require(fgetc(stream) == EOF && !ferror(stream) && fclose(stream) == 0, "exact file length");
}

static int local_socket(struct sockaddr_in *address)
{
    int descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct timeval timeout = {.tv_sec = 2};
    socklen_t size = sizeof(*address);
    *address = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    require(descriptor >= 0, "UDP socket");
    require(setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
            setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0, "socket bounds");
    require(bind(descriptor, (struct sockaddr *)address, sizeof(*address)) == 0 &&
            getsockname(descriptor, (struct sockaddr *)address, &size) == 0 && size == sizeof(*address) &&
            address->sin_family == AF_INET && address->sin_addr.s_addr == htonl(INADDR_LOOPBACK), "owned loopback endpoint");
    return descriptor;
}

static void network_task(void)
{
    struct sockaddr_in server_address, client_address, source;
    int server = local_socket(&server_address), client = local_socket(&client_address);
    unsigned char expected[256], received[256];
    for (int sequence = 0; sequence < 64; sequence++) {
        for (size_t offset = 0; offset < sizeof(expected); offset++)
            expected[offset] = (unsigned char)((sequence * 7 + offset * 13) % 251);
        socklen_t size = sizeof(source);
        require(sendto(client, expected, sizeof(expected), 0, (struct sockaddr *)&server_address, sizeof(server_address)) == sizeof(expected), "UDP send");
        require(recvfrom(server, received, sizeof(received), 0, (struct sockaddr *)&source, &size) == sizeof(received) &&
                size == sizeof(source) && source.sin_addr.s_addr == client_address.sin_addr.s_addr &&
                source.sin_port == client_address.sin_port && memcmp(received, expected, sizeof(expected)) == 0, "actual server receive");
        require(sendto(server, received, sizeof(received), 0, (struct sockaddr *)&client_address, sizeof(client_address)) == sizeof(received), "UDP reply");
        size = sizeof(source);
        require(recvfrom(client, received, sizeof(received), 0, (struct sockaddr *)&source, &size) == sizeof(received) &&
                size == sizeof(source) && source.sin_addr.s_addr == server_address.sin_addr.s_addr &&
                source.sin_port == server_address.sin_port && memcmp(received, expected, sizeof(expected)) == 0, "actual client echo");
    }
    require(close(client) == 0 && close(server) == 0, "socket closes");
}

int main(int argument_count, char **arguments)
{
    require(argument_count == 2, "task argument");
    if (strcmp(arguments[1], "file") == 0)
        file_task();
    else if (strcmp(arguments[1], "network") == 0)
        network_task();
    else
        return 2;
    printf("{\"status\":\"accepted\",\"task\":\"%s\",\"pid\":%ld,\"pointer_bits\":%zu,\"file_bytes\":%d,\"actual_udp_echoes\":%d}\n",
           arguments[1], (long)getpid(), sizeof(void *) * 8, strcmp(arguments[1], "file") == 0 ? 16777216 : 0,
           strcmp(arguments[1], "network") == 0 ? 64 : 0);
    return 0;
}