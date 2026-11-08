/* lowrate_gen: benign low-rate background traffic for the sealed lab, of the kind always-on devices and
 * daemons produce: periodic polls, keepalives, DNS lookups, NTP queries and TLS heartbeats. Every
 * activity runs on a fixed period and the program exits on its own after DURATION_MS, so a run ends
 * with status 0 inside the 20-s observation. Destinations are restricted to 10.0.0.0/8 and 127.0.0.0/8.
 * Prints a JSON receipt with the number of successful and failed operations per activity.
 *
 *   lowrate_gen poll      PERIOD_MS DURATION_MS DST [PORT=80]    # new TCP connection + HTTP GET each period
 *   lowrate_gen keepalive PERIOD_MS DURATION_MS DST [PORT=80]    # one connection, HTTP/1.1 GET each period
 *   lowrate_gen dns       PERIOD_MS DURATION_MS DST [PORT=53]    # DNS A query each period
 *   lowrate_gen ntp       PERIOD_MS DURATION_MS DST [PORT=123]   # NTP client request each period
 *   lowrate_gen tlspoll   PERIOD_MS DURATION_MS DST [PORT=443]   # new TLS connection + HTTPS GET each period
 *   lowrate_gen tlskeep   PERIOD_MS DURATION_MS DST [PORT=443]   # one TLS connection, HTTPS GET each period
 *   lowrate_gen device    PROFILE   DURATION_MS DST              # mixed schedules, PROFILE a, b or c
 *
 * Build: gcc -O2 -static -Wall -Wextra -Werror -o lowrate_gen lowrate_gen.c -lssl -lcrypto -lpthread -ldl
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

enum kind { POLL, KEEP, DNS, NTP, TLSPOLL, TLSKEEP };
static const char *KIND_NAME[] = {"poll", "keepalive", "dns", "ntp", "tlspoll", "tlskeep"};

struct activity {
    enum kind kind;
    long period_ms, offset_ms, next_ms;
    int port;
    long ok, failed;
    int fd;      /* persistent TCP connection (keepalive, tlskeep) */
    SSL *ssl;    /* persistent TLS session (tlskeep) */
};

static struct sockaddr_in dst;
static SSL_CTX *ctx;
static long start_ms;
static unsigned short dns_id = 0x2a00;

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static void sleep_until(long target_ms) {
    long d = target_ms - now_ms();
    if (d > 0) {
        struct timespec t = {d / 1000, (d % 1000) * 1000000L};
        nanosleep(&t, NULL);
    }
}

static void set_timeout(int fd, long ms) {
    struct timeval tv = {ms / 1000, (ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

static int tcp_connect(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    set_timeout(fd, 2000);
    struct sockaddr_in a = dst;
    a.sin_port = htons(port);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static SSL *tls_open(int fd) {
    SSL *ssl = SSL_new(ctx);
    if (!ssl) return NULL;
    SSL_set_tlsext_host_name(ssl, "sink.lab");
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        return NULL;
    }
    return ssl;
}

static const char *request(int keep) {
    return keep ? "GET /status HTTP/1.1\r\nHost: sink\r\nConnection: keep-alive\r\n\r\n"
                : "GET /status HTTP/1.0\r\nHost: sink\r\n\r\n";
}

/* Read a response: until EOF for one-shot requests, or the first read for keepalive requests. */
static long read_plain(int fd, int until_eof) {
    char buf[8192];
    long total = 0, n;
    while ((n = read(fd, buf, sizeof buf)) > 0) {
        total += n;
        if (!until_eof) break;
    }
    return n < 0 && total == 0 ? -1 : total;
}

static long read_tls(SSL *ssl, int until_eof) {
    char buf[8192];
    long total = 0;
    int n;
    while ((n = SSL_read(ssl, buf, sizeof buf)) > 0) {
        total += n;
        if (!until_eof) break;
    }
    return total > 0 ? total : -1;
}

static void close_persistent(struct activity *a) {
    if (a->ssl) {
        SSL_shutdown(a->ssl);
        SSL_free(a->ssl);
        a->ssl = NULL;
    }
    if (a->fd >= 0) {
        close(a->fd);
        a->fd = -1;
    }
}

static int udp_exchange(int port, const unsigned char *msg, size_t len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    set_timeout(fd, 1000);
    struct sockaddr_in a = dst;
    a.sin_port = htons(port);
    unsigned char reply[1024];
    int ok = sendto(fd, msg, len, 0, (struct sockaddr *)&a, sizeof a) == (ssize_t)len &&
             recvfrom(fd, reply, sizeof reply, 0, NULL, NULL) > 0;
    close(fd);
    return ok;
}

static int do_dns(int port) {
    static const char *names[] = {"api", "time", "update", "telemetry"};
    unsigned char q[64];
    size_t n = 0;
    unsigned short id = dns_id++;
    unsigned char header[] = {id >> 8, id & 0xff, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
    memcpy(q, header, sizeof header);
    n = sizeof header;
    const char *label = names[id % 4];
    q[n++] = (unsigned char)strlen(label);
    memcpy(q + n, label, strlen(label));
    n += strlen(label);
    const unsigned char rest[] = {4, 's', 'i', 'n', 'k', 3, 'l', 'a', 'b', 0, 0, 1, 0, 1};
    memcpy(q + n, rest, sizeof rest);
    n += sizeof rest;
    return udp_exchange(port, q, n);
}

static int do_ntp(int port) {
    unsigned char m[48] = {0x23};  /* LI 0, version 4, client mode */
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    unsigned long secs = (unsigned long)t.tv_sec + 2208988800UL;
    unsigned long frac = (unsigned long)(((unsigned long long)t.tv_nsec << 32) / 1000000000ULL);
    for (int i = 0; i < 4; i++) {
        m[40 + i] = (secs >> (24 - 8 * i)) & 0xff;
        m[44 + i] = (frac >> (24 - 8 * i)) & 0xff;
    }
    return udp_exchange(port, m, sizeof m);
}

static int run_once(struct activity *a) {
    switch (a->kind) {
    case POLL: {
        int fd = tcp_connect(a->port);
        if (fd < 0) return 0;
        const char *r = request(0);
        int ok = write(fd, r, strlen(r)) == (ssize_t)strlen(r) && read_plain(fd, 1) > 0;
        close(fd);
        return ok;
    }
    case KEEP:
    case TLSKEEP: {
        for (int attempt = 0; attempt < 2; attempt++) {
            if (a->fd < 0) {
                a->fd = tcp_connect(a->port);
                if (a->fd < 0) return 0;
                if (a->kind == TLSKEEP && !(a->ssl = tls_open(a->fd))) {
                    close_persistent(a);
                    return 0;
                }
            }
            const char *r = request(1);
            long got;
            if (a->kind == KEEP)
                got = write(a->fd, r, strlen(r)) == (ssize_t)strlen(r) ? read_plain(a->fd, 0) : -1;
            else
                got = SSL_write(a->ssl, r, strlen(r)) == (int)strlen(r) ? read_tls(a->ssl, 0) : -1;
            if (got > 0) return 1;
            close_persistent(a); /* server closed the connection: reconnect once */
        }
        return 0;
    }
    case DNS:
        return do_dns(a->port);
    case NTP:
        return do_ntp(a->port);
    case TLSPOLL: {
        int fd = tcp_connect(a->port);
        if (fd < 0) return 0;
        SSL *ssl = tls_open(fd);
        int ok = 0;
        if (ssl) {
            const char *r = request(0);
            ok = SSL_write(ssl, r, strlen(r)) == (int)strlen(r) && read_tls(ssl, 1) > 0;
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(fd);
        return ok;
    }
    }
    return 0;
}

static int add(struct activity *list, int n, enum kind kind, long period, long offset, int port) {
    list[n] = (struct activity){kind, period, offset, 0, port, 0, 0, -1, NULL};
    return n + 1;
}

static int default_port(enum kind k) {
    return k == DNS ? 53 : k == NTP ? 123 : (k == TLSPOLL || k == TLSKEEP) ? 443 : 80;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: lowrate_gen MODE PERIOD_MS|PROFILE DURATION_MS DST [PORT]\n");
        return 2;
    }
    signal(SIGPIPE, SIG_IGN); /* a server that closed the connection must not kill the client */
    const char *mode = argv[1];
    long duration = atol(argv[3]);
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    if (inet_pton(AF_INET, argv[4], &dst.sin_addr) != 1) {
        fprintf(stderr, "bad destination %s\n", argv[4]);
        return 2;
    }
    unsigned first = ntohl(dst.sin_addr.s_addr) >> 24;
    if (first != 10 && first != 127) {
        fprintf(stderr, "destination %s outside 10.0.0.0/8 and 127.0.0.0/8\n", argv[4]);
        return 2;
    }
    if (duration <= 0 || duration > 60000) {
        fprintf(stderr, "duration must be 1..60000 ms\n");
        return 2;
    }

    struct activity acts[8];
    int n = 0;
    if (!strcmp(mode, "device")) {
        const char *p = argv[2];
        if (!strcmp(p, "a")) {
            n = add(acts, n, DNS, 10000, 0, 53);
            n = add(acts, n, NTP, 16000, 300, 123);
            n = add(acts, n, TLSKEEP, 5000, 600, 443);
        } else if (!strcmp(p, "b")) {
            n = add(acts, n, DNS, 7000, 0, 53);
            n = add(acts, n, POLL, 3000, 400, 80);
        } else if (!strcmp(p, "c")) {
            n = add(acts, n, DNS, 4000, 0, 53);
            n = add(acts, n, NTP, 10000, 200, 123);
            n = add(acts, n, TLSPOLL, 8000, 500, 443);
        } else {
            fprintf(stderr, "unknown device profile %s\n", p);
            return 2;
        }
    } else {
        long period = atol(argv[2]);
        int k;
        for (k = 0; k <= TLSKEEP; k++)
            if (!strcmp(mode, KIND_NAME[k])) break;
        if (k > TLSKEEP || period < 100) {
            fprintf(stderr, "unknown mode %s or period below 100 ms\n", mode);
            return 2;
        }
        n = add(acts, n, (enum kind)k, period, 0, argc > 5 ? atoi(argv[5]) : default_port((enum kind)k));
    }

    int tls = 0;
    for (int i = 0; i < n; i++) tls |= acts[i].kind == TLSPOLL || acts[i].kind == TLSKEEP;
    if (tls) {
        OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) return 1;
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    start_ms = now_ms();
    for (int i = 0; i < n; i++) acts[i].next_ms = start_ms + acts[i].offset_ms;
    for (;;) {
        int next = 0;
        for (int i = 1; i < n; i++)
            if (acts[i].next_ms < acts[next].next_ms) next = i;
        if (acts[next].next_ms >= start_ms + duration) break;
        sleep_until(acts[next].next_ms);
        if (run_once(&acts[next])) acts[next].ok++;
        else acts[next].failed++;
        acts[next].next_ms += acts[next].period_ms;
    }
    for (int i = 0; i < n; i++) close_persistent(&acts[i]);
    sleep_until(start_ms + duration);

    printf("{\"mode\":\"%s\",\"duration_ms\":%ld,\"activities\":[", mode, duration);
    for (int i = 0; i < n; i++)
        printf("%s{\"kind\":\"%s\",\"period_ms\":%ld,\"port\":%d,\"ok\":%ld,\"failed\":%ld}", i ? "," : "",
               KIND_NAME[acts[i].kind], acts[i].period_ms, acts[i].port, acts[i].ok, acts[i].failed);
    printf("]}\n");
    if (ctx) SSL_CTX_free(ctx);
    return 0;
}
