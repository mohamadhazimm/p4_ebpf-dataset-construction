/* benign_host_gen -- a benign, rate-limited, fixed-duration host-activity generator.
 *
 * Purpose: give the 5-minute observation-length cohort more HOST-ACTIVE benign programs. The real coreutils we can
 * stretch to 5 min without a shell loop or a giant fixture are few (rsync --bwlimit, find -exec, sort -S); CPU-bound
 * tools (openssl speed, in-memory sqlite) go syscall-silent and recreate the "quiet tail = benign" shortcut. This
 * generator is the HOST analog of the study's lowrate_gen network generator: it performs real filesystem system calls
 * (opendir/readdir, open/read/close, write/fsync, stat/lstat/access) at a CONTROLLED rate for a FIXED duration, over a
 * small pre-built tree, so it stays active in every 0.5 s window, exits cleanly at the deadline (never idle-tail), and
 * keeps total syscalls far under the .22 collector's MAX_RETAINED_EBPF_EVENTS = 4,000,000 cap (no overflow rejection).
 *
 * It is entirely benign: it only reads a tree given on argv, writes/unlinks a bounded set of files in its own CWD, and
 * calls no network/exec/privileged syscalls. No shell, stdin unused (the production runner sets stdin=DEVNULL).
 *
 * Each MODE is a distinct host-syscall PROFILE (so each is a separate benign group for the held-out split):
 *   walk   -- directory enumeration: opendir + readdir loop + closedir over the tree's subdirs.
 *   read   -- file reads: open + read(64 KiB) + close, round-robin over the tree's files.
 *   write  -- file writes: open(O_CREAT|O_TRUNC) + write(4 KiB) + fsync + close over a bounded set of CWD files.
 *   stat   -- metadata: stat + lstat + access(R_OK) round-robin over the tree's files.
 *   mixed  -- rotates walk/read/write/stat each op.
 *
 * Rate model: do OPS_PER_TICK ops, then nanosleep 10 ms (~100 ticks/s). With ops/op ~2-4 syscalls, OPS_PER_TICK=20
 * gives ~6 k syscalls/s -> ~1.8 M over 300 s, comfortably under the 4 M cap and active in all 600 windows.
 *
 * Usage:  benign_host_gen MODE DURATION_S OPS_PER_TICK TREE_DIR
 *   MODE in {walk,read,write,stat,mixed}; DURATION_S e.g. 320; OPS_PER_TICK e.g. 20; TREE_DIR = pre-built fixture tree.
 * Exit 0 on clean completion; 2 on usage/setup error. Deterministic given args (no RNG in the hot loop).
 *
 * Build (static amd64, self-contained; no network so static glibc has no NSS issue):
 *   gcc -static -O2 -Wall -Wextra -Werror -o benign_host_gen benign_host_gen.c
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

enum { MODE_WALK, MODE_READ, MODE_WRITE, MODE_STAT, MODE_MIXED };

#define MAX_FILES 200000
#define MAX_DIRS  20000
#define READ_BUF  (64 * 1024)
#define WRITE_BUF (4 * 1024)
#define WRITE_SLOTS 16

static char *g_files[MAX_FILES];
static int   g_nfiles = 0;
static char *g_dirs[MAX_DIRS];
static int   g_ndirs = 0;

/* Recursively record every regular file and directory under root (one scan at startup, bounded). */
static void scan(const char *root)
{
    if (g_ndirs < MAX_DIRS)
        g_dirs[g_ndirs++] = strdup(root);
    DIR *d = opendir(root);
    if (!d)
        return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", root, e->d_name);
        struct stat st;
        if (lstat(path, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            scan(path);
        } else if (S_ISREG(st.st_mode) && g_nfiles < MAX_FILES) {
            g_files[g_nfiles++] = strdup(path);
        }
    }
    closedir(d);
}

static long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

static void op_walk(int i)
{
    if (g_ndirs == 0)
        return;
    const char *dir = g_dirs[i % g_ndirs];
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct dirent *e;
    while ((e = readdir(d)))
        ; /* enumerate the whole directory */
    closedir(d);
}

static void op_read(int i, char *buf)
{
    if (g_nfiles == 0)
        return;
    int fd = open(g_files[i % g_nfiles], O_RDONLY);
    if (fd < 0)
        return;
    while (read(fd, buf, READ_BUF) > 0)
        ; /* read to EOF */
    close(fd);
}

static void op_write(int i, char *buf)
{
    char name[64];
    snprintf(name, sizeof(name), "bhg_w%d.tmp", i % WRITE_SLOTS);
    int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return;
    (void)!write(fd, buf, WRITE_BUF);
    fsync(fd);
    close(fd);
}

static void op_stat(int i)
{
    if (g_nfiles == 0)
        return;
    const char *f = g_files[i % g_nfiles];
    struct stat st;
    stat(f, &st);
    lstat(f, &st);
    access(f, R_OK);
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s MODE DURATION_S OPS_PER_TICK TREE_DIR\n", argv[0]);
        return 2;
    }
    int mode;
    if (!strcmp(argv[1], "walk"))       mode = MODE_WALK;
    else if (!strcmp(argv[1], "read"))  mode = MODE_READ;
    else if (!strcmp(argv[1], "write")) mode = MODE_WRITE;
    else if (!strcmp(argv[1], "stat"))  mode = MODE_STAT;
    else if (!strcmp(argv[1], "mixed")) mode = MODE_MIXED;
    else { fprintf(stderr, "bad mode: %s\n", argv[1]); return 2; }

    long duration_s = atol(argv[2]);
    int ops_per_tick = atoi(argv[3]);
    const char *tree = argv[4];
    if (duration_s <= 0 || ops_per_tick <= 0) {
        fprintf(stderr, "duration and ops_per_tick must be > 0\n");
        return 2;
    }

    scan(tree);
    if (mode != MODE_WRITE && g_nfiles == 0 && g_ndirs <= 1) {
        fprintf(stderr, "tree has no files/subdirs to exercise: %s\n", tree);
        return 2;
    }

    char *rbuf = malloc(READ_BUF);
    char *wbuf = malloc(WRITE_BUF);
    if (!rbuf || !wbuf) { fprintf(stderr, "oom\n"); return 2; }
    memset(wbuf, 'b', WRITE_BUF);

    const long deadline = now_ns() + duration_s * 1000000000L;
    const struct timespec tick = {0, 10 * 1000000L};  /* 10 ms between ticks */
    long i = 0;
    unsigned long ops = 0;
    while (now_ns() < deadline) {
        for (int t = 0; t < ops_per_tick; t++, i++) {
            int m = (mode == MODE_MIXED) ? (int)(i & 3) : mode;
            switch (m) {
            case MODE_WALK:  op_walk((int)i); break;
            case MODE_READ:  op_read((int)i, rbuf); break;
            case MODE_WRITE: op_write((int)i, wbuf); break;
            case MODE_STAT:  op_stat((int)i); break;
            }
            ops++;
        }
        nanosleep(&tick, NULL);
    }

    /* clean up the bounded write set so the CWD is left tidy (benign housekeeping) */
    for (int s = 0; s < WRITE_SLOTS; s++) {
        char name[64];
        snprintf(name, sizeof(name), "bhg_w%d.tmp", s);
        unlink(name);
    }
    printf("benign_host_gen mode=%s duration=%lds ops=%lu files=%d dirs=%d\n",
           argv[1], duration_s, ops, g_nfiles, g_ndirs);
    free(rbuf);
    free(wbuf);
    return 0;
}
