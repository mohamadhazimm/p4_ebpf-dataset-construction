// Benign known-answer workload for thread/exec tracking.
// "exec": a non-leader thread execs /bin/sh, which writes a local file 200 times.
// "leader-exit": the main thread exits first; a worker thread writes a local file 200 times.
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *mode;

static void write_loop(const char *path)
{
    for (int i = 0; i < 200; i++) {
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0)
            return;
        char buffer[32];
        int length = snprintf(buffer, sizeof buffer, "%d\n", i);
        if (write(fd, buffer, (size_t)length) < 0) {
            close(fd);
            return;
        }
        close(fd);
        usleep(5000);
    }
}

static void *worker(void *unused)
{
    (void)unused;
    usleep(200000);
    if (strcmp(mode, "exec") == 0) {
        char *const argv[] = {"sh", "-c",
            "i=0; while [ $i -lt 200 ]; do echo $i > ka_thread_exec.txt; i=$((i+1)); done", NULL};
        execv("/bin/sh", argv);
        _exit(126);
    }
    write_loop("ka_leader_exit.txt");
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t thread;
    if (argc != 2 || (strcmp(argv[1], "exec") && strcmp(argv[1], "leader-exit")))
        return 2;
    mode = argv[1];
    if (pthread_create(&thread, NULL, worker, NULL))
        return 3;
    if (strcmp(mode, "exec") == 0) {
        for (;;)
            pause();
    }
    pthread_exit(NULL);
}
