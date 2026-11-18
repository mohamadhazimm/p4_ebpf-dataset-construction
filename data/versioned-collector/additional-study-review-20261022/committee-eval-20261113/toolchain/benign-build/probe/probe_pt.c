#include <stdio.h>
#include <pthread.h>
static void *w(void *a) { return a; }
int main(void) {
    pthread_t t; void *r;
    pthread_create(&t, 0, w, (void *)1);
    pthread_join(t, &r);
    printf("joined %p\n", r);
    return 0;
}
