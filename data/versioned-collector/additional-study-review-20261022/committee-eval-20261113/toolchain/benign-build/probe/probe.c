#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char buf[256];
    FILE *f = fopen(argc > 1 ? argv[1] : "/etc/hostname", "r");
    size_t n = f ? fread(buf, 1, sizeof buf, f) : 0;
    if (f) fclose(f);
    printf("read %zu\n", n);
    return 0;
}
