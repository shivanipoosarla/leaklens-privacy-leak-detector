#include <stdio.h>
#include <klee/klee.h>

static void log_data(const char *data) {
    fprintf(stderr, "LOG: %s\n", data);  // privacy sink: logging output
}

int main(void) {
    char secret[4];
    klee_make_symbolic(secret, sizeof(secret), "secret");
    secret[3] = '\0';

    if (secret[0] == 'k') {
        log_data(secret);
    }

    return 0;
}
