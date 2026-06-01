#include <stddef.h>
#include <string.h>
#include <klee/klee.h>

/* External sink declaration for analysis. The example is meant to compile to
   LLVM bitcode for KLEE-style exploration; it is not intended to open a real
   network socket during local syntax checks. */
extern long send(int sockfd, const void *buf, unsigned long len, int flags);

static void network_send(const char *buf) {
    send(1, buf, strlen(buf), 0);  // privacy sink: network-style output
}

int main(void) {
    char sensitive[4];
    klee_make_symbolic(sensitive, sizeof(sensitive), "sensitive");
    sensitive[3] = '\0';

    if (sensitive[0] == 'a' && sensitive[1] == 'b' && sensitive[2] == 'c') {
        network_send(sensitive);
    }

    return 0;
}
