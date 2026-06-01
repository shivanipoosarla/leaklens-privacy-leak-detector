#include <string.h>
#include <klee/klee.h>

int main(void) {
    char input[4];
    klee_make_symbolic(input, sizeof(input), "input");
    input[3] = '\0';

    /* Safe local use: the symbolic input influences a branch but is not sent to
       a configured output sink such as printf(), fprintf(), send(), or write(). */
    if (strlen(input) > 2 && input[0] == 'x') {
        return 1;
    }

    return 0;
}
