#ifndef KLEE_KLEE_H
#define KLEE_KLEE_H

#include <stddef.h>

/* Minimal local stub for syntax-checking examples without installing KLEE.
   Use the real <klee/klee.h> when running examples under KLEE. */
static inline void klee_make_symbolic(void *addr, size_t nbytes, const char *name) {
    (void)addr;
    (void)nbytes;
    (void)name;
}

#endif
