#ifndef _STDLIB_H
#define _STDLIB_H

// Definitions are taken from musl: https://www.musl-libc.org

typedef unsigned long size_t;

void *malloc (size_t);

void free (void *);

#endif
