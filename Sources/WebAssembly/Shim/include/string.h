#ifndef    _STRING_H
#define    _STRING_H

// Definitions are taken from musl: https://www.musl-libc.org

typedef unsigned long size_t;

void *memcpy (void *__restrict, const void *__restrict, size_t);

void *memset (void *, int, size_t);

int memcmp (const void *, const void *, size_t);

size_t strlen (const char *);

int strncmp (const char *, const char *, size_t);

#endif
