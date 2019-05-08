
#import "libopaque.h"

#import <stdint.h>

// LibECC

void ext_printf(const char *format, ...) {
}

int get_random(unsigned char *buf, uint16_t len) {
    opq_generate_random_bytes(buf, len);
    return 0;
}

// TweetNaCl

void randombytes(unsigned char *buf, uint64_t len) {
    opq_generate_random_bytes(buf, len);
}


