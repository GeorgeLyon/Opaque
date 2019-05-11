#include "libopaque.h"

// MARK: - Allocation

extern unsigned char __heap_base;

static unsigned char *heap_top = &__heap_base;
static const unsigned long wasm_page_size = 65536;

static void align_heap_top()     {
    unsigned int alignment_error = (((unsigned int)heap_top) & 0x7);
    if (alignment_error != 0) {
        heap_top += 8 - alignment_error;
    }
}

void *malloc(unsigned long buffer_length) {
    align_heap_top();
    
    void *buffer = heap_top;
    heap_top += buffer_length;
    
    align_heap_top();
    
    unsigned long current_page_count = __builtin_wasm_memory_size(0);
    unsigned long target_page_count = (((unsigned long)heap_top) + wasm_page_size - 1) / wasm_page_size;
    if (current_page_count < target_page_count) {
        unsigned int delta = target_page_count - current_page_count;
        
        if (__builtin_wasm_memory_grow(0, delta) < 0) {
            return (void *)0;
        }
    }
    
    return buffer;
}

void free(void* buffer) {
    // Do nothing. We expect the WebAssembly module to explode before running out of memory.
    // Inspiration: https://groups.google.com/forum/message/raw?msg=comp.lang.ada/E9bNCvDQ12k/1tezW24ZxdAJ
}
