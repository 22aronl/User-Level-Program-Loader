#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>

// gcc -Wall -shared -fPIC -o new_malloc.so new_malloc.c -ldl
void* (*real_malloc)(size_t) = NULL;

void* malloc(size_t size) {
    if (!real_malloc) {
        real_malloc = dlsym(RTLD_NEXT, "malloc");
    }
    void* ptr = real_malloc(size);
    if (ptr) {
        unsigned char* buffer = (unsigned char*)ptr;
        for (size_t i = 0; i < size; i++) {
            buffer[i] = 0xCC;
        }
    }

    return ptr;
}