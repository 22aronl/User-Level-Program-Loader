#include <assert.h>
#include <stdlib.h>
#include <cstdio>

#define SIZE 64

#define MAGIC 0xCC // (can be any value you want)

int main() {
    unsigned char *mem = (unsigned char*) malloc(SIZE);
    for (int i = 0; i < SIZE; i++)
        assert(mem[i] == MAGIC);
    printf("Test passed\n");
}