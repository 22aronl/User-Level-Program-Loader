#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(int argc, char* argv []) {
    printf("Hello, World!\n");
    void* ar = malloc(1000);

    printf("%ld\n", (uint64_t)ar);
    return 1;
    // printf("%p\n", (void *)zeroed);
}