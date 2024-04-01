#include <stdio.h>

int zeroed[100000] = {0};

int main(int argc, char* argv []) {
    printf("Hello, World!\n");
    printf("%d\n", zeroed[5000]);
    return 1;
    // printf("%p\n", (void *)zeroed);
}