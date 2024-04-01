#include <stdio.h>
#include <cstdlib>
#include <elf.h>


int main(int argc, char *argv[], char *envp[]) {
    int *zero = 0;
    printf("Hello, World!\n");
    return *zero;
}