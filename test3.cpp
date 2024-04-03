#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int zeroed[1000000] = {0};

int main(int argc, char* argv []) {
    
    int array[1000000];

    for(int i = 0; i < 1000000; i++) {
        zeroed[i] = array[i];
    }
    
    return 1;
}