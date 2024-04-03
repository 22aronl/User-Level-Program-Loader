#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int zeroed[1000000] = {0};

long x = 1, y = 4, z = 7, w = 13;

long simplerand(void) {
	long t = x;
	t ^= t << 11;
	t ^= t >> 8;
	x = y;
	y = z;
	z = w;
	w ^= w >> 19;
	w ^= t;
	return w;
}

int main(int argc, char* argv []) {
    
    uint64_t rand_index = 3;
    for(int i = 0; i < 10000; i++) {
        rand_index = (rand_index + simplerand()) % 1000000;
        zeroed[rand_index] = 1;
    }
    
    return 1;
}