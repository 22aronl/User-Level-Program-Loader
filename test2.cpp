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
    
    zeroed[0] = 2;
    zeroed[1000000 - 1] = 3;
    
    return 1;
}