#include <stdio.h>
#include <cstdlib>
#include <ctime>
#include <iostream>

int zeroed[1000000];
int global[100];

int main(int argc, char* argv []) {
    std::srand(std::time(nullptr));
    printf("Hello, World!\n");
    printf("%d\n", zeroed[5000]);
    int counter = 0;
    for (int i = 0; i < 1000000; i++) {
        // rand
        zeroed[i] += std::rand();    
    }
    for (int i = 0; i < 1000000; i++) {
        counter += zeroed[i];
    }
    printf("%d\n", counter);
    std::cout << "Address of zeroed: " << &zeroed << std::endl;
    std::cout << "Address of global: " << &global << std::endl;
    return 1;
    // printf("%p\n", (void *)zeroed);
}