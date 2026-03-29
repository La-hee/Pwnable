#include <stdio.h>
#include <stdlib.h>

int main() {
unsigned int seed = rand();
unsigned int exploit = 0xcafebabe;

unsigned int key = seed ^ exploit;

printf("seed : %d \n", seed);
printf("key : %d", key);
}