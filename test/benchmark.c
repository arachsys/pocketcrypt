#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "gimli.h"

static gimli_t state = { 0 };
static uint8_t buffer[65536];

static double permute(size_t repeat) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++)
    gimli(state);
  return 1.0e9 * (clock() - start) / CLOCKS_PER_SEC / repeat;
}

static double speed(void (*operation)(void), size_t repeat) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++)
    operation();
  double seconds = (double) (clock() - start) / CLOCKS_PER_SEC;
  return (double) repeat * sizeof(buffer) / seconds / (1 << 20);
}

void absorb(void) {
  gimli_absorb(state, buffer, sizeof(buffer), 0);
}

void squeeze(void) {
  gimli_squeeze(state, buffer, sizeof(buffer));
}

void encrypt(void) {
  gimli_encrypt(state, buffer, sizeof(buffer), 0);
}

void decrypt(void) {
  gimli_decrypt(state, buffer, sizeof(buffer), 0);
}

int main(void) {
  for (size_t i = 0; i < sizeof(buffer); i++)
    buffer[i] = (uint8_t) i;

  printf("Benchmark: gimli() takes %0.1f ns\n", permute(1 << 22));
  printf("Benchmark: gimli_absorb() runs at %0.1f MB/s\n",
    speed(absorb, 512));
  printf("Benchmark: gimli_squeeze() runs at %0.1f MB/s\n",
    speed(squeeze, 512));
  printf("Benchmark: gimli_encrypt() runs at %0.1f MB/s\n",
    speed(encrypt, 512));
  printf("Benchmark: gimli_decrypt() runs at %0.1f MB/s\n",
    speed(decrypt, 512));

  return EXIT_SUCCESS;
}
