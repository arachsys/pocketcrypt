#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define duplex_permute duplex_xoodoo
#include "duplex.h"

static duplex_t state = { 0 };
static uint8_t buffer[65536];

static double permute(size_t repeat) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++)
    duplex_permute(state);
  return 1.0e9 * (clock() - start) / CLOCKS_PER_SEC / repeat;
}

static double speed(void (*operation)(void), size_t repeat) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++)
    operation();
  double seconds = (double) (clock() - start) / CLOCKS_PER_SEC;
  return (double) repeat * sizeof(buffer) / seconds / (1 << 20);
}

static void absorb(void) {
  duplex_absorb(state, buffer, sizeof(buffer));
}

static void squeeze(void) {
  duplex_squeeze(state, buffer, sizeof(buffer));
}

static void encrypt(void) {
  duplex_encrypt(state, buffer, sizeof(buffer));
}

static void decrypt(void) {
  duplex_decrypt(state, buffer, sizeof(buffer));
}

int main(void) {
  for (size_t i = 0; i < sizeof(buffer); i++)
    buffer[i] = (uint8_t) i;

  permute(1 << 20); /* warm up any dynamic CPU frequency scaling */
  printf("Xoodoo permutes in %0.1f ns\n", permute(1 << 21));
  printf("Xoodoo duplex absorbs at %0.1f MB/s\n", speed(absorb, 512));
  printf("Xoodoo duplex squeezes at %0.1f MB/s\n", speed(squeeze, 512));
  printf("Xoodoo duplex encrypts at %0.1f MB/s\n", speed(encrypt, 512));
  printf("Xoodoo duplex decrypts at %0.1f MB/s\n\n", speed(decrypt, 512));

  return EXIT_SUCCESS;
}
