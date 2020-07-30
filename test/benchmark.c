#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "gimli.h"
#include "x25519.h"

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

static void absorb(void) {
  gimli_absorb(state, buffer, sizeof(buffer), 0);
}

static void squeeze(void) {
  gimli_squeeze(state, buffer, sizeof(buffer));
}

static void encrypt(void) {
  gimli_encrypt(state, buffer, sizeof(buffer), 0);
}

static void decrypt(void) {
  gimli_decrypt(state, buffer, sizeof(buffer), 0);
}

static double exchange(size_t repeat) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++)
    x25519(buffer + 64, buffer + 32, buffer);
  return 1.0e6 * (clock() - start) / CLOCKS_PER_SEC / repeat;
}

static double sign(size_t repeat) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++) {
    x25519_sign(buffer, buffer + 32, buffer + 64, buffer + 96);
    x25519(buffer + 64, buffer + 64, x25519_generator);
  }
  return 1.0e6 * (clock() - start) / CLOCKS_PER_SEC / repeat;
}

static double verify(size_t repeat) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++)
    x25519_verify(buffer, buffer + 32, buffer + 64, buffer + 96);
  return 1.0e6 * (clock() - start) / CLOCKS_PER_SEC / repeat;
}

int main(void) {
  for (size_t i = 0; i < sizeof(buffer); i++)
    buffer[i] = (uint8_t) i;

  printf("Benchmark: gimli permutes in %0.1f ns\n", permute(1 << 21));
  printf("Benchmark: gimli absorbs at %0.1f MB/s\n", speed(absorb, 512));
  printf("Benchmark: gimli squeezes at %0.1f MB/s\n", speed(squeeze, 512));
  printf("Benchmark: gimli encrypts at %0.1f MB/s\n", speed(encrypt, 512));
  printf("Benchmark: gimli decrypts at %0.1f MB/s\n\n", speed(decrypt, 512));

  printf("Benchmark: x25519 exchanges in %0.1f us\n", exchange(1024));
  printf("Benchmark: x25519 signs in %0.1f us\n", sign(1024));
  printf("Benchmark: x25519 verifies in %0.1f us\n\n", verify(1024));

  return EXIT_SUCCESS;
}
