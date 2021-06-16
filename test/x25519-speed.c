#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "x25519.h"

static uint8_t buffer[128];

static double exchange(size_t repeat) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++)
    x25519(buffer + 64, buffer + 32, buffer);
  return 1.0e6 * (clock() - start) / CLOCKS_PER_SEC / repeat;
}

static double invert(size_t repeat) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++)
    x25519_invert(buffer + 32, buffer);
  return 1.0e6 * (clock() - start) / CLOCKS_PER_SEC / repeat;
}

static double pointmap(size_t repeat) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++)
    x25519_point(buffer + 32, buffer);
  return 1.0e6 * (clock() - start) / CLOCKS_PER_SEC / repeat;
}

static double scalarmap(size_t repeat) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++)
    x25519_scalar(buffer + 32, buffer);
  return 1.0e9 * (clock() - start) / CLOCKS_PER_SEC / repeat;
}

static double sign(size_t repeat) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++) {
    x25519_sign(buffer, buffer + 32, buffer + 64, buffer + 96);
    x25519(buffer + 64, buffer + 64, x25519_base);
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

  exchange(512); /* warm up any dynamic CPU frequency scaling */
  printf("X25519 exchanges in %0.1f us\n", exchange(1024));
  printf("X25519 inverts scalars in %0.1f us\n", invert(8192));
  printf("X25519 maps to curve points in %0.1f us\n", pointmap(2<<12));
  printf("X25519 maps to safe scalars in %0.1f ns\n", scalarmap(2<<18));
  printf("X25519 signs in %0.1f us\n", sign(1024));
  printf("X25519 verifies in %0.1f us\n\n", verify(1024));

  return EXIT_SUCCESS;
}
