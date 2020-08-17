#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "duplex.h"
#include "x25519.h"

static duplex_t state = { 0 };
static uint8_t buffer[65536];

static double gimli(size_t repeat) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++)
    duplex_gimli(state);
  return 1.0e9 * (clock() - start) / CLOCKS_PER_SEC / repeat;
}

static double xoodoo(size_t repeat) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++)
    duplex_xoodoo(state);
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
  duplex_absorb(state, 0, buffer, sizeof(buffer));
}

static void squeeze(void) {
  duplex_squeeze(state, 0, buffer, sizeof(buffer));
}

static void encrypt(void) {
  duplex_encrypt(state, 0, buffer, sizeof(buffer));
}

static void decrypt(void) {
  duplex_decrypt(state, 0, buffer, sizeof(buffer));
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

  printf("Gimli permutes in %0.1f ns\n", gimli(1 << 21));
  printf("Xoodoo permutes in %0.1f ns\n\n", xoodoo(1 << 21));

  printf("Gimli duplex absorbs at %0.1f MB/s\n", speed(absorb, 512));
  printf("Gimli duplex squeezes at %0.1f MB/s\n", speed(squeeze, 512));
  printf("Gimli duplex encrypts at %0.1f MB/s\n", speed(encrypt, 512));
  printf("Gimli duplex decrypts at %0.1f MB/s\n\n", speed(decrypt, 512));

  printf("X25519 exchanges in %0.1f us\n", exchange(1024));
  printf("X25519 signs in %0.1f us\n", sign(1024));
  printf("X25519 verifies in %0.1f us\n\n", verify(1024));

  return EXIT_SUCCESS;
}
