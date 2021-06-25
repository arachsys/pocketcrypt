#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "shamir.h"

static secret_t entropy[254], secret;
static share_t shares[255];

static double combine(size_t repeat, uint8_t count) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++)
    shamir_combine(secret, count, shares);
  return 1.0e6 * (clock() - start) / CLOCKS_PER_SEC / repeat;
}

static double split(size_t repeat, uint8_t threshold) {
  clock_t start = clock();
  for (size_t i = 0; i < repeat; i++)
    for (uint8_t j = 0; j < 255; j++)
      shamir_split(shares[j], j, threshold, secret, entropy);
  return 1.0e6 * (clock() - start) / CLOCKS_PER_SEC / repeat / 255;
}

int main(void) {
  for (size_t i = 0; i < sizeof(secret); i++) {
    secret[i] = (uint8_t) i;
    for (size_t j = 0; j < 254; j++)
      entropy[j][i] = (uint8_t) (i + j);
  }

  printf("Secret sharing with threshold 2 takes %0.2f us\n", split(512, 2));
  printf("Secret sharing with threshold 3 takes %0.2f us\n", split(512, 3));
  printf("Secret sharing with threshold 10 takes %0.2f us\n", split(256, 10));

  printf("Combining 2 secret shares takes %0.2f us\n", combine(65536, 2));
  printf("Combining 3 secret shares takes %0.2f us\n", combine(32768, 3));
  printf("Combining 10 secret shares takes %0.2f us\n\n", combine(4096, 10));
  return EXIT_SUCCESS;
}
