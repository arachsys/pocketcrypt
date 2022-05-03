#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shamir.h"

static secret_t entropy[254], secret, secret2;
static share_t shares[255];
static uint32_t seed = 0x12345678;

static void bitflip(share_t key) {
  seed += seed * seed | 5;
  key[1 + (seed >> 27)] ^= 1 << (seed >> 24 & 7); /* secret index */
}

static void fill(uint8_t *out, size_t length) {
  for (size_t i = 0; i < length; i++) {
    seed += seed * seed | 5;
    out[i] = seed >> 24;
  }
}

int main(void) {
  for (uint8_t k = 255; k > 1; k = 15 * k >> 4) {
    fill(secret, secret_size);
    fill((uint8_t *) entropy, sizeof(entropy));

    for (uint8_t i = 0, j = 0; i < 255; i++) {
      /* Inline Fisher-Yates shuffle: random array indices */
      seed += seed * seed | 5, j = (uint64_t) seed * (i + 1) >> 32;
      memmove(shares[i], shares[j], share_size);
      shamir_split(shares[j], i, k, secret, entropy);
    }

    memset(secret2, 0, secret_size);
    shamir_combine(secret2, k, shares);
    if (memcmp(secret, secret2, secret_size) != 0) /* variable time */
      errx(EXIT_FAILURE, "Quorate secret reconstruction failed");

    memset(secret2, 0, secret_size);
    shamir_combine(secret2, 255, shares);
    if (memcmp(secret, secret2, secret_size) != 0) /* variable time */
      errx(EXIT_FAILURE, "Overconstrained secret reconstruction failed");

    memset(secret2, 0, secret_size);
    shamir_combine(secret2, k - 1, shares);
    if (memcmp(secret, secret2, secret_size) == 0) /* variable time */
      errx(EXIT_FAILURE, "Non-quorate secret reconstruction succeeded");

    bitflip(shares[0]); /* corrupt random share as shares are shuffled */
    memset(secret2, 0, secret_size);
    shamir_combine(secret2, k, shares);
    if (memcmp(secret, secret2, secret_size) == 0) /* variable time */
      errx(EXIT_FAILURE, "Invalid secret reconstruction succeeded");
  }

  printf("Secret sharing operations sanity-checked\n");
  return EXIT_SUCCESS;
}
