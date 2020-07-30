#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "x25519.h"

/* Based on test_x25519.c from Mike Hamburg's STROBE test suite */

static void bitflip(x25519_t key) {
  size_t bit = ((size_t *) key)[0] % (sizeof(x25519_t) << 3);
  ((uint8_t *) key)[bit >> 3] ^= 1 << (bit & 7); /* secret index */
}

static void generate(x25519_t key) {
  static uint32_t state = 0x12345678;
  for (size_t i = 0; i < sizeof(x25519_t); i++) {
    state += state * state | 5;
    key[i] = state >> 24;
  }
}

int main(void) {
  for (size_t i = 0; i < 1000; i++) {
    x25519_t shared1, shared2, public1, public2, secret1, secret2;

    generate(secret1);
    generate(secret2);

    x25519(public1, secret1, x25519_generator);
    x25519(public2, secret2, x25519_generator);

    x25519(shared1, secret1, public2);
    x25519(shared2, secret2, public1);
    if (memcmp(shared1, shared2, sizeof(shared1)) != 0) /* variable time */
      errx(EXIT_FAILURE, "Valid key exchange failed");

    bitflip(secret2); /* secret index */
    x25519(shared2, secret2, public1);
    if (memcmp(shared1, shared2, sizeof(shared1)) == 0) /* variable time */
      errx(EXIT_FAILURE, "Invalid key exchange succeeded");
  }

  for (size_t i = 0; i < 1000; i++) {
    x25519_t challenge, ephemeral, identity, response;

    generate(identity);
    generate(ephemeral);
    generate(challenge);
    x25519_sign(response, challenge, ephemeral, identity);

    x25519(ephemeral, ephemeral, x25519_generator);
    x25519(identity, identity, x25519_generator);
    if (x25519_verify(response, challenge, ephemeral, identity) != 0)
      errx(EXIT_FAILURE, "Valid signature failed to verify");

    bitflip(challenge);
    if (x25519_verify(response, challenge, ephemeral, identity) == 0)
      errx(EXIT_FAILURE, "Invalid signature successfully verified");
  }

  printf("Key exchange and signatures sanity-checked\n");
  return EXIT_SUCCESS;
}
