#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "x25519.h"

/* Based on test_x25519.c from Mike Hamburg's STROBE test suite */

static uint32_t seed = 0x12345678;

static void bitflip(x25519_t key) {
  seed += seed * seed | 5;
  key[seed >> 27] ^= 1 << (seed >> 24 & 7); /* secret index */
}

static void generate(x25519_t key) {
  for (size_t i = 0; i < x25519_size; i++) {
    seed += seed * seed | 5;
    key[i] = seed >> 24;
  }
}

int main(void) {
  for (size_t i = 0; i < 1000; i++) {
    x25519_t shared1, shared2, public1, public2, secret1, secret2;

    generate(secret1);
    generate(secret2);

    x25519(public1, secret1, x25519_base);
    x25519(public2, secret2, x25519_base);

    x25519(shared1, secret1, public2);
    x25519(shared2, secret2, public1);
    if (memcmp(shared1, shared2, x25519_size) != 0) /* variable time */
      errx(EXIT_FAILURE, "Valid key exchange failed");

    bitflip(secret2); /* secret index */
    x25519(shared2, secret2, public1);
    if (memcmp(shared1, shared2, x25519_size) == 0) /* variable time */
      errx(EXIT_FAILURE, "Invalid key exchange succeeded");
  }

  for (size_t i = 0; i < 1000; i++) {
    x25519_t challenge, ephemeral, identity, response;

    generate(identity);
    generate(ephemeral);
    generate(challenge);
    x25519_sign(response, challenge, ephemeral, identity);

    x25519(ephemeral, ephemeral, x25519_base);
    x25519(identity, identity, x25519_base);
    if (x25519_verify(response, challenge, ephemeral, identity) != 0)
      errx(EXIT_FAILURE, "Valid signature failed to verify");

    bitflip(challenge);
    if (x25519_verify(response, challenge, ephemeral, identity) == 0)
      errx(EXIT_FAILURE, "Invalid signature successfully verified");
  }

  for (size_t i = 0; i < 1000; i++) {
    x25519_t scalar1, scalar2, inverse, point1, point2, point3;

    generate(scalar1);
    generate(scalar2);
    x25519(point1, scalar1, x25519_base);
    x25519(point2, scalar2, x25519_base);
    x25519(point2, scalar1, point2);

    x25519_invert(inverse, scalar2);
    x25519(point3, inverse, point2);
    if (memcmp(point1, point3, x25519_size) != 0) /* variable time */
      errx(EXIT_FAILURE, "Valid scalar inversion failed");

    bitflip(scalar2);
    x25519_invert(inverse, scalar2);
    x25519(point3, inverse, point2);
    if (memcmp(point1, point3, x25519_size) == 0) /* variable time */
      errx(EXIT_FAILURE, "Invalid scalar inversion succeeded");
  }

  for (size_t i = 0; i < 1000; i++) {
    x25519_t scalar1, scalar2, point1, point2;
    generate(scalar1);
    x25519_scalar(scalar2, scalar1);
    if (scalar2[0] & 7)
      errx(EXIT_FAILURE, "Scalar representative is not torsion-free");

    x25519(point1, scalar1, x25519_base);
    x25519(point2, scalar2, x25519_base);
    if (memcmp(point1, point2, x25519_size) != 0) /* variable time */
      errx(EXIT_FAILURE, "Scalar representative is not equivalent");
  }

  printf("Key exchange and signatures sanity-checked\n");
  return EXIT_SUCCESS;
}
