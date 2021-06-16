#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "util.h"
#include "x25519.h"

int main(int argc, char **argv) {
  x25519_t point, scalar;

  if (argc != 3) {
    fprintf(stderr, "Usage: %s SK PK\n", argv[0]);
    return 64;
  }

  randomise(scalar, sizeof(scalar));
  scalar[0] &= 0xf8;
  scalar[sizeof(x25519_t) - 1] &= 0x7f;
  scalar[sizeof(x25519_t) - 1] |= 0x40;
  x25519(point, scalar, x25519_base);

  save(argv[1], scalar, sizeof(scalar));
  save(argv[2], point, sizeof(point));
  return EXIT_SUCCESS;
}
