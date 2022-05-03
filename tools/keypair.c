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

  randomise(scalar, x25519_size);
  scalar[0] &= 0xf8;
  scalar[x25519_size - 1] &= 0x7f;
  scalar[x25519_size - 1] |= 0x40;
  x25519(point, scalar, x25519_base);

  save(argv[1], scalar, x25519_size);
  save(argv[2], point, x25519_size);
  return EXIT_SUCCESS;
}
