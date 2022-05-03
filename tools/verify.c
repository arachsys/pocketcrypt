#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "duplex.h"
#include "util.h"
#include "x25519.h"

static void process(duplex_t state) {
  size_t chunk = 65536, length;
  uint8_t data[65536];

  while ((length = get(in, data, chunk)))
    duplex_absorb(state, data, length);
  duplex_pad(state);
}

int main(int argc, char **argv) {
  duplex_t state = { 0 };
  x25519_t challenge, identity, signature[2];

  if (argc != 2 && argc != 3) {
    fprintf(stderr, "Usage: %s PK [SIG]\n", argv[0]);
    return 64;
  }

  load(argv[1], identity, x25519_size);
  load(argv[2], signature, 2 * x25519_size);
  process(state);

  duplex_absorb(state, identity, x25519_size);
  duplex_absorb(state, signature[0], x25519_size);
  duplex_squeeze(state, challenge, x25519_size);

  if (x25519_verify(signature[1], challenge, signature[0], identity))
    errx(EXIT_FAILURE, "Verification failed");
  return EXIT_SUCCESS;
}
