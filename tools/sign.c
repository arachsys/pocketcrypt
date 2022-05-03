#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  duplex_t seed, state = { 0 };
  x25519_t challenge, identity, point, scalar, response, secret;

  if (argc != 2 && argc != 3) {
    fprintf(stderr, "Usage: %s SK [PK]\n", argv[0]);
    return 64;
  }

  load(argv[1], secret, x25519_size);
  if (argv[2])
    load(argv[2], identity, x25519_size);
  else
    x25519(identity, secret, x25519_base);

  process(state);
  duplex_absorb(state, identity, x25519_size);

  memcpy(seed, state, x25519_size);
  duplex_absorb(seed, secret, x25519_size);
  duplex_squeeze(seed, scalar, x25519_size);
  x25519(point, scalar, x25519_base);

  duplex_absorb(state, point, x25519_size);
  duplex_squeeze(state, challenge, x25519_size);
  x25519_sign(response, challenge, scalar, secret);

  put(out, point, x25519_size);
  put(out, response, x25519_size);
  return EXIT_SUCCESS;
}
