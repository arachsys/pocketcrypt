#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "duplex.h"
#include "util.h"
#include "x25519.h"

static void process(duplex_t state) {
  size_t length;
  uint8_t *data;

  if ((data = malloc(chunk)) == NULL)
    err(EXIT_FAILURE, "malloc");

  while ((length = get(in, data, chunk)))
    duplex_absorb(state, data, length);
  duplex_pad(state);
  free(data);
}

int main(int argc, char **argv) {
  duplex_t seed, state = { 0 };
  x25519_t challenge, identity, point, scalar, response, secret;

  if (argc != 2 && argc != 3) {
    fprintf(stderr, "Usage: %s SK [PK]\n", argv[0]);
    return 64;
  }

  load(argv[1], secret, sizeof(secret));
  if (argv[2])
    load(argv[2], identity, sizeof(identity));
  else
    x25519(identity, secret, x25519_base);

  process(state);
  duplex_absorb(state, identity, sizeof(identity));

  memcpy(seed, state, sizeof(seed));
  duplex_absorb(seed, secret, sizeof(secret));
  duplex_squeeze(seed, scalar, sizeof(scalar));
  x25519(point, scalar, x25519_base);

  duplex_absorb(state, point, sizeof(point));
  duplex_squeeze(state, challenge, sizeof(challenge));
  x25519_sign(response, challenge, scalar, secret);

  put(out, point, sizeof(point));
  put(out, response, sizeof(response));
  return EXIT_SUCCESS;
}
