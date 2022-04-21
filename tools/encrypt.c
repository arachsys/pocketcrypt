#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "duplex.h"
#include "util.h"
#include "x25519.h"

static void process(duplex_t state) {
  size_t chunk = 65536, length;
  uint8_t data[65536 + duplex_rate];

  do {
    length = get(in, data, chunk);
    duplex_encrypt(state, data, length);
    duplex_pad(state);
    duplex_squeeze(state, data + length, duplex_rate);
    put(out, data, length + duplex_rate);
  } while (length == chunk);
}

int main(int argc, char **argv) {
  duplex_t state = { 0 };
  x25519_t point, scalar;

  if (argc == 2) {
    randomise(scalar, sizeof(scalar));
    x25519(point, scalar, x25519_base);
    put(out, point, sizeof(point));
    load(argv[1], point, sizeof(point));
  } else if (argc == 3) {
    load(argv[1], scalar, sizeof(scalar));
    load(argv[2], point, sizeof(point));
  } else {
    fprintf(stderr, "Usage: %s [SK] PK\n", argv[0]);
    return 64;
  }

  if (x25519(point, scalar, point))
    errx(EXIT_FAILURE, "Invalid public identity");
  duplex_absorb(state, point, sizeof(point));

  if (argc == 3) {
    uint8_t nonce[duplex_rate];
    randomise(nonce, duplex_rate);
    put(out, nonce, duplex_rate);
    duplex_absorb(state, nonce, duplex_rate);
  }

  process(state);
  return EXIT_SUCCESS;
}
