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
    length = get(in, data, chunk + duplex_rate);
    if (length < duplex_rate)
      errx(EXIT_FAILURE, "Input is truncated");
    length -= duplex_rate;

    duplex_decrypt(state, data, length);
    duplex_pad(state);
    duplex_decrypt(state, data + length, duplex_rate);
    if (duplex_compare(data + length, 0, duplex_rate))
      errx(EXIT_FAILURE, "Authentication failed");
    put(out, data, length);
  } while (length == chunk);
}

int main(int argc, char **argv) {
  duplex_t state = { 0 };
  x25519_t point, scalar;

  if (argc == 2) {
    load(argv[1], scalar, x25519_size);
    if (get(in, point, x25519_size) != x25519_size)
      errx(EXIT_FAILURE, "Input is truncated");
  } else if (argc == 3) {
    load(argv[1], scalar, x25519_size);
    load(argv[2], point, x25519_size);
  } else {
    fprintf(stderr, "Usage: %s SK [PK]\n", argv[0]);
    return 64;
  }

  if (x25519(point, scalar, point))
    errx(EXIT_FAILURE, "Invalid public identity");
  duplex_absorb(state, point, x25519_size);

  if (argc == 3) {
    uint8_t nonce[duplex_rate];
    if (get(in, nonce, duplex_rate) != duplex_rate)
      errx(EXIT_FAILURE, "Input is truncated");
    duplex_absorb(state, nonce, duplex_rate);
  }

  process(state);
  return EXIT_SUCCESS;
}
