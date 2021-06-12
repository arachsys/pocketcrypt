#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "duplex.h"
#include "util.h"
#include "x25519.h"

static void process(duplex_t state) {
  size_t count, length = 0;
  uint8_t *data = NULL;

  do {
    if ((data = realloc(data, length + chunk)) == NULL)
      err(EXIT_FAILURE, "realloc");
    length += count = get(in, data + length, chunk);
  } while (count == chunk);

  if (length < duplex_rate)
    errx(EXIT_FAILURE, "Input is truncated");
  length = length - duplex_rate;

  duplex_decrypt(state, data, length);
  duplex_pad(state);

  duplex_decrypt(state, data + length, duplex_rate);
  if (duplex_compare(data + length, 0, duplex_rate))
    errx(EXIT_FAILURE, "Authentication failed");

  put(out, data, length);
  free(data);
}

int main(int argc, char **argv) {
  duplex_t state = { 0 };
  x25519_t point, scalar;

  if (argc == 2) {
    load(argv[1], scalar, sizeof(scalar));
    if (get(in, point, sizeof(point)) != sizeof(point))
      errx(EXIT_FAILURE, "Input is truncated");
  } else if (argc == 3) {
    load(argv[1], scalar, sizeof(scalar));
    load(argv[2], point, sizeof(point));
  } else {
    fprintf(stderr, "Usage: %s SK [PK]\n", argv[0]);
    return 64;
  }

  if (x25519(point, scalar, point))
    errx(EXIT_FAILURE, "Invalid public identity");
  duplex_absorb(state, point, sizeof(point));

  if (argc == 3) {
    uint8_t nonce[duplex_rate];
    if (get(in, nonce, duplex_rate) != duplex_rate)
      errx(EXIT_FAILURE, "Input is truncated");
    duplex_absorb(state, nonce, duplex_rate);
  }

  process(state);
  return EXIT_SUCCESS;
}
