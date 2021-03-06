#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "duplex.h"
#include "swirl.h"
#include "util.h"

static void process(duplex_t state) {
  size_t length;
  uint8_t *data;

  if ((data = malloc(chunk)) == NULL)
    err(EXIT_FAILURE, "malloc");

  while ((length = get(in, data, chunk))) {
    duplex_encrypt(state, data, length);
    put(out, data, length);
  }
  duplex_pad(state);

  duplex_squeeze(state, data, duplex_rate);
  put(out, data, duplex_rate);
  free(data);
}

int main(int argc, char **argv) {
  size_t size = argc >= 2 ? strtoul(argv[1], NULL, 10) : 64;
  size_t rounds = argc >= 3 ? strtoul(argv[2], NULL, 10) : 2;

  if (argc <= 3 && size > 0 && rounds > 0) {
    duplex_t seed, state = { 0 };
    uint8_t salt[duplex_rate];
    void *buffer, *password;

    if ((password = getpass("Password: ")) == NULL)
      errx(EXIT_FAILURE, "Failed to read password");
    randomise(salt, duplex_rate);
    put(out, salt, duplex_rate);

    duplex_absorb(state, salt, duplex_rate);
    duplex_copy(seed, state, sizeof(state));
    duplex_absorb(state, password, strlen(password));
    duplex_pad(state);

    if ((buffer = malloc(size << 20)) == NULL)
      err(EXIT_FAILURE, "malloc");
    duplex_swirl(state, seed, buffer, size << 20, rounds);
    free(buffer);

    process(state);
    return EXIT_SUCCESS;
  }

  fprintf(stderr, "Usage: %s [SIZE [ROUNDS]]\n", argv[0]);
  fprintf(stderr, "By default, SIZE is 64 (MB) and ROUNDS is 2.\n");
  return 64;
}
