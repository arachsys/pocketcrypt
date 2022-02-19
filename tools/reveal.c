#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "duplex.h"
#include "swirl.h"
#include "util.h"

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
  size_t size = argc >= 2 ? strtoul(argv[1], NULL, 10) : 64;
  size_t rounds = argc >= 3 ? strtoul(argv[2], NULL, 10) : 2;

  if (argc <= 3 && size > 0 && rounds > 0) {
    duplex_t seed, state = { 0 };
    uint8_t salt[duplex_rate];
    void *buffer, *password;

    if ((password = getpass("Password: ")) == NULL)
      errx(EXIT_FAILURE, "Failed to read password");
    if (get(in, salt, duplex_rate) != duplex_rate)
      errx(EXIT_FAILURE, "Input is truncated");

    duplex_absorb(state, salt, duplex_rate);
    memcpy(seed, state, sizeof(seed));
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
