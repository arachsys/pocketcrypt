#include <stdio.h>
#include <stdlib.h>

#include "shamir.h"
#include "util.h"

int main(int argc, char **argv) {
  size_t threshold = argv[1] ? strtoul(argv[1], NULL, 10) : 0;

  if (threshold && threshold < 256 && threshold + 2 < argc) {
    secret_t entropy[threshold - 1], secret;
    share_t share;

    load(argv[2], secret, secret_size);
    for (int i = 0; i < threshold - 1; i++)
      randomise(entropy[i], secret_size);

    for (int i = 0; i < argc - 3; i++) {
      shamir_split(share, i, threshold, secret, entropy);
      save(argv[i + 3], share, share_size);
    }
    return EXIT_SUCCESS;
  }

  fprintf(stderr, "Usage: %s THRESHOLD SECRET SHARE...\n", argv[0]);
  return 64;
}
