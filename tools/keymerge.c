#include <stdio.h>
#include <stdlib.h>

#include "shamir.h"
#include "util.h"

int main(int argc, char **argv) {
  if (argc >= 3) {
    secret_t secret;
    share_t shares[argc - 2];

    for (int i = 0; i < argc - 2; i++)
      load(argv[i + 2], shares[i], sizeof(share_t));
    shamir_combine(secret, argc - 2, shares);

    save(argv[1], secret, sizeof(secret));
    return EXIT_SUCCESS;
  }

  fprintf(stderr, "Usage: %s SECRET SHARE...\n", argv[0]);
  return 64;
}
