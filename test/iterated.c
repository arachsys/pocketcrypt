#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "duplex.h"

const duplex_t million_gimli = {
  0xcd014b11, 0x3600b721, 0xe5a6b267, 0x7e31ef72,
  0x6acf6a77, 0xc39228cb, 0x030bd9fc, 0xf7e0e5f3,
  0x44b677bb, 0x2fb0f7e1, 0x62caa406, 0x45a04dda
};

const duplex_t million_xoodoo = {
  0x132741d3, 0x195c5141, 0xc98fd290, 0x692ece17,
  0x520bf69c, 0x59532f0c, 0xfcc454f5, 0xe30cd8d4,
  0x644a4f3b, 0xf1f7fd4a, 0xea2607d5, 0x832f8421
};

int main(void) {
  duplex_t gimli = { 0 }, xoodoo = { 0 };

  for (size_t i = 0; i < 1000000; i++)
    duplex_gimli(gimli);
  if (memcmp(gimli, million_gimli, sizeof(duplex_t))) /* variable time */
    errx(EXIT_FAILURE, "Iterated Gimli failure");

  for (size_t i = 0; i < 1000000; i++)
    duplex_xoodoo(xoodoo);
  if (memcmp(xoodoo, million_xoodoo, sizeof(duplex_t))) /* variable time */
    errx(EXIT_FAILURE, "Iterated Xoodoo failure");

  printf("Reference permutations checked\n");
  return EXIT_SUCCESS;
}
