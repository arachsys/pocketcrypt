#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gimli.h"

void chunk_absorb(gimli_t state, uint8_t *buffer, size_t length,
    size_t chunk) {
  while (chunk <= length) {
    size_t tail = gimli_absorb(state, buffer, chunk, 0);
    buffer += chunk - tail, length -= chunk - tail;
  }
  gimli_absorb(state, buffer, length, 1);
}

void chunk_decrypt(gimli_t state, uint8_t *buffer, size_t length,
    size_t chunk) {
  while (chunk <= length) {
    size_t tail = gimli_decrypt(state, buffer, chunk, 0);
    buffer += chunk - tail, length -= chunk - tail;
  }
  gimli_decrypt(state, buffer, length, 1);
}

void chunk_encrypt(gimli_t state, uint8_t *buffer, size_t length,
    size_t chunk) {
  while (chunk <= length) {
    size_t tail = gimli_encrypt(state, buffer, chunk, 0);
    buffer += chunk - tail, length -= chunk - tail;
  }
  gimli_encrypt(state, buffer, length, 1);
}

static void fill(void *out1, void *out2, size_t length) {
  static uint32_t seed = 0x12345678;
  for (size_t i = 0; i < length; i++) {
    seed += seed * seed | 5;
    ((uint8_t *) out1)[i] = seed >> 24;
    ((uint8_t *) out2)[i] = seed >> 24;
  }
}

int main(void) {
  const size_t min = 16, max = 48, size = 4096;
  uint8_t buffer1[size], buffer2[size];
  gimli_t state1, state2;

  /* Check streaming absorb + pad matches a padded bulk absorb */
  for (size_t length = size - 15; length <= size; length++)
    for (size_t chunk = min; chunk <= max; chunk++) {
      fill(buffer1, buffer2, length);
      fill(state1, state2, sizeof(gimli_t));
      gimli_absorb(state1, buffer1, length, 1);
      chunk_absorb(state2, buffer2, length, chunk);
      if (memcmp(state1, state2, sizeof(gimli_t)))
        errx(EXIT_FAILURE, "Streaming absorb failure");
    }

  /* Check streaming decrypt + pad matches a padded bulk decrypt */
  for (size_t length = size - 15; length <= size; length++)
    for (size_t chunk = min; chunk <= max; chunk++) {
      fill(buffer1, buffer2, length);
      fill(state1, state2, sizeof(gimli_t));
      gimli_decrypt(state1, buffer1, length, 1);
      chunk_decrypt(state2, buffer2, length, chunk);
      if (memcmp(buffer1, buffer2, length))
        errx(EXIT_FAILURE, "Streaming decrypt failure");
      if (memcmp(state1, state2, sizeof(gimli_t)))
        errx(EXIT_FAILURE, "Streaming decrypt failure");
    }

  /* Check streaming encrypt + pad matches a padded bulk encrypt */
  for (size_t length = size - 15; length <= size; length++)
    for (size_t chunk = min; chunk <= max; chunk++) {
      fill(buffer1, buffer2, length);
      fill(state1, state2, sizeof(gimli_t));
      gimli_encrypt(state1, buffer1, length, 1);
      chunk_encrypt(state2, buffer2, length, chunk);
      if (memcmp(buffer1, buffer2, length))
        errx(EXIT_FAILURE, "Streaming encrypt failure");
      if (memcmp(state1, state2, sizeof(gimli_t)))
        errx(EXIT_FAILURE, "Streaming encrypt failure");
    }

  /* Check chunk-by-chunk squeeze matches a bulk squeeze */
  fill(state1, state2, sizeof(gimli_t));
  gimli_squeeze(state1, buffer1, size);
  for (size_t i = 0; i < size; i += 16)
    gimli_squeeze(state2, buffer2 + i, size < i + 16 ? size - i : 16);
  if (memcmp(buffer1, buffer2, size))
    errx(EXIT_FAILURE, "Streaming squeeze failure");

  printf("Streaming duplex operations sanity-checked\n");
  return EXIT_SUCCESS;
}
