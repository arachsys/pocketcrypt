#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gimli.h"

static void chunk_absorb(gimli_t state, uint8_t *buffer, size_t length,
    size_t chunk) {
  size_t offset = 0;
  while (chunk <= length) {
    offset = gimli_absorb(state, offset, buffer, chunk);
    buffer += chunk, length -= chunk;
  }
  gimli_pad(state, gimli_absorb(state, offset, buffer, length));
}

static void chunk_decrypt(gimli_t state, uint8_t *buffer, size_t length,
    size_t chunk) {
  size_t offset = 0;
  while (chunk <= length) {
    offset = gimli_decrypt(state, offset, buffer, chunk);
    buffer += chunk, length -= chunk;
  }
  gimli_pad(state, gimli_decrypt(state, offset, buffer, length));
}

static void chunk_encrypt(gimli_t state, uint8_t *buffer, size_t length,
    size_t chunk) {
  size_t offset = 0;
  while (chunk <= length) {
    offset = gimli_encrypt(state, offset, buffer, chunk);
    buffer += chunk, length -= chunk;
  }
  gimli_pad(state, gimli_encrypt(state, offset, buffer, length));
}

static void chunk_squeeze(gimli_t state, uint8_t *buffer, size_t length,
    size_t chunk) {
  size_t offset = 0;
  while (chunk <= length) {
    offset = gimli_squeeze(state, offset, buffer, chunk);
    buffer += chunk, length -= chunk;
  }
  gimli_squeeze(state, offset, buffer, length);
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
      gimli_pad(state1, gimli_absorb(state1, 0, buffer1, length));
      chunk_absorb(state2, buffer2, length, chunk);
      if (memcmp(state1, state2, sizeof(gimli_t)))
        errx(EXIT_FAILURE, "Streaming absorb failure");
    }

  /* Check streaming decrypt + pad matches a padded bulk decrypt */
  for (size_t length = size - 15; length <= size; length++)
    for (size_t chunk = min; chunk <= max; chunk++) {
      fill(buffer1, buffer2, length);
      fill(state1, state2, sizeof(gimli_t));
      gimli_pad(state1, gimli_decrypt(state1, 0, buffer1, length));
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
      gimli_pad(state1, gimli_encrypt(state1, 0, buffer1, length));
      chunk_encrypt(state2, buffer2, length, chunk);
      if (memcmp(buffer1, buffer2, length))
        errx(EXIT_FAILURE, "Streaming encrypt failure");
      if (memcmp(state1, state2, sizeof(gimli_t)))
        errx(EXIT_FAILURE, "Streaming encrypt failure");
    }

  /* Check streaming squeeze matches a bulk squeeze */
  for (size_t chunk = min; chunk <= max; chunk++) {
    fill(buffer1, buffer2, size);
    fill(state1, state2, sizeof(gimli_t));
    gimli_squeeze(state1, 0, buffer1, size);
    chunk_squeeze(state2, buffer2, size, chunk);
    if (memcmp(buffer1, buffer2, size))
      errx(EXIT_FAILURE, "Streaming squeeze failure");
    if (memcmp(state1, state2, sizeof(gimli_t)))
      errx(EXIT_FAILURE, "Streaming squeeze failure");
  }

  printf("Streaming duplex operations sanity-checked\n");
  return EXIT_SUCCESS;
}
