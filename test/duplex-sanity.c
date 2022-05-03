#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define duplex_permute duplex_xoodoo
#include "duplex.h"

static void chunk_absorb(duplex_t state, uint8_t *buffer, size_t length,
    size_t chunk) {
  while (chunk <= length) {
    duplex_absorb(state, buffer, chunk);
    buffer += chunk, length -= chunk;
  }
  duplex_absorb(state, buffer, length);
  duplex_pad(state);
}

static void chunk_decrypt(duplex_t state, uint8_t *buffer, size_t length,
    size_t chunk) {
  while (chunk <= length) {
    duplex_decrypt(state, buffer, chunk);
    buffer += chunk, length -= chunk;
  }
  duplex_decrypt(state, buffer, length);
  duplex_pad(state);
}

static void chunk_encrypt(duplex_t state, uint8_t *buffer, size_t length,
    size_t chunk) {
  while (chunk <= length) {
    duplex_encrypt(state, buffer, chunk);
    buffer += chunk, length -= chunk;
  }
  duplex_encrypt(state, buffer, length);
  duplex_pad(state);
}

static void chunk_squeeze(duplex_t state, uint8_t *buffer, size_t length,
    size_t chunk) {
  while (chunk <= length) {
    duplex_squeeze(state, buffer, chunk);
    buffer += chunk, length -= chunk;
  }
  duplex_squeeze(state, buffer, length);
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
  duplex_t state1, state2;

  /* Check streaming absorb + pad matches a padded bulk absorb */
  for (size_t length = size - 15; length <= size; length++)
    for (size_t chunk = min; chunk <= max; chunk++) {
      fill(buffer1, buffer2, length);
      fill(state1, state2, duplex_size);
      duplex_absorb(state1, buffer1, length);
      duplex_pad(state1);
      chunk_absorb(state2, buffer2, length, chunk);
      if (memcmp(state1, state2, duplex_size))
        errx(EXIT_FAILURE, "Streaming absorb failure");
    }

  /* Check streaming decrypt + pad matches a padded bulk decrypt */
  for (size_t length = size - 15; length <= size; length++)
    for (size_t chunk = min; chunk <= max; chunk++) {
      fill(buffer1, buffer2, length);
      fill(state1, state2, duplex_size);
      duplex_decrypt(state1, buffer1, length);
      duplex_pad(state1);
      chunk_decrypt(state2, buffer2, length, chunk);
      if (memcmp(buffer1, buffer2, length))
        errx(EXIT_FAILURE, "Streaming decrypt failure");
      if (memcmp(state1, state2, duplex_size))
        errx(EXIT_FAILURE, "Streaming decrypt failure");
    }

  /* Check streaming encrypt + pad matches a padded bulk encrypt */
  for (size_t length = size - 15; length <= size; length++)
    for (size_t chunk = min; chunk <= max; chunk++) {
      fill(buffer1, buffer2, length);
      fill(state1, state2, duplex_size);
      duplex_encrypt(state1, buffer1, length);
      duplex_pad(state1);
      chunk_encrypt(state2, buffer2, length, chunk);
      if (memcmp(buffer1, buffer2, length))
        errx(EXIT_FAILURE, "Streaming encrypt failure");
      if (memcmp(state1, state2, duplex_size))
        errx(EXIT_FAILURE, "Streaming encrypt failure");
    }

  /* Check streaming squeeze matches a bulk squeeze */
  for (size_t chunk = min; chunk <= max; chunk++) {
    fill(buffer1, buffer2, size);
    fill(state1, state2, duplex_size);
    duplex_squeeze(state1, buffer1, size);
    chunk_squeeze(state2, buffer2, size, chunk);
    if (memcmp(buffer1, buffer2, size))
      errx(EXIT_FAILURE, "Streaming squeeze failure");
    if (memcmp(state1, state2, duplex_size))
      errx(EXIT_FAILURE, "Streaming squeeze failure");
  }

  printf("Streaming duplex operations sanity-checked\n");
  return EXIT_SUCCESS;
}
