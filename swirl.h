/* swirl.h from Pocketcrypt: https://github.com/arachsys/pocketcrypt */

#ifndef SWIRL_H
#define SWIRL_H

#include <stddef.h>
#include <stdint.h>
#include "duplex.h"

static inline void duplex_spin(duplex_t state, size_t rounds) {
  for (size_t round = 0; round < rounds; round++)
    duplex_permute(state);
  duplex_counter(state) += rounds << 4;
}

static inline void duplex_swirl(duplex_t state, duplex_t seed, void *buffer,
    size_t size, size_t independent, size_t dependent) {
  uint32x4_t (*cells)[64] = buffer; /* 1kB pages of 64 uint32x4_t cells */
  size_t pages = size >> 42 ? 1ull << 32 : size >> 10;

  /* Argon2B graph, data-independent rounds before data-dependent rounds */
  for (size_t round = 0; round < independent + dependent; round++) {
    for (size_t page = 0; page < pages; page++) {
      uint64_t key = round < independent ? seed[0][page & 3] : state[0][0];
      uint64_t offset = 2 + ((key * key >> 32) * (page - 1) >> 32);
      for (size_t slot = 0; slot < 64; slot++) {
        if (round > 0)
          state[0] ^= cells[page][slot];
        if (page > 0)
          state[0] ^= cells[page - 1][slot];
        if (page > 1)
          state[0] ^= cells[page - offset][slot];
        duplex_spin(state, 1);
        cells[page][slot] = state[0];
      }
      if (round < independent && (page & 3) == 3)
        duplex_spin(seed, 1);
    }
    if (round < independent && (pages & 3) != 0)
      duplex_spin(seed, 1);
  }
}

#endif
