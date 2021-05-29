/* swirl.h from Pocketcrypt: https://github.com/arachsys/pocketcrypt */

#ifndef SWIRL_H
#define SWIRL_H

#include <stddef.h>
#include <stdint.h>
#include "duplex.h"

static inline void duplex_spin(duplex_t state, size_t rounds) {
  while (rounds-- > 0)
    duplex_permute(state);
}

static inline void duplex_swirl(duplex_t state, duplex_t seed, void *buffer,
    size_t size, size_t rounds) {
  uint32x4_t *cells = buffer; /* 1kB pages of 64 uint32x4_t cells */
  size_t pages = size >> 42 ? 1ull << 32 : size >> 10;

  /* Argon2B graph, data-independent for the first round only */
  for (size_t round = 0; round < rounds; round++)
    for (size_t page = 0; page < pages; page++) {
      uint64_t key = round == 0 ? seed[0][page & 3] : state[0][0];
      uint64_t offset = 128 + ((key * key >> 32) * (page - 1) >> 32 << 6);
      for (size_t slot = page << 6; slot >> 6 == page; slot++) {
        if (page > 1)
          state[0] ^= cells[slot - offset];
        if (round > 0)
          state[0] ^= cells[slot];
        duplex_permute(state);
        cells[slot] = state[0];
      }
      if (round == 0 && (page & 3) == 3)
        duplex_permute(seed);
    }

  if (pages & 3)
    duplex_permute(seed);
  duplex_counter(seed) += (uint64_t) (pages + 3) >> 2 << 4;
  duplex_counter(state) += (uint64_t) rounds * pages << 10;
}

#endif
