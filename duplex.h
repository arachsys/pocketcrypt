/* duplex.h from Pocketcrypt: https://github.com/arachsys/pocketcrypt */

#ifndef DUPLEX_H
#define DUPLEX_H

#include <stddef.h>
#include <stdint.h>

#if defined __clang_major__ && __clang_major__ >= 4
#define duplex_swap(x, ...) __builtin_shufflevector(x, x, __VA_ARGS__)
#elif defined __GNUC__ && __GNUC__ >= 5
#define duplex_swap(x, ...) __builtin_shuffle(x, (typeof(x)) { __VA_ARGS__ })
#else
#error Vector extensions require clang >= 4.0.0 or gcc >= 5.1.0
#endif

#if defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define duplex_byte(state, i) ((uint8_t *) state)[i]
#define duplex_bytes(words) ((uint8x16_t) words)
#define duplex_r24 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12
#define duplex_rho 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6
#elif defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define duplex_byte(state, i) ((uint8_t *) state)[(i) ^ ((i) < 48 ? 3 : 7)]
#define duplex_bytes(words) duplex_swap((uint8x16_t) words, \
  3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12)
#define duplex_r24 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14
#define duplex_rho 9, 10, 11, 8, 13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4
#else
#error Byte order could not be determined
#endif

#define duplex_copy __builtin_memcpy
#define duplex_counter(state) ((uint64_t *) state)[6]
#define duplex_extra(state) ((uint64_t *) state)[7]
#define duplex_words(bytes) ((uint32x4_t) duplex_bytes(bytes))
#define duplex_rate 16

#ifndef duplex_permute
#define duplex_permute duplex_xoodoo
#endif

typedef uint8_t uint8x16_t __attribute__((vector_size(16)));
typedef uint32_t uint32x4_t __attribute__((vector_size(16)));
typedef uint32x4_t duplex_t[4];

static inline void duplex_gimli(uint32x4_t state[3]) {
  for (int round = 24; round > 0; round--) {
    uint32x4_t x = (uint32x4_t) duplex_swap((uint8x16_t) state[0], duplex_r24);
    uint32x4_t y = state[1] << 9 | state[1] >> 23;
    uint32x4_t z = state[2];

    state[2] = x ^ (z << 1) ^ ((y & z) << 2);
    state[1] = y ^ x ^ ((x | z) << 1);
    state[0] = z ^ y ^ ((x & y) << 3);

    switch (round & 3) {
      case 0:
        state[0] = duplex_swap(state[0], 1, 0, 3, 2);
        state[0] ^= (uint32x4_t) { 0x9e377900 | round, 0, 0, 0 };
        break;
      case 2:
        state[0] = duplex_swap(state[0], 2, 3, 0, 1);
        break;
    }
  }
}

static inline void duplex_xoodoo(uint32x4_t state[3]) {
  const uint32_t rk[12] = {
    0x058, 0x038, 0x3c0, 0x0d0, 0x120, 0x014,
    0x060, 0x02c, 0x380, 0x0f0, 0x1a0, 0x012
  };

  for (int round = 0; round < 12; round++) {
    uint32x4_t p = duplex_swap(state[0] ^ state[1] ^ state[2], 3, 0, 1, 2);
    uint32x4_t e = (p << 5 | p >> 27) ^ (p << 14 | p >> 18);
    state[0] ^= e, state[1] ^= e, state[2] ^= e;

    uint32x4_t x = state[0] ^ (uint32x4_t) { rk[round], 0, 0, 0 };
    uint32x4_t y = duplex_swap(state[1], 3, 0, 1, 2);
    uint32x4_t z = state[2] << 11 | state[2] >> 21;

    state[0] = x ^ (~y & z);
    state[1] = y ^ (~z & x);
    state[2] = z ^ (~x & y);

    state[1] = state[1] << 1 | state[1] >> 31;
    state[2] = (uint32x4_t) duplex_swap((uint8x16_t) state[2], duplex_rho);
  }
}

static inline void duplex_absorb(duplex_t state, const uint8_t *data,
    size_t length) {
  uint8_t offset = duplex_counter(state) & 15;
  duplex_counter(state) += length;

  while (1) {
    if (length < 16 || offset > 0) {
      for (int i = offset; i < 16; i++, length--) {
        if (length == 0)
          return;
        duplex_byte(state, i) ^= data[i - offset];
      }
      data += 16 - offset, offset = 0;
      duplex_permute(state);
    }

    while (length >= 16) {
      uint8x16_t chunk;
      duplex_copy(&chunk, data, 16);
      chunk ^= duplex_bytes(state[0]);
      state[0] = duplex_words(chunk);
      data += 16, length -= 16;
      duplex_permute(state);
    }
  }
}

static inline int duplex_compare(const uint8_t *a, const uint8_t *b,
    size_t length) {
  uint8_t result = 0;

  for (size_t i = 0; i < length; i++)
    result |=  (a ? a[i] : 0) ^ (b ? b[i] : 0);
  return result ? -1 : 0;
}

static inline void duplex_decrypt(duplex_t state, uint8_t *data,
    size_t length) {
  uint8_t offset = duplex_counter(state) & 15;
  duplex_counter(state) += length;

  while (1) {
    if (length < 16 || offset > 0) {
      for (int i = offset; i < 16; i++, length--) {
        if (length == 0)
          return;
        data[i - offset] ^= duplex_byte(state, i);
        duplex_byte(state, i) ^= data[i - offset];
      }
      data += 16 - offset, offset = 0;
      duplex_permute(state);
    }

    while (length >= 16) {
      uint8x16_t chunk;
      duplex_copy(&chunk, data, 16);
      chunk ^= duplex_bytes(state[0]);
      state[0] ^= duplex_words(chunk);
      duplex_copy(data, &chunk, 16);
      data += 16, length -= 16;
      duplex_permute(state);
    }
  }
}

static inline void duplex_encrypt(duplex_t state, uint8_t *data,
    size_t length) {
  uint8_t offset = duplex_counter(state) & 15;
  duplex_counter(state) += length;

  while (1) {
    if (length < 16 || offset > 0) {
      for (int i = offset; i < 16; i++, length--) {
        if (length == 0)
          return;
        duplex_byte(state, i) ^= data[i - offset];
        data[i - offset] = duplex_byte(state, i);
      }
      data += 16 - offset, offset = 0;
      duplex_permute(state);
    }

    while (length >= 16) {
      uint8x16_t chunk;
      duplex_copy(&chunk, data, 16);
      chunk ^= duplex_bytes(state[0]);
      duplex_copy(data, &chunk, 16);
      state[0] = duplex_words(chunk);
      data += 16, length -= 16;
      duplex_permute(state);
    }
  }
}

static inline void duplex_pad(duplex_t state) {
  uint8_t offset = duplex_counter(state) & 15;
  duplex_counter(state) += 16 - offset;

  duplex_byte(state, offset) ^= 1;
  duplex_byte(state, 47) ^= 1;
  duplex_permute(state);
}

static inline void duplex_ratchet(duplex_t state) {
  uint8_t offset = duplex_counter(state) & 15;
  duplex_counter(state) += 16;

  for (int i = offset; i < 16; i++)
    duplex_byte(state, i) = 0;
  duplex_permute(state);
  for (int i = 0; i < offset; i++)
    duplex_byte(state, i) = 0;
}

static inline void duplex_squeeze(duplex_t state, uint8_t *data,
    size_t length) {
  uint8_t offset = duplex_counter(state) & 15;
  duplex_counter(state) += length;

  while (1) {
    if (length < 16 || offset > 0) {
      for (int i = offset; i < 16; i++, length--) {
        if (length == 0)
          return;
        data[i - offset] = duplex_byte(state, i);
      }
      data += 16 - offset, offset = 0;
      duplex_permute(state);
    }

    while (length >= 16) {
      uint8x16_t chunk = duplex_bytes(state[0]);
      duplex_copy(data, &chunk, 16);
      data += 16, length -= 16;
      duplex_permute(state);
    }
  }
}

static inline void duplex_zero(void *data, size_t length) {
  __builtin_memset(data, 0, length);
  __asm__ __volatile__ ("" :: "r" (data) : "memory");
}

#endif
