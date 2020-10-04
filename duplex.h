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
#define duplex_r24 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12
#define duplex_rho 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6
#elif defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define duplex_byte(state, i) ((uint8_t *) state)[i ^ 3]
#define duplex_r24 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14
#define duplex_rho 9, 10, 11, 8, 13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4
#else
#error Byte order could not be determined
#endif

#ifndef duplex_permute
#define duplex_permute duplex_gimli
#endif

typedef uint8_t uint8x16_t __attribute__((vector_size(16)));
typedef uint32_t uint32x4_t __attribute__((vector_size(16)));
typedef uint32x4_t duplex_t[3];

static const size_t duplex_rate = 16;

static inline uint32x4_t duplex_rotate24(uint32x4_t row) {
  return (uint32x4_t) duplex_swap((uint8x16_t) row, duplex_r24);
}

static inline void duplex_gimli(duplex_t state) {
  for (size_t round = 24; round > 0; round--) {
    uint32x4_t x = duplex_rotate24(state[0]);
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

static inline void duplex_xoodoo(duplex_t state) {
  const uint32_t rk[12] = {
    0x058, 0x038, 0x3c0, 0x0d0, 0x120, 0x014,
    0x060, 0x02c, 0x380, 0x0f0, 0x1a0, 0x012
  };

  for (size_t round = 0; round < 12; round++) {
    uint32x4_t p = duplex_swap(state[0] ^ state[1] ^ state[2], 3, 0, 1, 2);
    uint32x4_t e = (p << 5 | p >> 27) ^ (p << 14 | p >> 18);
    state[0] ^= e, state[1] ^= e, state[2] ^= e;

    state[0] ^= (uint32x4_t) { rk[round], 0, 0, 0 };
    state[1] = duplex_swap(state[1], 3, 0, 1, 2);
    state[2] = state[2] << 11 | state[2] >> 21;

    state[0] ^= ~state[1] & state[2];
    state[1] ^= ~state[2] & state[0];
    state[2] ^= ~state[0] & state[1];

    state[1] = state[1] << 1 | state[1] >> 31;
    state[2] = (uint32x4_t) duplex_swap((uint8x16_t) state[2], duplex_rho);
  }
}

static inline size_t duplex_absorb(duplex_t state, size_t counter,
    const uint8_t *data, size_t length) {
  uint8_t offset = counter & 15;
  counter += length;

  if (length + offset < 16) {
    for (uint8_t i = 0; i < length; i++)
      duplex_byte(state, i + offset) ^= data[i];
    return counter;
  }

  if (offset > 0) {
    for (uint8_t i = 0; i < 16 - offset; i++)
      duplex_byte(state, i + offset) ^= data[i];
    data += 16 - offset, length -= 16 - offset;
    duplex_permute(state);
  }

  while (length >= 16) {
    for (uint8_t i = 0; i < 16; i++)
      duplex_byte(state, i) ^= data[i];
    data += 16, length -= 16;
    duplex_permute(state);
  }

  for (uint8_t i = 0; i < length; i++)
    duplex_byte(state, i) ^= data[i];
  return counter;
}

static inline int duplex_compare(const uint8_t *a, const uint8_t *b,
    size_t length) {
  uint8_t result = 0;

  for (size_t i = 0; i < length; i++)
    result |=  (a ? a[i] : 0) ^ (b ? b[i] : 0);
  return result ? -1 : 0;
}

static inline size_t duplex_decrypt(duplex_t state, size_t counter,
    uint8_t *data, size_t length) {
  uint8_t offset = counter & 15;
  counter += length;

  if (length + offset < 16) {
    for (uint8_t i = 0; i < length; i++)
      data[i] ^= duplex_byte(state, i + offset);
    for (uint8_t i = 0; i < length; i++)
      duplex_byte(state, i + offset) ^= data[i];
    return counter;
  }

  if (offset > 0) {
    for (uint8_t i = 0; i < 16 - offset; i++)
      data[i] ^= duplex_byte(state, i + offset);
    for (uint8_t i = 0; i < 16 - offset; i++)
      duplex_byte(state, i + offset) ^= data[i];
    data += 16 - offset, length -= 16 - offset;
    duplex_permute(state);
  }

  while (length >= 16) {
    for (uint8_t i = 0; i < 16; i++)
      data[i] ^= duplex_byte(state, i);
    for (uint8_t i = 0; i < 16; i++)
      duplex_byte(state, i) ^= data[i];
    data += 16, length -= 16;
    duplex_permute(state);
  }

  for (uint8_t i = 0; i < length; i++)
    data[i] ^= duplex_byte(state, i);
  for (uint8_t i = 0; i < length; i++)
    duplex_byte(state, i) ^= data[i];
  return counter;
}

static inline size_t duplex_encrypt(duplex_t state, size_t counter,
    uint8_t *data, size_t length) {
  uint8_t offset = counter & 15;
  counter += length;

  if (length + offset < 16) {
    for (uint8_t i = 0; i < length; i++)
      duplex_byte(state, i + offset) ^= data[i];
    for (uint8_t i = 0; i < length; i++)
      data[i] = duplex_byte(state, i + offset);
    return counter;
  }

  if (offset > 0) {
    for (uint8_t i = 0; i < 16 - offset; i++)
      duplex_byte(state, i + offset) ^= data[i];
    for (uint8_t i = 0; i < 16 - offset; i++)
      data[i] = duplex_byte(state, i + offset);
    data += 16 - offset, length -= 16 - offset;
    duplex_permute(state);
  }

  while (length >= 16) {
    for (uint8_t i = 0; i < 16; i++)
      duplex_byte(state, i) ^= data[i];
    for (uint8_t i = 0; i < 16; i++)
      data[i] = duplex_byte(state, i);
    data += 16, length -= 16;
    duplex_permute(state);
  }

  for (uint8_t i = 0; i < length; i++)
    duplex_byte(state, i) ^= data[i];
  for (uint8_t i = 0; i < length; i++)
    data[i] = duplex_byte(state, i);
  return counter;
}

static inline size_t duplex_pad(duplex_t state, size_t counter) {
  duplex_byte(state, counter & 15) ^= 1;
  duplex_byte(state, 47) ^= 1;
  duplex_permute(state);
  return (counter | 15) + 1;
}

static inline size_t duplex_ratchet(duplex_t state, size_t counter) {
  for (uint8_t i = counter & 15; i < 16; i++)
    duplex_byte(state, i) = 0;
  duplex_permute(state);
  for (uint8_t i = 0; i < (counter & 15); i++)
    duplex_byte(state, i) = 0;
  return counter + 16;
}

static inline size_t duplex_squeeze(duplex_t state, size_t counter,
    uint8_t *data, size_t length) {
  uint8_t offset = counter & 15;
  counter += length;

  if (length + offset < 16) {
    for (uint8_t i = 0; i < length; i++)
      data[i] = duplex_byte(state, i + offset);
    return counter;
  }

  if (offset > 0) {
    for (uint8_t i = 0; i < 16 - offset; i++)
      data[i] = duplex_byte(state, i + offset);
    data += 16 - offset, length -= 16 - offset;
    duplex_permute(state);
  }

  while (length >= 16) {
    for (uint8_t i = 0; i < 16; i++)
      data[i] = duplex_byte(state, i);
    data += 16, length -= 16;
    duplex_permute(state);
  }

  for (uint8_t i = 0; i < length; i++)
    data[i] = duplex_byte(state, i);
  return counter;
}

#endif
