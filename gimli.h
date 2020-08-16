/* gimli.h from Pocketcrypt: https://github.com/arachsys/pocketcrypt */

#ifndef GIMLI_H
#define GIMLI_H

#include <stddef.h>
#include <stdint.h>

#if defined __has_builtin && __has_builtin(__builtin_shufflevector)
#define gimli_swap(x, ...) __builtin_shufflevector(x, x, __VA_ARGS__)
#elif defined __has_builtin && __has_builtin(__builtin_shuffle)
#define gimli_swap(x, ...) __builtin_shuffle(x, (typeof(x)) { __VA_ARGS__ })
#else
#error Vector extensions are not available
#endif

#if defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define gimli_byte(state, i) ((uint8_t *) state)[i]
#define gimli_r24 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12
#elif defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define gimli_byte(state, i) ((uint8_t *) state)[i ^ 3]
#define gimli_r24 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14
#else
#error Byte order could not be determined
#endif

typedef uint8_t uint8x16_t __attribute__((vector_size(16)));
typedef uint32_t uint32x4_t __attribute__((vector_size(16)));
typedef uint32x4_t gimli_t[3];

static inline uint32x4_t gimli_rotate24(uint32x4_t row) {
  return (uint32x4_t) gimli_swap((uint8x16_t) row, gimli_r24);
}

static inline void gimli(gimli_t state) {
  for (size_t round = 24; round > 0; round--) {
    uint32x4_t x = gimli_rotate24(state[0]);
    uint32x4_t y = state[1] << 9 | state[1] >> 23;
    uint32x4_t z = state[2];

    state[2] = x ^ (z << 1) ^ ((y & z) << 2);
    state[1] = y ^ x ^ ((x | z) << 1);
    state[0] = z ^ y ^ ((x & y) << 3);

    switch (round & 3) {
      case 0:
        state[0] = gimli_swap(state[0], 1, 0, 3, 2);
        state[0] ^= (uint32x4_t) { 0x9e377900 | round, 0, 0, 0 };
        break;
      case 2:
        state[0] = gimli_swap(state[0], 2, 3, 0, 1);
        break;
    }
  }
}

static inline size_t gimli_absorb(gimli_t state, size_t counter,
    const uint8_t *data, size_t length) {
  uint8_t offset = counter & 15;
  counter += length;

  if (length + offset < 16) {
    for (uint8_t i = 0; i < length; i++)
      gimli_byte(state, i + offset) ^= data[i];
    return counter;
  }

  if (offset > 0) {
    for (uint8_t i = 0; i < 16 - offset; i++)
      gimli_byte(state, i + offset) ^= data[i];
    data += 16 - offset, length -= 16 - offset;
    gimli(state);
  }

  while (length >= 16) {
    for (uint8_t i = 0; i < 16; i++)
      gimli_byte(state, i) ^= data[i];
    data += 16, length -= 16;
    gimli(state);
  }

  for (uint8_t i = 0; i < length; i++)
    gimli_byte(state, i) ^= data[i];
  return counter;
}

static inline int gimli_compare(const uint8_t *a, const uint8_t *b,
    size_t length) {
  uint8_t result = 0;

  for (size_t i = 0; i < length; i++)
    result |=  (a ? a[i] : 0) ^ (b ? b[i] : 0);
  return result ? -1 : 0;
}

static inline size_t gimli_decrypt(gimli_t state, size_t counter,
    uint8_t *data, size_t length) {
  uint8_t offset = counter & 15;
  counter += length;

  if (length + offset < 16) {
    for (uint8_t i = 0; i < length; i++)
      data[i] ^= gimli_byte(state, i + offset);
    for (uint8_t i = 0; i < length; i++)
      gimli_byte(state, i + offset) ^= data[i];
    return counter;
  }

  if (offset > 0) {
    for (uint8_t i = 0; i < 16 - offset; i++)
      data[i] ^= gimli_byte(state, i + offset);
    for (uint8_t i = 0; i < 16 - offset; i++)
      gimli_byte(state, i + offset) ^= data[i];
    data += 16 - offset, length -= 16 - offset;
    gimli(state);
  }

  while (length >= 16) {
    for (uint8_t i = 0; i < 16; i++)
      data[i] ^= gimli_byte(state, i);
    for (uint8_t i = 0; i < 16; i++)
      gimli_byte(state, i) ^= data[i];
    data += 16, length -= 16;
    gimli(state);
  }

  for (uint8_t i = 0; i < length; i++)
    data[i] ^= gimli_byte(state, i);
  for (uint8_t i = 0; i < length; i++)
    gimli_byte(state, i) ^= data[i];
  return counter;
}

static inline size_t gimli_encrypt(gimli_t state, size_t counter,
    uint8_t *data, size_t length) {
  uint8_t offset = counter & 15;
  counter += length;

  if (length + offset < 16) {
    for (uint8_t i = 0; i < length; i++)
      gimli_byte(state, i + offset) ^= data[i];
    for (uint8_t i = 0; i < length; i++)
      data[i] = gimli_byte(state, i + offset);
    return counter;
  }

  if (offset > 0) {
    for (uint8_t i = 0; i < 16 - offset; i++)
      gimli_byte(state, i + offset) ^= data[i];
    for (uint8_t i = 0; i < 16 - offset; i++)
      data[i] = gimli_byte(state, i + offset);
    data += 16 - offset, length -= 16 - offset;
    gimli(state);
  }

  while (length >= 16) {
    for (uint8_t i = 0; i < 16; i++)
      gimli_byte(state, i) ^= data[i];
    for (uint8_t i = 0; i < 16; i++)
      data[i] = gimli_byte(state, i);
    data += 16, length -= 16;
    gimli(state);
  }

  for (uint8_t i = 0; i < length; i++)
    gimli_byte(state, i) ^= data[i];
  for (uint8_t i = 0; i < length; i++)
    data[i] = gimli_byte(state, i);
  return counter;
}

static inline size_t gimli_pad(gimli_t state, size_t counter) {
  gimli_byte(state, counter & 15) ^= 1;
  gimli_byte(state, 47) ^= 1;
  gimli(state);
  return (counter | 15) + 1;
}

static inline size_t gimli_ratchet(gimli_t state, size_t counter) {
  for (uint8_t i = counter & 15; i < 16; i++)
    gimli_byte(state, i) = 0;
  gimli(state);
  for (uint8_t i = 0; i < (counter & 15); i++)
    gimli_byte(state, i) = 0;
  return counter + 16;
}

static inline size_t gimli_squeeze(gimli_t state, size_t counter,
    uint8_t *data, size_t length) {
  uint8_t offset = counter & 15;
  counter += length;

  if (length + offset < 16) {
    for (uint8_t i = 0; i < length; i++)
      data[i] = gimli_byte(state, i + offset);
    return counter;
  }

  if (offset > 0) {
    for (uint8_t i = 0; i < 16 - offset; i++)
      data[i] = gimli_byte(state, i + offset);
    data += 16 - offset, length -= 16 - offset;
    gimli(state);
  }

  while (length >= 16) {
    for (uint8_t i = 0; i < 16; i++)
      data[i] = gimli_byte(state, i);
    data += 16, length -= 16;
    gimli(state);
  }

  for (uint8_t i = 0; i < length; i++)
    data[i] = gimli_byte(state, i);
  return counter;
}

#endif
