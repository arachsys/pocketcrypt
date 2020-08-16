/* xoodoo.h from Pocketcrypt: https://github.com/arachsys/pocketcrypt */

#ifndef XOODOO_H
#define XOODOO_H

#include <stddef.h>
#include <stdint.h>

#if defined __has_builtin && __has_builtin(__builtin_shufflevector)
#define xoodoo_swap(x, ...) __builtin_shufflevector(x, x, __VA_ARGS__)
#elif defined __has_builtin && __has_builtin(__builtin_shuffle)
#define xoodoo_swap(x, ...) __builtin_shuffle(x, (typeof(x)) { __VA_ARGS__ })
#else
#error Vector extensions are not available
#endif

#if defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define xoodoo_byte(state, i) ((uint8_t *) state)[i]
#define xoodoo_rho 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6
#elif defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define xoodoo_byte(state, i) ((uint8_t *) state)[i ^ 3]
#define xoodoo_rho 9, 10, 11, 8, 13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4
#else
#error Byte order could not be determined
#endif

typedef uint8_t uint8x16_t __attribute__((vector_size(16)));
typedef uint32_t uint32x4_t __attribute__((vector_size(16)));
typedef uint32x4_t xoodoo_t[3];

static inline void xoodoo(xoodoo_t state) {
  const uint32_t rk[12] = {
    0x058, 0x038, 0x3c0, 0x0d0, 0x120, 0x014,
    0x060, 0x02c, 0x380, 0x0f0, 0x1a0, 0x012
  };

  for (size_t round = 0; round < 12; round++) {
    uint32x4_t p = xoodoo_swap(state[0] ^ state[1] ^ state[2], 3, 0, 1, 2);
    uint32x4_t e = (p << 5 | p >> 27) ^ (p << 14 | p >> 18);
    state[0] ^= e, state[1] ^= e, state[2] ^= e;

    state[0] ^= (uint32x4_t) { rk[round], 0, 0, 0 };
    state[1] = xoodoo_swap(state[1], 3, 0, 1, 2);
    state[2] = state[2] << 11 | state[2] >> 21;

    state[0] ^= ~state[1] & state[2];
    state[1] ^= ~state[2] & state[0];
    state[2] ^= ~state[0] & state[1];

    state[1] = state[1] << 1 | state[1] >> 31;
    state[2] = (uint32x4_t) xoodoo_swap((uint8x16_t) state[2], xoodoo_rho);
  }
}

static inline size_t xoodoo_absorb(xoodoo_t state, size_t counter,
    const uint8_t *data, size_t length) {
  uint8_t offset = counter & 15;
  counter += length;

  if (length + offset < 16) {
    for (uint8_t i = 0; i < length; i++)
      xoodoo_byte(state, i + offset) ^= data[i];
    return counter;
  }

  if (offset > 0) {
    for (uint8_t i = 0; i < 16 - offset; i++)
      xoodoo_byte(state, i + offset) ^= data[i];
    data += 16 - offset, length -= 16 - offset;
    xoodoo(state);
  }

  while (length >= 16) {
    for (uint8_t i = 0; i < 16; i++)
      xoodoo_byte(state, i) ^= data[i];
    data += 16, length -= 16;
    xoodoo(state);
  }

  for (uint8_t i = 0; i < length; i++)
    xoodoo_byte(state, i) ^= data[i];
  return counter;
}

static inline int xoodoo_compare(const uint8_t *a, const uint8_t *b,
    size_t length) {
  uint8_t result = 0;

  for (size_t i = 0; i < length; i++)
    result |=  (a ? a[i] : 0) ^ (b ? b[i] : 0);
  return result ? -1 : 0;
}

static inline size_t xoodoo_decrypt(xoodoo_t state, size_t counter,
    uint8_t *data, size_t length) {
  uint8_t offset = counter & 15;
  counter += length;

  if (length + offset < 16) {
    for (uint8_t i = 0; i < length; i++)
      data[i] ^= xoodoo_byte(state, i + offset);
    for (uint8_t i = 0; i < length; i++)
      xoodoo_byte(state, i + offset) ^= data[i];
    return counter;
  }

  if (offset > 0) {
    for (uint8_t i = 0; i < 16 - offset; i++)
      data[i] ^= xoodoo_byte(state, i + offset);
    for (uint8_t i = 0; i < 16 - offset; i++)
      xoodoo_byte(state, i + offset) ^= data[i];
    data += 16 - offset, length -= 16 - offset;
    xoodoo(state);
  }

  while (length >= 16) {
    for (uint8_t i = 0; i < 16; i++)
      data[i] ^= xoodoo_byte(state, i);
    for (uint8_t i = 0; i < 16; i++)
      xoodoo_byte(state, i) ^= data[i];
    data += 16, length -= 16;
    xoodoo(state);
  }

  for (uint8_t i = 0; i < length; i++)
    data[i] ^= xoodoo_byte(state, i);
  for (uint8_t i = 0; i < length; i++)
    xoodoo_byte(state, i) ^= data[i];
  return counter;
}

static inline size_t xoodoo_encrypt(xoodoo_t state, size_t counter,
    uint8_t *data, size_t length) {
  uint8_t offset = counter & 15;
  counter += length;

  if (length + offset < 16) {
    for (uint8_t i = 0; i < length; i++)
      xoodoo_byte(state, i + offset) ^= data[i];
    for (uint8_t i = 0; i < length; i++)
      data[i] = xoodoo_byte(state, i + offset);
    return counter;
  }

  if (offset > 0) {
    for (uint8_t i = 0; i < 16 - offset; i++)
      xoodoo_byte(state, i + offset) ^= data[i];
    for (uint8_t i = 0; i < 16 - offset; i++)
      data[i] = xoodoo_byte(state, i + offset);
    data += 16 - offset, length -= 16 - offset;
    xoodoo(state);
  }

  while (length >= 16) {
    for (uint8_t i = 0; i < 16; i++)
      xoodoo_byte(state, i) ^= data[i];
    for (uint8_t i = 0; i < 16; i++)
      data[i] = xoodoo_byte(state, i);
    data += 16, length -= 16;
    xoodoo(state);
  }

  for (uint8_t i = 0; i < length; i++)
    xoodoo_byte(state, i) ^= data[i];
  for (uint8_t i = 0; i < length; i++)
    data[i] = xoodoo_byte(state, i);
  return counter;
}

static inline size_t xoodoo_pad(xoodoo_t state, size_t counter) {
  xoodoo_byte(state, counter & 15) ^= 1;
  xoodoo_byte(state, 47) ^= 1;
  xoodoo(state);
  return (counter | 15) + 1;
}

static inline size_t xoodoo_ratchet(xoodoo_t state, size_t counter) {
  for (uint8_t i = counter & 15; i < 16; i++)
    xoodoo_byte(state, i) = 0;
  xoodoo(state);
  for (uint8_t i = 0; i < (counter & 15); i++)
    xoodoo_byte(state, i) = 0;
  return counter + 16;
}

static inline size_t xoodoo_squeeze(xoodoo_t state, size_t counter,
    uint8_t *data, size_t length) {
  uint8_t offset = counter & 15;
  counter += length;

  if (length + offset < 16) {
    for (uint8_t i = 0; i < length; i++)
      data[i] = xoodoo_byte(state, i + offset);
    return counter;
  }

  if (offset > 0) {
    for (uint8_t i = 0; i < 16 - offset; i++)
      data[i] = xoodoo_byte(state, i + offset);
    data += 16 - offset, length -= 16 - offset;
    xoodoo(state);
  }

  while (length >= 16) {
    for (uint8_t i = 0; i < 16; i++)
      data[i] = xoodoo_byte(state, i);
    data += 16, length -= 16;
    xoodoo(state);
  }

  for (uint8_t i = 0; i < length; i++)
    data[i] = xoodoo_byte(state, i);
  return counter;
}

#endif
