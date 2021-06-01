/* shamir.c from Pocketcrypt: https://github.com/arachsys/pocketcrypt */

#include <stdint.h>

typedef uint8_t secret_t[32];
typedef uint8_t share_t[33];
typedef uint32_t sliced_t[8];

static void add(sliced_t r, const sliced_t x, const sliced_t y) {
  for (int i = 0; i < 8; i++)
    r[i] = x[i] ^ y[i];
}

static void mla(sliced_t r, const sliced_t x, const sliced_t y,
    const sliced_t z) {
  uint32_t t[16] = { 0 };

  for (int i = 0; i < 8; i++)
    for (int j = 0; j < 8; j++)
      t[i + j] ^= x[i] & y[j];

  for (int i = 6; i >= 0; i--) {
    t[i + 4] ^= t[i + 8];
    t[i + 3] ^= t[i + 8];
    t[i + 1] ^= t[i + 8];
    t[i + 0] ^= t[i + 8];
  }

  for (int i = 0; i < 8; i++)
    r[i] = (z ? z[i] : 0) ^ t[i];
}

static void mul(sliced_t r, const sliced_t x, const sliced_t y) {
  mla(r, x, y, 0);
}

static void sqr(sliced_t r, sliced_t x) {
  uint32_t t[16] = {
    x[0], 0, x[1], 0, x[2], 0, x[3], 0,
    x[4], 0, x[5], 0, x[6], 0, x[7], 0
  };

  for (int i = 6; i >= 0; i--) {
    if (i == 5 || i == 3)
      continue;
    t[i + 4] ^= t[i + 8];
    t[i + 3] ^= t[i + 8];
    t[i + 1] ^= t[i + 8];
    t[i + 0] ^= t[i + 8];
  }

  for (int i = 0; i < 8; i++)
    r[i] = t[i];
}

static void div(sliced_t r, sliced_t x, sliced_t y) {
  sliced_t t, u, v;

  sqr(t, y);
  sqr(t, t);
  sqr(u, t);
  mul(v, u, y);
  sqr(u, u);
  mul(u, u, v);
  sqr(u, u);
  sqr(v, u);
  sqr(v, v);
  mul(u, u, t);
  mul(u, u, v);
  mul(r, u, x);
}

static void dice(secret_t r, const sliced_t x) {
  for (int i = 0; i < 8; i++)
    for (int j = 0; j < 32; j++)
      r[j] = (i ? r[j] : 0) ^ (x[i] >> j & 1) << i;
}

static void fill(sliced_t r, const uint8_t x) {
  for (int i = 0; i < 8; i++)
    r[i] = -(x >> i & 1);
}

static void slice(sliced_t r, const secret_t x) {
  for (int i = 0; i < 32; i++)
    for (int j = 0; j < 8; j++)
      r[j] = (i ? r[j] : 0) ^ ((uint32_t) x[i] >> j & 1) << i;
}

void shamir_combine(secret_t secret, uint8_t count,
    const share_t shares[count]) {
  sliced_t x[count], y[count], z = { 0 };

  for (int i = 0; i < count; i++) {
    fill(x[i], shares[i][0]);
    slice(y[i], shares[i] + 1);
  }

  for (int i = 0; i < count; i++) {
    sliced_t s = { -1 }, t = { -1 }, u;
    for (int j = 0; j < count; j++)
      if (i != j) {
        mul(s, s, x[j]);
        add(u, x[i], x[j]);
        mul(t, t, u);
      }
    div(s, s, t);
    mla(z, s, y[i], z);
  }

  dice(secret, z);
}

void shamir_split(share_t share, uint8_t index, uint8_t threshold,
    const secret_t secret, const secret_t entropy[threshold - 1]) {
  sliced_t x, y, z = { -1 };

  index += index != 255;
  fill(x, index);
  slice(y, secret);

  for (int i = 0; i < threshold - 1; i++) {
    mul(z, z, x);
    mla(y, z, (uint32_t *) entropy[i], y);
  }

  share[0] = index;
  dice(share + 1, y);
}
