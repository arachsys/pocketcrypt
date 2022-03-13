/* x25519.c from Pocketcrypt: https://github.com/arachsys/pocketcrypt */
/* Adapted from Mike Hamburg's STROBE: https://strobe.sourceforge.io/ */

#include <stdint.h>
#define memcpy __builtin_memcpy
#define memset __builtin_memset

typedef uint8_t x25519_t[32];
const x25519_t x25519_base = { 9 };

#ifdef __SIZEOF_INT128__

#define limb(x) x##ull
enum { limbs = 4, width = 64 };
typedef uint64_t limb_t;
typedef __uint128_t dlimb_t;
typedef __int128_t sdlimb_t;

#else /* __SIZEOF_INT128__ */

#define limb(x) (uint32_t) (x##ull), (uint32_t) ((x##ull) >> 32)
enum { limbs = 8, width = 32 };
typedef uint32_t limb_t;
typedef uint64_t dlimb_t;
typedef int64_t sdlimb_t;

#endif /* __SIZEOF_INT128__ */

typedef limb_t element_t[limbs];
typedef limb_t scalar_t[limbs];

static const limb_t zero[limbs] = { 0 }, one[limbs] = { 1 };

static const scalar_t scalar_l = {
  limb(0x5812631a5cf5d3ed), limb(0x14def9dea2f79cd6),
  limb(0x0000000000000000), limb(0x1000000000000000)
};

static const scalar_t scalar_r2 = {
  limb(0xa40611e3449c0f01), limb(0xd00e1ba768859347),
  limb(0xceec73d217f5be65), limb(0x0399411b7c309a3d)
};

static void propagate(element_t x, limb_t over) {
  over = x[limbs - 1] >> (width - 1) | over << 1;
  x[limbs - 1] &= ~((limb_t) 1 << (width - 1));

  dlimb_t carry = over * 19;
  for (int i = 0; i < limbs; i++)
    x[i] = carry = carry + x[i], carry >>= width;
}

static void add(element_t out, const element_t x, const element_t y) {
  dlimb_t carry = 0;
  for (int i = 0; i < limbs; i++)
    out[i] = carry = carry + x[i] + y[i], carry >>= width;
  propagate(out, carry);
}

static void sub(element_t out, const element_t x, const element_t y) {
  sdlimb_t carry = -38;
  for (int i = 0; i < limbs; i++)
    out[i] = carry = carry + x[i] - y[i], carry >>= width;
  propagate(out, 1 + carry);
}

static void mul(element_t out, const element_t x, const element_t y) {
  limb_t accum[2 * limbs] = { 0 };
  for (int i = 0; i < limbs; i++) {
    dlimb_t carry = 0;
    for (int j = 0; j < limbs; j++) {
      carry += (dlimb_t) y[i] * x[j] + accum[i + j];
      accum[i + j] = carry, carry >>= width;
    }
    accum[i + limbs] = carry;
  }

  dlimb_t carry = 0;
  for (int i = 0; i < limbs; i++) {
    carry += (dlimb_t) 38 * accum[i + limbs] + accum[i];
    out[i] = carry, carry >>= width;
  }
  propagate(out, carry);
}

static void mul1(element_t out, const element_t x, const limb_t y) {
  dlimb_t carry = 0;
  for (int i = 0; i < limbs; i++)
    out[i] = carry += (dlimb_t) y * x[i], carry >>= width;
  carry *= 38;
  for (int i = 0; i < limbs; i++)
    out[i] = carry += out[i], carry >>= width;
  propagate(out, carry);
}

static void mulsqrn(element_t out, const element_t x, const element_t y,
    uint8_t n) {
  for (int i = 0; i < n; i++)
    mul(out, x, x), x = out;
  mul(out, out, y);
}

static limb_t canon(element_t x) {
  dlimb_t carry0 = 19;
  for (int i = 0; i < limbs; i++)
    x[i] = carry0 += x[i], carry0 >>= width;
  propagate(x, carry0);

  limb_t result = 0;
  sdlimb_t carry = -19;
  for (int i = 0; i < limbs; i++)
    result |= x[i] = carry += x[i], carry >>= width;
  return ((dlimb_t) result - 1) >> width;
}

static void condswap(element_t x, element_t y, limb_t mask) {
  for (int i = 0; i < limbs; i++) {
    limb_t xor = (x[i] ^ y[i]) & mask;
    x[i] ^= xor, y[i] ^= xor;
  }
}

static limb_t invsqrt(element_t out, const element_t x) {
  const element_t sqrtm1 = {
    limb(0xc4ee1b274a0ea0b0), limb(0x2f431806ad2fe478),
    limb(0x2b4d00993dfbd7a7), limb(0x2b8324804fc1df0b)
  };

  element_t u, v, y, z;
  mulsqrn(u, x, x, 1);
  mulsqrn(u, u, x, 1);
  mulsqrn(v, u, u, 3);
  mulsqrn(u, v, v, 6);
  mulsqrn(z, u, x, 1);
  mulsqrn(z, z, u, 12);
  mulsqrn(v, z, z, 25);
  mulsqrn(u, v, z, 25);
  mulsqrn(u, u, v, 50);
  mulsqrn(z, u, u, 125);
  mulsqrn(z, z, x, 2);

  mul(y, z, z);
  mul(y, y, x);
  add(u, y, one);
  add(v, y, sqrtm1);
  mul(out, z, sqrtm1);
  condswap(out, z, ~canon(u) & ~canon(v));

  sub(v, y, one);
  return ~canon(u) & ~canon(v);
}

static void ladder1(element_t x2, element_t z2, element_t x3, element_t z3,
    element_t t1) {
  const limb_t a24 = 121665;

  add(t1, x2, z2);
  sub(z2, x2, z2);
  add(x2, x3, z3);
  sub(z3, x3, z3);
  mul(z3, z3, t1);
  mul(x2, x2, z2);
  add(x3, z3, x2);
  sub(z3, z3, x2);
  mul(t1, t1, t1);
  mul(z2, z2, z2);
  sub(x2, t1, z2);
  mul1(z2, x2, a24);
  add(z2, z2, t1);
}

static void ladder2(const element_t x1, element_t x2, element_t z2,
    element_t x3, element_t z3, const element_t t1) {
  mul(z3, z3, z3);
  mul(z3, z3, x1);
  mul(x3, x3, x3);
  mul(z2, z2, x2);
  sub(x2, t1, x2);
  mul(x2, x2, t1);
}

static void montmla(scalar_t out, const scalar_t x, const scalar_t y) {
  const limb_t montgomery = (limb_t) 0xd2b51da312547e1b;
  dlimb_t highcarry = 0;

  for (int i = 0; i < limbs; i++) {
    dlimb_t carry1 = 0, carry2 = 0;
    limb_t mand1 = x[i], mand2 = montgomery;
    for (int j = 0; j < limbs; j++) {
      carry1 += (dlimb_t) mand1 * y[j] + out[j];
      if (j == 0)
        mand2 *= (limb_t) carry1;
      carry2 += (dlimb_t) mand2 * scalar_l[j] + (limb_t) carry1;
      if (j > 0)
        out[j - 1] = carry2;
      carry1 >>= width, carry2 >>= width;
    }
    out[limbs - 1] = highcarry += carry1 + carry2;
    highcarry >>= width;
  }

  sdlimb_t scarry = 0;
  for (int i = 0; i < limbs; i++)
    out[i] = scarry = scarry + out[i] - scalar_l[i], scarry >>= width;

  dlimb_t addl = -(scarry + highcarry), carry = 0;
  for (int i = 0; i < limbs; i++)
    out[i] = carry += addl * scalar_l[i] + out[i], carry >>= width;
}

static void montmul(scalar_t out, const scalar_t x, const scalar_t y) {
  scalar_t z = { 0 };
  montmla(z, x, y);
  memcpy(out, z, sizeof(scalar_t));
}

static void get(limb_t out[limbs], const x25519_t in) {
  for (int i = 0; i < limbs; i++) {
    out[i] = (limb_t) *in++;
    for (int j = 8; j < width; j += 8)
      out[i] |= (limb_t) *in++ << j;
  }
}

static void put(x25519_t out, const limb_t in[limbs]) {
  for (int i = 0; i < limbs; i++) {
    for (int j = 0; j < width; j += 8)
      *out++ = (uint8_t) (in[i] >> j);
  }
}

static void x25519_core(element_t x2, element_t z2, const x25519_t scalar,
    const x25519_t point) {
  element_t x1, x3, z3, t1;
  limb_t swap = 0;

  get(x1, point);
  memcpy(x2, one, sizeof(element_t));
  memcpy(z2, zero, sizeof(element_t));
  memcpy(x3, x1, sizeof(element_t));
  memcpy(z3, one, sizeof(element_t));

  for (int i = 255; i >= 0; i--) {
    uint8_t byte = scalar[i >> 3];
    limb_t bit = -((limb_t) byte >> (i & 7) & 1);
    condswap(x2, x3, swap ^ bit);
    condswap(z2, z3, swap ^ bit);
    swap = bit;

    ladder1(x2, z2, x3, z3, t1);
    ladder2(x1, x2, z2, x3, z3, t1);
  }
  condswap(x2, x3, swap);
  condswap(z2, z3, swap);
}

int x25519(x25519_t out, const x25519_t scalar, const x25519_t point) {
  element_t t, u, v, x, z;
  x25519_core(x, z, scalar, point);

  mulsqrn(u, z, z, 1);
  mulsqrn(u, u, z, 1);
  mulsqrn(v, u, u, 3);
  mulsqrn(u, v, v, 6);
  mulsqrn(t, u, z, 1);
  mulsqrn(t, t, u, 12);
  mulsqrn(v, t, t, 25);
  mulsqrn(u, v, t, 25);
  mulsqrn(u, u, v, 50);
  mulsqrn(t, u, u, 125);
  mulsqrn(t, t, z, 2);
  mulsqrn(t, t, z, 2);
  mulsqrn(t, t, z, 1);
  mul(x, x, t);

  limb_t result = canon(x);
  put(out, x);
  return result;
}

void x25519_invert(x25519_t out, const x25519_t scalar) {
  scalar_t x, y, z[8];
  get(x, scalar);

  montmul(z[0], x, scalar_r2);
  montmul(z[7], z[0], z[0]);
  for (int i = 0; i < 7; i++)
    montmul(z[i + 1], z[i], z[7]);
  memcpy(y, z[0], sizeof(scalar_t));

  uint8_t residue = 0, trailing = 0;
  for (int i = 248; i >= -3; i--) {
    limb_t limb = i < 0 ? 0 : scalar_l[i / width] - (i < width ? 2 : 0);
    residue = residue << 1 | (limb >> (i % width) & 1);
    montmul(y, y, y);
    if (residue >> 3 != 0)
      trailing = residue, residue = 0;
    if (trailing > 0 && (trailing & 7) == 0)
      montmul(y, y, z[trailing >> 4]), trailing = 0;
    trailing <<= 1;
  }

  montmla(y, zero, zero);
  put(out, y);
}

void x25519_point(x25519_t out, const x25519_t element) {
  const limb_t a = 486662;
  const element_t k = {
    limb(0x7623c9b16be2be8d), limb(0xa179cff2a5a0370e),
    limb(0xa965fecd840850b1), limb(0x28f9b6ff607c41e9)
  };

  element_t r, s, x, y, z;
  get(r, element);

  mul(s, r, r);
  add(s, s, s);
  add(x, s, one);
  mul(y, x, x);
  mul1(z, s, a);
  mul1(z, z, a);
  sub(z, z, y);
  mul1(z, z, a);
  mul(s, y, x);
  mul(s, s, z);

  limb_t mask = invsqrt(s, s);
  mul1(x, s, a);
  mul(x, x, s);
  mul(x, x, y);
  mul(x, x, z);
  sub(x, zero, x);

  mul(s, k, r);
  mul(s, s, r);
  mul(s, s, x);
  condswap(x, s, mask);

  canon(x);
  put(out, x);
}

void x25519_scalar(x25519_t out, const x25519_t scalar) {
  const scalar_t k = {
    limb(0x6106e529e2dc2f79), limb(0x07d39db37d1cdad0),
    limb(0x0000000000000000), limb(0x0600000000000000)
  };

  scalar_t x;
  get(x, scalar);
  montmul(x, x, k);
  montmul(x, x, scalar_r2);

  dlimb_t carry = 0;
  for (int i = 0; i < limbs; i++)
    x[i] = carry += (dlimb_t) x[i] << 3, carry >>= width;
  put(out, x);
}

void x25519_sign(x25519_t response, const x25519_t challenge,
    const x25519_t ephemeral, const x25519_t identity) {
  scalar_t x, y, z;
  get(x, ephemeral);
  get(y, identity);
  get(z, challenge);

  montmla(x, y, z);
  montmul(y, x, scalar_r2);
  put(response, y);
}

int x25519_verify(const x25519_t response, const x25519_t challenge,
    const x25519_t ephemeral, const x25519_t identity) {
  element_t x1, z1, x2, z2, x3, z3, t1;
  x25519_core(x1, z1, challenge, identity);
  x25519_core(x2, z2, response, x25519_base);

  memcpy(x3, x1, sizeof(element_t));
  memcpy(z3, z1, sizeof(element_t));
  ladder1(x2, z2, x3, z3, t1);
  mul(z2, z2, x1);
  mul(z2, z2, z1);

  get(t1, ephemeral);
  mul(z2, z2, t1);
  mul1(z2, z2, 16);

  mul(z3, z3, t1);
  sub(z3, z3, x3);
  mul(z3, z3, z3);

  sub(z3, z3, z2);
  return canon(z2) | ~canon(z3);
}
