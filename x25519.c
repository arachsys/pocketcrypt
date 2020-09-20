/* x25519.c from Pocketcrypt: https://github.com/arachsys/pocketcrypt */
/* Adapted from Mike Hamburg's STROBE: https://strobe.sourceforge.io/ */

#include <stdint.h>
#include <string.h>

typedef uint8_t x25519_t[32];
const x25519_t x25519_generator = { 9 };

#ifdef __SIZEOF_INT128__

#define LIMB(x) x##ull
#define LIMBS 4
#define WBITS 64
typedef uint64_t limb_t;
typedef __uint128_t dlimb_t;
typedef __int128_t sdlimb_t;

#else /* __SIZEOF_INT128__ */

#define LIMB(x) (uint32_t) (x##ull), (uint32_t) ((x##ull) >> 32)
#define LIMBS 8
#define WBITS 32
typedef uint32_t limb_t;
typedef uint64_t dlimb_t;
typedef int64_t sdlimb_t;

#endif /* __SIZEOF_INT128__ */

typedef limb_t element_t[LIMBS];
typedef limb_t scalar_t[LIMBS];

static void propagate(element_t x, limb_t over) {
  over = x[LIMBS - 1] >> (WBITS - 1) | over << 1;
  x[LIMBS - 1] &= ~((limb_t) 1 << (WBITS - 1));

  dlimb_t carry = over * 19;
  for (uint8_t i = 0; i < LIMBS; i++)
    x[i] = carry = carry + x[i], carry >>= WBITS;
}

static void add(element_t out, const element_t x, const element_t y) {
  dlimb_t carry = 0;
  for (uint8_t i = 0; i < LIMBS; i++)
    out[i] = carry = carry + x[i] + y[i], carry >>= WBITS;
  propagate(out, carry);
}

static void sub(element_t out, const element_t x, const element_t y) {
  sdlimb_t carry = -38;
  for (uint8_t i = 0; i < LIMBS; i++)
    out[i] = carry = carry + x[i] - y[i], carry >>= WBITS;
  propagate(out, 1 + carry);
}

static void mul(element_t out, const element_t x, const element_t y) {
  limb_t accum[2 * LIMBS] = { 0 };
  for (uint8_t i = 0; i < LIMBS; i++) {
    dlimb_t carry = 0;
    for (uint8_t j = 0; j < LIMBS; j++) {
      carry += (dlimb_t) y[i] * x[j] + accum[i + j];
      accum[i + j] = carry, carry >>= WBITS;
    }
    accum[i + LIMBS] = carry;
  }

  dlimb_t carry = 0;
  for (uint8_t i = 0; i < LIMBS; i++) {
    carry += (dlimb_t) 38 * accum[i + LIMBS] + accum[i];
    out[i] = carry, carry >>= WBITS;
  }
  propagate(out, carry);
}

static void mul1(element_t out, const element_t x, const limb_t y) {
  dlimb_t carry = 0;
  for (uint8_t i = 0; i < LIMBS; i++)
    out[i] = carry += (dlimb_t) y * x[i], carry >>= WBITS;
  carry *= 38;
  for (uint8_t i = 0; i < LIMBS; i++)
    out[i] = carry += out[i], carry >>= WBITS;
  propagate(out, carry);
}

static void mulsqrn(element_t out, const element_t x, const element_t y,
    uint8_t n) {
  for (uint8_t i = 0; i < n; i++)
    mul(out, x, x), x = out;
  mul(out, out, y);
}

static limb_t canon(element_t x) {
  dlimb_t carry0 = 19;
  for (uint8_t i = 0; i < LIMBS; i++)
    x[i] = carry0 += x[i], carry0 >>= WBITS;
  propagate(x, carry0);

  limb_t result = 0;
  sdlimb_t carry = -19;
  for (uint8_t i = 0; i < LIMBS; i++)
    result |= x[i] = carry += x[i], carry >>= WBITS;
  return ((dlimb_t) result - 1) >> WBITS;
}

static void condswap(element_t x, element_t y, limb_t mask) {
  for (uint8_t i = 0; i < LIMBS; i++) {
    limb_t xor = (x[i] ^ y[i]) & mask;
    x[i] ^= xor, y[i] ^= xor;
  }
}

static limb_t invsqrt(element_t out, const element_t x) {
  const element_t one = { 1 }, sqrtm1 = {
    LIMB(0xc4ee1b274a0ea0b0), LIMB(0x2f431806ad2fe478),
    LIMB(0x2b4d00993dfbd7a7), LIMB(0x2b8324804fc1df0b)
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

static void ladder1(element_t xs[5]) {
  const limb_t a24 = 121665;
  limb_t *x2 = xs[0], *z2 = xs[1], *x3 = xs[2], *z3 = xs[3], *t1 = xs[4];

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

static void ladder2(element_t xs[5], const element_t x1) {
  limb_t *x2 = xs[0], *z2 = xs[1], *x3 = xs[2], *z3 = xs[3], *t1 = xs[4];

  mul(z3, z3, z3);
  mul(z3, z3, x1);
  mul(x3, x3, x3);
  mul(z2, z2, x2);
  sub(x2, t1, x2);
  mul(x2, x2, t1);
}

static void swapin(limb_t *out, const uint8_t *in) {
  for (uint8_t i = 0; i < LIMBS; i++) {
    out[i] = (limb_t) *in++;
    for (uint8_t j = 8; j < WBITS; j += 8)
      out[i] |= (limb_t) *in++ << j;
  }
}

static void swapout(uint8_t *out, limb_t *in) {
  for (uint8_t i = 0; i < LIMBS; i++) {
    for (uint8_t j = 0; j < WBITS; j += 8)
      *out++ = (uint8_t) (in[i] >> j);
  }
}

static void x25519_core(element_t xs[5], const x25519_t scalar,
    const x25519_t point) {
  element_t x1;
  swapin(x1, point);

  limb_t swap = 0, *x2 = xs[0], *z2 = xs[1], *x3 = xs[2], *z3 = xs[3];
  memset(xs, 0, 4 * sizeof(element_t));
  memcpy(x3, x1, sizeof(element_t));
  x2[0] = z3[0] = 1;

  for (int i = 255; i >= 0; i--) {
    uint8_t byte = scalar[i >> 3];
    limb_t bit = -((limb_t) byte >> (i & 7) & 1);
    condswap(x2, x3, swap ^ bit);
    condswap(z2, z3, swap ^ bit);
    swap = bit;

    ladder1(xs);
    ladder2(xs, x1);
  }
  condswap(x2, x3, swap);
  condswap(z2, z3, swap);
}

int x25519(x25519_t out, const x25519_t scalar, const x25519_t point) {
  element_t xs[5];
  limb_t *x2 = xs[0], *z2 = xs[1], *x3 = xs[2], *z3 = xs[3], *t1 = xs[4];
  x25519_core(xs, scalar, point);

  mulsqrn(x3, z2, z2, 1);
  mulsqrn(x3, x3, z2, 1);
  mulsqrn(t1, x3, x3, 3);
  mulsqrn(x3, t1, t1, 6);
  mulsqrn(z3, x3, z2, 1);
  mulsqrn(z3, z3, x3, 12);
  mulsqrn(t1, z3, z3, 25);
  mulsqrn(x3, t1, z3, 25);
  mulsqrn(x3, x3, t1, 50);
  mulsqrn(z3, x3, x3, 125);
  mulsqrn(z3, z3, z2, 2);
  mulsqrn(z3, z3, z2, 2);
  mulsqrn(z3, z3, z2, 1);
  mul(x2, x2, z3);

  limb_t result = canon(x2);
  swapout(out, x2);
  return result;
}

void x25519_point(x25519_t out, const x25519_t element) {
  const limb_t a = 486662;
  const element_t zero = { 0 }, one = { 1 }, k = {
    LIMB(0x7623c9b16be2be8d), LIMB(0xa179cff2a5a0370e),
    LIMB(0xa965fecd840850b1), LIMB(0x28f9b6ff607c41e9)
  };

  element_t r, s, x, y, z;
  swapin(r, element);

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
  swapout(out, x);
}

static void montmul(scalar_t out, const scalar_t x,
    const scalar_t y) {
  const limb_t montgomery = (limb_t) 0xd2b51da312547e1b;
  const scalar_t p = {
    LIMB(0x5812631a5cf5d3ed), LIMB(0x14def9dea2f79cd6),
    LIMB(0x0000000000000000), LIMB(0x1000000000000000)
  };

  dlimb_t highcarry = 0;
  for (uint8_t i = 0; i < LIMBS; i++) {
    dlimb_t carry1 = 0, carry2 = 0;
    limb_t mand1 = x[i], mand2 = montgomery;
    for (uint8_t j = 0; j < LIMBS; j++) {
      carry1 += (dlimb_t) mand1 * y[j] + out[j];
      if (j == 0)
        mand2 *= (limb_t) carry1;
      carry2 += (dlimb_t) mand2 * p[j] + (limb_t) carry1;
      if (j > 0)
        out[j - 1] = carry2;
      carry1 >>= WBITS, carry2 >>= WBITS;
    }
    out[LIMBS - 1] = highcarry += carry1 + carry2;
    highcarry >>= WBITS;
  }

  sdlimb_t scarry = 0;
  for (uint8_t i = 0; i < LIMBS; i++)
    out[i] = scarry = scarry + out[i] - p[i], scarry >>= WBITS;

  dlimb_t addp = -(scarry + highcarry), carry = 0;
  for (uint8_t i = 0; i < LIMBS; i++)
    out[i] = carry += addp * p[i] + out[i], carry >>= WBITS;
}

void x25519_sign(x25519_t response, const x25519_t challenge,
    const x25519_t ephemeral, const x25519_t identity) {
  const scalar_t r2 = {
    LIMB(0xa40611e3449c0f01), LIMB(0xd00e1ba768859347),
    LIMB(0xceec73d217f5be65), LIMB(0x0399411b7c309a3d)
  };

  scalar_t scalar1, scalar2, scalar3;
  swapin(scalar1, ephemeral);
  swapin(scalar2, identity);
  swapin(scalar3, challenge);

  montmul(scalar1, scalar2, scalar3);
  memset(scalar2, 0, sizeof(scalar_t));
  montmul(scalar2, scalar1, r2);
  swapout(response, scalar2);
}

int x25519_verify(const x25519_t response, const x25519_t challenge,
    const x25519_t ephemeral, const x25519_t identity) {
  element_t xs[7];
  limb_t *x1 = xs[0], *z1 = xs[1];
  limb_t *z2 = xs[3], *x3 = xs[4], *z3 = xs[5], *t1 = xs[6];

  x25519_core(xs, challenge, identity);
  x25519_core(xs + 2, response, x25519_generator);

  memcpy(xs + 4, xs, 2 * sizeof(element_t));
  ladder1(xs + 2);
  mul(z2, z2, x1);
  mul(z2, z2, z1);

  swapin(t1, ephemeral);
  mul(z2, z2, t1);
  mul1(z2, z2, 16);

  mul(z3, z3, t1);
  sub(z3, z3, x3);
  mul(z3, z3, z3);

  sub(z3, z3, z2);
  return canon(z2) | ~canon(z3);
}
