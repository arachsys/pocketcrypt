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

static void condswap(limb_t x[2*LIMBS], limb_t y[2*LIMBS], limb_t mask) {
  for (uint8_t i = 0; i < 2 * LIMBS; i++) {
    limb_t xor = (x[i] ^ y[i]) & mask;
    x[i] ^= xor, y[i] ^= xor;
  }
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

  limb_t swap = 0, *x2 = xs[0], *x3 = xs[2], *z3 = xs[3];
  memset(xs, 0, 4 * sizeof(element_t));
  memcpy(x3, x1, sizeof(element_t));
  x2[0] = z3[0] = 1;

  for (int i = 255; i >= 0; i--) {
    uint8_t byte = scalar[i >> 3];
    limb_t doswap = -((limb_t) byte >> (i & 7) & 1);
    condswap(x2, x3, swap ^ doswap);
    swap = doswap;

    ladder1(xs);
    ladder2(xs, x1);
  }
  condswap(x2, x3, swap);
}

int x25519(x25519_t out, const x25519_t scalar, const x25519_t point) {
  static const struct {
    uint8_t a, c, n;
  } steps[13] = {
    { 2, 1, 1 },
    { 2, 1, 1 },
    { 4, 2, 3 },
    { 2, 4, 6 },
    { 3, 1, 1 },
    { 3, 2, 12 },
    { 4, 3, 25 },
    { 2, 3, 25 },
    { 2, 4, 50 },
    { 3, 2, 125 },
    { 3, 1, 2 },
    { 3, 1, 2 },
    { 3, 1, 1 }
  };

  element_t xs[5];
  limb_t *x2 = xs[0], *z2 = xs[1], *z3 = xs[3], *p = z2;
  x25519_core(xs, scalar, point);

  for (uint8_t i = 0; i < 13; i++) {
    limb_t *a = xs[steps[i].a];
    for (uint8_t j = steps[i].n; j > 0; j--)
      mul(a, p, p), p = a;
    mul(a, xs[steps[i].c], a);
  }
  mul(x2, x2, z3);

  limb_t result = canon(x2);
  swapout(out, x2);
  return result;
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

static limb_t x25519_verify_core(element_t xs[5], const element_t other1[2],
    const x25519_t other2) {
  limb_t *z2 = xs[1], *x3 = xs[2], *z3 = xs[3], *t1 = xs[4];

  memcpy(xs + 2, other1, 2 * sizeof(element_t));
  ladder1(xs);
  mul(z2, z2, other1[0]);
  mul(z2, z2, other1[1]);

  swapin(t1, other2);
  mul(z2, z2, t1);
  mul1(z2, z2, 16);

  mul(z3, z3, t1);
  sub(z3, z3, x3);
  mul(z3, z3, z3);

  sub(z3, z3, z2);
  return canon(z2) | ~canon(z3);
}

int x25519_verify(const x25519_t response, const x25519_t challenge,
    const x25519_t ephemeral, const x25519_t identity) {
  element_t xs[7];
  x25519_core(xs, challenge, identity);
  x25519_core(xs + 2, response, x25519_generator);
  return x25519_verify_core(xs + 2, xs, ephemeral);
}
