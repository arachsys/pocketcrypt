/* x25519.c from Pocketcrypt: https://github.com/arachsys/pocketcrypt */
/* Adopted from Mike Hamburg's STROBE: https://strobe.sourceforge.io/ */

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

static inline limb_t umaal(limb_t *carry, limb_t acc, limb_t mand,
    limb_t mier) {
  dlimb_t result = (dlimb_t) mand * mier + acc + *carry;
  *carry = result >> WBITS;
  return result;
}

static inline limb_t adc(limb_t *carry, limb_t acc, limb_t mand) {
  dlimb_t total = (dlimb_t) *carry + acc + mand;
  *carry = total >> WBITS;
  return total;
}

static inline limb_t adc0(limb_t *carry, limb_t acc) {
  dlimb_t total = (dlimb_t) *carry + acc;
  *carry = total >> WBITS;
  return total;
}

static void propagate(element_t x, limb_t over) {
  over = x[LIMBS - 1] >> (WBITS - 1) | over << 1;
  x[LIMBS - 1] &= ~((limb_t) 1 << (WBITS - 1));

  limb_t carry = over * 19;
  for (unsigned i = 0; i < LIMBS; i++)
    x[i] = adc0(&carry, x[i]);
}

static void add(element_t out, const element_t a, const element_t b) {
  limb_t carry = 0;
  for (unsigned i = 0; i < LIMBS; i++)
    out[i] = adc(&carry, a[i], b[i]);
  propagate(out, carry);
}

static void sub(element_t out, const element_t a, const element_t b) {
  sdlimb_t carry = -38;
  for (unsigned i = 0; i < LIMBS; i++) {
    out[i] = carry = carry + a[i] - b[i];
    carry >>= WBITS;
  }
  propagate(out, 1 + carry);
}

static inline void swapin(limb_t *out, const uint8_t *in) {
  for (unsigned i = 0, j = 0; i < LIMBS; i++) {
    out[i] = 0;
    for (unsigned k = 0; k < sizeof(limb_t) << 3; k += 8)
      out[i] |= (limb_t) in[j++] << k;
  }
}

static inline void swapout(uint8_t *out, limb_t *in) {
  for (unsigned i = 0, j = 0; i < LIMBS; i++) {
    for (unsigned k = 0; k < sizeof(limb_t) << 3; k += 8)
      out[j++] = (uint8_t) (in[i] >> k);
  }
}

static void mul(element_t out, const element_t a, const element_t b,
    unsigned blen) {
  limb_t accum[2 * LIMBS] = { 0 };
  for (unsigned i = 0; i < blen; i++) {
    limb_t carry = 0, mand = b[i];
    for (unsigned j = 0; j < LIMBS; j++)
      accum[i + j] = umaal(&carry, accum[i + j], mand, a[j]);
    accum[i + LIMBS] = carry;
  }

  limb_t carry = 0, mand = 38;
  for (unsigned j = 0; j < LIMBS; j++)
     out[j] = umaal(&carry, accum[j], mand, accum[j + LIMBS]);
  propagate(out, carry);
}

static void sqr(element_t out, const element_t a) {
  mul(out, a, a, LIMBS);
}

static void mul1(element_t out, const element_t a) {
  mul(out, a, out, LIMBS);
}

static void sqr1(element_t a) {
  mul1(a, a);
}

static void condswap(limb_t a[2*LIMBS], limb_t b[2*LIMBS], limb_t mask) {
  for (unsigned i = 0; i < 2 * LIMBS; i++) {
    limb_t xor = (a[i] ^ b[i]) & mask;
    a[i] ^= xor;
    b[i] ^= xor;
  }
}

static limb_t canon(element_t x) {
  limb_t carry0 = 19;
  for (unsigned i = 0; i < LIMBS; i++)
    x[i] = adc0(&carry0, x[i]);
  propagate(x, carry0);

  sdlimb_t carry = -19;
  limb_t result = 0;
  for (unsigned i = 0; i < LIMBS; i++) {
    result |= x[i] = carry += x[i];
    carry >>= WBITS;
  }
  return ((dlimb_t) result - 1) >> WBITS;
}

static void ladder1(element_t xs[5]) {
  const limb_t a24[1] = { 121665 };
  limb_t *x2 = xs[0], *z2 = xs[1], *x3 = xs[2], *z3 = xs[3], *t1 = xs[4];

  add(t1, x2, z2);
  sub(z2, x2, z2);
  add(x2, x3, z3);
  sub(z3, x3, z3);
  mul1(z3, t1);
  mul1(x2, z2);
  add(x3, z3, x2);
  sub(z3, z3, x2);
  sqr1(t1);
  sqr1(z2);
  sub(x2, t1, z2);
  mul(z2, x2, a24, sizeof(a24) / sizeof(limb_t));
  add(z2, z2, t1);
}

static void ladder2(element_t xs[5], const element_t x1) {
  limb_t *x2 = xs[0], *z2 = xs[1], *x3 = xs[2], *z3 = xs[3], *t1 = xs[4];

  sqr1(z3);
  mul1(z3, x1);
  sqr1(x3);
  mul1(z2, x2);
  sub(x2, t1, x2);
  mul1(x2, t1);
}

static void x25519_core(element_t xs[5], const x25519_t scalar,
    const x25519_t point) {
  element_t x1;
  swapin(x1, point);

  limb_t swap = 0, *x2 = xs[0], *x3 = xs[2], *z3 = xs[3];
  memset(xs, 0, 4 * sizeof(element_t));
  x2[0] = z3[0] = 1;
  memcpy(x3, x1, sizeof(element_t));

  for (int i = 255; i >= 0; i--) {
    uint8_t byte = scalar[i >> 3];
    limb_t doswap = - (limb_t) ((byte >> (i % 8)) & 1);
    condswap(x2, x3, swap ^ doswap);
    swap = doswap;

    ladder1(xs);
    ladder2(xs, (const limb_t *) x1);
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
  x25519_core(xs, scalar, point);
  limb_t *x2 = xs[0], *z2 = xs[1], *z3 = xs[3], *p = z2;

  for (unsigned i = 0; i < 13; i++) {
    limb_t *a = xs[steps[i].a];
    for (unsigned j = steps[i].n; j > 0; j--)
      sqr(a, p), p = a;
    mul1(a, xs[steps[i].c]);
  }
  mul1(x2, z3);

  limb_t result = canon(x2);
  swapout(out, x2);
  return result;
}

static void montmul(scalar_t out, const scalar_t a,
    const scalar_t b) {
  const limb_t montgomery = (limb_t) 0xd2b51da312547e1b;
  const scalar_t p = {
    LIMB(0x5812631a5cf5d3ed), LIMB(0x14def9dea2f79cd6),
    LIMB(0x0000000000000000), LIMB(0x1000000000000000)
  };

  limb_t highcarry = 0;
  for (unsigned i = 0; i < LIMBS; i++) {
    limb_t carry1 = 0, carry2 = 0, mand1 = a[i], mand2 = montgomery;
    for (unsigned j = 0; j < LIMBS; j++) {
      limb_t acc = out[j];
      acc = umaal(&carry1, acc, mand1, b[j]);
      if (j == 0)
        mand2 *= acc;
      acc = umaal(&carry2, acc, mand2, p[j]);
      if (j > 0)
        out[j - 1] = acc;
    }
    out[LIMBS - 1] = adc(&highcarry, carry1, carry2);
  }

  sdlimb_t scarry = 0;
  for (unsigned i = 0; i < LIMBS; i++) {
    out[i] = scarry = scarry + out[i] - p[i];
    scarry >>= WBITS;
  }

  limb_t carry1 = 0, carry2 = - (scarry + highcarry);
  for (unsigned i = 0; i < LIMBS; i++)
    out[i] = umaal(&carry1, out[i], carry2, p[i]);
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

static limb_t x25519_verify_core(element_t xs[5], const limb_t *other1,
    const x25519_t other2) {
  limb_t *z2 = xs[1], *x3 = xs[2], *z3 = xs[3];
  element_t xo2;
  swapin(xo2, other2);

  memcpy(x3, other1, 2 * sizeof(element_t));
  ladder1(xs);

  mul1(z2, other1);
  mul1(z2, other1 + LIMBS);
  mul1(z2, xo2);

  const limb_t sixteen = 16;
  mul(z2, z2, &sixteen, 1);

  mul1(z3, xo2);
  sub(z3, z3, x3);
  sqr1(z3);

  sub(z3, z3, z2);
  return canon(z2) | ~canon(z3);
}

int x25519_verify(const x25519_t response, const x25519_t challenge,
    const x25519_t ephemeral, const x25519_t identity) {
  element_t xs[7];
  x25519_core(&xs[0], challenge, identity);
  x25519_core(&xs[2], response, x25519_generator);
  return x25519_verify_core(&xs[2], xs[0], ephemeral);
}
