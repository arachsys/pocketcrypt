/* x25519.h from Pocketcrypt: https://github.com/arachsys/pocketcrypt */

#ifndef X25519_H
#define X25519_H

#include <stdint.h>

enum { x25519_size = 32 };
typedef uint8_t x25519_t[x25519_size];

extern const x25519_t x25519_base;

int x25519(x25519_t out, const x25519_t scalar, const x25519_t point);

void x25519_invert(x25519_t out, const x25519_t scalar);

void x25519_point(x25519_t out, const x25519_t element);

void x25519_scalar(x25519_t out, const x25519_t scalar);

void x25519_sign(x25519_t response, const x25519_t challenge,
  const x25519_t ephemeral, const x25519_t identity);

int x25519_verify(const x25519_t response, const x25519_t challenge,
  const x25519_t ephemeral, const x25519_t identity);

#endif
