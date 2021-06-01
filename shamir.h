/* shamir.h from Pocketcrypt: https://github.com/arachsys/pocketcrypt */

#ifndef SHAMIR_H
#define SHAMIR_H

#include <stdint.h>

typedef uint8_t secret_t[32];
typedef uint8_t share_t[33];

extern void shamir_combine(secret_t secret, uint8_t count,
  const share_t shares[count]);

extern void shamir_split(share_t share, uint8_t index, uint8_t threshold,
  const secret_t secret, const secret_t entropy[threshold - 1]);

#endif
