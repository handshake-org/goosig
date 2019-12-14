/*!
 * chacha20.h - chacha20 for C89
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

#ifndef _GOO_CHACHA20_H
#define _GOO_CHACHA20_H

#include <stdlib.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct goo_chacha20_s {
  uint32_t state[16];
  union {
    uint32_t ints[16];
    unsigned char bytes[64];
  } stream;
  size_t pos;
} goo_chacha20_t;

void
goo_chacha20_init(goo_chacha20_t *ctx,
                  const unsigned char *key32,
                  const unsigned char *nonce24);

void
goo_chacha20_encrypt(goo_chacha20_t *ctx,
                     unsigned char *out,
                     const unsigned char *data,
                     size_t len);

void
goo_chacha20_derive(unsigned char *out,
                    const unsigned char *key32,
                    const unsigned char *nonce16);

#if defined(__cplusplus)
}
#endif

#endif
