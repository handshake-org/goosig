/*!
 * hmac.c - hmac for C89
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

#ifndef _GOOSIG_HMAC_H
#define _GOOSIG_HMAC_H

#include <stdlib.h>
#include "sha256.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct goo_hmac_s {
  goo_sha256_t inner;
  goo_sha256_t outer;
} goo_hmac_t;

void
goo_hmac_init(goo_hmac_t *hmac, const unsigned char *key, size_t len);

void
goo_hmac_update(goo_hmac_t *hmac, const void *data, size_t len);

void
goo_hmac_final(goo_hmac_t *hmac, unsigned char *out);

void
goo_hmac(unsigned char *out,
         const void *data,
         size_t len,
         const unsigned char *key,
         size_t klen);

#if defined(__cplusplus)
}
#endif

#endif
