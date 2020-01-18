/*!
 * sha256.h - sha256 for C89
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

#ifndef _GOO_SHA256_H
#define _GOO_SHA256_H

#include <stdlib.h>
#include <stdint.h>

#define GOO_SHA256_HASH_SIZE 32
#define GOO_SHA256_BLOCK_SIZE 64

typedef struct goo_sha256_s {
  uint32_t state[8];
  uint8_t block[64];
  uint64_t size;
} goo_sha256_t;

void
goo_sha256_init(goo_sha256_t *ctx);

void
goo_sha256_update(goo_sha256_t *ctx, const void *data, size_t len);

void
goo_sha256_final(goo_sha256_t *ctx, unsigned char *out);

void
goo_sha256(unsigned char *out, const void *data, size_t len);

#endif
