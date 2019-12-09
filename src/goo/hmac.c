/*!
 * hmac.c - hmac for C
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "hmac.h"

void
goo_hmac_init(goo_hmac_t *hmac, const unsigned char *key, size_t len) {
  unsigned char k[GOO_BLOCK_SIZE];
  unsigned char pad[GOO_BLOCK_SIZE];
  size_t i;

  if (len > GOO_BLOCK_SIZE) {
    goo_sha256(&k[0], key, len);
    len = GOO_HASH_SIZE;
  } else {
    memcpy(&k[0], key, len);
  }

  for (i = 0; i < len; i++)
    pad[i] = k[i] ^ 0x36;

  for (i = len; i < GOO_BLOCK_SIZE; i++)
    pad[i] = 0x36;

  goo_sha256_init(&hmac->inner);
  goo_sha256_update(&hmac->inner, &pad[0], GOO_BLOCK_SIZE);

  for (i = 0; i < len; i++)
    pad[i] = k[i] ^ 0x5c;

  for (i = len; i < GOO_BLOCK_SIZE; i++)
    pad[i] = 0x5c;

  goo_sha256_init(&hmac->outer);
  goo_sha256_update(&hmac->outer, &pad[0], GOO_BLOCK_SIZE);
}

void
goo_hmac_update(goo_hmac_t *hmac, const unsigned char *data, size_t len) {
  goo_sha256_update(&hmac->inner, data, len);
}

void
goo_hmac_final(goo_hmac_t *hmac, unsigned char *out) {
  goo_sha256_final(&hmac->inner, out);
  goo_sha256_update(&hmac->outer, out, GOO_HASH_SIZE);
  goo_sha256_final(&hmac->outer, out);
}

void
goo_hmac(
  unsigned char *out,
  const unsigned char *in,
  size_t len,
  const unsigned char *key,
  size_t klen
) {
  goo_hmac_t hmac;
  goo_hmac_init(&hmac, key, klen);
  goo_hmac_update(&hmac, in, len);
  goo_hmac_final(&hmac, out);
}
