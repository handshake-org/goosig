/*!
 * drbg.c - hmac-drbg for C
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc6979
 *   https://csrc.nist.gov/publications/detail/sp/800-90a/archive/2012-01-23
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "drbg.h"

static const unsigned char ZERO[1] = { 0x00 };
static const unsigned char ONE[1] = { 0x01 };

static void
goo_drbg_update(goo_drbg_t *drbg, const unsigned char *seed, size_t seed_len);

void
goo_drbg_init(goo_drbg_t *drbg, const unsigned char *seed, size_t seed_len) {
  assert(seed != NULL);
  assert(seed_len >= 24);

  for (size_t i = 0; i < GOO_HASH_SIZE; i++) {
    drbg->K[i] = 0x00;
    drbg->V[i] = 0x01;
  }

  goo_drbg_update(drbg, seed, seed_len);
  drbg->rounds = 1;
}

static void
goo_drbg_update(goo_drbg_t *drbg, const unsigned char *seed, size_t seed_len) {
  goo_hmac_init(&drbg->kmac, drbg->K, GOO_HASH_SIZE);
  goo_hmac_update(&drbg->kmac, drbg->V, GOO_HASH_SIZE);
  goo_hmac_update(&drbg->kmac, &ZERO[0], 1);

  if (seed)
    goo_hmac_update(&drbg->kmac, seed, seed_len);

  goo_hmac_final(&drbg->kmac, drbg->K);

  goo_hmac_init(&drbg->kmac, drbg->K, GOO_HASH_SIZE);
  goo_hmac_update(&drbg->kmac, drbg->V, GOO_HASH_SIZE);
  goo_hmac_final(&drbg->kmac, drbg->V);

  if (seed) {
    goo_hmac_init(&drbg->kmac, drbg->K, GOO_HASH_SIZE);
    goo_hmac_update(&drbg->kmac, drbg->V, GOO_HASH_SIZE);
    goo_hmac_update(&drbg->kmac, &ONE[0], 1);
    goo_hmac_update(&drbg->kmac, seed, seed_len);
    goo_hmac_final(&drbg->kmac, drbg->K);

    goo_hmac_init(&drbg->kmac, drbg->K, GOO_HASH_SIZE);
    goo_hmac_update(&drbg->kmac, drbg->V, GOO_HASH_SIZE);
    goo_hmac_final(&drbg->kmac, drbg->V);
  }
}

void
goo_drbg_reseed(goo_drbg_t *drbg, const unsigned char *seed, size_t seed_len) {
  assert(seed != NULL);
  assert(seed_len >= 24);

  goo_drbg_update(drbg, seed, seed_len);
  drbg->rounds = 1;
}

void
goo_drbg_generate(goo_drbg_t *drbg, unsigned char *out, size_t len) {
  size_t pos = 0;
  size_t left = len;
  size_t outlen = GOO_HASH_SIZE;

  assert(drbg->rounds <= GOO_RESEED_INTERVAL);

  while (pos < len) {
    goo_hmac_init(&drbg->kmac, drbg->K, GOO_HASH_SIZE);
    goo_hmac_update(&drbg->kmac, drbg->V, GOO_HASH_SIZE);
    goo_hmac_final(&drbg->kmac, drbg->V);

    if (outlen > left)
      outlen = left;

    memcpy(&out[pos], &drbg->V[0], outlen);

    pos += outlen;
    left -= outlen;
  }

  assert(pos == len);
  assert(left == 0);

  goo_drbg_update(drbg, NULL, 0);
  drbg->rounds += 1;
}
