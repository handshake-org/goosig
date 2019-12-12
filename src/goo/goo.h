/*!
 * goo.c - groups of unknown order for C89
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

#ifndef _GOOSIG_H
#define _GOOSIG_H

#include <stdlib.h>

#ifdef GOO_HAS_GMP
#include <gmp.h>
#else
#include "mini-gmp.h"
#endif

#include "drbg.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define GOO_DEFAULT_G 2
#define GOO_DEFAULT_H 3
#define GOO_MIN_RSA_BITS 1024
#define GOO_MAX_RSA_BITS 4096
#define GOO_EXPONENT_SIZE 2048
#define GOO_WINDOW_SIZE 6
#define GOO_MAX_COMB_SIZE 512
#define GOO_CHAL_BITS 128
#define GOO_ELL_BITS 136
#define GOO_ELLDIFF_MAX 512
#define GOO_TABLEN (1 << (GOO_WINDOW_SIZE - 2))

/* SHA256("Goo Signature")
 *
 * This, combined with the group hash of
 * SHA256(g || h || n), gives us an IV of:
 *
 *   0x4332417d
 *   0xf3a92851
 *   0xd59e8673
 *   0x6cbbfa97
 *   0xd44855ed
 *   0x385a0490
 *   0xa2297690
 *   0x0e0ea0e4
 */
static const unsigned char GOO_HASH_PREFIX[32] = {
  0xc8, 0x30, 0xd5, 0xfd, 0xdc, 0xb2, 0x23, 0xcd,
  0x86, 0x00, 0x7a, 0xbf, 0x91, 0xc4, 0x40, 0x27,
  0x6b, 0x00, 0x80, 0x66, 0xbc, 0xb6, 0x45, 0x91,
  0xef, 0x80, 0x61, 0xc8, 0x9c, 0x1c, 0x58, 0x82
};

/* SHA512("Goo PRNG") */
static const unsigned char GOO_DRBG_PERS[64] = {
  0xd8, 0x92, 0x57, 0xb2, 0x80, 0x9d, 0x26, 0x50,
  0xe7, 0xd5, 0x1e, 0x80, 0x83, 0xaa, 0x75, 0xd8,
  0x24, 0xfd, 0x12, 0x44, 0x4e, 0xa0, 0x3b, 0x71,
  0x84, 0x66, 0x2d, 0x07, 0xb0, 0x5f, 0x95, 0x11,
  0x60, 0x91, 0x4f, 0x6f, 0xe5, 0x94, 0x08, 0xa9,
  0xc9, 0x2f, 0x13, 0x33, 0x95, 0x0f, 0xf1, 0x24,
  0x6a, 0xc4, 0x50, 0x55, 0x22, 0x97, 0xf5, 0xd5,
  0x14, 0xdf, 0x2d, 0x05, 0xe2, 0xfb, 0xbf, 0x9b
};

/* SHA256("Goo RNG") */
static const unsigned char GOO_DRBG_LOCAL[32] = {
  0xbe, 0xe9, 0xc0, 0xa5, 0x17, 0x2e, 0x45, 0x61,
  0x9d, 0xca, 0x94, 0x92, 0x8e, 0xb5, 0x7a, 0x6e,
  0xf6, 0x0b, 0xa7, 0x99, 0x5a, 0x27, 0x60, 0x08,
  0x9f, 0x9a, 0x3c, 0x6c, 0x23, 0x30, 0x26, 0x0c
};

typedef struct goo_combspec_s {
  long points_per_add;
  long adds_per_shift;
  long shifts;
  long bits_per_window;
  long size;
} goo_combspec_t;

typedef struct goo_comb_s {
  long points_per_add;
  long adds_per_shift;
  long shifts;
  long bits_per_window;
  long bits;
  long points_per_subcomb;
  long size;
  mpz_t *items;
  long **wins;
} goo_comb_t;

typedef struct goo_comb_item_s {
  goo_comb_t g;
  goo_comb_t h;
} goo_comb_item_t;

typedef struct goo_prng_s {
  goo_drbg_t ctx;
  mpz_t save;
  unsigned long total;
  mpz_t tmp;
} goo_prng_t;

typedef struct goo_sig_s {
  mpz_t C2;
  mpz_t C3;
  mpz_t t;
  mpz_t chal;
  mpz_t ell;
  mpz_t Aq;
  mpz_t Bq;
  mpz_t Cq;
  mpz_t Dq;
  mpz_t Eq;
  mpz_t z_w;
  mpz_t z_w2;
  mpz_t z_s1;
  mpz_t z_a;
  mpz_t z_an;
  mpz_t z_s1w;
  mpz_t z_sa;
  mpz_t z_s2;
} goo_sig_t;

typedef struct goo_group_s {
  /* Group parameters */
  mpz_t n;
  mpz_t g;
  mpz_t h;
  mpz_t nh;
  size_t bits;
  size_t size;
  size_t rand_bits;

  /* PRNG */
  goo_prng_t prng;

  /* Cached SHA midstate */
  goo_sha256_t sha;

  /* WNAF */
  mpz_t table_p1[GOO_TABLEN];
  mpz_t table_n1[GOO_TABLEN];
  mpz_t table_n2[GOO_TABLEN];
  mpz_t table_p2[GOO_TABLEN];
  long wnaf0[GOO_MAX_RSA_BITS + 1];
  long wnaf1[GOO_ELL_BITS + 1];
  long wnaf2[GOO_ELL_BITS + 1];

  /* Combs */
  long combs_len;
  goo_comb_item_t combs[2];

  /* Used for goo_group_hash() */
  unsigned char slab[(GOO_MAX_RSA_BITS + 7) / 8];
} goo_group_t;

typedef struct goo_group_s goo_ctx_t;

int
goo_init(goo_ctx_t *ctx,
         const unsigned char *n,
         size_t n_len,
         unsigned long g,
         unsigned long h,
         unsigned long modbits);

void
goo_uninit(goo_ctx_t *ctx);

int
goo_challenge(goo_ctx_t *ctx,
              unsigned char **C1,
              size_t *C1_len,
              const unsigned char *s_prime,
              const unsigned char *n,
              size_t n_len);

int
goo_validate(goo_ctx_t *ctx,
             const unsigned char *s_prime,
             const unsigned char *C1,
             size_t C1_len,
             const unsigned char *p,
             size_t p_len,
             const unsigned char *q,
             size_t q_len);

int
goo_sign(goo_ctx_t *ctx,
         unsigned char **out,
         size_t *out_len,
         const unsigned char *msg,
         size_t msg_len,
         const unsigned char *s_prime,
         const unsigned char *p,
         size_t p_len,
         const unsigned char *q,
         size_t q_len,
         const unsigned char *seed);

int
goo_verify(goo_ctx_t *ctx,
           const unsigned char *msg,
           size_t msg_len,
           const unsigned char *sig,
           size_t sig_len,
           const unsigned char *C1,
           size_t C1_len);

#ifdef GOO_TEST
void
goo_test(void);
#endif

#if defined(__cplusplus)
}
#endif

#endif
