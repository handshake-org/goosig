/*!
 * goo.c - groups of unknown order for C
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
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

/* SHA256("Goo Signature") */
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

#define GOO_TABLEN (1 << (GOO_WINDOW_SIZE - 2))

typedef struct goo_combspec_s {
  int exists;
  long points_per_add;
  long adds_per_shift;
  long shifts;
  long bits_per_window;
  long ops;
  long size;
} goo_combspec_t;

typedef struct goo_comb_s {
  int exists;
  long points_per_add;
  long adds_per_shift;
  long shifts;
  long bits_per_window;
  long bits;
  long points_per_subcomb;
  long size;
  long **wins;
  mpz_t *items;
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
  /* Parameters */
  mpz_t n;
  size_t bits;
  size_t size;
  mpz_t nh;
  mpz_t g;
  mpz_t h;
  size_t rand_bits;

  /* Combs */
  long combs_len;
  goo_comb_item_t combs[2];

  /* WNAF */
  mpz_t table_p1[GOO_TABLEN];
  mpz_t table_n1[GOO_TABLEN];
  mpz_t table_n2[GOO_TABLEN];
  mpz_t table_p2[GOO_TABLEN];
  long wnaf1[GOO_ELL_BITS + 1];
  long wnaf2[GOO_ELL_BITS + 1];

  goo_prng_t prng;
  goo_sha256_t sha;

  /* Temporary variables (for verification) */
  /* goo_group_verify() */
  mpz_t msg;
  goo_sig_t sig;
  mpz_t C1;
  mpz_t C1i;
  mpz_t C2i;
  mpz_t C3i;
  mpz_t Aqi;
  mpz_t Bqi;
  mpz_t Cqi;
  mpz_t Dqi;
  mpz_t A;
  mpz_t B;
  mpz_t C;
  mpz_t D;
  mpz_t E;
  mpz_t z_w2_m_an;
  mpz_t tmp;
  mpz_t chal0;
  mpz_t ell0;
  mpz_t ell1;

  /* goo_group_wnaf() */
  mpz_t e;

  /* goo_group_recon() */
  mpz_t gh;

  /* goo_hash_all() */
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
goo_generate(goo_ctx_t *ctx, unsigned char *s_prime);

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
         size_t q_len);

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
