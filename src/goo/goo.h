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
#define GOO_ELLDIFF_MAX 512
#define GOO_HASH_PREFIX "libGooPy:"
#define GOO_DRBG_PERS "libGooPy_prng"

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
  mpz_t tmp;
} goo_prng_t;

typedef struct goo_sig_s {
  mpz_t C2;
  mpz_t t;
  mpz_t chal;
  mpz_t ell;
  mpz_t Aq;
  mpz_t Bq;
  mpz_t Cq;
  mpz_t Dq;
  mpz_t z_w;
  mpz_t z_w2;
  mpz_t z_s1;
  mpz_t z_a;
  mpz_t z_an;
  mpz_t z_s1w;
  mpz_t z_sa;
} goo_sig_t;

typedef struct goo_group_s {
  // parameters
  mpz_t n;
  mpz_t nh;
  mpz_t g;
  mpz_t h;
  size_t rand_bits;

  // combs
  long combs_len;
  goo_comb_item_t combs[2];

  // wnaf
  mpz_t pctab_p1[GOO_TABLEN];
  mpz_t pctab_n1[GOO_TABLEN];
  mpz_t pctab_n2[GOO_TABLEN];
  mpz_t pctab_p2[GOO_TABLEN];
  long e1bits[GOO_CHAL_BITS + 1];
  long e2bits[GOO_CHAL_BITS + 1];

  goo_prng_t prng;

  // temporary variables
  mpz_t b12;
  mpz_t b34;
  mpz_t b1234;
  mpz_t b12345;
  mpz_t b12_inv;
  mpz_t b34_inv;
  mpz_t b1234_inv;
  mpz_t b12345_inv;
  mpz_t bsq;
  mpz_t val;
  mpz_t mask;
  mpz_t r;
  mpz_t gh;
  mpz_t C1_inv;
  mpz_t C2_inv;
  mpz_t Aq_inv;
  mpz_t Bq_inv;
  mpz_t Cq_inv;
  mpz_t A;
  mpz_t B;
  mpz_t C;
  mpz_t D;
  mpz_t z_w2_m_an;
  mpz_t tmp;
  mpz_t chal_out;
  mpz_t ell_r_out;
  mpz_t elldiff;
  mpz_t msg;
  goo_sig_t sig;
  mpz_t C1;

  unsigned char slab[2 + ((GOO_MAX_RSA_BITS + 7) / 8) * 2];
} goo_group_t;

typedef struct goo_group_s goo_ctx_t;

int
goo_init(
  goo_ctx_t *ctx,
  const unsigned char *n,
  size_t n_len,
  unsigned long g,
  unsigned long h,
  unsigned long modbits
);

void
goo_uninit(goo_ctx_t *ctx);

int
goo_challenge(
  goo_ctx_t *ctx,
  unsigned char **s_prime,
  size_t *s_prime_len,
  unsigned char **C1,
  size_t *C1_len,
  const unsigned char *n,
  size_t n_len
);

int
goo_sign(
  goo_ctx_t *ctx,
  unsigned char **out,
  size_t *out_len,
  const unsigned char *msg,
  size_t msg_len,
  const unsigned char *s_prime,
  size_t s_prime_len,
  const unsigned char *C1,
  size_t C1_len,
  const unsigned char *n,
  size_t n_len,
  const unsigned char *p,
  size_t p_len,
  const unsigned char *q,
  size_t q_len
);

int
goo_verify(
  goo_ctx_t *ctx,
  const unsigned char *msg,
  size_t msg_len,
  const unsigned char *sig,
  size_t sig_len,
  const unsigned char *C1,
  size_t C1_len
);

#ifdef GOO_TEST
void
goo_test(void);
#endif

#if defined(__cplusplus)
}
#endif

#endif
