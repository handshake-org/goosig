#ifndef _GOOSIG_H
#define _GOOSIG_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <gmp.h>
#include "drbg.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define GOO_POINTS_PER_ADD 8
#define GOO_ADDS_PER_SHIFT 2
#define GOO_NSHIFTS 8
#define GOO_BITS_PER_WINDOW 16
#define GOO_NBITS 128
#define GOO_POINTS_PER_SUBCOMB 255
// #define GOO_COMB_ITEMS (((1 << GOO_POINTS_PER_ADD) - 1) * GOO_ADDS_PER_SHIFT)
#define GOO_COMB_ITEMS 510
#define GOO_WINSIZE 6
// #define GOO_TABLEN (1 << (GOO_WINSIZE - 2))
#define GOO_TABLEN 16
#define GOO_RAND_EXPONENT_SIZE 2048
#define GOO_EBITS_SIZE (GOO_RAND_EXPONENT_SIZE * 2 + 2)
#define GOO_ELLDIFF_MAX 512
#define GOO_CHALBITS 128

typedef struct goo_comb_s {
  long wins[GOO_NSHIFTS][GOO_ADDS_PER_SHIFT];
  mpz_t items[GOO_COMB_ITEMS];
} goo_comb_t;

typedef struct goo_prng_s {
  goo_drbg_t ctx;
  mpz_t r_save;
  mpz_t tmp;
  mpz_t m256;
  unsigned char state[64];
} goo_prng_t;

typedef struct goo_group_s {
  // parameters
  mpz_t n;
  mpz_t nh;
  mpz_t g;
  mpz_t h;

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
  mpz_t zp_w2_m_an;
  mpz_t tmp;
  mpz_t chall_out;
  mpz_t ell_r_out;
  mpz_t elldiff;
  mpz_t C1;
  mpz_t C2;
  mpz_t t;
  mpz_t msg;
  mpz_t chall;
  mpz_t ell;
  mpz_t Aq;
  mpz_t Bq;
  mpz_t Cq;
  mpz_t Dq;
  mpz_t zp_w;
  mpz_t zp_w2;
  mpz_t zp_s1;
  mpz_t zp_a;
  mpz_t zp_an;
  mpz_t zp_s1w;
  mpz_t zp_sa;

  // combs
  goo_comb_t g_comb;
  goo_comb_t h_comb;

  // wnaf
  mpz_t pctab_p1[GOO_TABLEN];
  mpz_t pctab_n1[GOO_TABLEN];
  mpz_t pctab_n2[GOO_TABLEN];
  mpz_t pctab_p2[GOO_TABLEN];
  long e1bits[GOO_EBITS_SIZE];
  long e2bits[GOO_EBITS_SIZE];
} goo_group_t;

typedef struct goo_group_s goo_ctx_t;

int
goo_init(
  goo_ctx_t *ctx,
  const unsigned char *n,
  size_t n_len,
  unsigned long g,
  unsigned long h
);

void
goo_uninit(goo_ctx_t *ctx);

int
goo_verify(
  goo_ctx_t *group,
  const unsigned char *msg,
  size_t msg_len,
  const unsigned char *proof,
  size_t proof_len
);

#if defined(__cplusplus)
}
#endif

#endif
