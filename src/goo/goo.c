#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>
#include "goo.h"

#define goo_mpz_import(ret, data, len) \
  mpz_import((ret), (len), 1, sizeof((data)[0]), 0, 0, (data))

#define goo_mpz_export(data, size, n) \
  mpz_export((data), (size), 1, sizeof((data)[0]), 0, 0, (n));

#define goo_mpz_print(n) \
  (mpz_out_str(stdout, 16, (n)), printf("\n"))

#define goo_print_hex(data, len) do { \
  mpz_t n; \
  mpz_init(n); \
  goo_mpz_import(n, (data), (len)); \
  goo_mpz_print(n); \
  mpz_clear(n); \
} while (0)

static inline size_t
goo_mpz_bitlen(const mpz_t n) {
  size_t bits = mpz_sizeinbase(n, 2);

  if (bits == 1 && mpz_cmp_ui(n, 0) == 0)
    bits = 0;

  return bits;
}

#define goo_mpz_bytesize(n) \
  (goo_mpz_bitlen((n)) + 7) / 8

static const char goo_prefix[] = "libGooPy:";
static const char goo_pers[] = "libGooPy_prng";

static unsigned int goo_primes[168] = {
  2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
  73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
  157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
  239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
  331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
  421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
  509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
  613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
  709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
  821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
  919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997
};

static void
goo_group_pow(
  goo_group_t *group,
  mpz_t ret,
  const mpz_t b,
  const mpz_t b_inv,
  const mpz_t e
);

static void
goo_group_mul(goo_group_t *group, mpz_t ret, const mpz_t m1, const mpz_t m2);

static void
goo_prng_init(goo_prng_t *prng, unsigned char key[32]) {
  memset((void *)prng, 0x00, sizeof(goo_prng_t));

  assert(sizeof(goo_pers) == 14);

  unsigned char entropy[64 + sizeof(goo_pers) - 1];

  memcpy(&entropy[0], &key[0], 32);
  memset(&entropy[32], 0x00, 32);
  memcpy(&entropy[64], &goo_pers[0], sizeof(goo_pers) - 1);

  assert(sizeof(entropy) == 77);

  goo_drbg_init(&prng->ctx, entropy, sizeof(entropy));

  mpz_init_set_ui(prng->r_save, 0);
  mpz_init(prng->tmp);
  mpz_init_set_ui(prng->m256, 2);
  mpz_pow_ui(prng->m256, prng->m256, 256);
}

static void
goo_prng_uninit(goo_prng_t *prng) {
  mpz_clear(prng->r_save);
  mpz_clear(prng->tmp);
  mpz_clear(prng->m256);
}

static void
goo_prng_nextrand(goo_prng_t *prng, unsigned char out[32]) {
  goo_drbg_generate(&prng->ctx, &out[0], 32);
}

static void
goo_prng_getrandbits(goo_prng_t *prng, mpz_t r, unsigned int nbits) {
  mpz_set(r, prng->r_save);

  unsigned int b = goo_mpz_bitlen(r);
  unsigned char out[32];

  while (b < nbits) {
    mpz_mul(r, r, prng->m256);
    goo_prng_nextrand(prng, &out[0]);
    goo_mpz_import(prng->tmp, &out[0], 32);
    mpz_add(r, r, prng->tmp);
    b += 256;
  }

  unsigned int left = b - nbits;

  // this.r_save = r & ((1n << left) - 1n);
  mpz_set_ui(prng->tmp, 2);
  mpz_pow_ui(prng->tmp, prng->tmp, left);
  mpz_sub_ui(prng->tmp, prng->tmp, 1);
  mpz_set(prng->r_save, r);
  mpz_and(prng->r_save, prng->r_save, prng->tmp);

  // r >>= left;
  mpz_add_ui(prng->tmp, prng->tmp, 1);
  mpz_fdiv_q(r, r, prng->tmp);
}

static void
goo_comb_init(goo_comb_t *comb, goo_group_t *group, mpz_t g) {
  memset((void *)comb, 0x00, sizeof(goo_comb_t));

  for (int i = 0; i < GOO_COMB_ITEMS; i++)
    mpz_init(comb->items[i]);

  int nskip = (1 << GOO_POINTS_PER_ADD) - 1;

  mpz_set(comb->items[0], g);

  mpz_t *it = &comb->items[0];

  mpz_t win;
  mpz_init(win);

  mpz_set_ui(win, 1 << GOO_BITS_PER_WINDOW);

  for (int i = 1; i < GOO_POINTS_PER_ADD; i++) {
    int oval = 1 << i;
    int ival = oval >> 1;

    goo_group_pow(group, it[oval - 1], it[ival - 1], NULL, win);

    for (int j = oval + 1; j < 2 * oval; j++)
      goo_group_mul(group, it[j - 1], it[j - oval - 1], it[oval - 1]);
  }

  mpz_set_ui(win, 1 << GOO_NSHIFTS);

  for (int i = 1; i < GOO_ADDS_PER_SHIFT; i++) {
    for (int j = 0; j < nskip; j++) {
      int k = i * nskip + j;

      goo_group_pow(group, it[k], it[k - nskip], NULL, win);
    }
  }

  mpz_clear(win);
}

static void
goo_comb_uninit(goo_comb_t *comb) {
  for (int i = 0; i < GOO_COMB_ITEMS; i++)
    mpz_clear(comb->items[i]);
}

static int
goo_to_comb_exp(goo_comb_t *comb, const mpz_t e) {
  int len = (int)goo_mpz_bitlen(e);

  if (len < 0 || len > GOO_NBITS)
    return 0;

  int pad = GOO_NBITS - len;

  for (int i = GOO_ADDS_PER_SHIFT - 1; i >= 0; i--) {
    for (int j = 0; j < GOO_NSHIFTS; j++) {
      long ret = 0;

      for (int k = 0; k < GOO_POINTS_PER_ADD; k++) {
        int b = (i + k * GOO_ADDS_PER_SHIFT) * GOO_NSHIFTS + j;

        ret <<= 1;

        if (b < pad)
          continue;

        int p = (GOO_NBITS - 1) - b;
        assert(p >= 0);

        ret += (long)mpz_tstbit(e, p);
      }

      comb->wins[j][(GOO_ADDS_PER_SHIFT - 1) - i] = ret;
    }
  }

  return 1;
}

static int
goo_group_init(
  goo_group_t *group,
  const unsigned char *n,
  size_t n_len,
  unsigned long g,
  unsigned long h
) {
  memset((void *)group, 0x00, sizeof(goo_group_t));

  mpz_init(group->n);
  mpz_init(group->nh);
  mpz_init(group->g);
  mpz_init(group->h);
  mpz_init(group->b12);
  mpz_init(group->b34);
  mpz_init(group->b1234);
  mpz_init(group->b12345);
  mpz_init(group->b12_inv);
  mpz_init(group->b34_inv);
  mpz_init(group->b1234_inv);
  mpz_init(group->b12345_inv);
  mpz_init(group->bsq);
  mpz_init(group->val);
  mpz_init(group->mask);
  mpz_init(group->r);
  mpz_init(group->gh);
  mpz_init(group->C1_inv);
  mpz_init(group->C2_inv);
  mpz_init(group->Aq_inv);
  mpz_init(group->Bq_inv);
  mpz_init(group->Cq_inv);
  mpz_init(group->A);
  mpz_init(group->B);
  mpz_init(group->C);
  mpz_init(group->D);
  mpz_init(group->zp_w2_m_an);
  mpz_init(group->tmp);
  mpz_init(group->chall_out);
  mpz_init(group->ell_r_out);
  mpz_init(group->elldiff);
  mpz_init(group->C1);
  mpz_init(group->C2);
  mpz_init(group->t);
  mpz_init(group->msg);
  mpz_init(group->chall);
  mpz_init(group->ell);
  mpz_init(group->Aq);
  mpz_init(group->Bq);
  mpz_init(group->Cq);
  mpz_init(group->Dq);
  mpz_init(group->zp_w);
  mpz_init(group->zp_w2);
  mpz_init(group->zp_s1);
  mpz_init(group->zp_a);
  mpz_init(group->zp_an);
  mpz_init(group->zp_s1w);
  mpz_init(group->zp_sa);

  for (int i = 0; i < GOO_TABLEN; i++) {
    mpz_init(group->pctab_p1[i]);
    mpz_init(group->pctab_n1[i]);
    mpz_init(group->pctab_p2[i]);
    mpz_init(group->pctab_n2[i]);
  }

  goo_mpz_import(group->n, n, n_len);

  mpz_set(group->nh, group->n);
  mpz_fdiv_q_ui(group->nh, group->nh, 2);

  mpz_set_ui(group->g, g);
  mpz_set_ui(group->h, h);

  goo_comb_init(&group->g_comb, group, group->g);
  goo_comb_init(&group->h_comb, group, group->h);

  return 1;
}

static void
goo_group_uninit(goo_group_t *group) {
  mpz_clear(group->n);
  mpz_clear(group->nh);
  mpz_clear(group->g);
  mpz_clear(group->h);
  mpz_clear(group->b12);
  mpz_clear(group->b34);
  mpz_clear(group->b1234);
  mpz_clear(group->b12345);
  mpz_clear(group->b12_inv);
  mpz_clear(group->b34_inv);
  mpz_clear(group->b1234_inv);
  mpz_clear(group->b12345_inv);
  mpz_clear(group->bsq);
  mpz_clear(group->val);
  mpz_clear(group->mask);
  mpz_clear(group->r);
  mpz_clear(group->gh);
  mpz_clear(group->C1_inv);
  mpz_clear(group->C2_inv);
  mpz_clear(group->Aq_inv);
  mpz_clear(group->Bq_inv);
  mpz_clear(group->Cq_inv);
  mpz_clear(group->A);
  mpz_clear(group->B);
  mpz_clear(group->C);
  mpz_clear(group->D);
  mpz_clear(group->zp_w2_m_an);
  mpz_clear(group->tmp);
  mpz_clear(group->chall_out);
  mpz_clear(group->ell_r_out);
  mpz_clear(group->elldiff);
  mpz_clear(group->C1);
  mpz_clear(group->C2);
  mpz_clear(group->t);
  mpz_clear(group->msg);
  mpz_clear(group->chall);
  mpz_clear(group->ell);
  mpz_clear(group->Aq);
  mpz_clear(group->Bq);
  mpz_clear(group->Cq);
  mpz_clear(group->Dq);
  mpz_clear(group->zp_w);
  mpz_clear(group->zp_w2);
  mpz_clear(group->zp_s1);
  mpz_clear(group->zp_a);
  mpz_clear(group->zp_an);
  mpz_clear(group->zp_s1w);
  mpz_clear(group->zp_sa);

  for (int i = 0; i < GOO_TABLEN; i++) {
    mpz_clear(group->pctab_p1[i]);
    mpz_clear(group->pctab_n1[i]);
    mpz_clear(group->pctab_p2[i]);
    mpz_clear(group->pctab_n2[i]);
  }

  goo_comb_uninit(&group->g_comb);
  goo_comb_uninit(&group->h_comb);
}

static void
goo_group_reduce(goo_group_t *group, mpz_t ret, const mpz_t b) {
  if (mpz_cmp(b, group->nh) > 0)
    mpz_sub(ret, group->n, b);
}

static int
goo_group_is_reduced(goo_group_t *group, const mpz_t b) {
  return mpz_cmp(b, group->nh) <= 0 ? 1 : 0;
}

static void
goo_group_sqr(goo_group_t *group, mpz_t ret, const mpz_t b) {
  mpz_powm_ui(ret, b, 2, group->n);
}

static void
goo_group_pow(
  goo_group_t *group,
  mpz_t ret,
  const mpz_t b,
  const mpz_t b_inv,
  const mpz_t e
) {
  mpz_powm(ret, b, e, group->n);
}

static void
goo_group_mul(goo_group_t *group, mpz_t ret, const mpz_t m1, const mpz_t m2) {
  mpz_mul(ret, m1, m2);
  mpz_mod(ret, ret, group->n);
}

static int
goo_group_inv(goo_group_t *group, mpz_t ret, const mpz_t b) {
  return mpz_invert(ret, b, group->n) != 0 ? 1 : 0;
}

static int
goo_group_inv2(
  goo_group_t *group,
  mpz_t r1,
  mpz_t r2,
  const mpz_t b1,
  const mpz_t b2
) {
  mpz_mul(group->b12_inv, b1, b2);

  if (!goo_group_inv(group, group->b12_inv, group->b12_inv))
    return 0;

  goo_group_mul(group, r1, b2, group->b12_inv);
  goo_group_mul(group, r2, b1, group->b12_inv);

  return 1;
}

static int
goo_group_inv5(
  goo_group_t *group,
  mpz_t r1,
  mpz_t r2,
  mpz_t r3,
  mpz_t r4,
  mpz_t r5,
  const mpz_t b1,
  const mpz_t b2,
  const mpz_t b3,
  const mpz_t b4,
  const mpz_t b5
) {
  goo_group_mul(group, group->b12, b1, b2);
  goo_group_mul(group, group->b34, b3, b4);
  goo_group_mul(group, group->b1234, group->b12, group->b34);
  goo_group_mul(group, group->b12345, group->b1234, b5);

  if (!goo_group_inv(group, group->b12345_inv, group->b12345))
    return 0;

  goo_group_mul(group, group->b1234_inv, group->b12345_inv, b5);
  goo_group_mul(group, group->b34_inv, group->b1234_inv, group->b12);
  goo_group_mul(group, group->b12_inv, group->b1234_inv, group->b34);

  goo_group_mul(group, r1, group->b12_inv, b2);
  goo_group_mul(group, r2, group->b12_inv, b1);
  goo_group_mul(group, r3, group->b34_inv, b4);
  goo_group_mul(group, r4, group->b34_inv, b3);
  goo_group_mul(group, r5, group->b12345_inv, group->b1234);

  return 1;
}

static int
goo_group_powgh(goo_group_t *group, mpz_t ret, const mpz_t e1, const mpz_t e2) {
  goo_comb_t *gcomb = &group->g_comb;
  goo_comb_t *hcomb = &group->h_comb;

  if (!goo_to_comb_exp(gcomb, e1))
    return 0;

  if (!goo_to_comb_exp(hcomb, e2))
    return 0;

  mpz_set_ui(ret, 1);

  for (int i = 0; i < GOO_NSHIFTS; i++) {
    long *e1vs = gcomb->wins[i];
    long *e2vs = hcomb->wins[i];

    if (mpz_cmp_ui(ret, 1) != 0)
      goo_group_sqr(group, ret, ret);

    for (int j = 0; j < GOO_ADDS_PER_SHIFT; j++) {
      long e1v = e1vs[j];
      long e2v = e2vs[j];

      if (e1v != 0) {
        mpz_t *g = &gcomb->items[j * GOO_POINTS_PER_SUBCOMB + e1v - 1];
        goo_group_mul(group, ret, ret, *g);
      }

      if (e2v != 0) {
        mpz_t *h = &hcomb->items[j * GOO_POINTS_PER_SUBCOMB + e2v - 1];
        goo_group_mul(group, ret, ret, *h);
      }
    }
  }

  return 1;
}

static int
goo_group_wnaf_pc_help(goo_group_t *group, const mpz_t b, mpz_t *out) {
  goo_group_sqr(group, group->bsq, b);

  mpz_set(out[0], b);

  for (int i = 1; i < GOO_TABLEN; i++)
    goo_group_mul(group, out[i], out[i - 1], group->bsq);

  return 1;
}

static int
goo_group_precomp_wnaf(
  goo_group_t *group,
  const mpz_t b,
  const mpz_t b_inv,
  mpz_t *p,
  mpz_t *n
) {
  if (!goo_group_wnaf_pc_help(group, b, p))
    return 0;

  if (!goo_group_wnaf_pc_help(group, b_inv, n))
    return 0;

  return 1;
}

static long *
goo_group_wnaf(goo_group_t *group, const mpz_t e, long *out, int bitlen) {
  long w = GOO_WINSIZE;

  mpz_set(group->r, e);

  for (int i = bitlen - 1; i >= 0; i--) {
    mpz_set_ui(group->val, 0);

    // if (mpz_tstbit(group->r, 1)) {
    if (mpz_odd_p(group->r)) {
      mpz_set_ui(group->mask, (1 << w) - 1);
      mpz_and(group->val, group->r, group->mask);
      if (mpz_tstbit(group->val, w - 1))
        mpz_sub_ui(group->val, group->val, 1 << w);
      mpz_sub(group->r, group->r, group->val);
    }

    assert(mpz_fits_slong_p(group->val));
    out[i] = mpz_get_si(group->val);

    mpz_fdiv_q_ui(group->r, group->r, 2);
  }

  assert(mpz_cmp_ui(group->r, 0) == 0);

  return out;
}

static void
goo_group_one_mul(
  goo_group_t *group,
  mpz_t ret,
  long w,
  const mpz_t *p,
  const mpz_t *n
) {
  if (w > 0)
    goo_group_mul(group, ret, ret, p[(w - 1) >> 1]);
  else if (w < 0)
    goo_group_mul(group, ret, ret, n[(-1 - w) >> 1]);
}

static int
goo_group_pow2(
  goo_group_t *group,
  mpz_t ret,
  const mpz_t b1,
  const mpz_t b1_inv,
  const mpz_t e1,
  const mpz_t b2,
  const mpz_t b2_inv,
  const mpz_t e2
) {
  mpz_t *p1 = &group->pctab_p1[0];
  mpz_t *n1 = &group->pctab_n1[0];
  mpz_t *p2 = &group->pctab_p2[0];
  mpz_t *n2 = &group->pctab_n2[0];

  if (!goo_group_precomp_wnaf(group, b1, b1_inv, p1, n1))
    return 0;

  if (!goo_group_precomp_wnaf(group, b2, b2_inv, p2, n2))
    return 0;

  size_t e1len = goo_mpz_bitlen(e1);
  size_t e2len = goo_mpz_bitlen(e2);
  size_t totlen = (e1len > e2len ? e1len : e2len) + 1;

  long *e1bits = goo_group_wnaf(group, e1, &group->e1bits[0], totlen);
  long *e2bits = goo_group_wnaf(group, e2, &group->e2bits[0], totlen);

  mpz_init_set_ui(ret, 1); // XXX

  for (size_t i = 0; i < totlen; i++) {
    long w1 = e1bits[i];
    long w2 = e2bits[i];

    if (mpz_cmp_ui(ret, 1) != 0)
      goo_group_sqr(group, ret, ret);

    goo_group_one_mul(group, ret, w1, p1, n1);
    goo_group_one_mul(group, ret, w2, p2, n2);
  }

  return 1;
}

static int
goo_group_recon(
  goo_group_t *group,
  mpz_t ret,
  const mpz_t b1,
  const mpz_t b1_inv,
  const mpz_t e1,
  const mpz_t b2,
  const mpz_t b2_inv,
  const mpz_t e2,
  const mpz_t e3,
  const mpz_t e4
) {
  if (!goo_group_pow2(group, ret, b1, b1_inv, e1, b2, b2_inv, e2))
    return 0;

  if (!goo_group_powgh(group, group->gh, e3, e4))
    return 0;

  goo_group_mul(group, ret, ret, group->gh);
  goo_group_reduce(group, ret, ret);

  return 1;
}

static void
goo_hash_item(
  goo_sha256_t *ctx,
  const mpz_t n,
  unsigned char *size,
  unsigned char *buf
) {
  size_t len = 0;

  assert(goo_mpz_bytesize(n) <= 768);
  goo_mpz_export(&buf[0], &len, n);
  assert(len <= 768);

  // Commit to sign.
  if (mpz_cmp_ui(n, 0) < 0)
    len |= 0x8000;

  size[0] = len;
  size[1] = len >> 8;

  len &= ~0x8000;

  goo_sha256_update(ctx, size, 2);
  goo_sha256_update(ctx, buf, len);
}

static void
goo_hash_all(
  unsigned char *out,
  goo_group_t *group,
  const mpz_t C1,
  const mpz_t C2,
  const mpz_t t,
  const mpz_t A,
  const mpz_t B,
  const mpz_t C,
  const mpz_t D,
  const mpz_t msg
) {
  goo_sha256_t ctx;
  goo_sha256_init(&ctx);
  assert(sizeof(goo_prefix) == 10);
  goo_sha256_update(&ctx, (const void *)goo_prefix, sizeof(goo_prefix) - 1);

  unsigned char size[2];
  unsigned char buf[768];

  goo_hash_item(&ctx, group->n, size, buf);
  goo_hash_item(&ctx, group->g, size, buf);
  goo_hash_item(&ctx, group->h, size, buf);
  goo_hash_item(&ctx, C1, size, buf);
  goo_hash_item(&ctx, C2, size, buf);
  goo_hash_item(&ctx, t, size, buf);
  goo_hash_item(&ctx, A, size, buf);
  goo_hash_item(&ctx, B, size, buf);
  goo_hash_item(&ctx, C, size, buf);
  goo_hash_item(&ctx, D, size, buf);
  goo_hash_item(&ctx, msg, size, buf);

  goo_sha256_final(&ctx, &out[0]);
}

static void
goo_fs_chal(
  mpz_t chall_out,
  mpz_t ell_r_out,
  goo_group_t *group,
  const mpz_t C1,
  const mpz_t C2,
  const mpz_t t,
  const mpz_t A,
  const mpz_t B,
  const mpz_t C,
  const mpz_t D,
  const mpz_t msg
) {
  unsigned char key[32];

  goo_hash_all(&key[0], group, C1, C2, t, A, B, C, D, msg);

  goo_prng_t prng;
  goo_prng_init(&prng, &key[0]);
  goo_prng_getrandbits(&prng, chall_out, GOO_CHALBITS);
  goo_prng_getrandbits(&prng, ell_r_out, GOO_CHALBITS);
  goo_prng_uninit(&prng);
}

static int
goo_is_prime(const mpz_t p) {
  return mpz_probab_prime_p(p, 2) != 0 ? 1 : 0;
}

static int
goo_group_verify(
  goo_group_t *group,

  // pubkey
  const mpz_t C1,
  const mpz_t C2,
  const mpz_t t,

  // msg
  const mpz_t msg,

  // sigma
  const mpz_t chall,
  const mpz_t ell,
  const mpz_t Aq,
  const mpz_t Bq,
  const mpz_t Cq,
  const mpz_t Dq,

  // z_prime
  const mpz_t zp_w,
  const mpz_t zp_w2,
  const mpz_t zp_s1,
  const mpz_t zp_a,
  const mpz_t zp_an,
  const mpz_t zp_s1w,
  const mpz_t zp_sa
) {
  mpz_t *C1_inv = &group->C1_inv;
  mpz_t *C2_inv = &group->C2_inv;
  mpz_t *Aq_inv = &group->Aq_inv;
  mpz_t *Bq_inv = &group->Bq_inv;
  mpz_t *Cq_inv = &group->Cq_inv;
  mpz_t *A = &group->A;
  mpz_t *B = &group->B;
  mpz_t *C = &group->C;
  mpz_t *D = &group->D;
  mpz_t *zp_w2_m_an = &group->zp_w2_m_an;
  mpz_t *tmp = &group->tmp;
  mpz_t *chall_out = &group->chall_out;
  mpz_t *ell_r_out = &group->ell_r_out;
  mpz_t *elldiff = &group->elldiff;

  // `t` must be one of the small primes in our list.
  int found = 0;

  for (int i = 0; i < 168; i++) {
    if (mpz_cmp_ui(t, goo_primes[i]) == 0) {
      found = 1;
      break;
    }
  }

  if (!found)
    return 0;

  // All group elements must be the "canonical"
  // element of the quotient group (Z/n)/{1,-1}.
  if (!goo_group_is_reduced(group, C1)
      || !goo_group_is_reduced(group, C2)
      || !goo_group_is_reduced(group, Aq)
      || !goo_group_is_reduced(group, Bq)
      || !goo_group_is_reduced(group, Cq)) {
    return 0;
  }

  // compute inverses of C1, C2, Aq, Bq, Cq
  if (!goo_group_inv5(group, *C1_inv, *C2_inv, *Aq_inv,
                      *Bq_inv, *Cq_inv, C1, C2, Aq, Bq, Cq)) {
    return 0;
  }

  // Step 1: reconstruct A, B, C, and D from signature.
  if (!goo_group_recon(group, *A, Aq, *Aq_inv, ell,
                       *C2_inv, C2, chall, zp_w, zp_s1)) {
    return 0;
  }

  if (!goo_group_recon(group, *B, Bq, *Bq_inv, ell,
                       *C2_inv, C2, zp_w, zp_w2, zp_s1w)) {
    return 0;
  }

  if (!goo_group_recon(group, *C, Cq, *Cq_inv, ell,
                       *C1_inv, C1, zp_a, zp_an, zp_sa)) {
    return 0;
  }

  // Make sure sign of (zp_w2 - zp_an) is positive.
  mpz_sub(*zp_w2_m_an, zp_w2, zp_an);

  mpz_mul(*D, Dq, ell);
  mpz_add(*D, *D, *zp_w2_m_an);
  mpz_mul(*tmp, t, chall);
  mpz_sub(*D, *D, *tmp);

  if (mpz_cmp_ui(*zp_w2_m_an, 0) < 0)
    mpz_add(*D, *D, ell);

  // Step 2: recompute implicitly claimed V message, viz., chal and ell.
  goo_fs_chal(*chall_out, *ell_r_out, group, C1, C2, t, *A, *B, *C, *D, msg);

  // Final checks.
  // chal has to match
  // AND 0 <= (ell_r_out - ell) <= elldiff_max
  // AND ell is prime
  mpz_sub(*elldiff, ell, *ell_r_out);

  if (mpz_cmp(chall, *chall_out) != 0
      || mpz_cmp_ui(*elldiff, 0) < 0
      || mpz_cmp_ui(*elldiff, GOO_ELLDIFF_MAX) > 0
      || !goo_is_prime(ell)) {
    return 0;
  }

  return 1;
}

/*
 * Expose
 */

int
goo_init(
  goo_ctx_t *ctx,
  const unsigned char *n,
  size_t n_len,
  unsigned long g,
  unsigned long h
) {
  if (ctx == NULL || n == NULL)
    return 0;

  return goo_group_init(ctx, n, n_len, g, h);
}

void
goo_uninit(goo_ctx_t *ctx) {
  if (ctx != NULL)
    goo_group_uninit(ctx);
}

#define goo_read_item(n) do {              \
  if (p + 2 > proof_len)                   \
    return 0;                              \
                                           \
  len = (proof[p + 1] * 0x100) | proof[p]; \
                                           \
  if (len > 768)                           \
    return 0;                              \
                                           \
  p += 2;                                  \
                                           \
  if (p + len > proof_len)                 \
    return 0;                              \
                                           \
  goo_mpz_import((n), &proof[p], len);     \
  p += len;                                \
} while (0)                                \

#define goo_read_final() do { \
  assert(p <= proof_len);     \
                              \
  if (p != proof_len)         \
    return 0;                 \
} while (0)                   \

int
goo_verify(
  goo_ctx_t *ctx,
  const unsigned char *msg,
  size_t msg_len,
  const unsigned char *proof,
  size_t proof_len
) {
  if (ctx == NULL || msg == NULL || proof == NULL)
    return 0;

  // if (msg_len < 20 || msg_len > 128)
  //   return 0;

  goo_mpz_import(ctx->msg, msg, msg_len);

  size_t p = 0;
  size_t len = 0;

  goo_read_item(ctx->C1);
  goo_read_item(ctx->C2);
  goo_read_item(ctx->t);

  goo_read_item(ctx->chall);
  goo_read_item(ctx->ell);
  goo_read_item(ctx->Aq);
  goo_read_item(ctx->Bq);
  goo_read_item(ctx->Cq);
  goo_read_item(ctx->Dq);

  goo_read_item(ctx->zp_w);
  goo_read_item(ctx->zp_w2);
  goo_read_item(ctx->zp_s1);
  goo_read_item(ctx->zp_a);
  goo_read_item(ctx->zp_an);
  goo_read_item(ctx->zp_s1w);
  goo_read_item(ctx->zp_sa);

  goo_read_final();

  return goo_group_verify(
    ctx,

    // pubkey
    ctx->C1,
    ctx->C2,
    ctx->t,

    // msg
    ctx->msg,

    // sigma
    ctx->chall,
    ctx->ell,
    ctx->Aq,
    ctx->Bq,
    ctx->Cq,
    ctx->Dq,

    // z_prime
    ctx->zp_w,
    ctx->zp_w2,
    ctx->zp_s1,
    ctx->zp_a,
    ctx->zp_an,
    ctx->zp_s1w,
    ctx->zp_sa
  );
}
