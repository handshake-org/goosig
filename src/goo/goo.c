/*!
 * goo.c - groups of unknown order for C89
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Parts of this software are based on kwantam/libGooPy:
 *   Copyright (c) 2018, Dan Boneh, Riad S. Wahby (Apache License).
 *   https://github.com/kwantam/GooSig
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Parts of this software are based on indutny/miller-rabin:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/miller-rabin
 *
 * Resources:
 *   https://github.com/kwantam/GooSig/blob/master/protocol.txt
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/group_ops.py
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/group_mixins.py
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/tokengen.py
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/sign.py
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/verify.py
 *   https://github.com/golang/go/blob/master/src/math/big/prime.go
 *   https://github.com/golang/go/blob/master/src/math/big/int.go
 *   https://github.com/golang/go/blob/master/src/math/big/nat.go
 *   https://github.com/golang/go/blob/master/src/crypto/rand/util.go
 *   https://github.com/indutny/miller-rabin/blob/master/lib/mr.js
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "goo.h"
#include "primes.h"

/*
 * Allocator
 */

static void *
goo_malloc(size_t size) {
  void *ptr;

  if (size == 0)
    return NULL;

  ptr = malloc(size);

  if (ptr == NULL)
    abort();

  return ptr;
}

static void *
goo_calloc(size_t nmemb, size_t size) {
  void *ptr;

  if (nmemb == 0 || size == 0)
    return NULL;

  ptr = calloc(nmemb, size);

  if (ptr == NULL)
    abort();

  return ptr;
}

static void *
goo_realloc(void *ptr, size_t size) {
  if (size == 0)
    return realloc(ptr, size);

  ptr = realloc(ptr, size);

  if (ptr == NULL)
    abort();

  return ptr;
}

static void
goo_free(void *ptr) {
  if (ptr != NULL)
    free(ptr);
}

/*
 * GMP helpers
 */

#define goo_mpz_import(ret, data, len) \
  mpz_import((ret), (len), 1, sizeof((data)[0]), 0, 0, (data))

#define goo_mpz_export(data, size, n) \
  mpz_export((data), (size), 1, sizeof((data)[0]), 0, 0, (n));

#define goo_mpz_print(n) \
  (mpz_out_str(stdout, 16, (n)), printf("\n"))

/* For debugging */
#define goo_print_hex(data, len) do { \
  mpz_t n;                            \
  mpz_init(n);                        \
  goo_mpz_import(n, (data), (len));   \
  goo_mpz_print(n);                   \
  mpz_clear(n);                       \
} while (0)

#define goo_mpz_bytelen(n) \
  (goo_mpz_bitlen((n)) + 7) / 8

#define goo_mpz_lshift mpz_mul_2exp
#define goo_mpz_rshift mpz_fdiv_q_2exp
#define goo_mpz_urshift mpz_tdiv_q_2exp
#define goo_mpz_mod_ui mpz_fdiv_ui
#define goo_mpz_and_ui(x, y) (mpz_getlimbn((x), 0) & (y))

/* Note: violates strict aliasing. */
#define goo_mpz_unconst(n) *((mpz_t *)&(n))

#define VERIFY_POS(x) if (mpz_sgn((x)) < 0) goto fail

static size_t
goo_mpz_bitlen(const mpz_t n) {
  if (mpz_sgn(n) == 0)
    return 0;

  return mpz_sizeinbase(n, 2);
}

static void *
goo_mpz_pad(unsigned char *out, size_t size, const mpz_t n) {
  size_t len = goo_mpz_bytelen(n);
  size_t pos;

  if (len > size)
    return NULL;

  if (size == 0)
    return NULL;

  if (out == NULL)
    out = goo_malloc(size);

  pos = size - len;

  memset(out, 0x00, pos);

  goo_mpz_export(out + pos, NULL, n);

  return out;
}

static unsigned long
goo_mpz_zerobits(const mpz_t n) {
  /* Note: mpz_ptr is undocumented. */
  /* https://gmplib.org/list-archives/gmp-discuss/2009-May/003769.html */
  /* https://gmplib.org/list-archives/gmp-devel/2013-February/002775.html */
  int sgn = mpz_sgn(n);
  unsigned long bits;

  if (sgn == 0)
    return 0;

  if (sgn < 0)
    mpz_neg((mpz_ptr)n, n);

  bits = mpz_scan1(n, 0);

  if (sgn < 0)
    mpz_neg((mpz_ptr)n, n);

  return bits;
}

static void
goo_mpz_mask(mpz_t r, const mpz_t n, unsigned long bit, mpz_t tmp) {
  mpz_ptr mask = tmp;

  if (bit == 0) {
    mpz_set_ui(r, 0);
    return;
  }

  /* mask = (1 << bit) - 1 */
  mpz_set_ui(mask, 1);
  mpz_mul_2exp(mask, mask, bit);
  mpz_sub_ui(mask, mask, 1);

  /* r = n & mask */
  mpz_and(r, n, mask);
}

#if !defined(GOO_HAS_GMP) || defined(GOO_TEST)
/* https://github.com/golang/go/blob/aadaec5/src/math/big/int.go#L754 */
static int
goo_mpz_jacobi(const mpz_t x, const mpz_t y) {
  mpz_t a, b, c;
  unsigned long s, bmod8;
  int j;

  /* Undefined behavior. */
  /* if y == 0 or y & 1 == 0 */
  if (mpz_sgn(y) == 0 || mpz_even_p(y))
    return 0;

  mpz_init(a);
  mpz_init(b);
  mpz_init(c);

  /* a = x */
  mpz_set(a, x);
  /* b = y */
  mpz_set(b, y);
  j = 1;

  /* if b < 0 */
  if (mpz_sgn(b) < 0) {
    /* if a < 0 */
    if (mpz_sgn(a) < 0)
      j = -1;
    /* b = -b */
    mpz_neg(b, b);
  }

  for (;;) {
    /* if b == 1 */
    if (mpz_cmp_ui(b, 1) == 0)
      break;

    /* if a == 0 */
    if (mpz_sgn(a) == 0) {
      j = 0;
      break;
    }

    /* a = a mod b */
    mpz_mod(a, a, b);

    /* if a == 0 */
    if (mpz_sgn(a) == 0) {
      j = 0;
      break;
    }

    /* s = a factors of 2 */
    s = goo_mpz_zerobits(a);

    if (s & 1) {
      /* bmod8 = b mod 8 */
      bmod8 = mpz_getlimbn(b, 0) & 7;

      if (bmod8 == 3 || bmod8 == 5)
        j = -j;
    }

    /* c = a >> s */
    mpz_tdiv_q_2exp(c, a, s);

    /* if b mod 4 == 3 and c mod 4 == 3 */
    if ((mpz_getlimbn(b, 0) & 3) == 3 && (mpz_getlimbn(c, 0) & 3) == 3)
      j = -j;

    /* a = b */
    mpz_set(a, b);
    /* b = c */
    mpz_set(b, c);
  }

  mpz_clear(a);
  mpz_clear(b);
  mpz_clear(c);

  return j;
}
#endif

#ifndef GOO_HAS_GMP
/* Jacobi is not implemented in mini-gmp. */
#define mpz_jacobi goo_mpz_jacobi
#endif

static void
goo_mpz_add_si(mpz_t r, const mpz_t n, long val) {
  if (val < 0)
    mpz_sub_ui(r, n, -val);
  else
    mpz_add_ui(r, n, val);
}

static void
goo_mpz_sub_si(mpz_t r, const mpz_t n, long val) {
  if (val < 0)
    mpz_add_ui(r, n, -val);
  else
    mpz_sub_ui(r, n, val);
}

/*
 * PRNG
 */

static void
goo_prng_init(goo_prng_t *prng) {
  mpz_init(prng->save);
  mpz_init(prng->tmp);
}

static void
goo_prng_uninit(goo_prng_t *prng) {
  mpz_clear(prng->save);
  mpz_clear(prng->tmp);
}

static void
goo_prng_seed(goo_prng_t *prng, const unsigned char *key) {
  unsigned char entropy[96];

  memcpy(&entropy[0], key, 32);
  memcpy(&entropy[32], GOO_DRBG_PERS, 64);

  goo_drbg_init(&prng->ctx, entropy, 96);

  mpz_set_ui(prng->save, 0);
  prng->total = 0;
}

static void
goo_prng_seed_local(goo_prng_t *prng, const unsigned char *seed) {
  unsigned char entropy[96];

  memcpy(&entropy[0], seed, 64);
  memcpy(&entropy[64], GOO_DRBG_LOCAL, 32);

  goo_drbg_init(&prng->ctx, entropy, 96);

  mpz_set_ui(prng->save, 0);
  prng->total = 0;
}

static void
goo_prng_generate(goo_prng_t *prng, void *out, size_t len) {
  (void)goo_drbg_generate(&prng->ctx, out, len);
}

static void
goo_prng_random_bits(goo_prng_t *prng, mpz_t ret, unsigned long bits) {
  unsigned long total = prng->total;
  unsigned char out[32];
  unsigned long left;

  /* ret = save */
  mpz_set(ret, prng->save);

  while (total < bits) {
    /* ret = ret << 256 */
    mpz_mul_2exp(ret, ret, 256);

    /* tmp = random 256 bit integer */
    goo_prng_generate(prng, &out[0], 32);
    goo_mpz_import(prng->tmp, &out[0], 32);

    /* ret = ret | tmp */
    mpz_ior(ret, ret, prng->tmp);
    total += 256;
  }

  left = total - bits;

  /* save = ret & ((1 << left) - 1) */
  goo_mpz_mask(prng->save, ret, left, prng->tmp);
  prng->total = left;

  /* ret >>= left */
  mpz_tdiv_q_2exp(ret, ret, left);
}

static void
goo_prng_random_int(goo_prng_t *prng, mpz_t ret, const mpz_t max) {
  size_t bits;

  /* if max <= 0 */
  if (mpz_sgn(max) <= 0) {
    /* ret = 0 */
    mpz_set_ui(ret, 0);
    return;
  }

  /* ret = max */
  mpz_set(ret, max);

  /* bits = ceil(log2(ret)) */
  bits = goo_mpz_bitlen(ret);

  assert(bits > 0);

  /* while ret >= max */
  while (mpz_cmp(ret, max) >= 0)
    goo_prng_random_bits(prng, ret, bits);
}

static unsigned long
goo_prng_random_num(goo_prng_t *prng, unsigned long max) {
  unsigned long x, r;

  if (max == 0)
    return 0;

  /* http://www.pcg-random.org/posts/bounded-rands.html */
  do {
    goo_prng_generate(prng, (void *)&x, sizeof(unsigned long));
    r = x % max;
  } while (x - r > (-max));

  return r;
}

/*
 * Utils
 */

static unsigned long
goo_isqrt(unsigned long x) {
  unsigned long len = 0;
  unsigned long y = x;
  unsigned long z1, z2;

  if (x <= 1)
    return x;

  while (y) {
    len += 1;
    y >>= 1;
  }

  z1 = 1 << ((len >> 1) + 1);

  for (;;) {
    z2 = x / z1;
    z2 += z1;
    z2 >>= 1;

    if (z2 >= z1)
      return z1;

    z1 = z2;
  }
}

/* https://github.com/golang/go/blob/c86d464/src/math/big/int.go#L906 */
static int
goo_mpz_sqrtm(mpz_t ret, const mpz_t num, const mpz_t p) {
  int r = 0;
  mpz_t x, e, t, a, s, n, y, b, g;
  unsigned long z, k;

  mpz_init(x);
  mpz_init(e);
  mpz_init(t);
  mpz_init(a);
  mpz_init(s);
  mpz_init(n);
  mpz_init(y);
  mpz_init(b);
  mpz_init(g);

  /* x = num */
  mpz_set(x, num);

  if (mpz_sgn(p) <= 0 || !mpz_odd_p(p))
    goto fail;

  /* if x < 0 || x >= p */
  if (mpz_sgn(x) < 0 || mpz_cmp(x, p) >= 0) {
    /* x = x mod p */
    mpz_mod(x, x, p);
  }

  /* if p mod 4 == 3 */
  if ((mpz_getlimbn(p, 0) & 3) == 3) {
    /* e = (p + 1) / 4 */
    mpz_add_ui(e, p, 1);
    mpz_tdiv_q_2exp(e, e, 2);

    /* b = x^e mod p */
    mpz_powm(b, x, e, p);

    /* g = b^2 mod p */
    mpz_mul(g, b, b);
    mpz_mod(g, g, p);

    /* g != x */
    if (mpz_cmp(g, x) != 0)
      goto fail;

    /* ret = b */
    mpz_set(ret, b);

    goto success;
  }

  /* if p mod 8 == 5 */
  if ((mpz_getlimbn(p, 0) & 7) == 5) {
    /* e = (p - 5) / 8 */
    mpz_tdiv_q_2exp(e, p, 3);

    /* t = x * 2 mod p */
    mpz_mul_2exp(t, x, 1);
    mpz_mod(t, t, p);

    /* a = t^e mod p */
    mpz_powm(a, t, e, p);

    /* b = a^2 mod p */
    mpz_mul(b, a, a);
    mpz_mod(b, b, p);

    /* b = b * t mod p */
    mpz_mul(b, b, t);
    mpz_mod(b, b, p);

    /* b = (b - 1) mod p */
    mpz_sub_ui(b, b, 1);
    mpz_mod(b, b, p);

    /* b = b * x mod p */
    mpz_mul(b, b, x);
    mpz_mod(b, b, p);

    /* b = b * a mod p */
    mpz_mul(b, b, a);
    mpz_mod(b, b, p);

    /* g = b^2 mod p */
    mpz_mul(g, b, b);
    mpz_mod(g, g, p);

    /* g != x */
    if (mpz_cmp(g, x) != 0)
      goto fail;

    /* ret = b */
    mpz_set(ret, b);

    goto success;
  }

  /* p = 1 */
  if (mpz_cmp_ui(p, 1) == 0)
    goto fail;

  switch (mpz_jacobi(x, p)) {
    case -1:
      goto fail;
    case 0:
      mpz_set_ui(ret, 0);
      goto success;
    case 1:
      break;
  }

  /* s = p - 1 */
  mpz_sub_ui(s, p, 1);

  /* z = s factors of 2 */
  z = goo_mpz_zerobits(s);

  /* s = s >> z */
  mpz_tdiv_q_2exp(s, s, z);

  /* n = 2 */
  mpz_set_ui(n, 2);

  /* while (n^((p - 1) / 2) mod p) != -1 */
  while (mpz_jacobi(n, p) != -1) {
    /* n = n + 1 */
    mpz_add_ui(n, n, 1);
  }

  /* y = s + 1 */
  mpz_add_ui(y, s, 1);

  /* y = y >> 1 */
  mpz_tdiv_q_2exp(y, y, 1);

  /* y = x^y mod p */
  mpz_powm(y, x, y, p);

  /* b = x^s mod p */
  mpz_powm(b, x, s, p);

  /* g = n^s mod p */
  mpz_powm(g, n, s, p);

  /* k = z */
  k = z;

  for (;;) {
    unsigned long m = 0;

    /* t = b */
    mpz_set(t, b);

    /* while t != 1 */
    while (mpz_cmp_ui(t, 1) != 0) {
      /* t = t^2 mod p */
      mpz_mul(t, t, t);
      mpz_mod(t, t, p);
      m += 1;
    }

    /* if m == 0 */
    if (m == 0)
      break;

    /* if m >= k */
    if (m >= k)
      goto fail;

    /* t = 1 << (k - m - 1) */
    mpz_set_ui(t, 1);
    mpz_mul_2exp(t, t, k - m - 1);

    /* t = g^t mod p */
    mpz_powm(t, g, t, p);

    /* g = t^2 mod p */
    mpz_mul(g, t, t);
    mpz_mod(g, g, p);

    /* y = y * t mod p */
    mpz_mul(y, y, t);
    mpz_mod(y, y, p);

    /* b = b * g mod p */
    mpz_mul(b, b, g);
    mpz_mod(b, b, p);

    /* k = m */
    k = m;
  }

  /* ret = y */
  mpz_set(ret, y);
success:
  r = 1;
fail:
  mpz_clear(x);
  mpz_clear(e);
  mpz_clear(t);
  mpz_clear(a);
  mpz_clear(s);
  mpz_clear(n);
  mpz_clear(y);
  mpz_clear(b);
  mpz_clear(g);
  return r;
}

static int
goo_mpz_sqrtpq(mpz_t ret, const mpz_t x, const mpz_t p, const mpz_t q) {
  /* Compute x^(1 / 2) mod (p * q). */
  int r = 0;
  mpz_t sp, sq, mp, mq, xx, yy;

  mpz_init(sp);
  mpz_init(sq);
  mpz_init(mp);
  mpz_init(mq);
  mpz_init(xx);
  mpz_init(yy);

  /* sp = x^(1 / 2) mod p */
  /* sq = x^(1 / 2) mod q */
  if (!goo_mpz_sqrtm(sp, x, p)
      || !goo_mpz_sqrtm(sq, x, q)) {
    goto fail;
  }

  /* [mp, mq] = bezout coefficients for egcd(p, q) */
  mpz_gcdext(xx, mp, mq, p, q);

  /* xx = sq * mp * p */
  mpz_mul(xx, sq, mp);
  mpz_mul(xx, xx, p);

  /* yy = sp * mq * q */
  mpz_mul(yy, sp, mq);
  mpz_mul(yy, yy, q);

  /* xx = xx + yy */
  mpz_add(xx, xx, yy);

  /* yy = p * q */
  mpz_mul(yy, p, q);

  /* ret = xx mod yy */
  mpz_mod(ret, xx, yy);

  r = 1;
fail:
  mpz_clear(sp);
  mpz_clear(sq);
  mpz_clear(mp);
  mpz_clear(mq);
  mpz_clear(xx);
  mpz_clear(yy);
  return r;
}

/*
 * Primes
 */

static int
goo_is_prime_div(const mpz_t n) {
  long i;

  /* if n <= 1 */
  if (mpz_cmp_ui(n, 1) <= 0)
    return 0;

  for (i = 0; i < GOO_TEST_PRIMES_LEN; i++) {
    /* if p == test_primes[i] */
    if (mpz_cmp_ui(n, goo_test_primes[i]) == 0)
      return 2;

    /* if n mod test_primes[i] == 0 */
    if (mpz_fdiv_ui(n, goo_test_primes[i]) == 0)
      return 0;
  }

  return 1;
}

/* https://github.com/golang/go/blob/aadaec5/src/math/big/prime.go#L81 */
/* https://github.com/indutny/miller-rabin/blob/master/lib/mr.js */
static int
goo_is_prime_mr(
  const mpz_t n,
  const unsigned char *key,
  long reps,
  int force2
) {
  int r = 0;
  mpz_t nm1, nm3, q, x, y;
  unsigned long k, j;
  long i;
  goo_prng_t prng;

  /* if n < 7 */
  if (mpz_cmp_ui(n, 7) < 0) {
    /* if n == 2 or n == 3 or n == 5 */
    if (mpz_cmp_ui(n, 2) == 0
        || mpz_cmp_ui(n, 3) == 0
        || mpz_cmp_ui(n, 5) == 0) {
      return 1;
    }
    return 0;
  }

  mpz_init(nm1);
  mpz_init(nm3);
  mpz_init(q);
  mpz_init(x);
  mpz_init(y);

  /* nm1 = n - 1 */
  mpz_sub_ui(nm1, n, 1);

  /* nm3 = nm1 - 2 */
  mpz_sub_ui(nm3, nm1, 2);

  /* k = nm1 factors of 2 */
  k = goo_mpz_zerobits(nm1);

  /* q = nm1 >> k */
  mpz_tdiv_q_2exp(q, nm1, k);

  /* Setup PRNG. */
  goo_prng_init(&prng);
  goo_prng_seed(&prng, key);

  for (i = 0; i < reps; i++) {
    if (i == reps - 1 && force2) {
      /* x = 2 */
      mpz_set_ui(x, 2);
    } else {
      /* x = random int in [2,n-1] */
      goo_prng_random_int(&prng, x, nm3);
      mpz_add_ui(x, x, 2);
    }

    /* y = x^q mod n */
    mpz_powm(y, x, q, n);

    /* if y == 1 || y == nm1 */
    if (mpz_cmp_ui(y, 1) == 0 || mpz_cmp(y, nm1) == 0)
      continue;

    for (j = 1; j < k; j++) {
      /* y = y^2 mod n */
      mpz_mul(y, y, y);
      mpz_mod(y, y, n);

      /* if y == nm1 */
      if (mpz_cmp(y, nm1) == 0)
        goto next;

      /* if y == 1 */
      if (mpz_cmp_ui(y, 1) == 0)
        goto fail;
    }

    goto fail;
next:
    ;
  }

  r = 1;
fail:
  mpz_clear(nm1);
  mpz_clear(nm3);
  mpz_clear(q);
  mpz_clear(x);
  mpz_clear(y);
  return r;
}

/* https://github.com/golang/go/blob/aadaec5/src/math/big/prime.go#L150 */
static int
goo_is_prime_lucas(const mpz_t n) {
  int r = 0;
  unsigned long p;
  mpz_t d;
  mpz_t s, nm2;
  mpz_t vk, vk1;
  mpz_t t1, t2, t3;
  int j;
  unsigned long zb, bp;
  long i, t;

  mpz_init(d);
  mpz_init(s);
  mpz_init(nm2);
  mpz_init(vk);
  mpz_init(vk1);
  mpz_init(t1);
  mpz_init(t2);
  mpz_init(t3);

  /* Ignore 0 and 1. */
  /* if n <= 1 */
  if (mpz_cmp_ui(n, 1) <= 0)
    goto fail;

  /* Two is the only even prime. */
  /* if n & 1 == 0 */
  if (mpz_even_p(n)) {
    /* if n == 2 */
    if (mpz_cmp_ui(n, 2) == 0)
      goto succeed;
    goto fail;
  }

  /* Baillie-OEIS "method C" for choosing D, P, Q. */
  /* See: https://oeis.org/A217719/a217719.txt. */
  /* p = 3 */
  p = 3;
  /* d = 1 */
  mpz_set_ui(d, 1);

  for (;;) {
    if (p > 10000) {
      /* Thought to be impossible. */
      goto fail;
    }

    if (p > 50) {
      /* It's thought to be impossible for `p` */
      /* to be larger than 10,000, but fail */
      /* on anything higher than 50 to prevent */
      /* DoS attacks. `p` never seems to be */
      /* higher than 30 in practice. */
      goto fail;
    }

    /* d = p * p - 4 */
    mpz_set_ui(d, p * p - 4);

    j = mpz_jacobi(d, n);

    if (j == -1)
      break;

    if (j == 0) {
      /* if n == p + 2 */
      if (mpz_cmp_ui(n, p + 2) == 0)
        goto succeed;
      goto fail;
    }

    if (p == 40) {
      /* if (n^(1 / 2))^2 == n */
      if (mpz_perfect_square_p(n))
        goto fail;
    }

    p += 1;
  }

  /* Check for Grantham definition of */
  /* "extra strong Lucas pseudoprime". */
  /* s = n + 1 */
  mpz_add_ui(s, n, 1);

  /* zb = s factors of 2 */
  zb = goo_mpz_zerobits(s);

  /* nm2 = n - 2 */
  mpz_sub_ui(nm2, n, 2);

  /* s >>= zb */
  mpz_tdiv_q_2exp(s, s, zb);

  /* bp = p */
  bp = p;

  /* vk = 2 */
  mpz_set_ui(vk, 2);
  /* vk1 = p */
  mpz_set_ui(vk1, p);

  for (i = (long)goo_mpz_bitlen(s); i >= 0; i--) {
    if (mpz_tstbit(s, i)) {
      /* t1 = vk * vk1 */
      mpz_mul(t1, vk, vk1);
      /* t1 += n */
      mpz_add(t1, t1, n);
      /* t1 -= bp */
      mpz_sub_ui(t1, t1, bp);
      /* vk = t1 mod n */
      mpz_mod(vk, t1, n);
      /* t1 = vk1 * vk1 */
      mpz_mul(t1, vk1, vk1);
      /* t1 += nm2 */
      mpz_add(t1, t1, nm2);
      /* vk1 = t1 mod n */
      mpz_mod(vk1, t1, n);
    } else {
      /* t1 = vk * vk1 */
      mpz_mul(t1, vk, vk1);
      /* t1 += n */
      mpz_add(t1, t1, n);
      /* t1 -= bp */
      mpz_sub_ui(t1, t1, bp);
      /* vk1 = t1 mod n */
      mpz_mod(vk1, t1, n);
      /* t1 = vk * vk */
      mpz_mul(t1, vk, vk);
      /* t1 += nm2 */
      mpz_add(t1, t1, nm2);
      /* vk = t1 mod n */
      mpz_mod(vk, t1, n);
    }
  }

  /* if vk == 2 or vk == nm2 */
  if (mpz_cmp_ui(vk, 2) == 0 || mpz_cmp(vk, nm2) == 0) {
    /* t1 = vk * bp */
    mpz_mul_ui(t1, vk, bp);
    /* t2 = vk1 << 1 */
    mpz_mul_2exp(t2, vk1, 1);

    /* if t1 < t2 */
    if (mpz_cmp(t1, t2) < 0) {
      /* [t1, t2] = [t2, t1] */
      mpz_swap(t1, t2);
    }

    /* t1 -= t2 */
    mpz_sub(t1, t1, t2);

    /* t3 = t1 mod n */
    mpz_mod(t3, t1, n);

    /* if t3 == 0 */
    if (mpz_sgn(t3) == 0)
      goto succeed;
  }

  for (t = 0; t < (long)zb - 1; t++) {
    /* if vk == 0 */
    if (mpz_sgn(vk) == 0)
      goto succeed;

    /* if vk == 2 */
    if (mpz_cmp_ui(vk, 2) == 0)
      goto fail;

    /* t1 = vk * vk */
    mpz_mul(t1, vk, vk);
    /* t1 -= 2 */
    mpz_sub_ui(t1, t1, 2);
    /* vk = t1 mod n */
    mpz_mod(vk, t1, n);
  }

  goto fail;

succeed:
  r = 1;
fail:
  mpz_clear(d);
  mpz_clear(s);
  mpz_clear(nm2);
  mpz_clear(vk);
  mpz_clear(vk1);
  mpz_clear(t1);
  mpz_clear(t2);
  mpz_clear(t3);
  return r;
}

static int
goo_is_prime(const mpz_t p, const unsigned char *key) {
  int ret;

  /* if p <= 1 */
  if (mpz_cmp_ui(p, 1) <= 0)
    return 0;

  /* 0 = not prime */
  /* 1 = maybe prime */
  /* 2 = definitely prime */
  ret = goo_is_prime_div(p);

  if (ret == 0)
    return 0;

  /* Early exit. */
  if (ret == 2)
    return 1;

  if (!goo_is_prime_mr(p, key, 16 + 1, 1))
    return 0;

  if (!goo_is_prime_lucas(p))
    return 0;

  return 1;
}

static int
goo_next_prime(
  mpz_t ret,
  const mpz_t p,
  const unsigned char *key,
  unsigned long max
) {
  unsigned long inc = 0;

  mpz_set(ret, p);

  if (mpz_even_p(ret)) {
    inc += 1;
    mpz_add_ui(ret, ret, 1);
  }

  while (!goo_is_prime(ret, key)) {
    if (max != 0 && inc > max)
      break;

    mpz_add_ui(ret, ret, 2);
    inc += 2;
  }

  if (max != 0 && inc > max)
    return 0;

  return 1;
}

/*
 * Signature
 */

static void
goo_sig_init(goo_sig_t *sig) {
  mpz_init(sig->C2);
  mpz_init(sig->C3);
  mpz_init(sig->t);
  mpz_init(sig->chal);
  mpz_init(sig->ell);
  mpz_init(sig->Aq);
  mpz_init(sig->Bq);
  mpz_init(sig->Cq);
  mpz_init(sig->Dq);
  mpz_init(sig->Eq);
  mpz_init(sig->z_w);
  mpz_init(sig->z_w2);
  mpz_init(sig->z_s1);
  mpz_init(sig->z_a);
  mpz_init(sig->z_an);
  mpz_init(sig->z_s1w);
  mpz_init(sig->z_sa);
  mpz_init(sig->z_s2);
}

static void
goo_sig_uninit(goo_sig_t *sig) {
  mpz_clear(sig->C2);
  mpz_clear(sig->C3);
  mpz_clear(sig->t);
  mpz_clear(sig->chal);
  mpz_clear(sig->ell);
  mpz_clear(sig->Aq);
  mpz_clear(sig->Bq);
  mpz_clear(sig->Cq);
  mpz_clear(sig->Dq);
  mpz_clear(sig->Eq);
  mpz_clear(sig->z_w);
  mpz_clear(sig->z_w2);
  mpz_clear(sig->z_s1);
  mpz_clear(sig->z_a);
  mpz_clear(sig->z_an);
  mpz_clear(sig->z_s1w);
  mpz_clear(sig->z_sa);
  mpz_clear(sig->z_s2);
}

static size_t
goo_sig_size(const goo_sig_t *sig, size_t bits) {
  size_t mod_bytes = (bits + 7) / 8;
  size_t exp_bytes = (GOO_EXPONENT_SIZE + 7) / 8;
  size_t chal_bytes = (GOO_CHAL_BITS + 7) / 8;
  size_t ell_bytes = (GOO_ELL_BITS + 7) / 8;
  size_t len = 0;

  len += mod_bytes; /* C2 */
  len += mod_bytes; /* C3 */
  len += 2; /* t */
  len += chal_bytes; /* chal */
  len += ell_bytes; /* ell */
  len += mod_bytes; /* Aq */
  len += mod_bytes; /* Bq */
  len += mod_bytes; /* Cq */
  len += mod_bytes; /* Dq */
  len += exp_bytes; /* Eq */
  len += ell_bytes * 8; /* z' */
  len += 1; /* Eq sign */

  return len;
}

#define goo_write_int(n, size) do {     \
  size_t bytes = goo_mpz_bytelen((n));  \
  size_t pad;                           \
                                        \
  if (bytes > (size))                   \
    return 0;                           \
                                        \
  pad = (size) - bytes;                 \
  memset(&out[pos], 0x00, pad);         \
  pos += pad;                           \
                                        \
  goo_mpz_export(&out[pos], NULL, (n)); \
  pos += bytes;                         \
} while (0)

static int
goo_sig_export(unsigned char *out, const goo_sig_t *sig, size_t bits) {
  size_t mod_bytes = (bits + 7) / 8;
  size_t exp_bytes = (GOO_EXPONENT_SIZE + 7) / 8;
  size_t chal_bytes = (GOO_CHAL_BITS + 7) / 8;
  size_t ell_bytes = (GOO_ELL_BITS + 7) / 8;
  size_t pos = 0;

  goo_write_int(sig->C2, mod_bytes);
  goo_write_int(sig->C3, mod_bytes);
  goo_write_int(sig->t, 2);

  goo_write_int(sig->chal, chal_bytes);
  goo_write_int(sig->ell, ell_bytes);
  goo_write_int(sig->Aq, mod_bytes);
  goo_write_int(sig->Bq, mod_bytes);
  goo_write_int(sig->Cq, mod_bytes);
  goo_write_int(sig->Dq, mod_bytes);
  goo_write_int(sig->Eq, exp_bytes);

  goo_write_int(sig->z_w, ell_bytes);
  goo_write_int(sig->z_w2, ell_bytes);
  goo_write_int(sig->z_s1, ell_bytes);
  goo_write_int(sig->z_a, ell_bytes);
  goo_write_int(sig->z_an, ell_bytes);
  goo_write_int(sig->z_s1w, ell_bytes);
  goo_write_int(sig->z_sa, ell_bytes);
  goo_write_int(sig->z_s2, ell_bytes);

  out[pos] = mpz_sgn(sig->Eq) < 0 ? 1 : 0;
  pos += 1;

  assert(goo_sig_size(sig, bits) == pos);

  return 1;
}

#undef goo_write_int

#define goo_read_int(n, size) do {         \
  goo_mpz_import((n), &data[pos], (size)); \
  pos += (size);                           \
} while (0)                                \

static int
goo_sig_import(goo_sig_t *sig,
               const unsigned char *data,
               size_t data_len,
               size_t bits) {
  size_t mod_bytes = (bits + 7) / 8;
  size_t exp_bytes = (GOO_EXPONENT_SIZE + 7) / 8;
  size_t chal_bytes = (GOO_CHAL_BITS + 7) / 8;
  size_t ell_bytes = (GOO_ELL_BITS + 7) / 8;
  size_t pos = 0;
  unsigned char sign;

  if (data_len != goo_sig_size(sig, bits)) {
    /* Invalid signature size. */
    return 0;
  }

  goo_read_int(sig->C2, mod_bytes);
  goo_read_int(sig->C3, mod_bytes);
  goo_read_int(sig->t, 2);

  goo_read_int(sig->chal, chal_bytes);
  goo_read_int(sig->ell, ell_bytes);
  goo_read_int(sig->Aq, mod_bytes);
  goo_read_int(sig->Bq, mod_bytes);
  goo_read_int(sig->Cq, mod_bytes);
  goo_read_int(sig->Dq, mod_bytes);
  goo_read_int(sig->Eq, exp_bytes);

  goo_read_int(sig->z_w, ell_bytes);
  goo_read_int(sig->z_w2, ell_bytes);
  goo_read_int(sig->z_s1, ell_bytes);
  goo_read_int(sig->z_a, ell_bytes);
  goo_read_int(sig->z_an, ell_bytes);
  goo_read_int(sig->z_s1w, ell_bytes);
  goo_read_int(sig->z_sa, ell_bytes);
  goo_read_int(sig->z_s2, ell_bytes);

  sign = data[pos];
  pos += 1;

  assert(pos == data_len);

  if (sign > 1) {
    /* Non-minimal serialization. */
    return 0;
  }

  if (sign)
    mpz_neg(sig->Eq, sig->Eq);

  return 1;
}

#undef goo_read_int

/*
 * CombSpec
 */

static size_t
combspec_size(long bits) {
  long max = 0;
  long ppa, bpw, sqrt, aps, shifts, ops1, ops2, ops;

  for (ppa = 2; ppa < 18; ppa++) {
    bpw = (bits + ppa - 1) / ppa;
    sqrt = goo_isqrt(bpw);

    for (aps = 1; aps < sqrt + 2; aps++) {
      if (bpw % aps != 0)
        continue;

      shifts = bpw / aps;
      ops1 = shifts * (aps + 1) - 1;
      ops2 = aps * (shifts + 1) - 1;
      ops = (ops1 > ops2 ? ops1 : ops2) + 1;

      if (ops > max)
        max = ops;
    }
  }

  return max;
}

static void
combspec_generate(goo_combspec_t **specs,
                  size_t specs_len,
                  long shifts,
                  long aps,
                  long ppa,
                  long bps) {
  long ops = shifts * (aps + 1) - 1;
  long size = ((1 << ppa) - 1) * aps;
  goo_combspec_t *best;

  assert(ops >= 0);
  assert((size_t)ops < specs_len);

  if (specs[ops] == NULL) {
    specs[ops] = goo_malloc(sizeof(goo_combspec_t));
    specs[ops]->size = LONG_MAX;
  }

  best = specs[ops];

  if (best->size > size) {
    best->points_per_add = ppa;
    best->adds_per_shift = aps;
    best->shifts = shifts;
    best->bits_per_window = bps;
    best->size = size;
  }
}

static int
goo_combspec_init(goo_combspec_t *out, long bits, long maxsize) {
  int r = 0;
  size_t specs_len, i;
  goo_combspec_t **specs, *ret;
  long ppa, bpw, sqrt, aps, shifts, sm;

  if (bits < 0 || maxsize < 0)
    return 0;

  /* We don't have a hash table, so this allocates up to ~70kb. */
  specs_len = combspec_size(bits);
  specs = goo_calloc(specs_len, sizeof(goo_combspec_t *));

  for (ppa = 2; ppa < 18; ppa++) {
    bpw = (bits + ppa - 1) / ppa;
    sqrt = goo_isqrt(bpw);

    for (aps = 1; aps < sqrt + 2; aps++) {
      if (bpw % aps != 0)
        continue;

      shifts = bpw / aps;

      combspec_generate(specs, specs_len, shifts, aps, ppa, bpw);
      combspec_generate(specs, specs_len, aps, shifts, ppa, bpw);
    }
  }

  sm = LONG_MAX;
  ret = NULL;

  for (i = 0; i < specs_len; i++) {
    goo_combspec_t *spec = specs[i];

    if (spec == NULL)
      continue;

    if (sm <= spec->size)
      continue;

    sm = spec->size;

    if (sm <= maxsize) {
      ret = spec;
      break;
    }
  }

  if (ret == NULL)
    goto fail;

  memcpy(out, ret, sizeof(goo_combspec_t));

  r = 1;
fail:
  for (i = 0; i < specs_len; i++)
    goo_free(specs[i]);

  goo_free(specs);

  return r;
}

/*
 * Comb
 */

static int
goo_group_pow_slow(goo_group_t *group,
                   mpz_t ret,
                   const mpz_t b,
                   const mpz_t e);

static void
goo_group_mul(goo_group_t *group, mpz_t ret, const mpz_t m1, const mpz_t m2);

static void
goo_comb_init(goo_comb_t *comb,
              goo_group_t *group,
              mpz_t base,
              goo_combspec_t *spec) {
  long i, j, skip;
  mpz_t *items, exp;

  assert((size_t)spec->points_per_add < sizeof(long) * 8);

  mpz_init(exp);

  comb->points_per_add = spec->points_per_add;
  comb->adds_per_shift = spec->adds_per_shift;
  comb->shifts = spec->shifts;
  comb->bits_per_window = spec->bits_per_window;
  comb->bits = spec->bits_per_window * spec->points_per_add;
  comb->points_per_subcomb = (1 << spec->points_per_add) - 1;
  comb->size = spec->size;
  comb->items = goo_calloc(comb->size, sizeof(mpz_t));
  comb->wins = goo_calloc(comb->shifts, sizeof(long *));

  for (i = 0; i < comb->size; i++)
    mpz_init(comb->items[i]);

  for (i = 0; i < comb->shifts; i++)
    comb->wins[i] = goo_calloc(comb->adds_per_shift, sizeof(long));

  mpz_set(comb->items[0], base);

  items = &comb->items[0];

  /* exp = 1 << bits_per_window */
  mpz_set_ui(exp, 1);
  mpz_mul_2exp(exp, exp, comb->bits_per_window);

  for (i = 1; i < comb->points_per_add; i++) {
    long x = 1 << i;
    long y = x >> 1;

    goo_group_pow_slow(group, items[x - 1], items[y - 1], exp);

    for (j = x + 1; j < 2 * x; j++)
      goo_group_mul(group, items[j - 1], items[j - x - 1], items[x - 1]);
  }

  /* exp = 1 << shifts */
  mpz_set_ui(exp, 1);
  mpz_mul_2exp(exp, exp, comb->shifts);

  skip = comb->points_per_subcomb;

  for (i = 1; i < comb->adds_per_shift; i++) {
    for (j = 0; j < skip; j++) {
      long k = i * skip + j;

      goo_group_pow_slow(group, items[k], items[k - skip], exp);
    }
  }

  mpz_clear(exp);
}

static void
goo_comb_uninit(goo_comb_t *comb) {
  long i;

  for (i = 0; i < comb->size; i++)
    mpz_clear(comb->items[i]);

  for (i = 0; i < comb->shifts; i++)
    goo_free(comb->wins[i]);

  goo_free(comb->items);
  goo_free(comb->wins);

  comb->shifts = 0;
  comb->size = 0;
  comb->items = NULL;
  comb->wins = NULL;
}

static int
goo_comb_recode(goo_comb_t *comb, const mpz_t e) {
  long len = (long)goo_mpz_bitlen(e);
  long i, j, k, ret, b;

  if (len < 0 || len > comb->bits)
    return 0;

  if (mpz_sgn(e) < 0)
    return 0;

  for (i = comb->adds_per_shift - 1; i >= 0; i--) {
    for (j = 0; j < comb->shifts; j++) {
      ret = 0;

      for (k = 0; k < comb->points_per_add; k++) {
        b = (i + k * comb->adds_per_shift) * comb->shifts + j;
        ret <<= 1;
        ret |= (long)mpz_tstbit(e, (comb->bits - 1) - b);
      }

      comb->wins[j][(comb->adds_per_shift - 1) - i] = ret;
    }
  }

  return 1;
}

/*
 * Group
 */

static int
goo_hash_int(goo_sha256_t *ctx,
             const mpz_t n,
             size_t size,
             unsigned char *slab);

static int
goo_group_init(goo_group_t *group,
               const mpz_t n,
               unsigned long g,
               unsigned long h,
               unsigned long bits) {
  long i;

  if (bits != 0) {
    if (bits < GOO_MIN_RSA_BITS || bits > GOO_MAX_RSA_BITS)
      return 0;
  }

  mpz_init(group->n);
  mpz_init(group->nh);
  mpz_init(group->g);
  mpz_init(group->h);

  mpz_set(group->n, n);

  group->bits = goo_mpz_bitlen(group->n);
  group->size = (group->bits + 7) / 8;

  mpz_tdiv_q_2exp(group->nh, group->n, 1);

  mpz_set_ui(group->g, g);
  mpz_set_ui(group->h, h);

  group->rand_bits = goo_mpz_bitlen(group->n) - 1;

  if (bits != 0) {
    long big1 = 2 * bits;
    long big2 = bits + group->rand_bits;
    long big = big1 > big2 ? big1 : big2;
    long big_bits = big + GOO_ELL_BITS + 1;
    long small_bits = group->rand_bits;
    goo_combspec_t big_spec, small_spec;

    assert(goo_combspec_init(&big_spec, big_bits, GOO_MAX_COMB_SIZE));
    assert(goo_combspec_init(&small_spec, small_bits, GOO_MAX_COMB_SIZE));

    group->combs_len = 2;
    goo_comb_init(&group->combs[0].g, group, group->g, &small_spec);
    goo_comb_init(&group->combs[0].h, group, group->h, &small_spec);
    goo_comb_init(&group->combs[1].g, group, group->g, &big_spec);
    goo_comb_init(&group->combs[1].h, group, group->h, &big_spec);
  } else {
    long tiny_bits = GOO_ELL_BITS;
    goo_combspec_t tiny_spec;

    assert(goo_combspec_init(&tiny_spec, tiny_bits, GOO_MAX_COMB_SIZE));

    group->combs_len = 1;
    goo_comb_init(&group->combs[0].g, group, group->g, &tiny_spec);
    goo_comb_init(&group->combs[0].h, group, group->h, &tiny_spec);
  }

  for (i = 0; i < GOO_TABLEN; i++) {
    mpz_init(group->table_p1[i]);
    mpz_init(group->table_n1[i]);
    mpz_init(group->table_p2[i]);
    mpz_init(group->table_n2[i]);
  }

  goo_prng_init(&group->prng);

  goo_sha256_init(&group->sha);
  assert(goo_hash_int(&group->sha, group->g, 4, group->slab));
  assert(goo_hash_int(&group->sha, group->h, 4, group->slab));
  assert(goo_hash_int(&group->sha, group->n, group->size, group->slab));
  goo_sha256_final(&group->sha, group->slab);

  goo_sha256_init(&group->sha);
  goo_sha256_update(&group->sha, GOO_HASH_PREFIX, 32);
  goo_sha256_update(&group->sha, group->slab, 32);

  return 1;
}

static void
goo_group_uninit(goo_group_t *group) {
  long i;

  mpz_clear(group->n);
  mpz_clear(group->nh);
  mpz_clear(group->g);
  mpz_clear(group->h);

  for (i = 0; i < group->combs_len; i++) {
    goo_comb_uninit(&group->combs[i].g);
    goo_comb_uninit(&group->combs[i].h);
  }

  group->combs_len = 0;

  for (i = 0; i < GOO_TABLEN; i++) {
    mpz_clear(group->table_p1[i]);
    mpz_clear(group->table_n1[i]);
    mpz_clear(group->table_p2[i]);
    mpz_clear(group->table_n2[i]);
  }

  goo_prng_uninit(&group->prng);
}

static void
goo_group_reduce(goo_group_t *group, mpz_t ret, const mpz_t b) {
  /* if b > nh */
  if (mpz_cmp(b, group->nh) > 0) {
    /* ret = n - b */
    mpz_sub(ret, group->n, b);
  }
}

static int
goo_group_is_reduced(goo_group_t *group, const mpz_t b) {
  /* b <= nh */
  return mpz_cmp(b, group->nh) <= 0;
}

static void
goo_group_sqr(goo_group_t *group, mpz_t ret, const mpz_t b) {
  /* ret = b^2 mod n */
  mpz_mul(ret, b, b);
  mpz_mod(ret, ret, group->n);
}

static void
goo_group_mul(goo_group_t *group, mpz_t ret, const mpz_t m1, const mpz_t m2) {
  /* ret = m1 * m2 mod n */
  mpz_mul(ret, m1, m2);
  mpz_mod(ret, ret, group->n);
}

static int
goo_group_inv(goo_group_t *group, mpz_t ret, const mpz_t b) {
  /* ret = b^-1 mod n */
  return mpz_invert(ret, b, group->n);
}

static int
goo_group_inv2(goo_group_t *group,
               mpz_t r1,
               mpz_t r2,
               const mpz_t b1,
               const mpz_t b2) {
  int r = 0;
  mpz_ptr b12i = r2;

  /* b12i = (b1 * b2)^-1 mod n */
  mpz_mul(b12i, b1, b2);

  if (!goo_group_inv(group, b12i, b12i))
    goto fail;

  /* r1 = b2 * b12i mod n */
  goo_group_mul(group, r1, b2, b12i);
  /* r2 = b1 * b12i mod n */
  goo_group_mul(group, r2, b1, b12i);

  r = 1;
fail:
  return r;
}

static int
goo_group_inv7(goo_group_t *group,
               mpz_t r1,
               mpz_t r2,
               mpz_t r3,
               mpz_t r4,
               mpz_t r5,
               mpz_t r6,
               mpz_t r7,
               const mpz_t b1,
               const mpz_t b2,
               const mpz_t b3,
               const mpz_t b4,
               const mpz_t b5,
               const mpz_t b6,
               const mpz_t b7) {
  int r = 0;

  /* Tricky memory management */
  /* to avoid allocations. */
  mpz_ptr b12 = r4;
  mpz_ptr b34 = r2;
  mpz_ptr b56 = r3;
  mpz_ptr b1234 = r1;
  mpz_ptr b123456 = r5;
  mpz_ptr b1234567 = r7;
  mpz_ptr b1234567i = r7;
  mpz_ptr b123456i = r6;
  mpz_ptr b1234i = r3;
  mpz_ptr b56i = r1;
  mpz_ptr b34i = r4;
  mpz_ptr b12i = r2;

  /* b12 = b1 * b2 mod n */
  goo_group_mul(group, b12, b1, b2);
  /* b34 = b3 * b4 mod n */
  goo_group_mul(group, b34, b3, b4);
  /* b56 = b5 * b6 mod n */
  goo_group_mul(group, b56, b5, b6);
  /* b1234 = b12 * b34 mod n */
  goo_group_mul(group, b1234, b12, b34);
  /* b123456 = b1234 * b56 mod n */
  goo_group_mul(group, b123456, b1234, b56);
  /* b1234567 = b123456 * b7 mod n */
  goo_group_mul(group, b1234567, b123456, b7);

  /* b1234567i = b1234567^-1 mod n */
  if (!goo_group_inv(group, b1234567i, b1234567))
    goto fail;

  /* b123456i = b1234567i * b7 mod n */
  goo_group_mul(group, b123456i, b1234567i, b7);
  /* b1234i = b123456i * b56 mod n */
  goo_group_mul(group, b1234i, b123456i, b56);
  /* b56i = b123456i * b1234 mod n */
  goo_group_mul(group, b56i, b123456i, b1234);
  /* b34i = b1234i * b12 mod n */
  goo_group_mul(group, b34i, b1234i, b12);
  /* b12i = b1234i * b34 mod n */
  goo_group_mul(group, b12i, b1234i, b34);

  /* r7 = b1234567i * b123456 mod n */
  goo_group_mul(group, r7, b1234567i, b123456);
  /* r5 = b56i * b6 mod n */
  goo_group_mul(group, r5, b56i, b6);
  /* r6 = b56i * b5 mod n */
  goo_group_mul(group, r6, b56i, b5);
  /* r1 = b12i * b2 mod n */
  goo_group_mul(group, r1, b12i, b2);
  /* r2 = b12i * b1 mod n */
  goo_group_mul(group, r2, b12i, b1);
  /* r3 = b34i * b4 mod n */
  goo_group_mul(group, r3, b34i, b4);
  /* r4 = b34i * b3 mod n */
  goo_group_mul(group, r4, b34i, b3);

  r = 1;
fail:
  return r;
}

static int
goo_group_powgh_slow(
  goo_group_t *group,
  mpz_t ret,
  const mpz_t e1,
  const mpz_t e2
) {
  /* Compute g^e1 * h*e2 mod n (slowly). */
  mpz_t q1, q2;

  if (mpz_sgn(e1) < 0 || mpz_sgn(e2) < 0)
    return 0;

  mpz_init(q1);
  mpz_init(q2);

  /* q1 = g^e1 mod n */
  mpz_powm(q1, group->g, e1, group->n);

  /* q2 = h^e2 mod n */
  mpz_powm(q2, group->h, e2, group->n);

  /* ret = q1 * q2 mod n */
  mpz_mul(ret, q1, q2);
  mpz_mod(ret, ret, group->n);

  mpz_clear(q1);
  mpz_clear(q2);

  return 1;
}

static int
goo_group_powgh(goo_group_t *group, mpz_t ret, const mpz_t e1, const mpz_t e2) {
  /* Compute g^e1 * h*e2 mod n. */
  goo_comb_t *gcomb = NULL;
  goo_comb_t *hcomb = NULL;
  long bits1 = (long)goo_mpz_bitlen(e1);
  long bits2 = (long)goo_mpz_bitlen(e2);
  long bits = bits1 > bits2 ? bits1 : bits2;
  long i;

  for (i = 0; i < group->combs_len; i++) {
    if (bits <= group->combs[i].g.bits) {
      gcomb = &group->combs[i].g;
      hcomb = &group->combs[i].h;
      break;
    }
  }

  if (!gcomb || !hcomb)
    return 0;

  if (!goo_comb_recode(gcomb, e1))
    return 0;

  if (!goo_comb_recode(hcomb, e2))
    return 0;

  mpz_set_ui(ret, 1);

  for (i = 0; i < gcomb->shifts; i++) {
    long *us = gcomb->wins[i];
    long *vs = hcomb->wins[i];
    long j;

    if (i != 0)
      goo_group_sqr(group, ret, ret);

    for (j = 0; j < gcomb->adds_per_shift; j++) {
      long u = us[j];
      long v = vs[j];

      if (u != 0) {
        mpz_t *g = &gcomb->items[j * gcomb->points_per_subcomb + u - 1];
        goo_group_mul(group, ret, ret, *g);
      }

      if (v != 0) {
        mpz_t *h = &hcomb->items[j * hcomb->points_per_subcomb + v - 1];
        goo_group_mul(group, ret, ret, *h);
      }
    }
  }

  return 1;
}

static void
goo_group_precomp_table(goo_group_t *group, mpz_t *out, const mpz_t b) {
  mpz_t *b2 = &out[GOO_TABLEN - 1];
  long i;

  goo_group_sqr(group, *b2, b);

  mpz_set(out[0], b);

  for (i = 1; i < GOO_TABLEN; i++)
    goo_group_mul(group, out[i], out[i - 1], *b2);
}

static void
goo_group_precomp_wnaf(goo_group_t *group,
                       mpz_t *p,
                       mpz_t *n,
                       const mpz_t b,
                       const mpz_t bi) {
  goo_group_precomp_table(group, p, b);
  goo_group_precomp_table(group, n, bi);
}

static void
goo_group_wnaf(goo_group_t *group, long *out, const mpz_t exp, long bits) {
  long w = GOO_WINDOW_SIZE;
  long mask = (1 << w) - 1;
  long i, val;
  mpz_t e;

  mpz_init(e);
  mpz_set(e, exp);

  for (i = bits - 1; i >= 0; i--) {
    val = 0;

    if (mpz_odd_p(e)) {
      val = mpz_getlimbn(e, 0) & mask;

      if (val & (1 << (w - 1)))
        val -= 1 << w;

      if (val < 0)
        mpz_add_ui(e, e, -val);
      else
        mpz_sub_ui(e, e, val);
    }

    out[i] = val;

    mpz_tdiv_q_2exp(e, e, 1);
  }

  assert(mpz_sgn(e) == 0);

  mpz_clear(e);
}

static void
goo_group_one_mul(goo_group_t *group, mpz_t ret, long w, mpz_t *p, mpz_t *n) {
  if (w > 0)
    goo_group_mul(group, ret, ret, p[(w - 1) >> 1]);
  else if (w < 0)
    goo_group_mul(group, ret, ret, n[(-1 - w) >> 1]);
}

static int
goo_group_pow_slow(goo_group_t *group,
                   mpz_t ret,
                   const mpz_t b,
                   const mpz_t e) {
  /* Compute b^e mod n (slowly). */
  if (mpz_sgn(e) < 0)
    return 0;

  mpz_powm(ret, b, e, group->n);

  return 1;
}

static int
goo_group_pow(goo_group_t *group,
              mpz_t ret,
              const mpz_t b,
              const mpz_t bi,
              const mpz_t e) {
  /* Compute b^e mod n. */
  mpz_t *p = &group->table_p1[0];
  mpz_t *n = &group->table_n1[0];
  size_t bits = goo_mpz_bitlen(e) + 1;
  size_t i;

  if (bits > GOO_MAX_RSA_BITS + 1)
    return 0;

  if (mpz_sgn(e) < 0)
    return 0;

  goo_group_precomp_wnaf(group, p, n, b, bi);
  goo_group_wnaf(group, group->wnaf0, e, bits);

  mpz_set_ui(ret, 1);

  for (i = 0; i < bits; i++) {
    long w = group->wnaf0[i];

    if (i != 0)
      goo_group_sqr(group, ret, ret);

    goo_group_one_mul(group, ret, w, p, n);
  }

  return 1;
}

static int
goo_group_pow2_slow(goo_group_t *group,
                    mpz_t ret,
                    const mpz_t b1,
                    const mpz_t e1,
                    const mpz_t b2,
                    const mpz_t e2) {
  /* Compute b1^e1 * b2^e2 mod n (slowly). */
  mpz_t q1, q2;

  if (mpz_sgn(e1) < 0 || mpz_sgn(e2) < 0)
    return 0;

  mpz_init(q1);
  mpz_init(q2);

  /* q1 = b1^e2 mod n */
  mpz_powm(q1, b1, e1, group->n);

  /* q2 = b2^e2 mod n */
  mpz_powm(q2, b2, e2, group->n);

  /* ret = q1 * q2 mod n */
  mpz_mul(ret, q1, q2);
  mpz_mod(ret, ret, group->n);

  mpz_clear(q1);
  mpz_clear(q2);

  return 1;
}

static int
goo_group_pow2(goo_group_t *group,
               mpz_t ret,
               const mpz_t b1,
               const mpz_t b1i,
               const mpz_t e1,
               const mpz_t b2,
               const mpz_t b2i,
               const mpz_t e2) {
  /* Compute b1^e1 * b2^e2 mod n. */
  mpz_t *p1 = &group->table_p1[0];
  mpz_t *n1 = &group->table_n1[0];
  mpz_t *p2 = &group->table_p2[0];
  mpz_t *n2 = &group->table_n2[0];
  size_t bits1 = goo_mpz_bitlen(e1);
  size_t bits2 = goo_mpz_bitlen(e2);
  size_t bits = (bits1 > bits2 ? bits1 : bits2) + 1;
  size_t i;

  if (bits > GOO_ELL_BITS + 1)
    return 0;

  if (mpz_sgn(e1) < 0 || mpz_sgn(e2) < 0)
    return 0;

  goo_group_precomp_wnaf(group, p1, n1, b1, b1i);
  goo_group_precomp_wnaf(group, p2, n2, b2, b2i);

  goo_group_wnaf(group, group->wnaf1, e1, bits);
  goo_group_wnaf(group, group->wnaf2, e2, bits);

  mpz_set_ui(ret, 1);

  for (i = 0; i < bits; i++) {
    long w1 = group->wnaf1[i];
    long w2 = group->wnaf2[i];

    if (i != 0)
      goo_group_sqr(group, ret, ret);

    goo_group_one_mul(group, ret, w1, p1, n1);
    goo_group_one_mul(group, ret, w2, p2, n2);
  }

  return 1;
}

static int
goo_group_recover(goo_group_t *group,
                  mpz_t ret,
                  const mpz_t b1,
                  const mpz_t b1i,
                  const mpz_t e1,
                  const mpz_t b2,
                  const mpz_t b2i,
                  const mpz_t e2,
                  const mpz_t e3,
                  const mpz_t e4) {
  /* Compute b1^e1 * g^e3 * h^e4 / b2^e2 mod n. */
  int r = 0;
  mpz_t a;
  mpz_ptr b = ret;

  mpz_init(a);

  /* a = b1^e1 / b2^e2 mod n */
  if (!goo_group_pow2(group, a, b1, b1i, e1, b2i, b2, e2))
    goto fail;

  /* b = g^e3 * h^e4 mod n */
  if (!goo_group_powgh(group, b, e3, e4))
    goto fail;

  /* ret = a * b mod n */
  goo_group_mul(group, ret, a, b);

  /* ret = n - ret if ret > n / 2 */
  goo_group_reduce(group, ret, ret);

  r = 1;
fail:
  mpz_clear(a);
  return r;
}

static int
goo_hash_int(goo_sha256_t *ctx,
             const mpz_t n,
             size_t size,
             unsigned char *slab) {
  size_t len = goo_mpz_bytelen(n);
  size_t pos;

  if (len > size)
    return 0;

  if (len > (GOO_MAX_RSA_BITS + 7) / 8)
    return 0;

  pos = size - len;

  memset(slab, 0x00, pos);

  if (len != 0)
    goo_mpz_export(slab + pos, NULL, n);

  goo_sha256_update(ctx, slab, size);

  return 1;
}

static int
goo_group_hash(goo_group_t *group,
               unsigned char *out,
               const mpz_t C1,
               const mpz_t C2,
               const mpz_t C3,
               const mpz_t t,
               const mpz_t A,
               const mpz_t B,
               const mpz_t C,
               const mpz_t D,
               const mpz_t E,
               const unsigned char *msg,
               size_t msg_len) {
  unsigned char *slab = &group->slab[0];
  size_t mod_bytes = group->size;
  size_t exp_bytes = (GOO_EXPONENT_SIZE + 7) / 8;
  unsigned char sign[1] = {mpz_sgn(E) < 0 ? 1 : 0};
  goo_sha256_t ctx;

  VERIFY_POS(C1);
  VERIFY_POS(C2);
  VERIFY_POS(C3);
  VERIFY_POS(t);
  VERIFY_POS(A);
  VERIFY_POS(B);
  VERIFY_POS(C);
  VERIFY_POS(D);

  /* Copy the state of SHA256(prefix || SHA256(g || h || n)). */
  /* This gives us a minor speedup. */
  memcpy(&ctx, &group->sha, sizeof(goo_sha256_t));

  if (!goo_hash_int(&ctx, C1, mod_bytes, slab)
      || !goo_hash_int(&ctx, C2, mod_bytes, slab)
      || !goo_hash_int(&ctx, C3, mod_bytes, slab)
      || !goo_hash_int(&ctx, t, 4, slab)
      || !goo_hash_int(&ctx, A, mod_bytes, slab)
      || !goo_hash_int(&ctx, B, mod_bytes, slab)
      || !goo_hash_int(&ctx, C, mod_bytes, slab)
      || !goo_hash_int(&ctx, D, mod_bytes, slab)
      || !goo_hash_int(&ctx, E, exp_bytes, slab)) {
    return 0;
  }

  goo_sha256_update(&ctx, &sign[0], 1);
  goo_sha256_update(&ctx, msg, msg_len);
  goo_sha256_final(&ctx, out);

  return 1;
fail:
  return 0;
}

static int
goo_group_derive(goo_group_t *group,
                 mpz_t chal,
                 mpz_t ell,
                 unsigned char *key,
                 const mpz_t C1,
                 const mpz_t C2,
                 const mpz_t C3,
                 const mpz_t t,
                 const mpz_t A,
                 const mpz_t B,
                 const mpz_t C,
                 const mpz_t D,
                 const mpz_t E,
                 const unsigned char *msg,
                 size_t msg_len) {
  if (!goo_group_hash(group, key, C1, C2, C3, t, A, B, C, D, E, msg, msg_len))
    return 0;

  goo_prng_seed(&group->prng, key);
  goo_prng_random_bits(&group->prng, chal, GOO_CHAL_BITS);
  goo_prng_random_bits(&group->prng, ell, GOO_ELL_BITS);

  return 1;
}

static int
goo_group_expand_sprime(goo_group_t *group, mpz_t s,
                        const unsigned char *s_prime) {
  goo_prng_seed(&group->prng, s_prime);
  goo_prng_random_bits(&group->prng, s, GOO_EXPONENT_SIZE);
  return 1;
}

static int
goo_group_random_scalar(goo_group_t *group, goo_prng_t *prng, mpz_t ret) {
  size_t bits = group->rand_bits;

  if (bits > GOO_EXPONENT_SIZE)
    bits = GOO_EXPONENT_SIZE;

  goo_prng_random_bits(prng, ret, bits);

  return 1;
}

static int
goo_is_valid_prime(const mpz_t n) {
  /* if n <= 0 */
  if (mpz_sgn(n) <= 0)
    return 0;

  /* if bitlen(n) > 4096 */
  if (goo_mpz_bitlen(n) > GOO_MAX_RSA_BITS)
    return 0;

  return 1;
}

static int
goo_is_valid_rsa(const mpz_t n) {
  size_t bits;

  /* if n <= 0 */
  if (mpz_sgn(n) <= 0)
    return 0;

  bits = goo_mpz_bitlen(n);

  /* if bitlen(n) < 1024 or bitlen(n) > 4096 */
  if (bits < GOO_MIN_RSA_BITS || bits > GOO_MAX_RSA_BITS)
    return 0;

  return 1;
}

static int
goo_group_challenge(goo_group_t *group,
                    mpz_t C1,
                    const unsigned char *s_prime,
                    const mpz_t n) {
  int r = 0;
  mpz_t s;

  mpz_init(s);

  VERIFY_POS(n);

  if (!goo_is_valid_rsa(n)) {
    /* Invalid RSA public key. */
    goto fail;
  }

  if (!goo_group_expand_sprime(group, s, s_prime))
    goto fail;

  /* Commit to the RSA modulus:
   *
   *   C1 = g^n * h^s in G
   */
  if (!goo_group_powgh(group, C1, n, s))
    goto fail;

  goo_group_reduce(group, C1, C1);

  r = 1;
fail:
  mpz_clear(s);
  return r;
}

static int
goo_group_validate(goo_group_t *group,
                   const unsigned char *s_prime,
                   const mpz_t C1,
                   const mpz_t p,
                   const mpz_t q) {
  int r = 0;
  mpz_t n, s, x;

  mpz_init(n);
  mpz_init(s);
  mpz_init(x);

  VERIFY_POS(C1);
  VERIFY_POS(p);
  VERIFY_POS(q);

  if (!goo_is_valid_prime(p) || !goo_is_valid_prime(q))
    goto fail;

  if (!goo_group_is_reduced(group, C1))
    goto fail;

  /* Validate the private key with:
   *
   *   n = p * q
   *   C1' = g^n * h^s in G
   *   C1 == C1'
   */
  mpz_mul(n, p, q);

  if (!goo_is_valid_rsa(n))
    goto fail;

  if (!goo_group_expand_sprime(group, s, s_prime))
    goto fail;

  if (!goo_group_powgh(group, x, n, s))
    goto fail;

  goo_group_reduce(group, x, x);

  if (mpz_cmp(C1, x) != 0)
    goto fail;

  r = 1;
fail:
  mpz_clear(n);
  mpz_clear(s);
  mpz_clear(x);
  return r;
}

static int
goo_group_sign(goo_group_t *group,
               goo_sig_t *S,
               const unsigned char *msg,
               size_t msg_len,
               const unsigned char *s_prime,
               const mpz_t p,
               const mpz_t q,
               const unsigned char *seed) {
  int r = 0;
  int found;
  unsigned long primes[GOO_PRIMES_LEN];
  unsigned char key[32];
  goo_prng_t prng;
  long i;

  mpz_t n, s, C1, w, a, s1, s2;
  mpz_t t1, t2, t3, t4, t5;
  mpz_t C1i, C2i;
  mpz_t r_w, r_w2, r_s1, r_a, r_an, r_s1w, r_sa, r_s2;
  mpz_t A, B, C, D, E;

  mpz_t *C2 = &S->C2;
  mpz_t *C3 = &S->C3;
  mpz_t *t = &S->t;
  mpz_t *chal = &S->chal;
  mpz_t *ell = &S->ell;
  mpz_t *Aq = &S->Aq;
  mpz_t *Bq = &S->Bq;
  mpz_t *Cq = &S->Cq;
  mpz_t *Dq = &S->Dq;
  mpz_t *Eq = &S->Eq;
  mpz_t *z_w = &S->z_w;
  mpz_t *z_w2 = &S->z_w2;
  mpz_t *z_s1 = &S->z_s1;
  mpz_t *z_a = &S->z_a;
  mpz_t *z_an = &S->z_an;
  mpz_t *z_s1w = &S->z_s1w;
  mpz_t *z_sa = &S->z_sa;
  mpz_t *z_s2 = &S->z_s2;

  goo_prng_init(&prng);
  goo_prng_seed_local(&prng, seed);

  mpz_init(n);
  mpz_init(s);
  mpz_init(C1);
  mpz_init(w);
  mpz_init(a);
  mpz_init(s1);
  mpz_init(s2);
  mpz_init(t1);
  mpz_init(t2);
  mpz_init(t3);
  mpz_init(t4);
  mpz_init(t5);
  mpz_init(C1i);
  mpz_init(C2i);
  mpz_init(r_w);
  mpz_init(r_w2);
  mpz_init(r_s1);
  mpz_init(r_a);
  mpz_init(r_an);
  mpz_init(r_s1w);
  mpz_init(r_sa);
  mpz_init(r_s2);
  mpz_init(A);
  mpz_init(B);
  mpz_init(C);
  mpz_init(D);
  mpz_init(E);

  VERIFY_POS(p);
  VERIFY_POS(q);

  if (!goo_is_valid_prime(p) || !goo_is_valid_prime(q))
    goto fail;

  mpz_mul(n, p, q);

  if (!goo_is_valid_rsa(n)) {
    /* Invalid RSA public key. */
    goto fail;
  }

  /* Find a small quadratic residue prime `t`. */
  found = 0;

  memcpy(&primes[0], &goo_primes[0], sizeof(goo_primes));

  for (i = 0; i < GOO_PRIMES_LEN; i++) {
    /* Fisher-Yates shuffle to choose random `t`. */
    unsigned long j = goo_prng_random_num(&prng, GOO_PRIMES_LEN - i);
    unsigned long u = primes[i];
    unsigned long v = primes[i + j];

    primes[i] = v;
    primes[i + j] = u;

    mpz_set_ui(*t, primes[i]);

    /* w = t^(1 / 2) mod (p * q) */
    if (goo_mpz_sqrtpq(w, *t, p, q)) {
      found = 1;
      break;
    }
  }

  if (!found) {
    /* No prime quadratic residue less than 1000 mod N! */
    goto fail;
  }

  assert(mpz_sgn(w) > 0);

  /* a = (w^2 - t) / n */
  mpz_mul(a, w, w);
  mpz_sub(a, a, *t);
  mpz_fdiv_q(a, a, n);

  assert(mpz_sgn(a) >= 0);

  /* `w` and `a` must satisfy `w^2 = t + a * n`. */
  mpz_mul(t1, a, n);
  mpz_mul(t2, w, w);
  mpz_sub(t2, t2, *t);

  if (mpz_cmp(t1, t2) != 0) {
    /* w^2 - t was not divisible by N! */
    goto fail;
  }

  /* Commit to `n`, `w`, and `a` with:
   *
   *   C1 = g^n * h^s in G
   *   C2 = g^w * h^s1 in G
   *   C3 = g^a * h^s2 in G
   *
   * Where `s`, `s1`, and `s2` are
   * random 2048-bit integers.
   */
  if (!goo_group_expand_sprime(group, s, s_prime))
    goto fail;

  if (!goo_group_powgh(group, C1, n, s))
    goto fail;

  goo_group_reduce(group, C1, C1);

  if (!goo_group_random_scalar(group, &prng, s1)
      || !goo_group_powgh(group, *C2, w, s1)) {
    goto fail;
  }

  goo_group_reduce(group, *C2, *C2);

  if (!goo_group_random_scalar(group, &prng, s2)
      || !goo_group_powgh(group, *C3, a, s2)) {
    goto fail;
  }

  goo_group_reduce(group, *C3, *C3);

  /* Inverses of `C1` and `C2`. */
  if (!goo_group_inv2(group, C1i, C2i, C1, *C2))
    goto fail;

  /* Eight random 2048-bit integers: */
  /*   r_w, r_w2, r_s1, r_a, r_an, r_s1w, r_sa, r_s2 */
  if (!goo_group_random_scalar(group, &prng, r_w)
      || !goo_group_random_scalar(group, &prng, r_w2)
      || !goo_group_random_scalar(group, &prng, r_a)
      || !goo_group_random_scalar(group, &prng, r_an)
      || !goo_group_random_scalar(group, &prng, r_s1w)
      || !goo_group_random_scalar(group, &prng, r_sa)
      || !goo_group_random_scalar(group, &prng, r_s2)) {
    goto fail;
  }

  /* Compute:
   *
   *   A = g^r_w * h^r_s1 in G
   *   B = g^r_a * h^r_s2 in G
   *   C = g^r_w2 * h^r_s1w / C2^r_w in G
   *   D = g^r_an * h^r_sa / C1^r_a in G
   *   E = r_w2 - r_an
   *
   * `A` must be recomputed until a prime
   * `ell` is found within range.
   */
  if (!goo_group_powgh(group, B, r_a, r_s2))
    goto fail;

  goo_group_reduce(group, B, B);

  goo_group_pow(group, t1, C2i, *C2, r_w);

  if (!goo_group_powgh(group, t2, r_w2, r_s1w))
    goto fail;

  goo_group_mul(group, C, t1, t2);
  goo_group_reduce(group, C, C);

  goo_group_pow(group, t1, C1i, C1, r_a);

  if (!goo_group_powgh(group, t2, r_an, r_sa))
    goto fail;

  goo_group_mul(group, D, t1, t2);
  goo_group_reduce(group, D, D);

  mpz_sub(E, r_w2, r_an);

  mpz_set_ui(*ell, 0);

  while (goo_mpz_bitlen(*ell) != GOO_ELL_BITS) {
    if (!goo_group_random_scalar(group, &prng, r_s1)
        || !goo_group_powgh(group, A, r_w, r_s1)) {
      goto fail;
    }

    goo_group_reduce(group, A, A);

    if (!goo_group_derive(group,
                          *chal, *ell, &key[0], C1, *C2, *C3,
                          *t, A, B, C, D, E, msg, msg_len)) {
      goto fail;
    }

    if (!goo_next_prime(*ell, *ell, key, GOO_ELLDIFF_MAX))
      mpz_set_ui(*ell, 0);
  }

  /* Compute the integer vector `z`:
   *
   *   z_w = chal * w + r_w
   *   z_w2 = chal * w^2 + r_w2
   *   z_s1 = chal * s1 + r_s1
   *   z_a = chal * a + r_a
   *   z_an = chal * a * n + r_an
   *   z_s1w = chal * s1 * w + r_s1w
   *   z_sa = chal * s * a + r_sa
   *   z_s2 = chal * s2 + r_s2
   */
  mpz_mul(*z_w, *chal, w);
  mpz_add(*z_w, *z_w, r_w);

  mpz_mul(*z_w2, *chal, w);
  mpz_mul(*z_w2, *z_w2, w);
  mpz_add(*z_w2, *z_w2, r_w2);

  mpz_mul(*z_s1, *chal, s1);
  mpz_add(*z_s1, *z_s1, r_s1);

  mpz_mul(*z_a, *chal, a);
  mpz_add(*z_a, *z_a, r_a);

  mpz_mul(*z_an, *chal, a);
  mpz_mul(*z_an, *z_an, n);
  mpz_add(*z_an, *z_an, r_an);

  mpz_mul(*z_s1w, *chal, s1);
  mpz_mul(*z_s1w, *z_s1w, w);
  mpz_add(*z_s1w, *z_s1w, r_s1w);

  mpz_mul(*z_sa, *chal, s);
  mpz_mul(*z_sa, *z_sa, a);
  mpz_add(*z_sa, *z_sa, r_sa);

  mpz_mul(*z_s2, *chal, s2);
  mpz_add(*z_s2, *z_s2, r_s2);

  /* Compute quotient commitments:
   *
   *   Aq = g^(z_w / ell) * h^(z_s1  / ell) in G
   *   Bq = g^(z_a / ell) * h^(z_s2  / ell) in G
   *   Cq = g^(z_w2 / ell) * h^(z_s1w / ell) / C2^(z_w / ell) in G
   *   Dq = g^(z_an / ell) * h^(z_sa  / ell) / C1^(z_a / ell) in G
   *   Eq = (z_w2 - z_an) / ell
   */
  mpz_fdiv_q(t1, *z_w, *ell);
  mpz_fdiv_q(t2, *z_s1, *ell);

  if (!goo_group_powgh(group, *Aq, t1, t2))
    goto fail;

  goo_group_reduce(group, *Aq, *Aq);

  mpz_fdiv_q(t1, *z_a, *ell);
  mpz_fdiv_q(t2, *z_s2, *ell);

  if (!goo_group_powgh(group, *Bq, t1, t2))
    goto fail;

  goo_group_reduce(group, *Bq, *Bq);

  mpz_fdiv_q(t1, *z_w, *ell);
  mpz_fdiv_q(t2, *z_w2, *ell);
  mpz_fdiv_q(t3, *z_s1w, *ell);
  goo_group_pow(group, t4, C2i, *C2, t1);

  if (!goo_group_powgh(group, t5, t2, t3))
    goto fail;

  goo_group_mul(group, *Cq, t4, t5);
  goo_group_reduce(group, *Cq, *Cq);

  mpz_fdiv_q(t1, *z_a, *ell);
  mpz_fdiv_q(t2, *z_an, *ell);
  mpz_fdiv_q(t3, *z_sa, *ell);
  goo_group_pow(group, t4, C1i, C1, t1);

  if (!goo_group_powgh(group, t5, t2, t3))
    goto fail;

  goo_group_mul(group, *Dq, t4, t5);
  goo_group_reduce(group, *Dq, *Dq);

  mpz_sub(*Eq, *z_w2, *z_an);
  mpz_fdiv_q(*Eq, *Eq, *ell);

  assert(goo_mpz_bitlen(*Eq) <= GOO_EXPONENT_SIZE);

  /* Compute `z' = (z mod ell)`. */
  mpz_mod(*z_w, *z_w, *ell);
  mpz_mod(*z_w2, *z_w2, *ell);
  mpz_mod(*z_s1, *z_s1, *ell);
  mpz_mod(*z_a, *z_a, *ell);
  mpz_mod(*z_an, *z_an, *ell);
  mpz_mod(*z_s1w, *z_s1w, *ell);
  mpz_mod(*z_sa, *z_sa, *ell);
  mpz_mod(*z_s2, *z_s2, *ell);

  /* S = (C2, C3, t, chal, ell, Aq, Bq, Cq, Dq, Eq, z') */
  r = 1;
fail:
  goo_prng_uninit(&prng);
  mpz_clear(n);
  mpz_clear(s);
  mpz_clear(C1);
  mpz_clear(w);
  mpz_clear(a);
  mpz_clear(s1);
  mpz_clear(s2);
  mpz_clear(t1);
  mpz_clear(t2);
  mpz_clear(t3);
  mpz_clear(t4);
  mpz_clear(t5);
  mpz_clear(C1i);
  mpz_clear(C2i);
  mpz_clear(r_w);
  mpz_clear(r_w2);
  mpz_clear(r_s1);
  mpz_clear(r_a);
  mpz_clear(r_an);
  mpz_clear(r_s1w);
  mpz_clear(r_sa);
  mpz_clear(r_s2);
  mpz_clear(A);
  mpz_clear(B);
  mpz_clear(C);
  mpz_clear(D);
  mpz_clear(E);
  return r;
}

static int
goo_group_verify(goo_group_t *group,
                 const unsigned char *msg,
                 size_t msg_len,
                 const goo_sig_t *S,
                 const mpz_t C1) {
  int ret = 0;
  const mpz_t *C2 = &S->C2;
  const mpz_t *C3 = &S->C3;
  const mpz_t *t = &S->t;
  const mpz_t *chal = &S->chal;
  const mpz_t *ell = &S->ell;
  const mpz_t *Aq = &S->Aq;
  const mpz_t *Bq = &S->Bq;
  const mpz_t *Cq = &S->Cq;
  const mpz_t *Dq = &S->Dq;
  const mpz_t *Eq = &S->Eq;
  const mpz_t *z_w = &S->z_w;
  const mpz_t *z_w2 = &S->z_w2;
  const mpz_t *z_s1 = &S->z_s1;
  const mpz_t *z_a = &S->z_a;
  const mpz_t *z_an = &S->z_an;
  const mpz_t *z_s1w = &S->z_s1w;
  const mpz_t *z_sa = &S->z_sa;
  const mpz_t *z_s2 = &S->z_s2;

  mpz_t C1i, C2i, C3i, Aqi, Bqi, Cqi, Dqi;
  mpz_t A, B, C, D, E;
  mpz_t tmp, chal0, ell0, ell1;

  unsigned char key[32];
  int found, i;

  mpz_init(C1i);
  mpz_init(C2i);
  mpz_init(C3i);
  mpz_init(Aqi);
  mpz_init(Bqi);
  mpz_init(Cqi);
  mpz_init(Dqi);
  mpz_init(A);
  mpz_init(B);
  mpz_init(C);
  mpz_init(D);
  mpz_init(E);
  mpz_init(tmp);
  mpz_init(chal0);
  mpz_init(ell0);
  mpz_init(ell1);

  VERIFY_POS(C1);
  VERIFY_POS(*C2);
  VERIFY_POS(*C3);
  VERIFY_POS(*t);
  VERIFY_POS(*chal);
  VERIFY_POS(*ell);
  VERIFY_POS(*Aq);
  VERIFY_POS(*Bq);
  VERIFY_POS(*Cq);
  VERIFY_POS(*Dq);
  VERIFY_POS(*z_w);
  VERIFY_POS(*z_w2);
  VERIFY_POS(*z_s1);
  VERIFY_POS(*z_a);
  VERIFY_POS(*z_an);
  VERIFY_POS(*z_s1w);
  VERIFY_POS(*z_sa);
  VERIFY_POS(*z_s2);

  /* `t` must be one of the small primes in our list. */
  found = 0;

  for (i = 0; i < GOO_PRIMES_LEN; i++) {
    if (mpz_cmp_ui(*t, goo_primes[i]) == 0) {
      found = 1;
      break;
    }
  }

  if (!found)
    goto fail;

  /* `chal` must be in range. */
  if (goo_mpz_bitlen(*chal) > GOO_CHAL_BITS)
    goto fail;

  /* `ell` must be in range. */
  if (goo_mpz_bitlen(*ell) > GOO_ELL_BITS)
    goto fail;

  /* All group elements must be the canonical */
  /* element of the quotient group (Z/n)/{1,-1}. */
  if (!goo_group_is_reduced(group, C1)
      || !goo_group_is_reduced(group, *C2)
      || !goo_group_is_reduced(group, *C3)
      || !goo_group_is_reduced(group, *Aq)
      || !goo_group_is_reduced(group, *Bq)
      || !goo_group_is_reduced(group, *Cq)
      || !goo_group_is_reduced(group, *Dq)) {
    goto fail;
  }

  /* `Eq` must be in range. */
  if (goo_mpz_bitlen(*Eq) > GOO_EXPONENT_SIZE)
    goto fail;

  /* `z'` must be within range. */
  if (mpz_cmp(*z_w, *ell) >= 0
      || mpz_cmp(*z_w2, *ell) >= 0
      || mpz_cmp(*z_s1, *ell) >= 0
      || mpz_cmp(*z_a, *ell) >= 0
      || mpz_cmp(*z_an, *ell) >= 0
      || mpz_cmp(*z_s1w, *ell) >= 0
      || mpz_cmp(*z_sa, *ell) >= 0
      || mpz_cmp(*z_s2, *ell) >= 0) {
    goto fail;
  }

  /* Compute inverses of C1, C2, C3, Aq, Bq, Cq, Dq. */
  if (!goo_group_inv7(group, C1i, C2i, C3i, Aqi, Bqi, Cqi, Dqi,
                             C1, *C2, *C3, *Aq, *Bq, *Cq, *Dq)) {
    goto fail;
  }

  /* Reconstruct A, B, C, D, and E from signature:
   *
   *   A = Aq^ell * g^z_w * h^z_s1 / C2^chal in G
   *   B = Bq^ell * g^z_a * h^z_s2 / C3^chal in G
   *   C = Cq^ell * g^z_w2 * h^z_s1w / C2^z_w in G
   *   D = Dq^ell * g^z_an * h^z_sa / C1^z_a in G
   *   E = Eq * ell + ((z_w2 - z_an) mod ell) - t * chal
   */
  if (!goo_group_recover(group, A, *Aq, Aqi, *ell,
                         *C2, C2i, *chal, *z_w, *z_s1)) {
    goto fail;
  }

  if (!goo_group_recover(group, B, *Bq, Bqi, *ell,
                         *C3, C3i, *chal, *z_a, *z_s2)) {
    goto fail;
  }

  if (!goo_group_recover(group, C, *Cq, Cqi, *ell,
                         *C2, C2i, *z_w, *z_w2, *z_s1w)) {
    goto fail;
  }

  if (!goo_group_recover(group, D, *Dq, Dqi, *ell,
                         C1, C1i, *z_a, *z_an, *z_sa)) {
    goto fail;
  }

  mpz_sub(tmp, *z_w2, *z_an);
  mpz_mod(tmp, tmp, *ell);
  mpz_mul(E, *Eq, *ell);
  mpz_add(E, E, tmp);
  mpz_mul(tmp, *t, *chal);
  mpz_sub(E, E, tmp);

  /* Recompute `chal` and `ell`. */
  if (!goo_group_derive(group, chal0, ell0, &key[0],
                        C1, *C2, *C3, *t, A, B, C, D, E,
                        msg, msg_len)) {
    goto fail;
  }

  /* `chal` must be equal to the computed value. */
  if (mpz_cmp(*chal, chal0) != 0)
    goto fail;

  /* `ell` must be in the interval [ell',ell'+512]. */
  mpz_add_ui(ell1, ell0, GOO_ELLDIFF_MAX);

  if (mpz_cmp(*ell, ell0) < 0 || mpz_cmp(*ell, ell1) > 0)
    goto fail;

  /* `ell` must be prime. */
  if (!goo_is_prime(*ell, &key[0]))
    goto fail;

  ret = 1;
fail:
  mpz_clear(C1i);
  mpz_clear(C2i);
  mpz_clear(C3i);
  mpz_clear(Aqi);
  mpz_clear(Bqi);
  mpz_clear(Cqi);
  mpz_clear(Dqi);
  mpz_clear(A);
  mpz_clear(B);
  mpz_clear(C);
  mpz_clear(D);
  mpz_clear(E);
  mpz_clear(tmp);
  mpz_clear(chal0);
  mpz_clear(ell0);
  mpz_clear(ell1);
  return ret;
}

/*
 * API
 */

int
goo_init(goo_ctx_t *ctx,
         const unsigned char *n,
         size_t n_len,
         unsigned long g,
         unsigned long h,
         unsigned long bits) {
  int r = 0;
  mpz_t n_n;

  if (ctx == NULL || n == NULL)
    return 0;

  mpz_init(n_n);

  goo_mpz_import(n_n, n, n_len);

  if (!goo_group_init(ctx, n_n, g, h, bits))
    goto fail;

  r = 1;
fail:
  mpz_clear(n_n);
  return r;
}

void
goo_uninit(goo_ctx_t *ctx) {
  if (ctx != NULL)
    goo_group_uninit(ctx);
}

int
goo_challenge(goo_ctx_t *ctx,
              unsigned char **C1,
              size_t *C1_len,
              const unsigned char *s_prime,
              const unsigned char *n,
              size_t n_len) {
  int r = 0;
  mpz_t C1_n, n_n;

  if (ctx == NULL
      || s_prime == NULL
      || C1 == NULL
      || C1_len == NULL
      || n == NULL) {
    return 0;
  }

  mpz_init(C1_n);
  mpz_init(n_n);

  goo_mpz_import(n_n, n, n_len);

  if (!goo_group_challenge(ctx, C1_n, s_prime, n_n))
    goto fail;

  *C1_len = goo_mpz_bytelen(ctx->n);
  *C1 = goo_mpz_pad(NULL, *C1_len, C1_n);

  if (*C1 == NULL)
    goto fail;

  r = 1;
fail:
  mpz_clear(C1_n);
  mpz_clear(n_n);
  return r;
}

int
goo_validate(goo_ctx_t *ctx,
             const unsigned char *s_prime,
             const unsigned char *C1,
             size_t C1_len,
             const unsigned char *p,
             size_t p_len,
             const unsigned char *q,
             size_t q_len) {
  int r = 0;
  mpz_t C1_n, p_n, q_n;

  if (ctx == NULL
      || s_prime == NULL
      || C1 == NULL
      || p == NULL
      || q == NULL) {
    return 0;
  }

  if (C1_len != ctx->size)
    return 0;

  mpz_init(C1_n);
  mpz_init(p_n);
  mpz_init(q_n);

  goo_mpz_import(C1_n, C1, C1_len);
  goo_mpz_import(p_n, p, p_len);
  goo_mpz_import(q_n, q, q_len);

  if (!goo_group_validate(ctx, s_prime, C1_n, p_n, q_n))
    goto fail;

  r = 1;
fail:
  mpz_clear(C1_n);
  mpz_clear(p_n);
  mpz_clear(q_n);
  return r;
}

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
         const unsigned char *seed) {
  int r = 0;
  mpz_t p_n, q_n;
  goo_sig_t S;
  size_t size;
  unsigned char *data = NULL;

  if (ctx == NULL
      || out == NULL
      || out_len == NULL
      || s_prime == NULL
      || p == NULL
      || q == NULL
      || seed == NULL) {
    return 0;
  }

  mpz_init(p_n);
  mpz_init(q_n);
  goo_sig_init(&S);

  goo_mpz_import(p_n, p, p_len);
  goo_mpz_import(q_n, q, q_len);

  if (!goo_group_sign(ctx, &S, msg, msg_len, s_prime, p_n, q_n, seed))
    goto fail;

  size = goo_sig_size(&S, ctx->bits);
  data = goo_malloc(size);

  if (!goo_sig_export(data, &S, ctx->bits))
    goto fail;

  *out = data;
  *out_len = size;

  r = 1;
fail:
  mpz_clear(p_n);
  mpz_clear(q_n);
  goo_sig_uninit(&S);

  if (r == 0)
    goo_free(data);

  return r;
}

int
goo_verify(goo_ctx_t *ctx,
           const unsigned char *msg,
           size_t msg_len,
           const unsigned char *sig,
           size_t sig_len,
           const unsigned char *C1,
           size_t C1_len) {
  int ret = 0;
  goo_sig_t S;
  mpz_t C1_n;

  if (ctx == NULL || sig == NULL || C1 == NULL)
    return 0;

  if (C1_len != ctx->size)
    return 0;

  goo_sig_init(&S);
  mpz_init(C1_n);

  goo_mpz_import(C1_n, C1, C1_len);

  if (!goo_sig_import(&S, sig, sig_len, ctx->bits))
    goto fail;

  if (!goo_group_verify(ctx, msg, msg_len, &S, C1_n))
    goto fail;

  ret = 1;
fail:
  goo_sig_uninit(&S);
  mpz_clear(C1_n);
  return ret;
}

#ifdef GOO_TEST
#include <stdio.h>

static int
goo_hex_cmp(const unsigned char *data, size_t len, const char *expect) {
  mpz_t x, y;
  int r;

  mpz_init(x);
  mpz_init(y);

  goo_mpz_import(x, data, len);

  assert(mpz_set_str(y, expect, 16) == 0);

  r = mpz_cmp(x, y);

  mpz_clear(x);
  mpz_clear(y);

  return r;
}

static void
run_hmac_test(void) {
  static const char data[] = "hello world";
  unsigned char key[32];
  unsigned char out[32];

  static const char expect[] =
    "42eb78776ad82f001179f44e9e88264f2d804251e02d988c1194b95de823a14e";

  goo_hmac_t ctx;

  memset(&key[0], 0xff, 32);

  printf("Testing HMAC...\n");

  goo_hmac_init(&ctx, &key[0], 32);
  goo_hmac_update(&ctx, (unsigned char *)data, sizeof(data) - 1);

  goo_hmac_final(&ctx, &out[0]);

  assert(goo_hex_cmp(&out[0], 32, expect) == 0);
}

static void
run_drbg_test(void) {
  unsigned char entropy[64];
  unsigned char out[32];

  static const char expect1[] =
    "40e95c4dba22fd05d15784075b05ca7c0b063a43dcec3307122575a7b5e32d3b";

  static const char expect2[] = "4d065662afc2927a3426c12dd1c35262";
  static const char expect3[] = "705119fd1536e2a7ec804db49f8262ce";

  goo_drbg_t ctx;

  memset(&entropy[0], 0xaa, 64);

  printf("Testing DRBG...\n");

  goo_drbg_init(&ctx, &entropy[0], 64);

  goo_drbg_generate(&ctx, &out[0], 32);
  assert(goo_hex_cmp(&out[0], 32, expect1) == 0);

  goo_drbg_generate(&ctx, &out[0], 16);
  assert(goo_hex_cmp(&out[0], 16, expect2) == 0);

  goo_drbg_generate(&ctx, &out[0], 16);
  assert(goo_hex_cmp(&out[0], 16, expect3) == 0);
}

static void
rng_init(goo_prng_t *prng) {
  unsigned char key[64];
  size_t i;

  for (i = 0; i < 64; i++)
    key[i] = (unsigned char)rand();

  goo_prng_init(prng);
  goo_prng_seed_local(prng, &key[0]);
}

static void
rng_clear(goo_prng_t *prng) {
  goo_prng_uninit(prng);
}

static void
run_prng_test(void) {
  goo_prng_t prng;
  unsigned char key[32];
  mpz_t x, y;

  printf("Testing PRNG...\n");

  memset(&key[0], 0xaa, 32);
  goo_prng_init(&prng);
  mpz_init(x);
  mpz_init(y);

  goo_prng_seed(&prng, key);

  goo_prng_random_bits(&prng, x, 256);
  assert(mpz_sgn(x) > 0);
  assert(goo_mpz_bitlen(x) <= 256);

  goo_prng_random_int(&prng, y, x);
  assert(mpz_sgn(y) > 0);
  assert(goo_mpz_bitlen(y) <= 256);
  assert(mpz_cmp(y, x) < 0);

  goo_prng_random_bits(&prng, x, 30);
  assert(mpz_cmp_ui(x, 889224476) == 0);
  goo_prng_random_bits(&prng, x, 31);
  assert(mpz_cmp_ui(x, 1264675751) == 0);
  goo_prng_random_bits(&prng, x, 31);
  goo_prng_random_int(&prng, y, x);
  assert(mpz_cmp_ui(y, 768829332) == 0);

  mpz_clear(x);
  mpz_clear(y);
  goo_prng_uninit(&prng);
}

static void
run_util_test(void) {
  goo_prng_t rng;

  rng_init(&rng);

  /* test bitlen and zerobits */
  {
    mpz_t n;

    printf("Testing bitlen & zerobits...\n");

    mpz_init(n);

    mpz_set_ui(n, 0x010001);

    assert(goo_mpz_zerobits(n) == 0);
    assert(goo_mpz_bitlen(n) == 17);

    mpz_set_si(n, -0x010001);

    assert(goo_mpz_zerobits(n) == 0);
    assert(goo_mpz_bitlen(n) == 17);

    mpz_set_ui(n, 0x20000);

    assert(goo_mpz_zerobits(n) == 17);
    assert(goo_mpz_bitlen(n) == 18);

    mpz_set_si(n, -0x20000);

    assert(goo_mpz_zerobits(n) == 17);
    assert(goo_mpz_bitlen(n) == 18);

    mpz_clear(n);
  }

  /* test mask */
  {
    mpz_t n, t;

    printf("Testing mask...\n");

    mpz_init(n);
    mpz_init(t);

    mpz_set_ui(n, 0xffff1234);

    goo_mpz_mask(n, n, 16, t);

    assert(mpz_get_ui(n) == 0x1234);

    mpz_clear(n);
    mpz_clear(t);
  }

  /* test sqrt */
  {
    printf("Testing sqrt...\n");

    assert(goo_isqrt(1024) == 32);
    assert(goo_isqrt(1025) == 32);
  }

  /* test division */
  {
    mpz_t x, y, z;

    printf("Testing division...\n");

    mpz_init(x);
    mpz_init(y);
    mpz_init(z);

    mpz_set_si(x, 3);
    mpz_set_si(y, -2);
    mpz_fdiv_q(z, x, y);
    assert(mpz_get_si(z) == -2);
    assert(mpz_cmp_ui(z, 0) < 0);

    mpz_tdiv_q(z, x, y);
    assert(mpz_get_si(z) == -1);

    mpz_set_si(x, -3);
    mpz_set_si(y, 2);
    mpz_fdiv_q(z, x, y);
    assert(mpz_get_si(z) == -2);

    mpz_tdiv_q(z, x, y);
    assert(mpz_get_si(z) == -1);

    mpz_set_si(x, 4);
    mpz_set_si(y, -2);
    mpz_fdiv_q(z, x, y);
    assert(mpz_get_si(z) == -2);

    mpz_tdiv_q(z, x, y);
    assert(mpz_get_si(z) == -2);

    mpz_set_si(x, -4);
    mpz_set_si(y, 2);
    mpz_fdiv_q(z, x, y);
    assert(mpz_get_si(z) == -2);

    mpz_tdiv_q(z, x, y);
    assert(mpz_get_si(z) == -2);

    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(z);
  }

  /* test modulo */
  {
    mpz_t x, y, z;

    printf("Testing modulo...\n");

    mpz_init(x);
    mpz_init(y);
    mpz_init(z);

    /* Note: This equals 1 with mpz_mod. */
    mpz_set_si(x, 3);
    mpz_set_si(y, -2);
    mpz_fdiv_r(z, x, y);
    assert(mpz_get_si(z) == -1);

    /* Note: mpz_tdiv_r behaves like mpz_mod. */
    mpz_tdiv_r(z, x, y);
    assert(mpz_get_si(z) == 1);

    mpz_set_si(x, -3);
    mpz_set_si(y, 2);
    mpz_mod(z, x, y);
    assert(mpz_get_si(z) == 1);
    assert(mpz_tdiv_ui(x, 2) == 1);

    mpz_set_si(x, 3);
    mpz_set_si(y, -2);
    mpz_mod(z, x, y);
    assert(mpz_get_si(z) == 1);

    mpz_set_si(x, 4);
    mpz_set_si(y, -2);
    mpz_mod(z, x, y);
    assert(mpz_get_si(z) == 0);

    mpz_set_si(x, -4);
    mpz_set_si(y, 2);
    mpz_mod(z, x, y);
    assert(mpz_get_si(z) == 0);

    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(z);
  }

  /* test sqrts */
  {
    static const char p_hex[] = ""
      "ccbf79ad1f5e47086062274ea9815042fd938149a5557c8cb3b0c33d"
      "dcd87c58a53760826a99d196852460762e16a715e40bee5847324aa1"
      "9911e98bf58e8c9af65e06182bb307c706069df394e5d098fbe85701"
      "eb2e88089913834aadba3b134f646f6d48f2dacba00a5bfd15e8b8d9"
      "c0efe1f4209595b920691aeebfc4ba1b28592d88fc0f565b0d3dbcf2"
      "e3dda7b02e5452660c4bd4485e23cb68e1fdc9f3647f85c5ee0c3555"
      "c21ce8307320257fae148887af5412db2cece240044cd668c72c7219"
      "b2e6a32f5da0e0cd52ec9078e7ef521461f2fe5d83b240c412507961"
      "0512976d1c3b65fcb0ad75133012e2c7329ce55177556f07bdabb271"
      "622466fb";

    static const char q_hex[] = ""
      "842d18ae53b1e47aac1d2c7ff91ee656f669ce9676edc2689f39b2cd"
      "3052c9157e65b16241bb9d6eb0d15adfb4baa97a7f6f4b9d0621ef84"
      "d1ba262f5b3b98ec7b47a5492631e282ade5108d02fc14c965d9dbfd"
      "4683f740abc8f9120d0c7e2f79b0c94f68f0c91acdbd977a66f9a9e1"
      "59e680ec12ba632ed36f54f438e0eaefc24b6e25c6fd32da9a9c9271"
      "0cede05462335178baa574e2519aa0bd55a69e5ca130405174271afe"
      "9b92ad5e82c5ceae9f9124f1b361e22503ad1ca0bad526a2eef833ad"
      "84efc4203137b10704bab5ce6bb2eb58a2209ef738c44b7127655ed9"
      "37c5a937ae6ac9beaace7ece9fb33ae60e980da73730a6144e38ca9a"
      "537fe02d";

    mpz_t p, q, n;

    printf("Testing roots...\n");

    mpz_init(p);
    mpz_init(q);
    mpz_init(n);

    assert(mpz_set_str(p, p_hex, 16) == 0);
    assert(mpz_set_str(q, q_hex, 16) == 0);

    mpz_mul(n, p, q);

    /* test sqrt_modp */
    {
      mpz_t r1, sr1;

      printf("Testing sqrt_modp...\n");

      mpz_init(r1);
      mpz_init(sr1);

      goo_prng_random_int(&rng, r1, p);
      mpz_powm_ui(r1, r1, 2, p);

      assert(goo_mpz_sqrtm(sr1, r1, p));

      mpz_powm_ui(sr1, sr1, 2, p);

      assert(mpz_cmp(sr1, r1) == 0);

      mpz_clear(r1);
      mpz_clear(sr1);
    }

    /* test sqrt_modn */
    {
      mpz_t r2, sr2;

      printf("Testing sqrt_modn...\n");

      mpz_init(r2);
      mpz_init(sr2);

      goo_prng_random_int(&rng, r2, n);
      mpz_powm_ui(r2, r2, 2, n);

      assert(goo_mpz_sqrtpq(sr2, r2, p, q));

      mpz_powm_ui(sr2, sr2, 2, n);

      assert(mpz_cmp(sr2, r2) == 0);

      mpz_clear(r2);
      mpz_clear(sr2);
    }

    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
  }

#define GOO_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

  /* test jacobi */
  {
    static const int symbols[][3] = {
      /* https://github.com/golang/go/blob/aadaec5/src/math/big/int_test.go#L1590 */
      {0, 1, 1}, {0, -1, 1}, {1, 1, 1}, {1, -1, 1}, {0, 5, 0},
      {1, 5, 1}, {2, 5, -1}, {-2, 5, -1}, {2, -5, -1}, {-2, -5, 1},
      {3, 5, -1}, {5, 5, 0}, {-5, 5, 0}, {6, 5, 1}, {6, -5, 1},
      {-6, 5, 1}, {-6, -5, -1},

      /* https://en.wikipedia.org/wiki/Legendre_symbol#Table_of_values */
      {1, 3, 1}, {1, 5, 1}, {1, 7, 1}, {1, 11, 1}, {1, 13, 1},
      {1, 17, 1}, {1, 19, 1}, {1, 23, 1}, {1, 29, 1}, {1, 31, 1},
      {1, 37, 1}, {1, 41, 1}, {1, 43, 1}, {1, 47, 1}, {1, 53, 1},
      {1, 59, 1}, {1, 61, 1}, {1, 67, 1}, {1, 71, 1}, {1, 73, 1},
      {1, 79, 1}, {1, 83, 1}, {1, 89, 1}, {1, 97, 1}, {1, 101, 1},
      {1, 103, 1}, {1, 107, 1}, {1, 109, 1}, {1, 113, 1}, {1, 127, 1},
      {2, 3, -1}, {2, 5, -1}, {2, 7, 1}, {2, 11, -1}, {2, 13, -1},
      {2, 17, 1}, {2, 19, -1}, {2, 23, 1}, {2, 29, -1}, {2, 31, 1},
      {2, 37, -1}, {2, 41, 1}, {2, 43, -1}, {2, 47, 1}, {2, 53, -1},
      {2, 59, -1}, {2, 61, -1}, {2, 67, -1}, {2, 71, 1}, {2, 73, 1},
      {2, 79, 1}, {2, 83, -1}, {2, 89, 1}, {2, 97, 1}, {2, 101, -1},
      {2, 103, 1}, {2, 107, -1}, {2, 109, -1}, {2, 113, 1}, {2, 127, 1},
      {3, 3, 0}, {3, 5, -1}, {3, 7, -1}, {3, 11, 1}, {3, 13, 1},
      {3, 17, -1}, {3, 19, -1}, {3, 23, 1}, {3, 29, -1}, {3, 31, -1},
      {3, 37, 1}, {3, 41, -1}, {3, 43, -1}, {3, 47, 1}, {3, 53, -1},
      {3, 59, 1}, {3, 61, 1}, {3, 67, -1}, {3, 71, 1}, {3, 73, 1},
      {3, 79, -1}, {3, 83, 1}, {3, 89, -1}, {3, 97, 1}, {3, 101, -1},
      {3, 103, -1}, {3, 107, 1}, {3, 109, 1}, {3, 113, -1}, {3, 127, -1},
      {4, 3, 1}, {4, 5, 1}, {4, 7, 1}, {4, 11, 1}, {4, 13, 1},
      {4, 17, 1}, {4, 19, 1}, {4, 23, 1}, {4, 29, 1}, {4, 31, 1},
      {4, 37, 1}, {4, 41, 1}, {4, 43, 1}, {4, 47, 1}, {4, 53, 1},
      {4, 59, 1}, {4, 61, 1}, {4, 67, 1}, {4, 71, 1}, {4, 73, 1},
      {4, 79, 1}, {4, 83, 1}, {4, 89, 1}, {4, 97, 1}, {4, 101, 1},
      {4, 103, 1}, {4, 107, 1}, {4, 109, 1}, {4, 113, 1}, {4, 127, 1},
      {5, 3, -1}, {5, 5, 0}, {5, 7, -1}, {5, 11, 1}, {5, 13, -1},
      {5, 17, -1}, {5, 19, 1}, {5, 23, -1}, {5, 29, 1}, {5, 31, 1},
      {5, 37, -1}, {5, 41, 1}, {5, 43, -1}, {5, 47, -1}, {5, 53, -1},
      {5, 59, 1}, {5, 61, 1}, {5, 67, -1}, {5, 71, 1}, {5, 73, -1},
      {5, 79, 1}, {5, 83, -1}, {5, 89, 1}, {5, 97, -1}, {5, 101, 1},
      {5, 103, -1}, {5, 107, -1}, {5, 109, 1}, {5, 113, -1}, {5, 127, -1},
      {6, 3, 0}, {6, 5, 1}, {6, 7, -1}, {6, 11, -1}, {6, 13, -1},
      {6, 17, -1}, {6, 19, 1}, {6, 23, 1}, {6, 29, 1}, {6, 31, -1},
      {6, 37, -1}, {6, 41, -1}, {6, 43, 1}, {6, 47, 1}, {6, 53, 1},
      {6, 59, -1}, {6, 61, -1}, {6, 67, 1}, {6, 71, 1}, {6, 73, 1},
      {6, 79, -1}, {6, 83, -1}, {6, 89, -1}, {6, 97, 1}, {6, 101, 1},
      {6, 103, -1}, {6, 107, -1}, {6, 109, -1}, {6, 113, -1}, {6, 127, -1},
      {7, 3, 1}, {7, 5, -1}, {7, 7, 0}, {7, 11, -1}, {7, 13, -1},
      {7, 17, -1}, {7, 19, 1}, {7, 23, -1}, {7, 29, 1}, {7, 31, 1},
      {7, 37, 1}, {7, 41, -1}, {7, 43, -1}, {7, 47, 1}, {7, 53, 1},
      {7, 59, 1}, {7, 61, -1}, {7, 67, -1}, {7, 71, -1}, {7, 73, -1},
      {7, 79, -1}, {7, 83, 1}, {7, 89, -1}, {7, 97, -1}, {7, 101, -1},
      {7, 103, 1}, {7, 107, -1}, {7, 109, 1}, {7, 113, 1}, {7, 127, -1},
      {8, 3, -1}, {8, 5, -1}, {8, 7, 1}, {8, 11, -1}, {8, 13, -1},
      {8, 17, 1}, {8, 19, -1}, {8, 23, 1}, {8, 29, -1}, {8, 31, 1},
      {8, 37, -1}, {8, 41, 1}, {8, 43, -1}, {8, 47, 1}, {8, 53, -1},
      {8, 59, -1}, {8, 61, -1}, {8, 67, -1}, {8, 71, 1}, {8, 73, 1},
      {8, 79, 1}, {8, 83, -1}, {8, 89, 1}, {8, 97, 1}, {8, 101, -1},
      {8, 103, 1}, {8, 107, -1}, {8, 109, -1}, {8, 113, 1}, {8, 127, 1},
      {9, 3, 0}, {9, 5, 1}, {9, 7, 1}, {9, 11, 1}, {9, 13, 1},
      {9, 17, 1}, {9, 19, 1}, {9, 23, 1}, {9, 29, 1}, {9, 31, 1},
      {9, 37, 1}, {9, 41, 1}, {9, 43, 1}, {9, 47, 1}, {9, 53, 1},
      {9, 59, 1}, {9, 61, 1}, {9, 67, 1}, {9, 71, 1}, {9, 73, 1},
      {9, 79, 1}, {9, 83, 1}, {9, 89, 1}, {9, 97, 1}, {9, 101, 1},
      {9, 103, 1}, {9, 107, 1}, {9, 109, 1}, {9, 113, 1}, {9, 127, 1},
      {10, 3, 1}, {10, 5, 0}, {10, 7, -1}, {10, 11, -1}, {10, 13, 1},
      {10, 17, -1}, {10, 19, -1}, {10, 23, -1}, {10, 29, -1}, {10, 31, 1},
      {10, 37, 1}, {10, 41, 1}, {10, 43, 1}, {10, 47, -1}, {10, 53, 1},
      {10, 59, -1}, {10, 61, -1}, {10, 67, 1}, {10, 71, 1}, {10, 73, -1},
      {10, 79, 1}, {10, 83, 1}, {10, 89, 1}, {10, 97, -1}, {10, 101, -1},
      {10, 103, -1}, {10, 107, 1}, {10, 109, -1}, {10, 113, -1}, {10, 127, -1},
      {11, 3, -1}, {11, 5, 1}, {11, 7, 1}, {11, 11, 0}, {11, 13, -1},
      {11, 17, -1}, {11, 19, 1}, {11, 23, -1}, {11, 29, -1}, {11, 31, -1},
      {11, 37, 1}, {11, 41, -1}, {11, 43, 1}, {11, 47, -1}, {11, 53, 1},
      {11, 59, -1}, {11, 61, -1}, {11, 67, -1}, {11, 71, -1}, {11, 73, -1},
      {11, 79, 1}, {11, 83, 1}, {11, 89, 1}, {11, 97, 1}, {11, 101, -1},
      {11, 103, -1}, {11, 107, 1}, {11, 109, -1}, {11, 113, 1}, {11, 127, 1},
      {12, 3, 0}, {12, 5, -1}, {12, 7, -1}, {12, 11, 1}, {12, 13, 1},
      {12, 17, -1}, {12, 19, -1}, {12, 23, 1}, {12, 29, -1}, {12, 31, -1},
      {12, 37, 1}, {12, 41, -1}, {12, 43, -1}, {12, 47, 1}, {12, 53, -1},
      {12, 59, 1}, {12, 61, 1}, {12, 67, -1}, {12, 71, 1}, {12, 73, 1},
      {12, 79, -1}, {12, 83, 1}, {12, 89, -1}, {12, 97, 1}, {12, 101, -1},
      {12, 103, -1}, {12, 107, 1}, {12, 109, 1}, {12, 113, -1}, {12, 127, -1},
      {13, 3, 1}, {13, 5, -1}, {13, 7, -1}, {13, 11, -1}, {13, 13, 0},
      {13, 17, 1}, {13, 19, -1}, {13, 23, 1}, {13, 29, 1}, {13, 31, -1},
      {13, 37, -1}, {13, 41, -1}, {13, 43, 1}, {13, 47, -1}, {13, 53, 1},
      {13, 59, -1}, {13, 61, 1}, {13, 67, -1}, {13, 71, -1}, {13, 73, -1},
      {13, 79, 1}, {13, 83, -1}, {13, 89, -1}, {13, 97, -1}, {13, 101, 1},
      {13, 103, 1}, {13, 107, 1}, {13, 109, -1}, {13, 113, 1}, {13, 127, 1},
      {14, 3, -1}, {14, 5, 1}, {14, 7, 0}, {14, 11, 1}, {14, 13, 1},
      {14, 17, -1}, {14, 19, -1}, {14, 23, -1}, {14, 29, -1}, {14, 31, 1},
      {14, 37, -1}, {14, 41, -1}, {14, 43, 1}, {14, 47, 1}, {14, 53, -1},
      {14, 59, -1}, {14, 61, 1}, {14, 67, 1}, {14, 71, -1}, {14, 73, -1},
      {14, 79, -1}, {14, 83, -1}, {14, 89, -1}, {14, 97, -1}, {14, 101, 1},
      {14, 103, 1}, {14, 107, 1}, {14, 109, -1}, {14, 113, 1}, {14, 127, -1},
      {15, 3, 0}, {15, 5, 0}, {15, 7, 1}, {15, 11, 1}, {15, 13, -1},
      {15, 17, 1}, {15, 19, -1}, {15, 23, -1}, {15, 29, -1}, {15, 31, -1},
      {15, 37, -1}, {15, 41, -1}, {15, 43, 1}, {15, 47, -1}, {15, 53, 1},
      {15, 59, 1}, {15, 61, 1}, {15, 67, 1}, {15, 71, 1}, {15, 73, -1},
      {15, 79, -1}, {15, 83, -1}, {15, 89, -1}, {15, 97, -1}, {15, 101, -1},
      {15, 103, 1}, {15, 107, -1}, {15, 109, 1}, {15, 113, 1}, {15, 127, 1},
      {16, 3, 1}, {16, 5, 1}, {16, 7, 1}, {16, 11, 1}, {16, 13, 1},
      {16, 17, 1}, {16, 19, 1}, {16, 23, 1}, {16, 29, 1}, {16, 31, 1},
      {16, 37, 1}, {16, 41, 1}, {16, 43, 1}, {16, 47, 1}, {16, 53, 1},
      {16, 59, 1}, {16, 61, 1}, {16, 67, 1}, {16, 71, 1}, {16, 73, 1},
      {16, 79, 1}, {16, 83, 1}, {16, 89, 1}, {16, 97, 1}, {16, 101, 1},
      {16, 103, 1}, {16, 107, 1}, {16, 109, 1}, {16, 113, 1}, {16, 127, 1},
      {17, 3, -1}, {17, 5, -1}, {17, 7, -1}, {17, 11, -1}, {17, 13, 1},
      {17, 17, 0}, {17, 19, 1}, {17, 23, -1}, {17, 29, -1}, {17, 31, -1},
      {17, 37, -1}, {17, 41, -1}, {17, 43, 1}, {17, 47, 1}, {17, 53, 1},
      {17, 59, 1}, {17, 61, -1}, {17, 67, 1}, {17, 71, -1}, {17, 73, -1},
      {17, 79, -1}, {17, 83, 1}, {17, 89, 1}, {17, 97, -1}, {17, 101, 1},
      {17, 103, 1}, {17, 107, -1}, {17, 109, -1}, {17, 113, -1}, {17, 127, 1},
      {18, 3, 0}, {18, 5, -1}, {18, 7, 1}, {18, 11, -1}, {18, 13, -1},
      {18, 17, 1}, {18, 19, -1}, {18, 23, 1}, {18, 29, -1}, {18, 31, 1},
      {18, 37, -1}, {18, 41, 1}, {18, 43, -1}, {18, 47, 1}, {18, 53, -1},
      {18, 59, -1}, {18, 61, -1}, {18, 67, -1}, {18, 71, 1}, {18, 73, 1},
      {18, 79, 1}, {18, 83, -1}, {18, 89, 1}, {18, 97, 1}, {18, 101, -1},
      {18, 103, 1}, {18, 107, -1}, {18, 109, -1}, {18, 113, 1}, {18, 127, 1},
      {19, 3, 1}, {19, 5, 1}, {19, 7, -1}, {19, 11, -1}, {19, 13, -1},
      {19, 17, 1}, {19, 19, 0}, {19, 23, -1}, {19, 29, -1}, {19, 31, 1},
      {19, 37, -1}, {19, 41, -1}, {19, 43, -1}, {19, 47, -1}, {19, 53, -1},
      {19, 59, 1}, {19, 61, 1}, {19, 67, 1}, {19, 71, 1}, {19, 73, 1},
      {19, 79, 1}, {19, 83, -1}, {19, 89, -1}, {19, 97, -1}, {19, 101, 1},
      {19, 103, 1}, {19, 107, 1}, {19, 109, -1}, {19, 113, -1}, {19, 127, 1},
      {20, 3, -1}, {20, 5, 0}, {20, 7, -1}, {20, 11, 1}, {20, 13, -1},
      {20, 17, -1}, {20, 19, 1}, {20, 23, -1}, {20, 29, 1}, {20, 31, 1},
      {20, 37, -1}, {20, 41, 1}, {20, 43, -1}, {20, 47, -1}, {20, 53, -1},
      {20, 59, 1}, {20, 61, 1}, {20, 67, -1}, {20, 71, 1}, {20, 73, -1},
      {20, 79, 1}, {20, 83, -1}, {20, 89, 1}, {20, 97, -1}, {20, 101, 1},
      {20, 103, -1}, {20, 107, -1}, {20, 109, 1}, {20, 113, -1}, {20, 127, -1},
      {21, 3, 0}, {21, 5, 1}, {21, 7, 0}, {21, 11, -1}, {21, 13, -1},
      {21, 17, 1}, {21, 19, -1}, {21, 23, -1}, {21, 29, -1}, {21, 31, -1},
      {21, 37, 1}, {21, 41, 1}, {21, 43, 1}, {21, 47, 1}, {21, 53, -1},
      {21, 59, 1}, {21, 61, -1}, {21, 67, 1}, {21, 71, -1}, {21, 73, -1},
      {21, 79, 1}, {21, 83, 1}, {21, 89, 1}, {21, 97, -1}, {21, 101, 1},
      {21, 103, -1}, {21, 107, -1}, {21, 109, 1}, {21, 113, -1}, {21, 127, 1},
      {22, 3, 1}, {22, 5, -1}, {22, 7, 1}, {22, 11, 0}, {22, 13, 1},
      {22, 17, -1}, {22, 19, -1}, {22, 23, -1}, {22, 29, 1}, {22, 31, -1},
      {22, 37, -1}, {22, 41, -1}, {22, 43, -1}, {22, 47, -1}, {22, 53, -1},
      {22, 59, 1}, {22, 61, 1}, {22, 67, 1}, {22, 71, -1}, {22, 73, -1},
      {22, 79, 1}, {22, 83, -1}, {22, 89, 1}, {22, 97, 1}, {22, 101, 1},
      {22, 103, -1}, {22, 107, -1}, {22, 109, 1}, {22, 113, 1}, {22, 127, 1},
      {23, 3, -1}, {23, 5, -1}, {23, 7, 1}, {23, 11, 1}, {23, 13, 1},
      {23, 17, -1}, {23, 19, 1}, {23, 23, 0}, {23, 29, 1}, {23, 31, -1},
      {23, 37, -1}, {23, 41, 1}, {23, 43, 1}, {23, 47, -1}, {23, 53, -1},
      {23, 59, -1}, {23, 61, -1}, {23, 67, 1}, {23, 71, -1}, {23, 73, 1},
      {23, 79, 1}, {23, 83, 1}, {23, 89, -1}, {23, 97, -1}, {23, 101, 1},
      {23, 103, 1}, {23, 107, 1}, {23, 109, -1}, {23, 113, -1}, {23, 127, -1},
      {24, 3, 0}, {24, 5, 1}, {24, 7, -1}, {24, 11, -1}, {24, 13, -1},
      {24, 17, -1}, {24, 19, 1}, {24, 23, 1}, {24, 29, 1}, {24, 31, -1},
      {24, 37, -1}, {24, 41, -1}, {24, 43, 1}, {24, 47, 1}, {24, 53, 1},
      {24, 59, -1}, {24, 61, -1}, {24, 67, 1}, {24, 71, 1}, {24, 73, 1},
      {24, 79, -1}, {24, 83, -1}, {24, 89, -1}, {24, 97, 1}, {24, 101, 1},
      {24, 103, -1}, {24, 107, -1}, {24, 109, -1}, {24, 113, -1}, {24, 127, -1},
      {25, 3, 1}, {25, 5, 0}, {25, 7, 1}, {25, 11, 1}, {25, 13, 1},
      {25, 17, 1}, {25, 19, 1}, {25, 23, 1}, {25, 29, 1}, {25, 31, 1},
      {25, 37, 1}, {25, 41, 1}, {25, 43, 1}, {25, 47, 1}, {25, 53, 1},
      {25, 59, 1}, {25, 61, 1}, {25, 67, 1}, {25, 71, 1}, {25, 73, 1},
      {25, 79, 1}, {25, 83, 1}, {25, 89, 1}, {25, 97, 1}, {25, 101, 1},
      {25, 103, 1}, {25, 107, 1}, {25, 109, 1}, {25, 113, 1}, {25, 127, 1},
      {26, 3, -1}, {26, 5, 1}, {26, 7, -1}, {26, 11, 1}, {26, 13, 0},
      {26, 17, 1}, {26, 19, 1}, {26, 23, 1}, {26, 29, -1}, {26, 31, -1},
      {26, 37, 1}, {26, 41, -1}, {26, 43, -1}, {26, 47, -1}, {26, 53, -1},
      {26, 59, 1}, {26, 61, -1}, {26, 67, 1}, {26, 71, -1}, {26, 73, -1},
      {26, 79, 1}, {26, 83, 1}, {26, 89, -1}, {26, 97, -1}, {26, 101, -1},
      {26, 103, 1}, {26, 107, -1}, {26, 109, 1}, {26, 113, 1}, {26, 127, 1},
      {27, 3, 0}, {27, 5, -1}, {27, 7, -1}, {27, 11, 1}, {27, 13, 1},
      {27, 17, -1}, {27, 19, -1}, {27, 23, 1}, {27, 29, -1}, {27, 31, -1},
      {27, 37, 1}, {27, 41, -1}, {27, 43, -1}, {27, 47, 1}, {27, 53, -1},
      {27, 59, 1}, {27, 61, 1}, {27, 67, -1}, {27, 71, 1}, {27, 73, 1},
      {27, 79, -1}, {27, 83, 1}, {27, 89, -1}, {27, 97, 1}, {27, 101, -1},
      {27, 103, -1}, {27, 107, 1}, {27, 109, 1}, {27, 113, -1}, {27, 127, -1},
      {28, 3, 1}, {28, 5, -1}, {28, 7, 0}, {28, 11, -1}, {28, 13, -1},
      {28, 17, -1}, {28, 19, 1}, {28, 23, -1}, {28, 29, 1}, {28, 31, 1},
      {28, 37, 1}, {28, 41, -1}, {28, 43, -1}, {28, 47, 1}, {28, 53, 1},
      {28, 59, 1}, {28, 61, -1}, {28, 67, -1}, {28, 71, -1}, {28, 73, -1},
      {28, 79, -1}, {28, 83, 1}, {28, 89, -1}, {28, 97, -1}, {28, 101, -1},
      {28, 103, 1}, {28, 107, -1}, {28, 109, 1}, {28, 113, 1}, {28, 127, -1},
      {29, 3, -1}, {29, 5, 1}, {29, 7, 1}, {29, 11, -1}, {29, 13, 1},
      {29, 17, -1}, {29, 19, -1}, {29, 23, 1}, {29, 29, 0}, {29, 31, -1},
      {29, 37, -1}, {29, 41, -1}, {29, 43, -1}, {29, 47, -1}, {29, 53, 1},
      {29, 59, 1}, {29, 61, -1}, {29, 67, 1}, {29, 71, 1}, {29, 73, -1},
      {29, 79, -1}, {29, 83, 1}, {29, 89, -1}, {29, 97, -1}, {29, 101, -1},
      {29, 103, 1}, {29, 107, 1}, {29, 109, 1}, {29, 113, -1}, {29, 127, -1},
      {30, 3, 0}, {30, 5, 0}, {30, 7, 1}, {30, 11, -1}, {30, 13, 1},
      {30, 17, 1}, {30, 19, 1}, {30, 23, -1}, {30, 29, 1}, {30, 31, -1},
      {30, 37, 1}, {30, 41, -1}, {30, 43, -1}, {30, 47, -1}, {30, 53, -1},
      {30, 59, -1}, {30, 61, -1}, {30, 67, -1}, {30, 71, 1}, {30, 73, -1},
      {30, 79, -1}, {30, 83, 1}, {30, 89, -1}, {30, 97, -1}, {30, 101, 1},
      {30, 103, 1}, {30, 107, 1}, {30, 109, -1}, {30, 113, 1}, {30, 127, 1},
      {12345, 331, -1},

      /* https://en.wikipedia.org/wiki/Jacobi_symbol#Table_of_values */
      {1, 1, 1}, {1, 3, 1}, {1, 5, 1}, {1, 7, 1}, {1, 9, 1},
      {1, 11, 1}, {1, 13, 1}, {1, 15, 1}, {1, 17, 1}, {1, 19, 1},
      {1, 21, 1}, {1, 23, 1}, {1, 25, 1}, {1, 27, 1}, {1, 29, 1},
      {1, 31, 1}, {1, 33, 1}, {1, 35, 1}, {1, 37, 1}, {1, 39, 1},
      {1, 41, 1}, {1, 43, 1}, {1, 45, 1}, {1, 47, 1}, {1, 49, 1},
      {1, 51, 1}, {1, 53, 1}, {1, 55, 1}, {1, 57, 1}, {1, 59, 1},
      {2, 1, 1}, {2, 3, -1}, {2, 5, -1}, {2, 7, 1}, {2, 9, 1},
      {2, 11, -1}, {2, 13, -1}, {2, 15, 1}, {2, 17, 1}, {2, 19, -1},
      {2, 21, -1}, {2, 23, 1}, {2, 25, 1}, {2, 27, -1}, {2, 29, -1},
      {2, 31, 1}, {2, 33, 1}, {2, 35, -1}, {2, 37, -1}, {2, 39, 1},
      {2, 41, 1}, {2, 43, -1}, {2, 45, -1}, {2, 47, 1}, {2, 49, 1},
      {2, 51, -1}, {2, 53, -1}, {2, 55, 1}, {2, 57, 1}, {2, 59, -1},
      {3, 1, 1}, {3, 3, 0}, {3, 5, -1}, {3, 7, -1}, {3, 9, 0},
      {3, 11, 1}, {3, 13, 1}, {3, 15, 0}, {3, 17, -1}, {3, 19, -1},
      {3, 21, 0}, {3, 23, 1}, {3, 25, 1}, {3, 27, 0}, {3, 29, -1},
      {3, 31, -1}, {3, 33, 0}, {3, 35, 1}, {3, 37, 1}, {3, 39, 0},
      {3, 41, -1}, {3, 43, -1}, {3, 45, 0}, {3, 47, 1}, {3, 49, 1},
      {3, 51, 0}, {3, 53, -1}, {3, 55, -1}, {3, 57, 0}, {3, 59, 1},
      {4, 1, 1}, {4, 3, 1}, {4, 5, 1}, {4, 7, 1}, {4, 9, 1},
      {4, 11, 1}, {4, 13, 1}, {4, 15, 1}, {4, 17, 1}, {4, 19, 1},
      {4, 21, 1}, {4, 23, 1}, {4, 25, 1}, {4, 27, 1}, {4, 29, 1},
      {4, 31, 1}, {4, 33, 1}, {4, 35, 1}, {4, 37, 1}, {4, 39, 1},
      {4, 41, 1}, {4, 43, 1}, {4, 45, 1}, {4, 47, 1}, {4, 49, 1},
      {4, 51, 1}, {4, 53, 1}, {4, 55, 1}, {4, 57, 1}, {4, 59, 1},
      {5, 1, 1}, {5, 3, -1}, {5, 5, 0}, {5, 7, -1}, {5, 9, 1},
      {5, 11, 1}, {5, 13, -1}, {5, 15, 0}, {5, 17, -1}, {5, 19, 1},
      {5, 21, 1}, {5, 23, -1}, {5, 25, 0}, {5, 27, -1}, {5, 29, 1},
      {5, 31, 1}, {5, 33, -1}, {5, 35, 0}, {5, 37, -1}, {5, 39, 1},
      {5, 41, 1}, {5, 43, -1}, {5, 45, 0}, {5, 47, -1}, {5, 49, 1},
      {5, 51, 1}, {5, 53, -1}, {5, 55, 0}, {5, 57, -1}, {5, 59, 1},
      {6, 1, 1}, {6, 3, 0}, {6, 5, 1}, {6, 7, -1}, {6, 9, 0},
      {6, 11, -1}, {6, 13, -1}, {6, 15, 0}, {6, 17, -1}, {6, 19, 1},
      {6, 21, 0}, {6, 23, 1}, {6, 25, 1}, {6, 27, 0}, {6, 29, 1},
      {6, 31, -1}, {6, 33, 0}, {6, 35, -1}, {6, 37, -1}, {6, 39, 0},
      {6, 41, -1}, {6, 43, 1}, {6, 45, 0}, {6, 47, 1}, {6, 49, 1},
      {6, 51, 0}, {6, 53, 1}, {6, 55, -1}, {6, 57, 0}, {6, 59, -1},
      {7, 1, 1}, {7, 3, 1}, {7, 5, -1}, {7, 7, 0}, {7, 9, 1},
      {7, 11, -1}, {7, 13, -1}, {7, 15, -1}, {7, 17, -1}, {7, 19, 1},
      {7, 21, 0}, {7, 23, -1}, {7, 25, 1}, {7, 27, 1}, {7, 29, 1},
      {7, 31, 1}, {7, 33, -1}, {7, 35, 0}, {7, 37, 1}, {7, 39, -1},
      {7, 41, -1}, {7, 43, -1}, {7, 45, -1}, {7, 47, 1}, {7, 49, 0},
      {7, 51, -1}, {7, 53, 1}, {7, 55, 1}, {7, 57, 1}, {7, 59, 1},
      {8, 1, 1}, {8, 3, -1}, {8, 5, -1}, {8, 7, 1}, {8, 9, 1},
      {8, 11, -1}, {8, 13, -1}, {8, 15, 1}, {8, 17, 1}, {8, 19, -1},
      {8, 21, -1}, {8, 23, 1}, {8, 25, 1}, {8, 27, -1}, {8, 29, -1},
      {8, 31, 1}, {8, 33, 1}, {8, 35, -1}, {8, 37, -1}, {8, 39, 1},
      {8, 41, 1}, {8, 43, -1}, {8, 45, -1}, {8, 47, 1}, {8, 49, 1},
      {8, 51, -1}, {8, 53, -1}, {8, 55, 1}, {8, 57, 1}, {8, 59, -1},
      {9, 1, 1}, {9, 3, 0}, {9, 5, 1}, {9, 7, 1}, {9, 9, 0},
      {9, 11, 1}, {9, 13, 1}, {9, 15, 0}, {9, 17, 1}, {9, 19, 1},
      {9, 21, 0}, {9, 23, 1}, {9, 25, 1}, {9, 27, 0}, {9, 29, 1},
      {9, 31, 1}, {9, 33, 0}, {9, 35, 1}, {9, 37, 1}, {9, 39, 0},
      {9, 41, 1}, {9, 43, 1}, {9, 45, 0}, {9, 47, 1}, {9, 49, 1},
      {9, 51, 0}, {9, 53, 1}, {9, 55, 1}, {9, 57, 0}, {9, 59, 1},
      {10, 1, 1}, {10, 3, 1}, {10, 5, 0}, {10, 7, -1}, {10, 9, 1},
      {10, 11, -1}, {10, 13, 1}, {10, 15, 0}, {10, 17, -1}, {10, 19, -1},
      {10, 21, -1}, {10, 23, -1}, {10, 25, 0}, {10, 27, 1}, {10, 29, -1},
      {10, 31, 1}, {10, 33, -1}, {10, 35, 0}, {10, 37, 1}, {10, 39, 1},
      {10, 41, 1}, {10, 43, 1}, {10, 45, 0}, {10, 47, -1}, {10, 49, 1},
      {10, 51, -1}, {10, 53, 1}, {10, 55, 0}, {10, 57, -1}, {10, 59, -1},
      {11, 1, 1}, {11, 3, -1}, {11, 5, 1}, {11, 7, 1}, {11, 9, 1},
      {11, 11, 0}, {11, 13, -1}, {11, 15, -1}, {11, 17, -1}, {11, 19, 1},
      {11, 21, -1}, {11, 23, -1}, {11, 25, 1}, {11, 27, -1}, {11, 29, -1},
      {11, 31, -1}, {11, 33, 0}, {11, 35, 1}, {11, 37, 1}, {11, 39, 1},
      {11, 41, -1}, {11, 43, 1}, {11, 45, 1}, {11, 47, -1}, {11, 49, 1},
      {11, 51, 1}, {11, 53, 1}, {11, 55, 0}, {11, 57, -1}, {11, 59, -1},
      {12, 1, 1}, {12, 3, 0}, {12, 5, -1}, {12, 7, -1}, {12, 9, 0},
      {12, 11, 1}, {12, 13, 1}, {12, 15, 0}, {12, 17, -1}, {12, 19, -1},
      {12, 21, 0}, {12, 23, 1}, {12, 25, 1}, {12, 27, 0}, {12, 29, -1},
      {12, 31, -1}, {12, 33, 0}, {12, 35, 1}, {12, 37, 1}, {12, 39, 0},
      {12, 41, -1}, {12, 43, -1}, {12, 45, 0}, {12, 47, 1}, {12, 49, 1},
      {12, 51, 0}, {12, 53, -1}, {12, 55, -1}, {12, 57, 0}, {12, 59, 1},
      {13, 1, 1}, {13, 3, 1}, {13, 5, -1}, {13, 7, -1}, {13, 9, 1},
      {13, 11, -1}, {13, 13, 0}, {13, 15, -1}, {13, 17, 1}, {13, 19, -1},
      {13, 21, -1}, {13, 23, 1}, {13, 25, 1}, {13, 27, 1}, {13, 29, 1},
      {13, 31, -1}, {13, 33, -1}, {13, 35, 1}, {13, 37, -1}, {13, 39, 0},
      {13, 41, -1}, {13, 43, 1}, {13, 45, -1}, {13, 47, -1}, {13, 49, 1},
      {13, 51, 1}, {13, 53, 1}, {13, 55, 1}, {13, 57, -1}, {13, 59, -1},
      {14, 1, 1}, {14, 3, -1}, {14, 5, 1}, {14, 7, 0}, {14, 9, 1},
      {14, 11, 1}, {14, 13, 1}, {14, 15, -1}, {14, 17, -1}, {14, 19, -1},
      {14, 21, 0}, {14, 23, -1}, {14, 25, 1}, {14, 27, -1}, {14, 29, -1},
      {14, 31, 1}, {14, 33, -1}, {14, 35, 0}, {14, 37, -1}, {14, 39, -1},
      {14, 41, -1}, {14, 43, 1}, {14, 45, 1}, {14, 47, 1}, {14, 49, 0},
      {14, 51, 1}, {14, 53, -1}, {14, 55, 1}, {14, 57, 1}, {14, 59, -1},
      {15, 1, 1}, {15, 3, 0}, {15, 5, 0}, {15, 7, 1}, {15, 9, 0},
      {15, 11, 1}, {15, 13, -1}, {15, 15, 0}, {15, 17, 1}, {15, 19, -1},
      {15, 21, 0}, {15, 23, -1}, {15, 25, 0}, {15, 27, 0}, {15, 29, -1},
      {15, 31, -1}, {15, 33, 0}, {15, 35, 0}, {15, 37, -1}, {15, 39, 0},
      {15, 41, -1}, {15, 43, 1}, {15, 45, 0}, {15, 47, -1}, {15, 49, 1},
      {15, 51, 0}, {15, 53, 1}, {15, 55, 0}, {15, 57, 0}, {15, 59, 1},
      {16, 1, 1}, {16, 3, 1}, {16, 5, 1}, {16, 7, 1}, {16, 9, 1},
      {16, 11, 1}, {16, 13, 1}, {16, 15, 1}, {16, 17, 1}, {16, 19, 1},
      {16, 21, 1}, {16, 23, 1}, {16, 25, 1}, {16, 27, 1}, {16, 29, 1},
      {16, 31, 1}, {16, 33, 1}, {16, 35, 1}, {16, 37, 1}, {16, 39, 1},
      {16, 41, 1}, {16, 43, 1}, {16, 45, 1}, {16, 47, 1}, {16, 49, 1},
      {16, 51, 1}, {16, 53, 1}, {16, 55, 1}, {16, 57, 1}, {16, 59, 1},
      {17, 1, 1}, {17, 3, -1}, {17, 5, -1}, {17, 7, -1}, {17, 9, 1},
      {17, 11, -1}, {17, 13, 1}, {17, 15, 1}, {17, 17, 0}, {17, 19, 1},
      {17, 21, 1}, {17, 23, -1}, {17, 25, 1}, {17, 27, -1}, {17, 29, -1},
      {17, 31, -1}, {17, 33, 1}, {17, 35, 1}, {17, 37, -1}, {17, 39, -1},
      {17, 41, -1}, {17, 43, 1}, {17, 45, -1}, {17, 47, 1}, {17, 49, 1},
      {17, 51, 0}, {17, 53, 1}, {17, 55, 1}, {17, 57, -1}, {17, 59, 1},
      {18, 1, 1}, {18, 3, 0}, {18, 5, -1}, {18, 7, 1}, {18, 9, 0},
      {18, 11, -1}, {18, 13, -1}, {18, 15, 0}, {18, 17, 1}, {18, 19, -1},
      {18, 21, 0}, {18, 23, 1}, {18, 25, 1}, {18, 27, 0}, {18, 29, -1},
      {18, 31, 1}, {18, 33, 0}, {18, 35, -1}, {18, 37, -1}, {18, 39, 0},
      {18, 41, 1}, {18, 43, -1}, {18, 45, 0}, {18, 47, 1}, {18, 49, 1},
      {18, 51, 0}, {18, 53, -1}, {18, 55, 1}, {18, 57, 0}, {18, 59, -1},
      {19, 1, 1}, {19, 3, 1}, {19, 5, 1}, {19, 7, -1}, {19, 9, 1},
      {19, 11, -1}, {19, 13, -1}, {19, 15, 1}, {19, 17, 1}, {19, 19, 0},
      {19, 21, -1}, {19, 23, -1}, {19, 25, 1}, {19, 27, 1}, {19, 29, -1},
      {19, 31, 1}, {19, 33, -1}, {19, 35, -1}, {19, 37, -1}, {19, 39, -1},
      {19, 41, -1}, {19, 43, -1}, {19, 45, 1}, {19, 47, -1}, {19, 49, 1},
      {19, 51, 1}, {19, 53, -1}, {19, 55, -1}, {19, 57, 0}, {19, 59, 1},
      {20, 1, 1}, {20, 3, -1}, {20, 5, 0}, {20, 7, -1}, {20, 9, 1},
      {20, 11, 1}, {20, 13, -1}, {20, 15, 0}, {20, 17, -1}, {20, 19, 1},
      {20, 21, 1}, {20, 23, -1}, {20, 25, 0}, {20, 27, -1}, {20, 29, 1},
      {20, 31, 1}, {20, 33, -1}, {20, 35, 0}, {20, 37, -1}, {20, 39, 1},
      {20, 41, 1}, {20, 43, -1}, {20, 45, 0}, {20, 47, -1}, {20, 49, 1},
      {20, 51, 1}, {20, 53, -1}, {20, 55, 0}, {20, 57, -1}, {20, 59, 1},
      {21, 1, 1}, {21, 3, 0}, {21, 5, 1}, {21, 7, 0}, {21, 9, 0},
      {21, 11, -1}, {21, 13, -1}, {21, 15, 0}, {21, 17, 1}, {21, 19, -1},
      {21, 21, 0}, {21, 23, -1}, {21, 25, 1}, {21, 27, 0}, {21, 29, -1},
      {21, 31, -1}, {21, 33, 0}, {21, 35, 0}, {21, 37, 1}, {21, 39, 0},
      {21, 41, 1}, {21, 43, 1}, {21, 45, 0}, {21, 47, 1}, {21, 49, 0},
      {21, 51, 0}, {21, 53, -1}, {21, 55, -1}, {21, 57, 0}, {21, 59, 1},
      {22, 1, 1}, {22, 3, 1}, {22, 5, -1}, {22, 7, 1}, {22, 9, 1},
      {22, 11, 0}, {22, 13, 1}, {22, 15, -1}, {22, 17, -1}, {22, 19, -1},
      {22, 21, 1}, {22, 23, -1}, {22, 25, 1}, {22, 27, 1}, {22, 29, 1},
      {22, 31, -1}, {22, 33, 0}, {22, 35, -1}, {22, 37, -1}, {22, 39, 1},
      {22, 41, -1}, {22, 43, -1}, {22, 45, -1}, {22, 47, -1}, {22, 49, 1},
      {22, 51, -1}, {22, 53, -1}, {22, 55, 0}, {22, 57, -1}, {22, 59, 1},
      {23, 1, 1}, {23, 3, -1}, {23, 5, -1}, {23, 7, 1}, {23, 9, 1},
      {23, 11, 1}, {23, 13, 1}, {23, 15, 1}, {23, 17, -1}, {23, 19, 1},
      {23, 21, -1}, {23, 23, 0}, {23, 25, 1}, {23, 27, -1}, {23, 29, 1},
      {23, 31, -1}, {23, 33, -1}, {23, 35, -1}, {23, 37, -1}, {23, 39, -1},
      {23, 41, 1}, {23, 43, 1}, {23, 45, -1}, {23, 47, -1}, {23, 49, 1},
      {23, 51, 1}, {23, 53, -1}, {23, 55, -1}, {23, 57, -1}, {23, 59, -1},
      {24, 1, 1}, {24, 3, 0}, {24, 5, 1}, {24, 7, -1}, {24, 9, 0},
      {24, 11, -1}, {24, 13, -1}, {24, 15, 0}, {24, 17, -1}, {24, 19, 1},
      {24, 21, 0}, {24, 23, 1}, {24, 25, 1}, {24, 27, 0}, {24, 29, 1},
      {24, 31, -1}, {24, 33, 0}, {24, 35, -1}, {24, 37, -1}, {24, 39, 0},
      {24, 41, -1}, {24, 43, 1}, {24, 45, 0}, {24, 47, 1}, {24, 49, 1},
      {24, 51, 0}, {24, 53, 1}, {24, 55, -1}, {24, 57, 0}, {24, 59, -1},
      {25, 1, 1}, {25, 3, 1}, {25, 5, 0}, {25, 7, 1}, {25, 9, 1},
      {25, 11, 1}, {25, 13, 1}, {25, 15, 0}, {25, 17, 1}, {25, 19, 1},
      {25, 21, 1}, {25, 23, 1}, {25, 25, 0}, {25, 27, 1}, {25, 29, 1},
      {25, 31, 1}, {25, 33, 1}, {25, 35, 0}, {25, 37, 1}, {25, 39, 1},
      {25, 41, 1}, {25, 43, 1}, {25, 45, 0}, {25, 47, 1}, {25, 49, 1},
      {25, 51, 1}, {25, 53, 1}, {25, 55, 0}, {25, 57, 1}, {25, 59, 1},
      {26, 1, 1}, {26, 3, -1}, {26, 5, 1}, {26, 7, -1}, {26, 9, 1},
      {26, 11, 1}, {26, 13, 0}, {26, 15, -1}, {26, 17, 1}, {26, 19, 1},
      {26, 21, 1}, {26, 23, 1}, {26, 25, 1}, {26, 27, -1}, {26, 29, -1},
      {26, 31, -1}, {26, 33, -1}, {26, 35, -1}, {26, 37, 1}, {26, 39, 0},
      {26, 41, -1}, {26, 43, -1}, {26, 45, 1}, {26, 47, -1}, {26, 49, 1},
      {26, 51, -1}, {26, 53, -1}, {26, 55, 1}, {26, 57, -1}, {26, 59, 1},
      {27, 1, 1}, {27, 3, 0}, {27, 5, -1}, {27, 7, -1}, {27, 9, 0},
      {27, 11, 1}, {27, 13, 1}, {27, 15, 0}, {27, 17, -1}, {27, 19, -1},
      {27, 21, 0}, {27, 23, 1}, {27, 25, 1}, {27, 27, 0}, {27, 29, -1},
      {27, 31, -1}, {27, 33, 0}, {27, 35, 1}, {27, 37, 1}, {27, 39, 0},
      {27, 41, -1}, {27, 43, -1}, {27, 45, 0}, {27, 47, 1}, {27, 49, 1},
      {27, 51, 0}, {27, 53, -1}, {27, 55, -1}, {27, 57, 0}, {27, 59, 1},
      {28, 1, 1}, {28, 3, 1}, {28, 5, -1}, {28, 7, 0}, {28, 9, 1},
      {28, 11, -1}, {28, 13, -1}, {28, 15, -1}, {28, 17, -1}, {28, 19, 1},
      {28, 21, 0}, {28, 23, -1}, {28, 25, 1}, {28, 27, 1}, {28, 29, 1},
      {28, 31, 1}, {28, 33, -1}, {28, 35, 0}, {28, 37, 1}, {28, 39, -1},
      {28, 41, -1}, {28, 43, -1}, {28, 45, -1}, {28, 47, 1}, {28, 49, 0},
      {28, 51, -1}, {28, 53, 1}, {28, 55, 1}, {28, 57, 1}, {28, 59, 1},
      {29, 1, 1}, {29, 3, -1}, {29, 5, 1}, {29, 7, 1}, {29, 9, 1},
      {29, 11, -1}, {29, 13, 1}, {29, 15, -1}, {29, 17, -1}, {29, 19, -1},
      {29, 21, -1}, {29, 23, 1}, {29, 25, 1}, {29, 27, -1}, {29, 29, 0},
      {29, 31, -1}, {29, 33, 1}, {29, 35, 1}, {29, 37, -1}, {29, 39, -1},
      {29, 41, -1}, {29, 43, -1}, {29, 45, 1}, {29, 47, -1}, {29, 49, 1},
      {29, 51, 1}, {29, 53, 1}, {29, 55, -1}, {29, 57, 1}, {29, 59, 1},
      {30, 1, 1}, {30, 3, 0}, {30, 5, 0}, {30, 7, 1}, {30, 9, 0},
      {30, 11, -1}, {30, 13, 1}, {30, 15, 0}, {30, 17, 1}, {30, 19, 1},
      {30, 21, 0}, {30, 23, -1}, {30, 25, 0}, {30, 27, 0}, {30, 29, 1},
      {30, 31, -1}, {30, 33, 0}, {30, 35, 0}, {30, 37, 1}, {30, 39, 0},
      {30, 41, -1}, {30, 43, -1}, {30, 45, 0}, {30, 47, -1}, {30, 49, 1},
      {30, 51, 0}, {30, 53, -1}, {30, 55, 0}, {30, 57, 0}, {30, 59, -1},
      {1001, 9907, -1}
    };

    size_t i;

    printf("Testing jacobi...\n");

    assert(GOO_ARRAY_SIZE(symbols) > 0);

    for (i = 0; i < GOO_ARRAY_SIZE(symbols); i++) {
      const int *v = symbols[i];
      mpz_t x, y;

      mpz_init(x);
      mpz_init(y);

      mpz_set_si(x, v[0]);
      mpz_set_si(y, v[1]);

      assert(mpz_jacobi(x, y) == v[2]);
      assert(goo_mpz_jacobi(x, y) == v[2]);

      mpz_clear(x);
      mpz_clear(y);
    }
  }

  rng_clear(&rng);
}

static void
run_primes_test(void) {
  /* https://github.com/golang/go/blob/aadaec5/src/math/big/prime_test.go */
  static const char *primes[] = {
    "2",
    "3",
    "5",
    "7",
    "11",

    "13756265695458089029",
    "13496181268022124907",
    "10953742525620032441",
    "17908251027575790097",

    /* https://golang.org/issue/638 */
    "18699199384836356663",

    "98920366548084643601728869055592650835572950"
    "932266967461790948584315647051443",

    "94560208308847015747498523884063394671606671"
    "904944666360068158221458669711639",

    /* https://primes.utm.edu/lists/small/small3.html */
    "44941799905544149399470929709310851301537378"
    "70495584992054923478717299275731182628115083"
    "86655998299074566974373711472560655026288668"
    "09429169935784346436300314467494034591243112"
    "9144354948751003607115263071543163",

    "23097585999320415066642353898855783955556024"
    "39290654154349809042583105307530067238571397"
    "42334640122533598517597674807096648905501653"
    "46168760133978281431612497154796891289321400"
    "2992086353183070342498989426570593",

    "55217120996659062215404232070193333791252654"
    "62121169655563495403888449493493629943498064"
    "60453696177511076537774555037706789360724602"
    "06949729597808391514524577288553821135558677"
    "43022746090187341871655890805971735385789993",

    "20395687835640197740576586692903457728019399"
    "33143482630947726464532830627227012776329366"
    "16063144088173312372882677123879538709400158"
    "30656733832827915449969836607190676644003707"
    "42171178056908727928481491120222863321448761"
    "83376326512083574821647933992961249917319836"
    "219304274280243803104015000563790123",

    /* ECC primes: https://tools.ietf.org/html/draft-ladd-safecurves-02 */
    /* Curve1174: 2^251-9 */

    "36185027886661311069865932815214971204146870"
    "20801267626233049500247285301239",

    /* Curve25519: 2^255-19 */

    "57896044618658097711785492504343953926634992"
    "332820282019728792003956564819949",

    /* E-382: 2^382-105 */

    "98505015490986198030697600250359034512699348"
    "17616361666987073351061430442874302652853566"
    "563721228910201656997576599",

    /* Curve41417: 2^414-17 */

    "42307582002575910332922579714097346549017899"
    "70971399803421752289756197063912392613281210"
    "9468141778230245837569601494931472367",

    /* E-521: 2^521-1 */

    "68647976601306097149819007990813932172694353"
    "00143305409394463459185543183397656052122559"
    "64066145455497729631139148085803712198799971"
    "6643812574028291115057151",

    /* P-112 */

    "4451685225093714772084598273548427",

    /* P-192 */

    "62771017353866807638357894232076664160839087"
    "00390324961279",

    /* P-224 */

    "26959946667150639794667015087019630673557916"
    "260026308143510066298881",

    /* P-256 */

    "11579208921035624876269744694940757353008614"
    "3415290314195533631308867097853951",

    /* P-384 */

    "39402006196394479212279040100143613805079739"
    "27046544666794829340424572177149687032904726"
    "6088258938001861606973112319",

    /* P-521 (again) */

    "68647976601306097149819007990813932172694353"
    "00143305409394463459185543183397656052122559"
    "64066145455497729631139148085803712198799971"
    "6643812574028291115057151",

    /* K-256 */

    "11579208923731619542357098500868790785326998"
    "4665640564039457584007908834671663",

    /* K-256 Order */

    "11579208923731619542357098500868790785283756"
    "4279074904382605163141518161494337",

    /* P-25519 (again) */

    "57896044618658097711785492504343953926634992"
    "332820282019728792003956564819949",

    /* P-448 */

    "72683872429560689054932380788800453435364136"
    "06873180602814901991806123281667307726863963"
    "83698676545930088884461843637361053498018365"
    "439"
  };

  static const char *composites[] = {
    "0",
    "1",
    "2128417509121468791277119989830729774821167291"
    "4763848041968395774954376176754",
    "6084766654921918907427900243509372380954290099"
    "172559290432744450051395395951",
    "8459435049322191838921335299203232428036771124"
    "7940675652888030554255915464401",
    "82793403787388584738507275144194252681",

    /* Arnault, "Rabin-Miller Primality Test: Composite Numbers Which Pass It", */
    /* Mathematics of Computation, 64(209) (January 1995), pp. 335-361. */

    /* Strong pseudoprime to prime bases 2 through 29. */
    "1195068768795265792518361315725116351898245581",

    /* Strong pseudoprime to all prime bases up to 200. */
    "8038374574536394912570796143419421081388376882"
    "8755814583748891752229742737653336521865023361"
    "6396004545791504202360320876656996676098728404"
    "3965408232928738791850869166857328267761771029"
    "3896977394701670823042868710999743997654414484"
    "5341155872450633409279022275296229414984230688"
    "1685404326457534018329786111298960644845216191"
    "652872597534901",

    /* Extra-strong Lucas pseudoprimes. */
    /* https://oeis.org/A217719 */
    "989",
    "3239",
    "5777",
    "10877",
    "27971",
    "29681",
    "30739",
    "31631",
    "39059",
    "72389",
    "73919",
    "75077",
    "100127",
    "113573",
    "125249",
    "137549",
    "137801",
    "153931",
    "155819",
    "161027",
    "162133",
    "189419",
    "218321",
    "231703",
    "249331",
    "370229",
    "429479",
    "430127",
    "459191",
    "473891",
    "480689",
    "600059",
    "621781",
    "632249",
    "635627",

    "3673744903",
    "3281593591",
    "2385076987",
    "2738053141",
    "2009621503",
    "1502682721",
    "255866131",
    "117987841",
    "587861",

    "6368689",
    "8725753",
    "80579735209",
    "105919633"
  };

  static const unsigned long mr_pseudos[] = {
    /* https://oeis.org/A001262 */
    2047,
    3277,
    4033,
    4681,
    8321,
    15841,
    29341,
    42799,
    49141,
    52633,
    65281,
    74665,
    80581,
    85489,
    88357,
    90751
  };

  static const unsigned long lucas_pseudos[] = {
    /* https://oeis.org/A217719 */
    989,
    3239,
    5777,
    10877,
    27971,
    29681,
    30739,
    31631,
    39059,
    72389,
    73919,
    75077
  };

  goo_prng_t rng;

  unsigned char key[32];
  unsigned char zero[32];
  unsigned long i;

  rng_init(&rng);

  goo_prng_generate(&rng, key, 32);

  memset(&zero[0], 0x00, 32);

  printf("Testing primes...\n");

  assert(GOO_ARRAY_SIZE(primes) > 0);

  for (i = 0; i < GOO_ARRAY_SIZE(primes); i++) {
    mpz_t p;
    mpz_init(p);

    assert(mpz_set_str(p, primes[i], 10) == 0);
    assert(goo_is_prime_div(p));
    assert(goo_is_prime_mr(p, key, 16 + 1, 1));
    assert(goo_is_prime_mr(p, key, 1, 1));
    assert(goo_is_prime_mr(p, key, 1, 0));
    assert(goo_is_prime_mr(p, key, 0, 1));
    assert(goo_is_prime_lucas(p));
    assert(goo_is_prime(p, key));

    mpz_clear(p);
  }

  printf("Testing composites...\n");

  assert(GOO_ARRAY_SIZE(composites) > 0);

  for (i = 0; i < GOO_ARRAY_SIZE(composites); i++) {
    mpz_t p;
    mpz_init(p);

    assert(mpz_set_str(p, composites[i], 10) == 0);

    if (i == 6 || i == 7 || (i >= 43 && i <= 49) || i == 54) {
      assert(goo_is_prime_div(p));
    } else {
      /* We actually catch a surpising */
      /* number of composites here. */
      assert(!goo_is_prime_div(p));
    }

    /* MR with a deterministic key. */
    assert(!goo_is_prime_mr(p, zero, 16 + 1, 1));
    assert(!goo_is_prime_mr(p, zero, 4, 1));
    assert(!goo_is_prime_mr(p, zero, 4, 0));

    if (i >= 8 && i <= 42) {
      /* Lucas pseudoprime. */
      assert(goo_is_prime_lucas(p));
    } else {
      assert(!goo_is_prime_lucas(p));
    }

    /* No composite should ever pass */
    /* Baillie-PSW, random or otherwise. */
    assert(!goo_is_prime(p, zero));
    assert(!goo_is_prime(p, key));

    mpz_clear(p);
  }

  printf("Testing miller-rabin pseudo-primes...\n");

  {
    const unsigned long *want = &mr_pseudos[0];
    size_t len = GOO_ARRAY_SIZE(mr_pseudos);
    mpz_t n;

    mpz_init(n);

    assert(len > 0);

    for (i = 3; i < 100000; i += 2) {
      int pseudo;

      mpz_set_ui(n, i);

      pseudo = goo_is_prime_mr(n, zero, 1, 1)
            && !goo_is_prime_lucas(n);

      if (pseudo && (len == 0 || i != want[0]))
        assert(0 && "miller-rabin: want false");
      else if (!pseudo && len >= 1 && i == want[0])
        assert(0 && "miller-rabin: want true");

      if (len > 0 && i == want[0]) {
        want++;
        len--;
      }
    }

    assert(len == 0);

    mpz_clear(n);
  }

  printf("Testing lucas pseudo-primes...\n");

  {
    const unsigned long *want = &lucas_pseudos[0];
    size_t len = GOO_ARRAY_SIZE(lucas_pseudos);
    mpz_t n;

    mpz_init(n);

    assert(len > 0);

    for (i = 3; i < 100000; i += 2) {
      int pseudo;

      mpz_set_ui(n, i);

      pseudo = goo_is_prime_lucas(n)
           && !goo_is_prime_mr(n, zero, 1, 1);

      if (pseudo && (len == 0 || i != want[0]))
        assert(0 && "lucas: want false");
      else if (!pseudo && len >= 1 && i == want[0])
        assert(0 && "lucas: want true");

      if (len > 0 && i == want[0]) {
        want++;
        len--;
      }
    }

    assert(len == 0);

    mpz_clear(n);
  }

#undef GOO_ARRAY_SIZE

  /* test next_prime */
  {
    mpz_t n;

    printf("Testing next_prime...\n");

    mpz_init(n);
    mpz_set_ui(n, 4);

    assert(goo_next_prime(n, n, zero, 512));

    assert(mpz_get_ui(n) == 5);

    mpz_clear(n);
  }

  rng_clear(&rng);
}

static void
run_ops_test(void) {
  static const char mod_hex[] = ""
    "c7970ceedcc3b0754490201a7aa613cd73911081c790f5f1a8726f463550"
    "bb5b7ff0db8e1ea1189ec72f93d1650011bd721aeeacc2acde32a04107f0"
    "648c2813a31f5b0b7765ff8b44b4b6ffc93384b646eb09c7cf5e8592d40e"
    "a33c80039f35b4f14a04b51f7bfd781be4d1673164ba8eb991c2c4d730bb"
    "be35f592bdef524af7e8daefd26c66fc02c479af89d64d373f442709439d"
    "e66ceb955f3ea37d5159f6135809f85334b5cb1813addc80cd05609f10ac"
    "6a95ad65872c909525bdad32bc729592642920f24c61dc5b3c3b7923e56b"
    "16a4d9d373d8721f24a3fc0f1b3131f55615172866bccc30f95054c824e7"
    "33a5eb6817f7bc16399d48c6361cc7e5";

  goo_prng_t rng;
  mpz_t n;
  goo_group_t *goo;

  printf("Testing group ops...\n");

  rng_init(&rng);

  mpz_init(n);
  goo = goo_malloc(sizeof(goo_group_t));

  assert(mpz_set_str(n, mod_hex, 16) == 0);
  assert(goo_group_init(goo, n, 2, 3, 2048));

  {
    printf("Testing comb calculation...\n");

    assert(goo->combs[0].g.points_per_add == 8);
    assert(goo->combs[0].g.adds_per_shift == 2);
    assert(goo->combs[0].g.shifts == 128);
    assert(goo->combs[0].g.bits_per_window == 256);
    assert(goo->combs[0].g.bits == 2048);
    assert(goo->combs[0].g.points_per_subcomb == 255);
    assert(goo->combs[0].g.size == 510);

    assert(goo->combs[0].h.points_per_add == 8);
    assert(goo->combs[0].h.adds_per_shift == 2);
    assert(goo->combs[0].h.shifts == 128);
    assert(goo->combs[0].h.bits_per_window == 256);
    assert(goo->combs[0].h.bits == 2048);
    assert(goo->combs[0].h.points_per_subcomb == 255);
    assert(goo->combs[0].h.size == 510);

    assert(goo->combs[1].g.points_per_add == 8);
    assert(goo->combs[1].g.adds_per_shift == 2);
    assert(goo->combs[1].g.shifts == 265);
    assert(goo->combs[1].g.bits_per_window == 530);
    assert(goo->combs[1].g.bits == 4240);
    assert(goo->combs[1].g.points_per_subcomb == 255);
    assert(goo->combs[1].g.size == 510);

    assert(goo->combs[1].h.points_per_add == 8);
    assert(goo->combs[1].h.adds_per_shift == 2);
    assert(goo->combs[1].h.shifts == 265);
    assert(goo->combs[1].h.bits_per_window == 530);
    assert(goo->combs[1].h.bits == 4240);
    assert(goo->combs[1].h.points_per_subcomb == 255);
    assert(goo->combs[1].h.size == 510);
  }

  /* test pow */
  {
    mpz_t b, bi, e;
    mpz_t r1, r2;

    printf("Testing pow...\n");

    mpz_init(b);
    mpz_init(bi);
    mpz_init(e);
    mpz_init(r1);
    mpz_init(r2);

    goo_prng_random_bits(&rng, b, 2048);
    goo_prng_random_bits(&rng, e, 4096);

    assert(goo_group_inv(goo, bi, b));
    assert(goo_group_pow_slow(goo, r1, b, e));
    assert(goo_group_pow(goo, r2, b, bi, e));

    assert(mpz_cmp(r1, r2) == 0);

    mpz_clear(b);
    mpz_clear(bi);
    mpz_clear(e);
    mpz_clear(r1);
    mpz_clear(r2);
  }

  /* test pow2 */
  {
    mpz_t b1, b2, e1, e2;
    mpz_t b1i, b2i;
    mpz_t r1, r2;

    printf("Testing pow2...\n");

    mpz_init(b1);
    mpz_init(b2);
    mpz_init(e1);
    mpz_init(e2);

    mpz_init(b1i);
    mpz_init(b2i);

    mpz_init(r1);
    mpz_init(r2);

    goo_prng_random_bits(&rng, b1, 2048);
    goo_prng_random_bits(&rng, b2, 2048);
    goo_prng_random_bits(&rng, e1, 128);
    goo_prng_random_bits(&rng, e2, 128);

    assert(goo_group_inv2(goo, b1i, b2i, b1, b2));
    assert(goo_group_pow2_slow(goo, r1, b1, e1, b2, e2));
    assert(goo_group_pow2(goo, r2, b1, b1i, e1, b2, b2i, e2));

    assert(mpz_cmp(r1, r2) == 0);

    mpz_clear(b1);
    mpz_clear(b2);
    mpz_clear(e1);
    mpz_clear(e2);
    mpz_clear(b1i);
    mpz_clear(b2i);
    mpz_clear(r1);
    mpz_clear(r2);
  }

  /* test powgh */
  {
    mpz_t e1, e2;
    mpz_t r1, r2;

    printf("Testing powgh...\n");

    mpz_init(e1);
    mpz_init(e2);

    mpz_init(r1);
    mpz_init(r2);

    goo_prng_random_bits(&rng, e1, 2048 + GOO_ELL_BITS + 2 - 1);
    goo_prng_random_bits(&rng, e2, 2048 + GOO_ELL_BITS + 2 - 1);

    assert(goo_group_powgh_slow(goo, r1, e1, e2));
    assert(goo_group_powgh(goo, r2, e1, e2));

    assert(mpz_cmp(r1, r2) == 0);

    mpz_clear(e1);
    mpz_clear(e2);
    mpz_clear(r1);
    mpz_clear(r2);
  }

  /* test inv2 */
  {
    mpz_t e1, e2;
    mpz_t e1_s, e2_s;
    mpz_t e1_si, e2_si;
    mpz_t r1, r2;

    printf("Testing inv2...\n");

    mpz_init(e1);
    mpz_init(e2);
    mpz_init(e1_s);
    mpz_init(e2_s);
    mpz_init(e1_si);
    mpz_init(e2_si);

    mpz_init(r1);
    mpz_init(r2);

    goo_prng_random_bits(&rng, e1, 2048);
    goo_prng_random_bits(&rng, e2, 2048);

    mpz_fdiv_q_2exp(e1_s, e1, 1536);
    mpz_fdiv_q_2exp(e2_s, e2, 1536);

    assert(goo_group_inv2(goo, e1_si, e2_si, e1_s, e2_s));

    mpz_mul(r1, e1_s, e1_si);
    mpz_mod(r1, r1, goo->n);

    mpz_mul(r2, e2_s, e2_si);
    mpz_mod(r2, r1, goo->n);

    goo_group_reduce(goo, r1, r1);
    goo_group_reduce(goo, r2, r2);

    assert(mpz_cmp_ui(r1, 1) == 0);
    assert(mpz_cmp_ui(r2, 1) == 0);

    mpz_clear(e1);
    mpz_clear(e2);
    mpz_clear(e1_s);
    mpz_clear(e2_s);
    mpz_clear(e1_si);
    mpz_clear(e2_si);
    mpz_clear(r1);
    mpz_clear(r2);
  }

  /* test inv7 */
  {
    mpz_t evals[7];
    mpz_t einvs[7];
    int i;

    printf("Testing inv7...\n");

    for (i = 0; i < 7; i++) {
      mpz_init(evals[i]);
      mpz_init(einvs[i]);

      goo_prng_random_bits(&rng, evals[i], 2048);
    }

    assert(goo_group_inv7(goo,
      einvs[0], einvs[1], einvs[2], einvs[3], einvs[4], einvs[5], einvs[6],
      evals[0], evals[1], evals[2], evals[3], evals[4], evals[5], evals[6]));

    for (i = 0; i < 7; i++) {
      mpz_mul(evals[i], evals[i], einvs[i]);
      mpz_mod(evals[i], evals[i], goo->n);

      goo_group_reduce(goo, evals[i], evals[i]);

      assert(mpz_cmp_ui(evals[i], 1) == 0);

      mpz_clear(evals[i]);
      mpz_clear(einvs[i]);
    }
  }

  rng_clear(&rng);
  mpz_clear(n);
  goo_group_uninit(goo);
  goo_free(goo);
}

static void
run_combspec_test(void) {
  goo_combspec_t spec;
  long bits, points_per_subcomb;
  mpz_t n;
  goo_group_t *goo;

  static const char mod_hex[] = ""
    "c7970ceedcc3b0754490201a7aa613cd73911081c790f5f1a8726f463550"
    "bb5b7ff0db8e1ea1189ec72f93d1650011bd721aeeacc2acde32a04107f0"
    "648c2813a31f5b0b7765ff8b44b4b6ffc93384b646eb09c7cf5e8592d40e"
    "a33c80039f35b4f14a04b51f7bfd781be4d1673164ba8eb991c2c4d730bb"
    "be35f592bdef524af7e8daefd26c66fc02c479af89d64d373f442709439d"
    "e66ceb955f3ea37d5159f6135809f85334b5cb1813addc80cd05609f10ac"
    "6a95ad65872c909525bdad32bc729592642920f24c61dc5b3c3b7923e56b"
    "16a4d9d373d8721f24a3fc0f1b3131f55615172866bccc30f95054c824e7"
    "33a5eb6817f7bc16399d48c6361cc7e5";

  printf("Testing combspec...\n");

  assert(goo_combspec_init(&spec, GOO_CHAL_BITS, GOO_MAX_COMB_SIZE));

  bits = spec.bits_per_window * spec.points_per_add;
  points_per_subcomb = (1 << spec.points_per_add) - 1;

  assert(spec.points_per_add == 8);
  assert(spec.adds_per_shift == 2);
  assert(spec.shifts == 8);
  assert(spec.bits_per_window == 16);
  assert(bits == 128);
  assert(points_per_subcomb == 255);
  assert(spec.size == 510);

  mpz_init(n);
  goo = goo_malloc(sizeof(goo_group_t));

  assert(mpz_set_str(n, mod_hex, 16) == 0);
  assert(goo_group_init(goo, n, 2, 3, 0));

  assert(goo->combs[0].g.points_per_add == 7);
  assert(goo->combs[0].g.adds_per_shift == 4);
  assert(goo->combs[0].g.shifts == 5);
  assert(goo->combs[0].g.bits_per_window == 20);
  assert(goo->combs[0].g.bits == 140);
  assert(goo->combs[0].g.points_per_subcomb == 127);
  assert(goo->combs[0].g.size == 508);

  assert(goo->combs[0].h.points_per_add == 7);
  assert(goo->combs[0].h.adds_per_shift == 4);
  assert(goo->combs[0].h.shifts == 5);
  assert(goo->combs[0].h.bits_per_window == 20);
  assert(goo->combs[0].h.bits == 140);
  assert(goo->combs[0].h.points_per_subcomb == 127);
  assert(goo->combs[0].h.size == 508);

  mpz_clear(n);
  goo_group_uninit(goo);
  goo_free(goo);
}

static void
run_sig_test(void) {
  goo_sig_t sig1;
  goo_sig_t sig2;
  unsigned char *data = NULL;
  size_t size;

  printf("Testing signatures...\n");

  goo_sig_init(&sig1);
  goo_sig_init(&sig2);

  mpz_set_ui(sig1.C2, 0x01);
  mpz_set_ui(sig1.t, 0x02);
  mpz_set_ui(sig1.chal, 0x03);
  mpz_set_ui(sig1.ell, 0x04);
  mpz_set_ui(sig1.Aq, 0x05);
  mpz_set_ui(sig1.Bq, 0x06);
  mpz_set_ui(sig1.Cq, 0x07);
  mpz_set_ui(sig1.Dq, 0x08);
  mpz_set_ui(sig1.Eq, 0x100);
  mpz_set_ui(sig1.z_w, 0x09);
  mpz_set_ui(sig1.z_w2, 0x0a);
  mpz_set_ui(sig1.z_s1, 0x0b);
  mpz_set_ui(sig1.z_a, 0x0c);
  mpz_set_ui(sig1.z_an, 0x0d);
  mpz_set_ui(sig1.z_s1w, 0x0e);
  mpz_set_ui(sig1.z_sa, 0x0f);

  size = goo_sig_size(&sig1, 2048);
  data = goo_malloc(size);

  assert(goo_sig_export(data, &sig1, 2048));
  assert(goo_sig_import(&sig2, data, size, 2048));

  assert(mpz_cmp_ui(sig2.C2, 0x01) == 0);
  assert(mpz_cmp_ui(sig2.t, 0x02) == 0);
  assert(mpz_cmp_ui(sig2.chal, 0x03) == 0);
  assert(mpz_cmp_ui(sig2.ell, 0x04) == 0);
  assert(mpz_cmp_ui(sig2.Aq, 0x05) == 0);
  assert(mpz_cmp_ui(sig2.Bq, 0x06) == 0);
  assert(mpz_cmp_ui(sig2.Cq, 0x07) == 0);
  assert(mpz_cmp_ui(sig2.Dq, 0x08) == 0);
  assert(mpz_sgn(sig2.Eq) > 0);
  assert(mpz_cmp_ui(sig2.Eq, 0x100) == 0);
  assert(mpz_cmp_ui(sig2.z_w, 0x09) == 0);
  assert(mpz_cmp_ui(sig2.z_w2, 0x0a) == 0);
  assert(mpz_cmp_ui(sig2.z_s1, 0x0b) == 0);
  assert(mpz_cmp_ui(sig2.z_a, 0x0c) == 0);
  assert(mpz_cmp_ui(sig2.z_an, 0x0d) == 0);
  assert(mpz_cmp_ui(sig2.z_s1w, 0x0e) == 0);
  assert(mpz_cmp_ui(sig2.z_sa, 0x0f) == 0);

  mpz_set_si(sig1.Eq, -0x100);

  assert(goo_sig_export(data, &sig1, 2048));
  assert(goo_sig_import(&sig2, data, size, 2048));

  assert(mpz_cmp_ui(sig2.C2, 0x01) == 0);
  assert(mpz_cmp_ui(sig2.t, 0x02) == 0);
  assert(mpz_cmp_ui(sig2.chal, 0x03) == 0);
  assert(mpz_cmp_ui(sig2.ell, 0x04) == 0);
  assert(mpz_cmp_ui(sig2.Aq, 0x05) == 0);
  assert(mpz_cmp_ui(sig2.Bq, 0x06) == 0);
  assert(mpz_cmp_ui(sig2.Cq, 0x07) == 0);
  assert(mpz_cmp_ui(sig2.Dq, 0x08) == 0);
  assert(mpz_sgn(sig2.Eq) < 0);
  assert(mpz_cmp_si(sig2.Eq, -0x100) == 0);
  assert(mpz_cmp_ui(sig2.z_w, 0x09) == 0);
  assert(mpz_cmp_ui(sig2.z_w2, 0x0a) == 0);
  assert(mpz_cmp_ui(sig2.z_s1, 0x0b) == 0);
  assert(mpz_cmp_ui(sig2.z_a, 0x0c) == 0);
  assert(mpz_cmp_ui(sig2.z_an, 0x0d) == 0);
  assert(mpz_cmp_ui(sig2.z_s1w, 0x0e) == 0);
  assert(mpz_cmp_ui(sig2.z_sa, 0x0f) == 0);

  goo_sig_uninit(&sig1);
  goo_sig_uninit(&sig2);
  goo_free(data);
}

static void
run_goo_test(void) {
  static const char p_hex[] = ""
    "ccbf79ad1f5e47086062274ea9815042fd938149a5557c8cb3b0c33d"
    "dcd87c58a53760826a99d196852460762e16a715e40bee5847324aa1"
    "9911e98bf58e8c9af65e06182bb307c706069df394e5d098fbe85701"
    "eb2e88089913834aadba3b134f646f6d48f2dacba00a5bfd15e8b8d9"
    "c0efe1f4209595b920691aeebfc4ba1b28592d88fc0f565b0d3dbcf2"
    "e3dda7b02e5452660c4bd4485e23cb68e1fdc9f3647f85c5ee0c3555"
    "c21ce8307320257fae148887af5412db2cece240044cd668c72c7219"
    "b2e6a32f5da0e0cd52ec9078e7ef521461f2fe5d83b240c412507961"
    "0512976d1c3b65fcb0ad75133012e2c7329ce55177556f07bdabb271"
    "622466fb";

  static const char q_hex[] = ""
    "842d18ae53b1e47aac1d2c7ff91ee656f669ce9676edc2689f39b2cd"
    "3052c9157e65b16241bb9d6eb0d15adfb4baa97a7f6f4b9d0621ef84"
    "d1ba262f5b3b98ec7b47a5492631e282ade5108d02fc14c965d9dbfd"
    "4683f740abc8f9120d0c7e2f79b0c94f68f0c91acdbd977a66f9a9e1"
    "59e680ec12ba632ed36f54f438e0eaefc24b6e25c6fd32da9a9c9271"
    "0cede05462335178baa574e2519aa0bd55a69e5ca130405174271afe"
    "9b92ad5e82c5ceae9f9124f1b361e22503ad1ca0bad526a2eef833ad"
    "84efc4203137b10704bab5ce6bb2eb58a2209ef738c44b7127655ed9"
    "37c5a937ae6ac9beaace7ece9fb33ae60e980da73730a6144e38ca9a"
    "537fe02d";

  static const char mod_hex[] = ""
    "c7970ceedcc3b0754490201a7aa613cd73911081c790f5f1a8726f463550"
    "bb5b7ff0db8e1ea1189ec72f93d1650011bd721aeeacc2acde32a04107f0"
    "648c2813a31f5b0b7765ff8b44b4b6ffc93384b646eb09c7cf5e8592d40e"
    "a33c80039f35b4f14a04b51f7bfd781be4d1673164ba8eb991c2c4d730bb"
    "be35f592bdef524af7e8daefd26c66fc02c479af89d64d373f442709439d"
    "e66ceb955f3ea37d5159f6135809f85334b5cb1813addc80cd05609f10ac"
    "6a95ad65872c909525bdad32bc729592642920f24c61dc5b3c3b7923e56b"
    "16a4d9d373d8721f24a3fc0f1b3131f55615172866bccc30f95054c824e7"
    "33a5eb6817f7bc16399d48c6361cc7e5";

  goo_prng_t rng;
  mpz_t p, q, n;
  mpz_t mod_n;
  goo_group_t *goo;
  mpz_t C1;
  unsigned char s_prime[32];
  unsigned char msg[32];
  goo_sig_t sig;
  unsigned char seed[64];

  printf("Testing signing/verifying...\n");

  rng_init(&rng);
  mpz_init(p);
  mpz_init(q);
  mpz_init(n);
  mpz_init(mod_n);

  goo = goo_malloc(sizeof(goo_group_t));

  mpz_init(C1);
  goo_sig_init(&sig);

  assert(mpz_set_str(p, p_hex, 16) == 0);
  assert(mpz_set_str(q, q_hex, 16) == 0);

  mpz_mul(n, p, q);

  assert(mpz_set_str(mod_n, mod_hex, 16) == 0);

  assert(goo_group_init(goo, mod_n, 2, 3, 4096));

  goo_prng_generate(&rng, s_prime, 32);

  assert(goo_group_challenge(goo, C1, s_prime, n));

  memset(&msg[0], 0xaa, sizeof(msg));

  goo_prng_generate(&rng, seed, 64);

  assert(goo_group_validate(goo, s_prime, C1, p, q));
  assert(goo_group_sign(goo, &sig, msg, sizeof(msg), s_prime, p, q, seed));
  assert(goo_group_verify(goo, msg, sizeof(msg), &sig, C1));

  rng_clear(&rng);
  mpz_clear(p);
  mpz_clear(q);
  mpz_clear(n);
  mpz_clear(mod_n);
  mpz_clear(C1);
  goo_sig_uninit(&sig);
  goo_group_uninit(goo);
  goo_free(goo);
}

void
goo_test(void) {
  run_hmac_test();
  run_drbg_test();
  run_prng_test();
  run_util_test();
  run_primes_test();
  run_ops_test();
  run_combspec_test();
  run_sig_test();
  run_goo_test();
  printf("All tests passed!\n");
}
#endif
