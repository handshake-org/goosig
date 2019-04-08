/*!
 * goo.c - groups of unknown order for C
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
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

#include "goo.h"
#include "random.h"
#include "primes.h"

static const char goo_prefix[] = GOO_HASH_PREFIX;
static const char goo_pers[] = GOO_DRBG_PERS;

/*
 * GMP helpers
 */

#define goo_mpz_import(ret, data, len) \
  mpz_import((ret), (len), 1, sizeof((data)[0]), 0, 0, (data))

#define goo_mpz_export(data, size, n) \
  mpz_export((data), (size), 1, sizeof((data)[0]), 0, 0, (n));

#define goo_mpz_print(n) \
  (mpz_out_str(stdout, 16, (n)), printf("\n"))

// For debugging
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
#define goo_mpz_mod_ui mpz_tdiv_ui
#define goo_mpz_and_ui(x, y) mpz_tdiv_ui((x), (y) + 1)

// Note: violates strict aliasing.
#define goo_mpz_unconst(n) *((mpz_t *)&(n))

static inline size_t
goo_mpz_bitlen(const mpz_t n) {
  if (mpz_sgn(n) == 0)
    return 0;

  return mpz_sizeinbase(n, 2);
}

static inline void *
goo_mpz_pad(void *out, size_t size, const mpz_t n) {
  size_t len = goo_mpz_bytelen(n);

  if (len > size)
    return NULL;

  if (size == 0)
    return NULL;

  if (out == NULL) {
    out = malloc(size);
    if (out == NULL)
      return NULL;
  }

  size_t pos = size - len;

  memset(out, 0x00, pos);

  goo_mpz_export(out + pos, NULL, n);

  return out;
}

static inline unsigned long
goo_mpz_zerobits(const mpz_t n) {
  int sgn = mpz_sgn(n);

  // if n == 0
  if (sgn == 0)
    return 0;

  // Note: mpz_ptr is undocumented.
  // https://gmplib.org/list-archives/gmp-discuss/2009-May/003769.html
  // https://gmplib.org/list-archives/gmp-devel/2013-February/002775.html

  // if n < 0
  if (sgn < 0) {
    // n = -n;
    mpz_neg((mpz_ptr)n, n);
  }

  unsigned long bits = mpz_scan1(n, 0);

  if (sgn < 0) {
    // n = -n;
    mpz_neg((mpz_ptr)n, n);
  }

  return bits;
}

static inline void
goo_mpz_mask(mpz_t r, const mpz_t n, unsigned long bit, mpz_t mask) {
  if (bit == 0) {
    mpz_set_ui(r, 0);
    return;
  }

  // mask = (1 << bit) - 1
  mpz_set_ui(mask, 1);
  mpz_mul_2exp(mask, mask, bit);
  mpz_sub_ui(mask, mask, 1);

  // r = n & mask
  mpz_and(r, n, mask);
}

#if !defined(GOO_HAS_GMP) || defined(GOO_TEST)
// https://github.com/golang/go/blob/aadaec5/src/math/big/int.go#L754
static int
goo_mpz_jacobi(const mpz_t x, const mpz_t y) {
  // Undefined behavior.
  // if y == 0 || y & 1 == 0
  if (mpz_sgn(y) == 0 || mpz_even_p(y))
    return 0;

  mpz_t a;
  mpz_t b;
  mpz_t c;
  int j;

  mpz_init(a);
  mpz_init(b);
  mpz_init(c);
  j = 0;

  // a = x
  mpz_set(a, x);
  // b = y
  mpz_set(b, y);
  j = 1;

  // if b < 0
  if (mpz_sgn(b) < 0) {
    // if a < 0
    if (mpz_sgn(a) < 0)
      j = -1;
    // b = -b
    mpz_neg(b, b);
  }

  for (;;) {
    // if b == 1
    if (mpz_cmp_ui(b, 1) == 0)
      break;

    // if a == 0
    if (mpz_sgn(a) == 0) {
      j = 0;
      break;
    }

    // a = a mod b
    mpz_mod(a, a, b);

    // if a == 0
    if (mpz_sgn(a) == 0) {
      j = 0;
      break;
    }

    // s = bitlen(a)
    unsigned long s = goo_mpz_zerobits(a);

    if (s & 1) {
      // bmod8 = b & 7
      unsigned long bmod8 = mpz_tdiv_ui(b, 8);

      if (bmod8 == 3 || bmod8 == 5)
        j = -j;
    }

    // c = a >> s
    mpz_fdiv_q_2exp(c, a, s);

    // if b & 3 == 3 and c & 3 == 3
    if (mpz_tdiv_ui(b, 4) == 3 && mpz_tdiv_ui(c, 4) == 3)
      j = -j;

    // a = b
    mpz_set(a, b);
    // b = c
    mpz_set(b, c);
  }

  mpz_clear(a);
  mpz_clear(b);
  mpz_clear(c);

  return j;
}
#endif

#ifndef GOO_HAS_GMP
// Jacobi is not implemented in mini-gmp.
#define mpz_jacobi goo_mpz_jacobi
#endif

static inline void
goo_mpz_add_si(mpz_t r, const mpz_t n, long val) {
  if (val < 0)
    mpz_sub_ui(r, n, -val);
  else
    mpz_add_ui(r, n, val);
}

static inline void
goo_mpz_sub_si(mpz_t r, const mpz_t n, long val) {
  if (val < 0)
    mpz_add_ui(r, n, -val);
  else
    mpz_sub_ui(r, n, val);
}

/*
 * Allocator
 */

static inline void *
goo_malloc(size_t size) {
  if (size == 0)
    return NULL;

  void *ptr = malloc(size);
  assert(ptr != NULL);
  return ptr;
}

static inline void *
goo_calloc(size_t nmemb, size_t size) {
  if (nmemb == 0 || size == 0)
    return NULL;

  void *ptr = calloc(nmemb, size);
  assert(ptr != NULL);
  return ptr;
}

static inline void *
goo_realloc(void *ptr, size_t size) {
  if (size == 0)
    return realloc(ptr, size);

  void *p = realloc(ptr, size);
  assert(p != NULL);
  return p;
}

static inline void
goo_free(void *ptr) {
  if (ptr != NULL)
    free(ptr);
}

/*
 * RNG
 */

static int
goo_random_bits(mpz_t ret, unsigned long bits) {
  int r = 0;
  unsigned long total = 0;
  unsigned char out[32];

  mpz_t tmp;
  mpz_init(tmp);

  // ret = 0
  mpz_set_ui(ret, 0);

  while (total < bits) {
    // ret = ret << 256
    mpz_mul_2exp(ret, ret, 256);
    // tmp = nextrand()
    if (!goo_random(&out[0], 32))
      goto fail;
    goo_mpz_import(tmp, &out[0], 32);
    // ret = ret | tmp
    mpz_ior(ret, ret, tmp);
    total += 256;
  }

  unsigned long left = total - bits;

  // ret >>= left;
  mpz_fdiv_q_2exp(ret, ret, left);

  r = 1;
fail:
  mpz_clear(tmp);
  return r;
}

static int
goo_random_bits_nz(mpz_t ret, unsigned long bits) {
  assert(bits != 0);

  do {
    if (!goo_random_bits(ret, bits))
      return 0;
  } while (mpz_sgn(ret) == 0);

  return 1;
}

static int
goo_random_int(mpz_t ret, const mpz_t max) {
  // if max <= 0
  if (mpz_sgn(max) <= 0) {
    // ret = 0
    mpz_set_ui(ret, 0);
    return 1;
  }

  // ret = max
  mpz_set(ret, max);

  // bits = bitlen(ret)
  size_t bits = goo_mpz_bitlen(ret);

  assert(bits > 0);

  // while ret >= max
  while (mpz_cmp(ret, max) >= 0) {
    if (!goo_random_bits(ret, bits))
      return 0;
  }

  return 1;
}

static unsigned long
goo_random_num(unsigned long max) {
  if (max == 0)
    return 0;

  unsigned long rand;

  if (!goo_random((void *)&rand, sizeof(unsigned long)))
    assert(0 && "RNG failed.");

  return rand % max;
}

/*
 * PRNG
 */

static void
goo_prng_init(goo_prng_t *prng) {
  memset((void *)prng, 0x00, sizeof(goo_prng_t));

  mpz_init(prng->save);
  prng->total = 0;
  mpz_init(prng->tmp);
}

static void
goo_prng_uninit(goo_prng_t *prng) {
  mpz_clear(prng->save);
  mpz_clear(prng->tmp);
}

static void
goo_prng_seed(goo_prng_t *prng, const unsigned char *key) {
  unsigned char entropy[64 + sizeof(goo_pers) - 1];

  memcpy(&entropy[0], key, 32);
  memset(&entropy[32], 0x00, 32);
  memcpy(&entropy[64], &goo_pers[0], sizeof(goo_pers) - 1);

  goo_drbg_init(&prng->ctx, entropy, sizeof(entropy));

  mpz_set_ui(prng->save, 0);
  prng->total = 0;
}

static void
goo_prng_next_random(goo_prng_t *prng, unsigned char *out) {
  goo_drbg_generate(&prng->ctx, out, 32);
}

static void
goo_prng_random_bits(goo_prng_t *prng, mpz_t ret, unsigned long bits) {
  // ret = save
  mpz_set(ret, prng->save);

  unsigned long total = prng->total;
  unsigned char out[32];

  while (total < bits) {
    // ret = ret << 256
    mpz_mul_2exp(ret, ret, 256);
    // tmp = nextrand()
    goo_prng_next_random(prng, &out[0]);
    goo_mpz_import(prng->tmp, &out[0], 32);
    // ret = ret | tmp
    mpz_ior(ret, ret, prng->tmp);
    total += 256;
  }

  unsigned long left = total - bits;

  // save = ret & ((1 << left) - 1)
  goo_mpz_mask(prng->save, ret, left, prng->tmp);
  prng->total = left;

  // ret >>= left;
  mpz_fdiv_q_2exp(ret, ret, left);
}

static void
goo_prng_random_bits_nz(goo_prng_t *prng, mpz_t ret, unsigned long bits) {
  assert(bits != 0);

  do {
    goo_prng_random_bits(prng, ret, bits);
  } while (mpz_sgn(ret) == 0);
}

static void
goo_prng_random_int(goo_prng_t *prng, mpz_t ret, const mpz_t max) {
  // if max <= 0
  if (mpz_sgn(max) <= 0) {
    // ret = 0
    mpz_set_ui(ret, 0);
    return;
  }

  // ret = max
  mpz_set(ret, max);

  // bits = bitlen(ret)
  size_t bits = goo_mpz_bitlen(ret);

  assert(bits > 0);

  // while ret >= max
  while (mpz_cmp(ret, max) >= 0)
    goo_prng_random_bits(prng, ret, bits);
}

/*
 * Utils
 */

static unsigned long
goo_dsqrt(unsigned long x) {
  if (x <= 1)
    return x;

  unsigned long len = 0;
  unsigned long y = x;
  unsigned long z1, z2;

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

// https://github.com/golang/go/blob/c86d464/src/math/big/int.go#L906
static int
goo_mpz_sqrtp(mpz_t ret, const mpz_t num, const mpz_t p) {
  int r = 0;
  mpz_t x, e, t, a, s, n, y, b, g;

  mpz_init(x);
  mpz_init(e);
  mpz_init(t);
  mpz_init(a);
  mpz_init(s);
  mpz_init(n);
  mpz_init(y);
  mpz_init(b);
  mpz_init(g);

  // x = num
  mpz_set(x, num);

  if (mpz_sgn(p) <= 0 || mpz_even_p(p))
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

  // if x < 0 || x >= p
  if (mpz_sgn(x) < 0 || mpz_cmp(x, p) >= 0) {
    // x = x mod p
    mpz_mod(x, x, p);
  }

  // if p mod 4 == 3
  if (mpz_tdiv_ui(p, 4) == 3) {
    // e = (p + 1) >> 2
    mpz_add_ui(e, p, 1);
    mpz_fdiv_q_2exp(e, e, 2);
    // ret = x^e mod p
    mpz_powm(ret, x, e, p);
    goto success;
  }

  // if p mod 8 == 5
  if (mpz_tdiv_ui(p, 8) == 5) {
    // e = p >> 3
    mpz_fdiv_q_2exp(e, p, 3);
    // t = x << 1
    mpz_mul_2exp(t, x, 1);
    // a = t^e mod p
    mpz_powm(a, t, e, p);
    // b = a^2 mod p
    mpz_powm_ui(b, a, 2, p);
    // b = (b * t) mod p
    mpz_mul(b, b, t);
    mpz_mod(b, b, p);
    // b = (b - 1) mod p
    mpz_sub_ui(b, b, 1);
    mpz_mod(b, b, p);
    // b = (b * x) mod p
    mpz_mul(b, b, x);
    mpz_mod(b, b, p);
    // b = (b * a) mod p
    mpz_mul(b, b, a);
    mpz_mod(b, b, p);
    // ret = b
    mpz_set(ret, b);
    goto success;
  }

  // s = p - 1
  mpz_sub_ui(s, p, 1);

  // z = zerobits(s)
  unsigned long z = goo_mpz_zerobits(s);

  // s = s >> z
  mpz_fdiv_q_2exp(s, s, z);

  // n = 2
  mpz_set_ui(n, 2);

  // while jacobi(n, p) != -1
  while (mpz_jacobi(n, p) != -1) {
    // n = n + 1
    mpz_add_ui(n, n, 1);
  }

  // y = s + 1
  mpz_add_ui(y, s, 1);
  // y = y >> 1
  mpz_fdiv_q_2exp(y, y, 1);
  // y = x^y mod p
  mpz_powm(y, x, y, p);
  // b = x^s mod p
  mpz_powm(b, x, s, p);
  // g = n^s mod p
  mpz_powm(g, n, s, p);

  // k = z
  unsigned long k = z;

  for (;;) {
    unsigned long m = 0;

    // t = b
    mpz_set(t, b);

    // while t != 1
    while (mpz_cmp_ui(t, 1) != 0) {
      // t = t^2 mod p
      mpz_powm_ui(t, t, 2, p);
      m += 1;
    }

    // if m == 0
    if (m == 0)
      break;

    // if m == k
    if (m == k)
      goto fail;

    // t = 1 << (k - m - 1)
    mpz_set_ui(t, 1);
    mpz_mul_2exp(t, t, k - m - 1);
    // t = g^t mod p
    mpz_powm(t, g, t, p);
    // g = t^2 mod p
    mpz_powm_ui(g, t, 2, p);
    // y = (y * t) mod p
    mpz_mul(y, y, t);
    mpz_mod(y, y, p);
    // b = (b * g) mod p
    mpz_mul(b, b, g);
    mpz_mod(b, b, p);
    // k = m
    k = m;
  }

  // ret = y
  mpz_set(ret, y);
  goto success;

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
  int r = 0;
  mpz_t sp, sq, mp, mq, xx, yy;

  mpz_init(sp);
  mpz_init(sq);
  mpz_init(mp);
  mpz_init(mq);
  mpz_init(xx);
  mpz_init(yy);

  // sp = mod_sqrtp(x, p)
  // sq = mod_sqrtp(x, q)
  if (!goo_mpz_sqrtp(sp, x, p)
      || !goo_mpz_sqrtp(sq, x, q)) {
    goto fail;
  }

  // [mp, mq] = euclid_lr(p, q)
  mpz_gcdext(ret, mp, mq, p, q);

  // xx = sq * mp * p
  mpz_mul(xx, sq, mp);
  mpz_mul(xx, xx, p);

  // yy = sp * mq * q
  mpz_mul(yy, sp, mq);
  mpz_mul(yy, yy, q);

  // xx = xx + yy
  mpz_add(xx, xx, yy);

  // yy = p * q
  mpz_mul(yy, p, q);

  // ret = xx mod yy
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
  // if n <= 1
  if (mpz_cmp_ui(n, 1) <= 0)
    return 0;

  for (long i = 0; i < GOO_TEST_PRIMES_LEN; i++) {
    // if p == test_primes[i]
    if (mpz_cmp_ui(n, goo_test_primes[i]) == 0)
      return 2;

    // if n mod test_primes[i] == 0
    if (mpz_tdiv_ui(n, goo_test_primes[i]) == 0)
      return 0;
  }

  return 1;
}

// https://github.com/golang/go/blob/aadaec5/src/math/big/prime.go#L81
// https://github.com/indutny/miller-rabin/blob/master/lib/mr.js
static int
goo_is_prime_mr(
  const mpz_t n,
  const unsigned char *key,
  long reps,
  int force2
) {
  // if n < 7
  if (mpz_cmp_ui(n, 7) < 0) {
    // if n == 2 or n == 3 or n == 5
    if (mpz_cmp_ui(n, 2) == 0
        || mpz_cmp_ui(n, 3) == 0
        || mpz_cmp_ui(n, 5) == 0) {
      return 1;
    }
    return 0;
  }

  int r = 0;
  mpz_t nm1, nm3, q, x, y;
  unsigned long k;

  mpz_init(nm1);
  mpz_init(nm3);
  mpz_init(q);
  mpz_init(x);
  mpz_init(y);

  // nm1 = n - 1
  mpz_sub_ui(nm1, n, 1);

  // nm3 = nm1 - 2
  mpz_sub_ui(nm3, nm1, 2);

  // k = zero_bits(nm1)
  k = goo_mpz_zerobits(nm1);
  // q = nm1 >> k
  mpz_fdiv_q_2exp(q, nm1, k);

  // Setup PRNG.
  goo_prng_t prng;
  goo_prng_init(&prng);
  // XOR with the prime we're testing?
  goo_prng_seed(&prng, key);

  for (long i = 0; i < reps; i++) {
    if (i == reps - 1 && force2) {
      // x = 2
      mpz_set_ui(x, 2);
    } else {
      // x = getrandint(nm3)
      goo_prng_random_int(&prng, x, nm3);
      // x += 2
      mpz_add_ui(x, x, 2);
    }

    // y = x^q mod n
    mpz_powm(y, x, q, n);

    // if y == 1 || y == nm1
    if (mpz_cmp_ui(y, 1) == 0 || mpz_cmp(y, nm1) == 0)
      continue;

    for (unsigned long j = 1; j < k; j++) {
      // y = y^2 mod n
      mpz_powm_ui(y, y, 2, n);

      // if y == nm1
      if (mpz_cmp(y, nm1) == 0)
        goto next;

      // if y == 1
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

// https://github.com/golang/go/blob/aadaec5/src/math/big/prime.go#L150
static int
goo_is_prime_lucas(const mpz_t n) {
  int r = 0;
  unsigned long p;
  mpz_t d;
  mpz_t s, nm2;
  mpz_t vk, vk1;
  mpz_t t1, t2, t3;

  mpz_init(d);
  mpz_init(s);
  mpz_init(nm2);
  mpz_init(vk);
  mpz_init(vk1);
  mpz_init(t1);
  mpz_init(t2);
  mpz_init(t3);

  // Ignore 0 and 1.
  // if n <= 1
  if (mpz_cmp_ui(n, 1) <= 0)
    goto fail;

  // Two is the only even prime.
  // if n & 1 == 0
  if (mpz_even_p(n)) {
    // if n == 2
    if (mpz_cmp_ui(n, 2) == 0)
      goto succeed;
    goto fail;
  }

  // Baillie-OEIS "method C" for choosing D, P, Q.
  // See: https://oeis.org/A217719/a217719.txt.
  // p = 3
  p = 3;
  // d = 1
  mpz_set_ui(d, 1);

  for (;;) {
    if (p > 10000) {
      // Thought to be impossible.
      goto fail;
    }

    if (p > 50) {
      // It's thought to be impossible for `p`
      // to be larger than 10,000, but fail
      // on anything higher than 50 to prevent
      // DoS attacks. `p` never seems to be
      // higher than 30 in practice.
      goto fail;
    }

    // d = p * p - 4
    mpz_set_ui(d, p * p - 4);

    int j = mpz_jacobi(d, n);

    if (j == -1)
      break;

    if (j == 0) {
      // if n == p + 2
      if (mpz_cmp_ui(n, p + 2) == 0)
        goto succeed;
      goto fail;
    }

    if (p == 40) {
      // if is_square(n)
      if (mpz_perfect_square_p(n))
        goto fail;
    }

    p += 1;
  }

  // Check for Grantham definition of
  // "extra strong Lucas pseudoprime".
  // s = n + 1
  mpz_add_ui(s, n, 1);

  // zb = zerobits(s)
  unsigned long zb = goo_mpz_zerobits(s);

  // nm2 = n - 2
  mpz_sub_ui(nm2, n, 2);

  // s >>= zb
  mpz_fdiv_q_2exp(s, s, zb);

  unsigned long bp = p;

  // vk = 2
  mpz_set_ui(vk, 2);
  // vk1 = p
  mpz_set_ui(vk1, p);

  for (long i = (long)goo_mpz_bitlen(s); i >= 0; i--) {
    if (mpz_tstbit(s, i)) {
      // t1 = vk * vk1
      mpz_mul(t1, vk, vk1);
      // t1 += n
      mpz_add(t1, t1, n);
      // t1 -= bp
      mpz_sub_ui(t1, t1, bp);
      // vk = t1 mod n
      mpz_mod(vk, t1, n);
      // t1 = vk1 * vk1
      mpz_mul(t1, vk1, vk1);
      // t1 += nm2
      mpz_add(t1, t1, nm2);
      // vk1 = t1 mod n
      mpz_mod(vk1, t1, n);
    } else {
      // t1 = vk * vk1
      mpz_mul(t1, vk, vk1);
      // t1 += n
      mpz_add(t1, t1, n);
      // t1 -= bp
      mpz_sub_ui(t1, t1, bp);
      // vk1 = t1 mod n
      mpz_mod(vk1, t1, n);
      // t1 = vk * vk
      mpz_mul(t1, vk, vk);
      // t1 += nm2
      mpz_add(t1, t1, nm2);
      // vk = t1 mod n
      mpz_mod(vk, t1, n);
    }
  }

  // if vk == 2 or vk == nm2
  if (mpz_cmp_ui(vk, 2) == 0 || mpz_cmp(vk, nm2) == 0) {
    // t1 = vk * bp
    mpz_mul_ui(t1, vk, bp);
    // t2 = vk1 << 1
    mpz_mul_2exp(t2, vk1, 1);

    // if t1 < t2
    if (mpz_cmp(t1, t2) < 0) {
      // [t1, t2] = [t2, t1]
      mpz_swap(t1, t2);
    }

    // t1 -= t2
    mpz_sub(t1, t1, t2);

    // t3 = t1 mod n
    mpz_mod(t3, t1, n);

    // if t3 == 0
    if (mpz_sgn(t3) == 0)
      goto succeed;
  }

  for (long t = 0; t < (long)zb - 1; t++) {
    // if vk == 0
    if (mpz_sgn(vk) == 0)
      goto succeed;

    // if vk == 2
    if (mpz_cmp_ui(vk, 2) == 0)
      goto fail;

    // t1 = vk * vk
    mpz_mul(t1, vk, vk);
    // t1 -= 2
    mpz_sub_ui(t1, t1, 2);
    // vk = t1 mod n
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
  // if p <= 1
  if (mpz_cmp_ui(p, 1) <= 0)
    return 0;

  // 0 = not prime
  // 1 = maybe prime
  // 2 = definitely prime
  int ret = goo_is_prime_div(p);

  if (ret == 0)
    return 0;

  // Early exit.
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

  // ret = p
  mpz_set(ret, p);

  // if ret & 1 == 0
  if (mpz_even_p(ret)) {
    inc += 1;
    // ret += 1
    mpz_add_ui(ret, ret, 1);
  }

  while (!goo_is_prime(ret, key)) {
    if (max != 0 && inc > max)
      break;
    // ret += 2
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

static inline size_t
goo_sig_size(const goo_sig_t *sig, size_t bits) {
  size_t mod_bytes = (bits + 7) / 8;
  size_t exp_bytes = (GOO_EXPONENT_SIZE + 7) / 8;
  size_t chal_bytes = (GOO_CHAL_BITS + 7) / 8;
  size_t len = 0;

  len += mod_bytes; // C2
  len += mod_bytes; // C3
  len += 2; // t
  len += chal_bytes; // chal
  len += chal_bytes; // ell
  len += mod_bytes; // Aq
  len += mod_bytes; // Bq
  len += mod_bytes; // Cq
  len += mod_bytes; // Dq
  len += exp_bytes; // Eq
  len += chal_bytes * 8; // z_prime

  return len;
}

#define goo_write_int(n, size) do {     \
  size_t bytes = goo_mpz_bytelen((n));  \
                                        \
  if (bytes > (size))                   \
    return 0;                           \
                                        \
  size_t pad = (size) - bytes;          \
  memset(&out[pos], 0x00, pad);         \
  pos += pad;                           \
                                        \
  goo_mpz_export(&out[pos], NULL, (n)); \
  pos += bytes;                         \
} while (0)

static inline int
goo_sig_export(unsigned char *out, const goo_sig_t *sig, size_t bits) {
  size_t mod_bytes = (bits + 7) / 8;
  size_t exp_bytes = (GOO_EXPONENT_SIZE + 7) / 8;
  size_t chal_bytes = (GOO_CHAL_BITS + 7) / 8;
  size_t pos = 0;

  goo_write_int(sig->C2, mod_bytes);
  goo_write_int(sig->C3, mod_bytes);
  goo_write_int(sig->t, 2);

  goo_write_int(sig->chal, chal_bytes);
  goo_write_int(sig->ell, chal_bytes);
  goo_write_int(sig->Aq, mod_bytes);
  goo_write_int(sig->Bq, mod_bytes);
  goo_write_int(sig->Cq, mod_bytes);
  goo_write_int(sig->Dq, mod_bytes);
  goo_write_int(sig->Eq, exp_bytes);

  goo_write_int(sig->z_w, chal_bytes);
  goo_write_int(sig->z_w2, chal_bytes);
  goo_write_int(sig->z_s1, chal_bytes);
  goo_write_int(sig->z_a, chal_bytes);
  goo_write_int(sig->z_an, chal_bytes);
  goo_write_int(sig->z_s1w, chal_bytes);
  goo_write_int(sig->z_sa, chal_bytes);
  goo_write_int(sig->z_s2, chal_bytes);

  assert(goo_sig_size(sig, bits) == pos);

  return 1;
}

#undef goo_write_int

#define goo_read_int(n, size) do {         \
  if (pos + (size) > data_len)             \
    return 0;                              \
                                           \
  goo_mpz_import((n), &data[pos], (size)); \
  pos += (size);                           \
} while (0)                                \

static inline int
goo_sig_import(
  goo_sig_t *sig,
  const unsigned char *data,
  size_t data_len,
  size_t bits
) {
  size_t mod_bytes = (bits + 7) / 8;
  size_t exp_bytes = (GOO_EXPONENT_SIZE + 7) / 8;
  size_t chal_bytes = (GOO_CHAL_BITS + 7) / 8;
  size_t pos = 0;

  goo_read_int(sig->C2, mod_bytes);
  goo_read_int(sig->C3, mod_bytes);
  goo_read_int(sig->t, 2);

  goo_read_int(sig->chal, chal_bytes);
  goo_read_int(sig->ell, chal_bytes);
  goo_read_int(sig->Aq, mod_bytes);
  goo_read_int(sig->Bq, mod_bytes);
  goo_read_int(sig->Cq, mod_bytes);
  goo_read_int(sig->Dq, mod_bytes);
  goo_read_int(sig->Eq, exp_bytes);

  goo_read_int(sig->z_w, chal_bytes);
  goo_read_int(sig->z_w2, chal_bytes);
  goo_read_int(sig->z_s1, chal_bytes);
  goo_read_int(sig->z_a, chal_bytes);
  goo_read_int(sig->z_an, chal_bytes);
  goo_read_int(sig->z_s1w, chal_bytes);
  goo_read_int(sig->z_sa, chal_bytes);
  goo_read_int(sig->z_s2, chal_bytes);

  assert(pos <= data_len);

  // non-minimal serialization
  if (pos != data_len)
    return 0;

  return 1;
}

#undef goo_read_int

/*
 * CombSpec
 */

static inline size_t
combspec_size(long bits) {
  long max = 0;

  for (long ppa = 2; ppa < 18; ppa++) {
    long bpw = (bits + ppa - 1) / ppa;
    long sqrt = goo_dsqrt(bpw);

    for (long aps = 1; aps < sqrt + 2; aps++) {
      if (bpw % aps != 0)
        continue;

      long shifts = bpw / aps;
      long ops1 = shifts * (aps + 1) - 1;
      long ops2 = aps * (shifts + 1) - 1;
      long ops = (ops1 > ops2 ? ops1 : ops2) + 1;

      if (ops > max)
        max = ops;
    }
  }

  return max;
}

static void
combspec_result(
  goo_combspec_t *combs,
  size_t map_size,
  long shifts,
  long aps,
  long ppa,
  long bps
) {
  long ops = shifts * (aps + 1) - 1;
  long size = ((1 << ppa) - 1) * aps;

  assert(ops >= 0);
  assert((size_t)ops < map_size);

  goo_combspec_t *best = &combs[ops];

  if (best->exists == 0 || best->size > size) {
    best->exists = 1;
    best->points_per_add = ppa;
    best->adds_per_shift = aps;
    best->shifts = shifts;
    best->bits_per_window = bps;
    best->ops = ops;
    best->size = size;
  }
}

int
goo_combspec_init(
  goo_combspec_t *combspec,
  long bits,
  long maxsize
) {
  if (bits < 128 || maxsize < 0)
    return 0;

  size_t map_size = combspec_size(bits);
  goo_combspec_t *combs = goo_calloc(map_size, sizeof(goo_combspec_t));

  for (long ppa = 2; ppa < 18; ppa++) {
    long bpw = (bits + ppa - 1) / ppa;
    long sqrt = goo_dsqrt(bpw);

    for (long aps = 1; aps < sqrt + 2; aps++) {
      if (bpw % aps != 0) {
        // Only factorizations of
        // bits_per_window are useful.
        continue;
      }

      long shifts = bpw / aps;

      combspec_result(combs, map_size, shifts, aps, ppa, bpw);
      combspec_result(combs, map_size, aps, shifts, ppa, bpw);
    }
  }

  long sm = 0;
  goo_combspec_t *ret = NULL;

  for (size_t i = 0; i < map_size; i++) {
    goo_combspec_t *comb = &combs[i];

    if (comb->exists == 0)
      continue;

    if (sm != 0 && sm <= comb->size)
      continue;

    sm = comb->size;

    if (sm <= maxsize) {
      ret = comb;
      break;
    }
  }

  if (ret == NULL) {
    goo_free(combs);
    return 0;
  }

  memcpy(combspec, ret, sizeof(goo_combspec_t));
  goo_free(combs);

  return 1;
}

/*
 * Comb
 */

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
goo_comb_init(
  goo_comb_t *comb,
  goo_group_t *group,
  mpz_t base,
  goo_combspec_t *spec
) {
  memset((void *)comb, 0x00, sizeof(goo_comb_t));

  long skip = (1 << spec->points_per_add) - 1;

  comb->points_per_add = spec->points_per_add;
  comb->adds_per_shift = spec->adds_per_shift;
  comb->shifts = spec->shifts;
  comb->bits_per_window = spec->bits_per_window;
  comb->bits = spec->bits_per_window * spec->points_per_add;
  comb->points_per_subcomb = skip;
  comb->size = spec->size;

  comb->wins = (long **)goo_calloc(comb->shifts, sizeof(long *));

  for (long i = 0; i < comb->shifts; i++)
    comb->wins[i] = (long *)goo_calloc(comb->adds_per_shift, sizeof(long));

  comb->items = (mpz_t *)goo_calloc(comb->size, sizeof(mpz_t));

  for (long i = 0; i < comb->size; i++)
    mpz_init(comb->items[i]);

  mpz_set(comb->items[0], base);

  mpz_t *it = &comb->items[0];

  mpz_t win;
  mpz_init(win);

  // win = 1 << bits_per_window
  mpz_set_ui(win, 1);
  mpz_mul_2exp(win, win, comb->bits_per_window);

  for (long i = 1; i < comb->points_per_add; i++) {
    long oval = 1 << i;
    long ival = oval >> 1;

    goo_group_pow(group, it[oval - 1], it[ival - 1], NULL, win);

    for (long j = oval + 1; j < 2 * oval; j++)
      goo_group_mul(group, it[j - 1], it[j - oval - 1], it[oval - 1]);
  }

  // win = 1 << shifts
  mpz_set_ui(win, 1);
  mpz_mul_2exp(win, win, comb->shifts);

  for (long i = 1; i < comb->adds_per_shift; i++) {
    for (long j = 0; j < skip; j++) {
      long k = i * skip + j;

      goo_group_pow(group, it[k], it[k - skip], NULL, win);
    }
  }

  mpz_clear(win);
}

static void
goo_comb_uninit(goo_comb_t *comb) {
  for (long i = 0; i < comb->size; i++)
    mpz_clear(comb->items[i]);

  for (long i = 0; i < comb->shifts; i++)
    goo_free(comb->wins[i]);

  goo_free(comb->wins);

  comb->size = 0;
  comb->shifts = 0;
  comb->items = NULL;
  comb->wins = NULL;
}

static int
goo_to_comb_exp(goo_comb_t *comb, const mpz_t e) {
  long len = (long)goo_mpz_bitlen(e);

  if (len < 0 || len > comb->bits)
    return 0;

  for (long i = comb->adds_per_shift - 1; i >= 0; i--) {
    for (long j = 0; j < comb->shifts; j++) {
      long ret = 0;

      for (long k = 0; k < comb->points_per_add; k++) {
        long b = (i + k * comb->adds_per_shift) * comb->shifts + j;

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

static inline int
goo_hash_item(
  goo_sha256_t *ctx,
  const mpz_t n,
  size_t size,
  unsigned char *buf
);

static int
goo_group_init(
  goo_group_t *group,
  const mpz_t n,
  unsigned long g,
  unsigned long h,
  unsigned long modbits
) {
  if (modbits != 0) {
    if (modbits < GOO_MIN_RSA_BITS || modbits > GOO_MAX_RSA_BITS)
      return 0;
  }

  memset((void *)group, 0x00, sizeof(goo_group_t));

  mpz_init(group->n);
  mpz_init(group->nh);
  mpz_init(group->g);
  mpz_init(group->h);

  // n = n
  mpz_set(group->n, n);

  group->bits = goo_mpz_bitlen(group->n);
  group->size = (group->bits + 7) / 8;

  // nh = n >> 1
  mpz_fdiv_q_2exp(group->nh, group->n, 1);

  // g = g
  mpz_set_ui(group->g, g);
  // h = h
  mpz_set_ui(group->h, h);

  group->rand_bits = goo_mpz_bitlen(group->n) - 1;

  if (modbits != 0) {
    long big1 = 2 * modbits;
    long big2 = modbits + group->rand_bits;
    long big = big1 > big2 ? big1 : big2;
    long big_bits = big + GOO_CHAL_BITS + 1;

    goo_combspec_t big_spec;
    assert(goo_combspec_init(&big_spec, big_bits, GOO_MAX_COMB_SIZE));

    long small_bits = group->rand_bits;
    goo_combspec_t small_spec;
    assert(goo_combspec_init(&small_spec, small_bits, GOO_MAX_COMB_SIZE));

    group->combs_len = 2;
    goo_comb_init(&group->combs[0].g, group, group->g, &small_spec);
    goo_comb_init(&group->combs[0].h, group, group->h, &small_spec);
    goo_comb_init(&group->combs[1].g, group, group->g, &big_spec);
    goo_comb_init(&group->combs[1].h, group, group->h, &big_spec);
  } else {
    long tiny_bits = GOO_CHAL_BITS;

    goo_combspec_t tiny_spec;
    assert(goo_combspec_init(&tiny_spec, tiny_bits, GOO_MAX_COMB_SIZE));

    group->combs_len = 1;
    goo_comb_init(&group->combs[0].g, group, group->g, &tiny_spec);
    goo_comb_init(&group->combs[0].h, group, group->h, &tiny_spec);
  }

  for (long i = 0; i < GOO_TABLEN; i++) {
    mpz_init(group->pctab_p1[i]);
    mpz_init(group->pctab_n1[i]);
    mpz_init(group->pctab_p2[i]);
    mpz_init(group->pctab_n2[i]);
  }

  goo_prng_init(&group->prng);

  goo_sha256_init(&group->sha);
  goo_sha256_update(&group->sha, (void *)goo_prefix, sizeof(goo_prefix) - 1);
  assert(goo_hash_item(&group->sha, group->n, group->size, group->slab));
  assert(goo_hash_item(&group->sha, group->g, 4, group->slab));
  assert(goo_hash_item(&group->sha, group->h, 4, group->slab));

  mpz_init(group->msg);
  goo_sig_init(&group->sig);
  mpz_init(group->C1);
  mpz_init(group->C1_inv);
  mpz_init(group->C2_inv);
  mpz_init(group->C3_inv);
  mpz_init(group->Aq_inv);
  mpz_init(group->Bq_inv);
  mpz_init(group->Cq_inv);
  mpz_init(group->Dq_inv);
  mpz_init(group->A);
  mpz_init(group->B);
  mpz_init(group->C);
  mpz_init(group->D);
  mpz_init(group->E);
  mpz_init(group->z_w2_m_an);
  mpz_init(group->tmp);
  mpz_init(group->chal_out);
  mpz_init(group->ell_r_out);
  mpz_init(group->elldiff);

  mpz_init(group->e);

  mpz_init(group->gh);

  return 1;
}

static void
goo_group_uninit(goo_group_t *group) {
  mpz_clear(group->n);
  mpz_clear(group->nh);
  mpz_clear(group->g);
  mpz_clear(group->h);

  for (long i = 0; i < group->combs_len; i++) {
    goo_comb_uninit(&group->combs[i].g);
    goo_comb_uninit(&group->combs[i].h);
  }

  group->combs_len = 0;

  for (long i = 0; i < GOO_TABLEN; i++) {
    mpz_clear(group->pctab_p1[i]);
    mpz_clear(group->pctab_n1[i]);
    mpz_clear(group->pctab_p2[i]);
    mpz_clear(group->pctab_n2[i]);
  }

  goo_prng_uninit(&group->prng);

  mpz_clear(group->msg);
  goo_sig_uninit(&group->sig);
  mpz_clear(group->C1);
  mpz_clear(group->C1_inv);
  mpz_clear(group->C2_inv);
  mpz_clear(group->C3_inv);
  mpz_clear(group->Aq_inv);
  mpz_clear(group->Bq_inv);
  mpz_clear(group->Cq_inv);
  mpz_clear(group->Dq_inv);
  mpz_clear(group->A);
  mpz_clear(group->B);
  mpz_clear(group->C);
  mpz_clear(group->D);
  mpz_clear(group->E);
  mpz_clear(group->z_w2_m_an);
  mpz_clear(group->tmp);
  mpz_clear(group->chal_out);
  mpz_clear(group->ell_r_out);
  mpz_clear(group->elldiff);

  mpz_clear(group->e);

  mpz_clear(group->gh);
}

static void
goo_group_reduce(goo_group_t *group, mpz_t ret, const mpz_t b) {
  // if b > nh
  if (mpz_cmp(b, group->nh) > 0) {
    // ret = n - b
    mpz_sub(ret, group->n, b);
  }
}

static int
goo_group_is_reduced(goo_group_t *group, const mpz_t b) {
  // b <= nh
  return mpz_cmp(b, group->nh) <= 0 ? 1 : 0;
}

static void
goo_group_sqr(goo_group_t *group, mpz_t ret, const mpz_t b) {
  // ret = b^2 mod n
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
  // ret = b^e mod n
  mpz_powm(ret, b, e, group->n);
}

static void
goo_group_mul(goo_group_t *group, mpz_t ret, const mpz_t m1, const mpz_t m2) {
  // ret = (m1 * m2) mod n
  mpz_mul(ret, m1, m2);
  mpz_mod(ret, ret, group->n);
}

static int
goo_group_inv(goo_group_t *group, mpz_t ret, const mpz_t b) {
  // ret = b^-1 mod n
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
  int r = 0;
  mpz_ptr b12_inv = r2;

  // b12_inv = (b1 * b2)^-1 mod n
  mpz_mul(b12_inv, b1, b2);

  if (!goo_group_inv(group, b12_inv, b12_inv))
    goto fail;

  // r1 = (b2 * b12_inv) mod n
  goo_group_mul(group, r1, b2, b12_inv);
  // r2 = (b1 * b12_inv) mod n
  goo_group_mul(group, r2, b1, b12_inv);

  r = 1;
fail:
  return r;
}

static int
goo_group_inv7(
  goo_group_t *group,
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
  const mpz_t b7
) {
  int r = 0;

  // Tricky memory management
  // to avoid allocations.
  mpz_ptr b12 = r4;
  mpz_ptr b34 = r2;
  mpz_ptr b56 = r3;
  mpz_ptr b1234 = r1;
  mpz_ptr b123456 = r5;
  mpz_ptr b1234567 = r7;
  mpz_ptr b1234567_inv = r7;
  mpz_ptr b123456_inv = r6;
  mpz_ptr b1234_inv = r3;
  mpz_ptr b56_inv = r1;
  mpz_ptr b34_inv = r4;
  mpz_ptr b12_inv = r2;

  // b12 = (b1 * b2) mod n
  goo_group_mul(group, b12, b1, b2);
  // b34 = (b3 * b4) mod n
  goo_group_mul(group, b34, b3, b4);
  // b56 = (b5 * b6) mod n
  goo_group_mul(group, b56, b5, b6);
  // b1234 = (b12 * b34) mod n
  goo_group_mul(group, b1234, b12, b34);
  // b123456 = (b1234 * b56) mod n
  goo_group_mul(group, b123456, b1234, b56);
  // b1234567 = (b123456 * b7) mod n
  goo_group_mul(group, b1234567, b123456, b7);

  // b1234567_inv = b1234567^-1 mod n
  if (!goo_group_inv(group, b1234567_inv, b1234567))
    goto fail;

  // b123456_inv = (b1234567_inv * b7) mod n
  goo_group_mul(group, b123456_inv, b1234567_inv, b7);
  // b1234_inv = (b123456_inv * b56) mod n
  goo_group_mul(group, b1234_inv, b123456_inv, b56);
  // b56_inv = (b123456_inv * b1234) mod n
  goo_group_mul(group, b56_inv, b123456_inv, b1234);
  // b34_inv = (b1234_inv * b12) mod n
  goo_group_mul(group, b34_inv, b1234_inv, b12);
  // b12_inv = (b1234_inv * b34) mod n
  goo_group_mul(group, b12_inv, b1234_inv, b34);

  // r7 = (b1234567_inv * b123456) mod n
  goo_group_mul(group, r7, b1234567_inv, b123456);
  // r5 = (b56_inv * b6) mod n
  goo_group_mul(group, r5, b56_inv, b6);
  // r6 = (b56_inv * b5) mod n
  goo_group_mul(group, r6, b56_inv, b5);
  // r1 = (b12_inv * b2) mod n
  goo_group_mul(group, r1, b12_inv, b2);
  // r2 = (b12_inv * b1) mod n
  goo_group_mul(group, r2, b12_inv, b1);
  // r3 = (b34_inv * b4) mod n
  goo_group_mul(group, r3, b34_inv, b4);
  // r4 = (b34_inv * b3) mod n
  goo_group_mul(group, r4, b34_inv, b3);

  r = 1;
fail:
  return r;
}

static int
goo_group_powgh(goo_group_t *group, mpz_t ret, const mpz_t e1, const mpz_t e2) {
  long e1bits = (long)goo_mpz_bitlen(e1);
  long e2bits = (long)goo_mpz_bitlen(e2);
  long loge = e1bits > e2bits ? e1bits : e2bits;

  goo_comb_t *gcomb = NULL;
  goo_comb_t *hcomb = NULL;

  for (long i = 0; i < group->combs_len; i++) {
    if (loge <= group->combs[i].g.bits) {
      gcomb = &group->combs[i].g;
      hcomb = &group->combs[i].h;
      break;
    }
  }

  if (!gcomb || !hcomb)
    return 0;

  if (!goo_to_comb_exp(gcomb, e1))
    return 0;

  if (!goo_to_comb_exp(hcomb, e2))
    return 0;

  // ret = 1
  mpz_set_ui(ret, 1);

  for (long i = 0; i < gcomb->shifts; i++) {
    long *e1vs = gcomb->wins[i];
    long *e2vs = hcomb->wins[i];

    // if ret != 1
    if (mpz_cmp_ui(ret, 1) != 0)
      goo_group_sqr(group, ret, ret);

    for (long j = 0; j < gcomb->adds_per_shift; j++) {
      long e1v = e1vs[j];
      long e2v = e2vs[j];

      if (e1v != 0) {
        mpz_t *g = &gcomb->items[j * gcomb->points_per_subcomb + e1v - 1];
        goo_group_mul(group, ret, ret, *g);
      }

      if (e2v != 0) {
        mpz_t *h = &hcomb->items[j * hcomb->points_per_subcomb + e2v - 1];
        goo_group_mul(group, ret, ret, *h);
      }
    }
  }

  return 1;
}

static int
goo_group_powgh_slow(
  goo_group_t *group,
  mpz_t ret,
  const mpz_t e1,
  const mpz_t e2
) {
  mpz_t q1, q2;
  mpz_init(q1);
  mpz_init(q2);
  // q1 = g^e1 mod n
  mpz_powm(q1, group->g, e1, group->n);
  // q2 = h^e2 mod n
  mpz_powm(q2, group->h, e2, group->n);
  // ret = (q1 * q2) mod n
  mpz_mul(ret, q1, q2);
  mpz_mod(ret, ret, group->n);
  mpz_clear(q1);
  mpz_clear(q2);
  return 1;
}

static void
goo_group_wnaf_pc_help(goo_group_t *group, const mpz_t b, mpz_t *out) {
  mpz_t *bsq = &out[GOO_TABLEN - 1];

  // bsq = b * b
  goo_group_sqr(group, *bsq, b);

  // out[0] = b
  mpz_set(out[0], b);

  for (long i = 1; i < GOO_TABLEN; i++) {
    // out[i] = out[i - 1] * bsq
    goo_group_mul(group, out[i], out[i - 1], *bsq);
  }
}

static void
goo_group_precomp_wnaf(
  goo_group_t *group,
  const mpz_t b,
  const mpz_t b_inv,
  mpz_t *p,
  mpz_t *n
) {
  goo_group_wnaf_pc_help(group, b, p);
  goo_group_wnaf_pc_help(group, b_inv, n);
}

static long *
goo_group_wnaf(goo_group_t *group, const mpz_t exp, long *out, long bitlen) {
  mpz_t *e = &group->e;
  long w = GOO_WINDOW_SIZE;
  long mask = (1 << w) - 1;
  long val;

  // e = exp
  mpz_set(*e, exp);

  for (long i = bitlen - 1; i >= 0; i--) {
    val = 0;

    // if e & 1
    if (mpz_tstbit(*e, 0)) {
      // val = e & mask;
      val = (long)mpz_tdiv_ui(*e, mask + 1);

      if (val & (1 << (w - 1)))
        val -= 1 << w;

      // e = e - val
      if (val < 0)
        mpz_add_ui(*e, *e, -val);
      else
        mpz_sub_ui(*e, *e, val);
    }

    // out[i] = val
    out[i] = val;

    // e = e >> 1
    mpz_fdiv_q_2exp(*e, *e, 1);
  }

  // e == 0
  assert(mpz_sgn(*e) == 0);

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

static void
goo_group_pow_wnaf(
  goo_group_t *group,
  mpz_t ret,
  const mpz_t b,
  const mpz_t b_inv,
  const mpz_t e
) {
  if (b_inv == NULL)
    return goo_group_pow(group, ret, b, b_inv, e);

  mpz_t *p = &group->pctab_p1[0];
  mpz_t *n = &group->pctab_n1[0];

  goo_group_precomp_wnaf(group, b, b_inv, p, n);

  size_t totlen = goo_mpz_bitlen(e) + 1;

  assert(totlen <= GOO_CHAL_BITS + 1);

  long *ebits = goo_group_wnaf(group, e, &group->e1bits[0], totlen);

  // ret = 1
  mpz_set_ui(ret, 1);

  for (size_t i = 0; i < totlen; i++) {
    long w = ebits[i];

    // if ret != 1
    if (mpz_cmp_ui(ret, 1) != 0)
      goo_group_sqr(group, ret, ret);

    goo_group_one_mul(group, ret, w, p, n);
  }
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

  goo_group_precomp_wnaf(group, b1, b1_inv, p1, n1);
  goo_group_precomp_wnaf(group, b2, b2_inv, p2, n2);

  size_t e1len = goo_mpz_bitlen(e1);
  size_t e2len = goo_mpz_bitlen(e2);
  size_t totlen = (e1len > e2len ? e1len : e2len) + 1;

  if (totlen > GOO_CHAL_BITS + 1)
    return 0;

  long *e1bits = goo_group_wnaf(group, e1, &group->e1bits[0], totlen);
  long *e2bits = goo_group_wnaf(group, e2, &group->e2bits[0], totlen);

  // ret = 1
  mpz_set_ui(ret, 1);

  for (size_t i = 0; i < totlen; i++) {
    long w1 = e1bits[i];
    long w2 = e2bits[i];

    // if ret != 1
    if (mpz_cmp_ui(ret, 1) != 0)
      goo_group_sqr(group, ret, ret);

    goo_group_one_mul(group, ret, w1, p1, n1);
    goo_group_one_mul(group, ret, w2, p2, n2);
  }

  return 1;
}

static int
goo_group_pow2_slow(
  goo_group_t *group,
  mpz_t ret,
  const mpz_t b1,
  const mpz_t b1_inv,
  const mpz_t e1,
  const mpz_t b2,
  const mpz_t b2_inv,
  const mpz_t e2
) {
  mpz_t q1, q2;
  mpz_init(q1);
  mpz_init(q2);
  // q1 = b1^e2 mod n
  mpz_powm(q1, b1, e1, group->n);
  // q2 = b2^e2 mod n
  mpz_powm(q2, b2, e2, group->n);
  // ret = (q1 * q2) mod n
  mpz_mul(ret, q1, q2);
  mpz_mod(ret, ret, group->n);
  mpz_clear(q1);
  mpz_clear(q2);
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
  int r = 0;
  mpz_ptr pow = ret;
  mpz_t *gh = &group->gh;

  // pow = pow2(b1, b1_inv, e1, b2, b2_inv, e2)
  if (!goo_group_pow2(group, pow, b1, b1_inv, e1, b2, b2_inv, e2))
    goto fail;

  // gh = powgh(e3, e4)
  if (!goo_group_powgh(group, *gh, e3, e4))
    goto fail;

  // ret = pow * gh
  goo_group_mul(group, ret, pow, *gh);

  // ret = reduce(ret)
  goo_group_reduce(group, ret, ret);

  r = 1;
fail:
  return r;
}

static inline int
goo_hash_item(
  goo_sha256_t *ctx,
  const mpz_t n,
  size_t size,
  unsigned char *buf
) {
  if (mpz_sgn(n) < 0)
    return 0;

  size_t len = goo_mpz_bytelen(n);

  if (len > size)
    return 0;

  if (len > (GOO_MAX_RSA_BITS + 7) / 8)
    return 0;

  size_t pos = size - len;

  memset(buf, 0x00, pos);

  if (len != 0)
    goo_mpz_export(buf + pos, NULL, n);

  goo_sha256_update(ctx, buf, size);

  return 1;
}

static int
goo_hash_all(
  unsigned char *out,
  goo_group_t *group,
  const mpz_t C1,
  const mpz_t C2,
  const mpz_t C3,
  const mpz_t t,
  const mpz_t A,
  const mpz_t B,
  const mpz_t C,
  const mpz_t D,
  const mpz_t E,
  const mpz_t msg
) {
  unsigned char *buf = &group->slab[0];
  size_t mod_bytes = group->size;
  size_t exp_bytes = (GOO_EXPONENT_SIZE + 7) / 8;

  goo_sha256_t ctx;

  // Copy the state of SHA256(prefix || n || g || h).
  // This gives us a very minor speedup.
  memcpy(&ctx, &group->sha, sizeof(goo_sha256_t));

  if (!goo_hash_item(&ctx, C1, mod_bytes, buf)
      || !goo_hash_item(&ctx, C2, mod_bytes, buf)
      || !goo_hash_item(&ctx, C3, mod_bytes, buf)
      || !goo_hash_item(&ctx, t, 4, buf)
      || !goo_hash_item(&ctx, A, mod_bytes, buf)
      || !goo_hash_item(&ctx, B, mod_bytes, buf)
      || !goo_hash_item(&ctx, C, mod_bytes, buf)
      || !goo_hash_item(&ctx, D, mod_bytes, buf)
      || !goo_hash_item(&ctx, E, exp_bytes, buf)
      || !goo_hash_item(&ctx, msg, 64, buf)) {
    return 0;
  }

  goo_sha256_final(&ctx, out);

  return 1;
}

static int
goo_group_fs_chal(
  goo_group_t *group,
  mpz_t chal,
  mpz_t ell,
  unsigned char *k,
  const mpz_t C1,
  const mpz_t C2,
  const mpz_t C3,
  const mpz_t t,
  const mpz_t A,
  const mpz_t B,
  const mpz_t C,
  const mpz_t D,
  const mpz_t E,
  const mpz_t msg,
  int verify
) {
  unsigned char key[32];

  if (!goo_hash_all(&key[0], group, C1, C2, C3, t, A, B, C, D, E, msg))
    return 0;

  goo_prng_seed(&group->prng, &key[0]);
  goo_prng_random_bits_nz(&group->prng, chal, GOO_CHAL_BITS);
  goo_prng_random_bits_nz(&group->prng, ell, GOO_CHAL_BITS);

  if (k != NULL)
    memcpy(k, key, 32);

  if (!verify) {
    // For prover, call next_prime on ell_r to get ell.
    if (!goo_next_prime(ell, ell, key, GOO_ELLDIFF_MAX)) {
      mpz_set_ui(chal, 0);
      mpz_set_ui(ell, 0);
      return 1;
    }
  }

  return 1;
}

static int
goo_group_expand_sprime(goo_group_t *group, mpz_t s, const mpz_t s_prime) {
  unsigned char key[32];
  size_t bytes = goo_mpz_bytelen(s_prime);

  if (bytes > 32)
    return 0;

  size_t pos = 32 - bytes;

  memset(&key[0], 0x00, pos);
  goo_mpz_export(&key[pos], NULL, s_prime);

  goo_prng_seed(&group->prng, &key[0]);
  goo_prng_random_bits_nz(&group->prng, s, GOO_EXPONENT_SIZE);

  return 1;
}

static int
goo_group_random_scalar(goo_group_t *group, mpz_t ret) {
  size_t bits = group->rand_bits;

  if (bits > GOO_EXPONENT_SIZE)
    bits = GOO_EXPONENT_SIZE;

  return goo_random_bits_nz(ret, bits);
}

static inline int
goo_is_valid_prime(const mpz_t n) {
  // if n <= 0
  if (mpz_sgn(n) <= 0)
    return 0;

  size_t bits = goo_mpz_bitlen(n);

  // if bitlen(n) > 4096
  if (bits > GOO_MAX_RSA_BITS)
    return 0;

  return 1;
}

static inline int
goo_is_valid_rsa(const mpz_t n) {
  // if n <= 0
  if (mpz_sgn(n) <= 0)
    return 0;

  size_t bits = goo_mpz_bitlen(n);

  // if bitlen(n) < 1024 or bitlen(n) > 4096
  if (bits < GOO_MIN_RSA_BITS || bits > GOO_MAX_RSA_BITS)
    return 0;

  return 1;
}

static int
goo_group_generate(goo_group_t *group, mpz_t s_prime) {
  // s_prime = randbits(256)
  if (!goo_random_bits_nz(s_prime, 256))
    return 0;

  return 1;
}

static int
goo_group_challenge(
  goo_group_t *group,
  mpz_t C1,
  const mpz_t s_prime,
  const mpz_t n
) {
  int r = 0;

  mpz_t s;
  mpz_init(s);

  if (mpz_sgn(s_prime) <= 0) {
    // Invalid seed length.
    goto fail;
  }

  // if n < 2^1023 or n > 2^4096 - 1
  if (!goo_is_valid_rsa(n)) {
    // Invalid RSA public key.
    goto fail;
  }

  // s = expand_sprime(s_prime)
  if (!goo_group_expand_sprime(group, s, s_prime))
    goto fail;

  // The challenge: a commitment to the RSA modulus.
  // C1 = powgh(n, s)
  if (!goo_group_powgh(group, C1, n, s))
    goto fail;

  // C1 = reduce(C1)
  goo_group_reduce(group, C1, C1);

  // if C1 <= 0
  if (mpz_sgn(C1) <= 0)
    goto fail;

  r = 1;
fail:
  mpz_clear(s);
  return r;
}

static int
goo_group_validate(
  goo_group_t *group,
  const mpz_t s_prime,
  const mpz_t C1,
  const mpz_t p,
  const mpz_t q
) {
  int r = 0;

  mpz_t n, s, x;
  mpz_init(n);
  mpz_init(s);
  mpz_init(x);

  // if s_prime <= 0 or C1 <= 0 or p <= 0 or q <= 0
  if (mpz_sgn(s_prime) <= 0
      || mpz_sgn(C1) <= 0
      || mpz_sgn(p) <= 0
      || mpz_sgn(q) <= 0) {
    // Invalid parameters.
    goto fail;
  }

  // if p > 2^4096 - 1 or q > 2^4096 - 1
  if (!goo_is_valid_prime(p) || !goo_is_valid_prime(q))
    goto fail;

  // n = p * q
  mpz_mul(n, p, q);

  // if n < 2^1023 or n > 2^4096 - 1
  if (!goo_is_valid_rsa(n)) {
    // Invalid RSA private key.
    goto fail;
  }

  // s = expand_sprime(s_prime)
  if (!goo_group_expand_sprime(group, s, s_prime))
    goto fail;

  // The challenge: a commitment to the RSA modulus.
  // x = powgh(n, s)
  if (!goo_group_powgh(group, x, n, s))
    goto fail;

  // x = reduce(x)
  goo_group_reduce(group, x, x);

  // if x <= 0
  if (mpz_sgn(x) <= 0)
    goto fail;

  // if C1 != x
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
goo_group_sign(
  goo_group_t *group,
  goo_sig_t *sig,
  const mpz_t msg,
  const mpz_t s_prime,
  const mpz_t p,
  const mpz_t q
) {
  int r = 0;

  mpz_t *C2 = &sig->C2;
  mpz_t *C3 = &sig->C3;
  mpz_t *t = &sig->t;
  mpz_t *chal = &sig->chal;
  mpz_t *ell = &sig->ell;
  mpz_t *Aq = &sig->Aq;
  mpz_t *Bq = &sig->Bq;
  mpz_t *Cq = &sig->Cq;
  mpz_t *Dq = &sig->Dq;
  mpz_t *Eq = &sig->Eq;
  mpz_t *z_w = &sig->z_w;
  mpz_t *z_w2 = &sig->z_w2;
  mpz_t *z_s1 = &sig->z_s1;
  mpz_t *z_a = &sig->z_a;
  mpz_t *z_an = &sig->z_an;
  mpz_t *z_s1w = &sig->z_s1w;
  mpz_t *z_sa = &sig->z_sa;
  mpz_t *z_s2 = &sig->z_s2;

  mpz_t n, s, C1, w, a, s1, s2;
  mpz_t x, y, z, xx, yy;
  mpz_t C1_inv, C2_inv;
  mpz_t r_w, r_w2, r_s1, r_a, r_an, r_s1w, r_sa, r_s2;
  mpz_t A, B, C, D, E;

  mpz_init(n);
  mpz_init(s);
  mpz_init(C1);
  mpz_init(w);
  mpz_init(a);
  mpz_init(s1);
  mpz_init(s2);
  mpz_init(x);
  mpz_init(y);
  mpz_init(z);
  mpz_init(xx);
  mpz_init(yy);
  mpz_init(C1_inv);
  mpz_init(C2_inv);
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

  // if s_prime <= 0 or p <= 0 or q <= 0
  if (mpz_sgn(s_prime) <= 0
      || mpz_sgn(p) <= 0
      || mpz_sgn(q) <= 0) {
    goto fail;
  }

  // if p > 2^4096 - 1 or q > 2^4096 - 1
  if (!goo_is_valid_prime(p) || !goo_is_valid_prime(q))
    goto fail;

  // n = p * q
  mpz_mul(n, p, q);

  // if n < 2^1023 or n > 2^4096 - 1
  if (!goo_is_valid_rsa(n)) {
    // Invalid RSA public key.
    goto fail;
  }

  // Preliminaries: compute values P needs to run the ZKPOK.
  // Find `t`.
  int found = 0;

  unsigned long primes[GOO_PRIMES_LEN];

  memcpy(&primes[0], &goo_primes[0], sizeof(goo_primes));

  for (long i = 0; i < GOO_PRIMES_LEN; i++) {
    // Partial in-place Fisher-Yates shuffle to choose random t.
    // Note: goo_random_num() is _exclusive_ of endpoints!
    unsigned long j = goo_random_num(GOO_PRIMES_LEN - i);
    unsigned long x = primes[i];
    unsigned long y = primes[i + j];

    primes[i] = y;
    primes[i + j] = x;

    // t = small_primes[i]
    mpz_set_ui(*t, primes[i]);

    // w = mod_sqrtn(t, p, q)
    if (goo_mpz_sqrtpq(w, *t, p, q)) {
      found = 1;
      break;
    }
  }

  if (!found) {
    // No prime quadratic residue less than 1000 mod N!
    goto fail;
  }

  // assert w > 0
  assert(mpz_sgn(w) > 0);

  // a = (w^2 - t) / n
  mpz_pow_ui(a, w, 2);
  mpz_sub(a, a, *t);
  mpz_tdiv_q(a, a, n);

  // assert a >= 0
  assert(mpz_sgn(a) >= 0);

  // x = a * n
  mpz_mul(x, a, n);

  // y = w^2 - t
  mpz_pow_ui(y, w, 2);
  mpz_sub(y, y, *t);

  // if x != y
  if (mpz_cmp(x, y) != 0) {
    // w^2 - t was not divisible by N!
    goto fail;
  }

  // Commitment to `n`.
  // s = expand_sprime(s_prime)
  if (!goo_group_expand_sprime(group, s, s_prime))
    goto fail;

  // C1 = powgh(n, s)
  if (!goo_group_powgh(group, C1, n, s))
    goto fail;

  // C1 = reduce(C1)
  goo_group_reduce(group, C1, C1);

  // Commitment to `w`.
  // s1 = rand_scalar()
  // C2 = powgh(w, s1)
  if (!goo_group_random_scalar(group, s1)
      || !goo_group_powgh(group, *C2, w, s1)) {
    goto fail;
  }

  goo_group_reduce(group, *C2, *C2);

  // Commitment to `a`.
  // s2 = rand_scalar()
  // C3 = powgh(a, s2)
  if (!goo_group_random_scalar(group, s2)
      || !goo_group_powgh(group, *C3, a, s2)) {
    goto fail;
  }

  goo_group_reduce(group, *C3, *C3);

  // if C1 <= 0 or C2 <= 0 or C3 <= 0
  if (mpz_sgn(C1) <= 0
      || mpz_sgn(*C2) <= 0
      || mpz_sgn(*C3) <= 0) {
    // Invalid C1, C2, or C3 value.
    goto fail;
  }

  // Inverses of `C1` and `C2`.
  // [C1_inv, C2_inv] = inv2(C1, C2)
  if (!goo_group_inv2(group, C1_inv, C2_inv, C1, *C2))
    goto fail;

  // P's first message: commit to randomness.
  // P's randomness (except for r_s1; see "V's message", below).
  // [r_w, r_w2, r_a, r_an, r_s1w, r_sa, r_s2] = rand_scalar(7)
  if (!goo_group_random_scalar(group, r_w)
      || !goo_group_random_scalar(group, r_w2)
      || !goo_group_random_scalar(group, r_a)
      || !goo_group_random_scalar(group, r_an)
      || !goo_group_random_scalar(group, r_s1w)
      || !goo_group_random_scalar(group, r_sa)
      || !goo_group_random_scalar(group, r_s2)) {
    goto fail;
  }

  // Prevent E from being negative.
  if (mpz_cmp(r_w2, r_an) < 0) {
    // [r_w2, r_an] = [r_an, r_w2]
    mpz_swap(r_w2, r_an);
  }

  // P's first message (except for A; see "V's message", below).
  // B = powgh(r_a, r_s2)
  if (!goo_group_powgh(group, B, r_a, r_s2))
    goto fail;

  goo_group_reduce(group, B, B);

  // C = pow(C2_inv, C2, r_w) * powgh(r_w2, r_s1w)
  goo_group_pow(group, x, C2_inv, *C2, r_w);

  if (!goo_group_powgh(group, y, r_w2, r_s1w))
    goto fail;

  goo_group_mul(group, C, x, y);
  goo_group_reduce(group, C, C);

  // D = pow(C1_inv, C1, r_a) * powgh(r_an, r_sa)
  goo_group_pow(group, x, C1_inv, C1, r_a);

  if (!goo_group_powgh(group, y, r_an, r_sa))
    goto fail;

  goo_group_mul(group, D, x, y);
  goo_group_reduce(group, D, D);

  // E = r_w2 - r_an
  mpz_sub(E, r_w2, r_an);

  // assert E >= 0
  assert(mpz_sgn(E) >= 0);

  // ell = 0
  mpz_set_ui(*ell, 0);

  // V's message: random challenge and random prime.
  // while bitlen(ell) != 128
  while (goo_mpz_bitlen(*ell) != 128) {
    // Randomize the signature until Fiat-Shamir
    // returns an admissable ell. Note that it's
    // not necessary to re-start the whole
    // signature! Just pick a new r_s1, which
    // only requires re-computing A.
    // r_s1 = rand_scalar()
    // A = powgh(r_w, r_s1)
    if (!goo_group_random_scalar(group, r_s1)
        || !goo_group_powgh(group, A, r_w, r_s1)) {
      goto fail;
    }

    goo_group_reduce(group, A, A);

    // [chal, ell] = fs_chal(C1, C2, C3, t, A, B, C, D, E, msg)
    if (!goo_group_fs_chal(group,
                           *chal, *ell, NULL, C1, *C2, *C3,
                           *t, A, B, C, D, E, msg, 0)) {
      goto fail;
    }
  }

  // if A <= 0 or B <= 0 or C <= 0 or D <= 0 or E <= 0
  if (mpz_sgn(A) <= 0
      || mpz_sgn(B) <= 0
      || mpz_sgn(C) <= 0
      || mpz_sgn(D) <= 0
      || mpz_sgn(E) <= 0) {
    // Invalid A, B, C, D, or E value.
    goto fail;
  }

  // P's second message: compute quotient message.
  // Compute z' = c*(w, w2, s1, a, an, s1w, sa, s2)
  //            + (r_w, r_w2, r_s1, r_a, r_an, r_s1w, r_sa, r_s2)
  // z_w = chal * w + r_w
  mpz_mul(*z_w, *chal, w);
  mpz_add(*z_w, *z_w, r_w);
  // z_w2 = chal * w * w + r_w2
  mpz_mul(*z_w2, *chal, w);
  mpz_mul(*z_w2, *z_w2, w);
  mpz_add(*z_w2, *z_w2, r_w2);
  // z_s1 = chal * s1 + r_s1
  mpz_mul(*z_s1, *chal, s1);
  mpz_add(*z_s1, *z_s1, r_s1);
  // z_a = chal * a + r_a
  mpz_mul(*z_a, *chal, a);
  mpz_add(*z_a, *z_a, r_a);
  // z_an = chal * a * n + r_an
  mpz_mul(*z_an, *chal, a);
  mpz_mul(*z_an, *z_an, n);
  mpz_add(*z_an, *z_an, r_an);
  // z_s1w = chal * s1 * w + r_s1w
  mpz_mul(*z_s1w, *chal, s1);
  mpz_mul(*z_s1w, *z_s1w, w);
  mpz_add(*z_s1w, *z_s1w, r_s1w);
  // z_sa = chal * s * a + r_sa
  mpz_mul(*z_sa, *chal, s);
  mpz_mul(*z_sa, *z_sa, a);
  mpz_add(*z_sa, *z_sa, r_sa);
  // z_s2 = chal * s2 + r_s2
  mpz_mul(*z_s2, *chal, s2);
  mpz_add(*z_s2, *z_s2, r_s2);

  // Compute quotient commitments.

  // Aq = powgh(z_w / ell, z_s1 / ell)
  mpz_tdiv_q(x, *z_w, *ell);
  mpz_tdiv_q(y, *z_s1, *ell);

  if (!goo_group_powgh(group, *Aq, x, y))
    goto fail;

  goo_group_reduce(group, *Aq, *Aq);

  // Bq = powgh(z_a / ell, z_s2 / ell)
  mpz_tdiv_q(x, *z_a, *ell);
  mpz_tdiv_q(y, *z_s2, *ell);

  if (!goo_group_powgh(group, *Bq, x, y))
    goto fail;

  goo_group_reduce(group, *Bq, *Bq);

  // Cq = pow(C2_inv, C2, z_w / ell) * powgh(z_w2 / ell, z_s1w / ell)
  mpz_tdiv_q(x, *z_w, *ell);
  mpz_tdiv_q(y, *z_w2, *ell);
  mpz_tdiv_q(z, *z_s1w, *ell);
  goo_group_pow(group, xx, C2_inv, *C2, x);

  if (!goo_group_powgh(group, yy, y, z))
    goto fail;

  goo_group_mul(group, *Cq, xx, yy);
  goo_group_reduce(group, *Cq, *Cq);

  // Dq = pow(C1_inv, C2, z_a / ell) * powgh(z_an / ell, z_sa / ell)
  mpz_tdiv_q(x, *z_a, *ell);
  mpz_tdiv_q(y, *z_an, *ell);
  mpz_tdiv_q(z, *z_sa, *ell);
  goo_group_pow(group, xx, C1_inv, *C2, x);

  if (!goo_group_powgh(group, yy, y, z))
    goto fail;

  goo_group_mul(group, *Dq, xx, yy);
  goo_group_reduce(group, *Dq, *Dq);

  // Eq = (z_w2 - z_an) / ell
  mpz_sub(*Eq, *z_w2, *z_an);
  mpz_tdiv_q(*Eq, *Eq, *ell);

  // assert Eq >= 0
  assert(mpz_sgn(*Eq) >= 0);
  assert(goo_mpz_bitlen(*Eq) <= GOO_EXPONENT_SIZE);

  // if Aq <= 0 or Bq <= 0 or Cq <= 0 or Dq <= 0 or Eq <= 0
  if (mpz_sgn(*Aq) <= 0
      || mpz_sgn(*Bq) <= 0
      || mpz_sgn(*Cq) <= 0
      || mpz_sgn(*Dq) <= 0
      || mpz_sgn(*Eq) <= 0) {
    // Invalid Aq, Bq, Cq, Dq, or Eq value.
    goto fail;
  }

  mpz_mod(*z_w, *z_w, *ell);
  mpz_mod(*z_w2, *z_w2, *ell);
  mpz_mod(*z_s1, *z_s1, *ell);
  mpz_mod(*z_a, *z_a, *ell);
  mpz_mod(*z_an, *z_an, *ell);
  mpz_mod(*z_s1w, *z_s1w, *ell);
  mpz_mod(*z_sa, *z_sa, *ell);
  mpz_mod(*z_s2, *z_s2, *ell);

  // if z_w <= 0 or z_w2 <= 0 or z_s1 <= 0 or z_a <= 0
  // or z_an <= 0 or z_s1w <= 0 or z_sa <= 0 or z_s2 <= 0
  if (mpz_sgn(*z_w) <= 0
      || mpz_sgn(*z_w2) <= 0
      || mpz_sgn(*z_s1) <= 0
      || mpz_sgn(*z_a) <= 0
      || mpz_sgn(*z_an) <= 0
      || mpz_sgn(*z_s1w) <= 0
      || mpz_sgn(*z_sa) <= 0
      || mpz_sgn(*z_s2) <= 0) {
    // Invalid z_prime value.
    goto fail;
  }

  // z_prime: (z_w, z_w2, z_s1, z_a, z_an, z_s1w, z_sa, z_s2).
  // Signature: (chal, ell, Aq, Bq, Cq, Dq, Eq, z_prime).

  r = 1;
fail:
  mpz_clear(n);
  mpz_clear(s);
  mpz_clear(C1);
  mpz_clear(w);
  mpz_clear(a);
  mpz_clear(s1);
  mpz_clear(s2);
  mpz_clear(x);
  mpz_clear(y);
  mpz_clear(z);
  mpz_clear(xx);
  mpz_clear(yy);
  mpz_clear(C1_inv);
  mpz_clear(C2_inv);
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
goo_group_verify(
  goo_group_t *group,
  const mpz_t msg,
  const goo_sig_t *sig,
  const mpz_t C1
) {
  const mpz_t *C2 = &sig->C2;
  const mpz_t *C3 = &sig->C3;
  const mpz_t *t = &sig->t;
  const mpz_t *chal = &sig->chal;
  const mpz_t *ell = &sig->ell;
  const mpz_t *Aq = &sig->Aq;
  const mpz_t *Bq = &sig->Bq;
  const mpz_t *Cq = &sig->Cq;
  const mpz_t *Dq = &sig->Dq;
  const mpz_t *Eq = &sig->Eq;
  const mpz_t *z_w = &sig->z_w;
  const mpz_t *z_w2 = &sig->z_w2;
  const mpz_t *z_s1 = &sig->z_s1;
  const mpz_t *z_a = &sig->z_a;
  const mpz_t *z_an = &sig->z_an;
  const mpz_t *z_s1w = &sig->z_s1w;
  const mpz_t *z_sa = &sig->z_sa;
  const mpz_t *z_s2 = &sig->z_s2;

  mpz_t *C1_inv = &group->C1_inv;
  mpz_t *C2_inv = &group->C2_inv;
  mpz_t *C3_inv = &group->C3_inv;
  mpz_t *Aq_inv = &group->Aq_inv;
  mpz_t *Bq_inv = &group->Bq_inv;
  mpz_t *Cq_inv = &group->Cq_inv;
  mpz_t *Dq_inv = &group->Dq_inv;
  mpz_t *A = &group->A;
  mpz_t *B = &group->B;
  mpz_t *C = &group->C;
  mpz_t *D = &group->D;
  mpz_t *E = &group->E;
  mpz_t *z_w2_m_an = &group->z_w2_m_an;
  mpz_t *tmp = &group->tmp;
  mpz_t *chal_out = &group->chal_out;
  mpz_t *ell_r_out = &group->ell_r_out;
  mpz_t *elldiff = &group->elldiff;

  unsigned char key[32];

  // Sanity check.
  if (mpz_sgn(C1) <= 0
      || mpz_sgn(*C2) <= 0
      || mpz_sgn(*C3) <= 0
      || mpz_sgn(*t) <= 0
      || mpz_sgn(*chal) <= 0
      || mpz_sgn(*ell) <= 0
      || mpz_sgn(*Aq) <= 0
      || mpz_sgn(*Bq) <= 0
      || mpz_sgn(*Cq) <= 0
      || mpz_sgn(*Dq) <= 0
      || mpz_sgn(*Eq) <= 0
      || mpz_sgn(*z_w) <= 0
      || mpz_sgn(*z_w2) <= 0
      || mpz_sgn(*z_s1) <= 0
      || mpz_sgn(*z_a) <= 0
      || mpz_sgn(*z_an) <= 0
      || mpz_sgn(*z_s1w) <= 0
      || mpz_sgn(*z_sa) <= 0
      || mpz_sgn(*z_s2) <= 0) {
    return 0;
  }

  // if bitlen(ell) > 128
  if (goo_mpz_bitlen(*ell) > 128)
    return 0;

  // `t` must be one of the small primes in our list.
  int found = 0;

  for (long i = 0; i < GOO_PRIMES_LEN; i++) {
    // if t == primes[i]
    if (mpz_cmp_ui(*t, goo_primes[i]) == 0) {
      found = 1;
      break;
    }
  }

  if (!found)
    return 0;

  // All group elements must be the "canonical"
  // element of the quotient group (Z/n)/{1,-1}.
  if (!goo_group_is_reduced(group, C1)
      || !goo_group_is_reduced(group, *C2)
      || !goo_group_is_reduced(group, *C3)
      || !goo_group_is_reduced(group, *Aq)
      || !goo_group_is_reduced(group, *Bq)
      || !goo_group_is_reduced(group, *Cq)
      || !goo_group_is_reduced(group, *Dq)) {
    return 0;
  }

  // Compute inverses of C1, C2, C3, Aq, Bq, Cq, Dq.
  // [C1_inv, C2_inv, C3_inv,
  //  Aq_inv, Bq_inv, Cq_inv, Dq_inv] = inv7(C1, C2, C3, Aq, Bq, Cq, Dq)
  if (!goo_group_inv7(group, *C1_inv, *C2_inv, *C3_inv,
                             *Aq_inv, *Bq_inv, *Cq_inv, *Dq_inv,
                              C1, *C2, *C3, *Aq, *Bq, *Cq, *Dq)) {
    return 0;
  }

  // Step 1: reconstruct A, B, C, D, and E from signature.
  // A = recon(Aq, Aq_inv, ell, C2_inv, C2, chal, z_w, z_s1)
  if (!goo_group_recon(group, *A, *Aq, *Aq_inv, *ell,
                       *C2_inv, *C2, *chal, *z_w, *z_s1)) {
    return 0;
  }

  // B = recon(Bq, Bq_inv, ell, C3_inv, C3, chal, z_a, z_s2)
  if (!goo_group_recon(group, *B, *Bq, *Bq_inv, *ell,
                       *C3_inv, *C3, *chal, *z_a, *z_s2)) {
    return 0;
  }

  // C = recon(Cq, Cq_inv, ell, C2_inv, C2, z_w, z_w2, z_s1w)
  if (!goo_group_recon(group, *C, *Cq, *Cq_inv, *ell,
                       *C2_inv, *C2, *z_w, *z_w2, *z_s1w)) {
    return 0;
  }

  // D = recon(Dq, Dq_inv, ell, C1_inv, C1, z_a, z_an, z_sa)
  if (!goo_group_recon(group, *D, *Dq, *Dq_inv, *ell,
                       *C1_inv, C1, *z_a, *z_an, *z_sa)) {
    return 0;
  }

  // Make sure sign of (z_w2 - z_an) is positive.
  // z_w2_m_an = z_w2 - z_an
  mpz_sub(*z_w2_m_an, *z_w2, *z_an);

  // E = Eq * ell + z_w2_m_an - t * chal
  mpz_mul(*E, *Eq, *ell);
  mpz_add(*E, *E, *z_w2_m_an);
  mpz_mul(*tmp, *t, *chal);
  mpz_sub(*E, *E, *tmp);

  // if z_w2_m_an < 0
  if (mpz_sgn(*z_w2_m_an) < 0) {
    // E += ell
    mpz_add(*E, *E, *ell);
  }

  // if E < 0
  if (mpz_sgn(*E) < 0)
    return 0;

  // Step 2: recompute implicitly claimed V message, viz., chal and ell.
  // [chal_out, ell_r_out, key] = fs_chal(C1, C2, t, A, B, C, D, msg)
  if (!goo_group_fs_chal(group, *chal_out, *ell_r_out, &key[0],
                         C1, *C2, *C3, *t, *A, *B, *C, *D, *E, msg, 1)) {
    return 0;
  }

  // Final checks.
  // chal has to match
  // AND 0 <= (ell_r_out - ell) <= elldiff_max
  // AND ell is prime
  // elldiff = ell - ell_r_out
  mpz_sub(*elldiff, *ell, *ell_r_out);

  // if chal != chal_out
  //   or elldiff < 0
  //   or elldiff > ELLDIFF_MAX
  //   or !is_prime(ell)
  if (mpz_cmp(*chal, *chal_out) != 0
      || mpz_cmp_ui(*elldiff, 0) < 0
      || mpz_cmp_ui(*elldiff, GOO_ELLDIFF_MAX) > 0
      || !goo_is_prime(*ell, &key[0])) {
    return 0;
  }

  return 1;
}

/*
 * API
 */

int
goo_init(
  goo_ctx_t *ctx,
  const unsigned char *n,
  size_t n_len,
  unsigned long g,
  unsigned long h,
  unsigned long modbits
) {
  int r = 0;

  if (ctx == NULL || n == NULL)
    return 0;

  mpz_t n_n;
  mpz_init(n_n);

  goo_mpz_import(n_n, n, n_len);

  if (!goo_group_init(ctx, n_n, g, h, modbits))
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
goo_generate(
  goo_ctx_t *ctx,
  unsigned char **s_prime,
  size_t *s_prime_len
) {
  int r = 0;

  if (ctx == NULL
      || s_prime == NULL
      || s_prime_len == NULL) {
    return 0;
  }

  mpz_t s_prime_n;
  mpz_init(s_prime_n);

  if (!goo_group_generate(ctx, s_prime_n))
    goto fail;

  *s_prime_len = 32;
  *s_prime = goo_mpz_pad(NULL, *s_prime_len, s_prime_n);

  if (*s_prime == NULL)
    goto fail;

  r = 1;
fail:
  mpz_clear(s_prime_n);
  return r;
}

int
goo_challenge(
  goo_ctx_t *ctx,
  unsigned char **C1,
  size_t *C1_len,
  const unsigned char *s_prime,
  size_t s_prime_len,
  const unsigned char *n,
  size_t n_len
) {
  int r = 0;

  if (ctx == NULL
      || s_prime == NULL
      || C1 == NULL
      || C1_len == NULL
      || n == NULL) {
    return 0;
  }

  if (s_prime_len != 32)
    return 0;

  mpz_t C1_n, s_prime_n, n_n;
  mpz_init(C1_n);
  mpz_init(s_prime_n);
  mpz_init(n_n);

  goo_mpz_import(s_prime_n, s_prime, s_prime_len);
  goo_mpz_import(n_n, n, n_len);

  if (!goo_group_challenge(ctx, C1_n, s_prime_n, n_n))
    goto fail;

  *C1_len = goo_mpz_bytelen(ctx->n);
  *C1 = goo_mpz_pad(NULL, *C1_len, C1_n);

  if (*C1 == NULL)
    goto fail;

  r = 1;
fail:
  mpz_clear(C1_n);
  mpz_clear(s_prime_n);
  mpz_clear(n_n);
  return r;
}

int
goo_validate(
  goo_ctx_t *ctx,
  const unsigned char *s_prime,
  size_t s_prime_len,
  const unsigned char *C1,
  size_t C1_len,
  const unsigned char *p,
  size_t p_len,
  const unsigned char *q,
  size_t q_len
) {
  int r = 0;

  if (ctx == NULL
      || s_prime == NULL
      || C1 == NULL
      || p == NULL
      || q == NULL) {
    return 0;
  }

  if (s_prime_len != 32)
    return 0;

  if (C1_len != ctx->size)
    return 0;

  mpz_t s_prime_n, C1_n, p_n, q_n;

  mpz_init(s_prime_n);
  mpz_init(C1_n);
  mpz_init(p_n);
  mpz_init(q_n);

  goo_mpz_import(s_prime_n, s_prime, s_prime_len);
  goo_mpz_import(C1_n, C1, C1_len);
  goo_mpz_import(p_n, p, p_len);
  goo_mpz_import(q_n, q, q_len);

  if (!goo_group_validate(ctx, s_prime_n, C1_n, p_n, q_n))
    goto fail;

  r = 1;
fail:
  mpz_clear(s_prime_n);
  mpz_clear(C1_n);
  mpz_clear(p_n);
  mpz_clear(q_n);

  return r;
}

int
goo_sign(
  goo_ctx_t *ctx,
  unsigned char **out,
  size_t *out_len,
  const unsigned char *msg,
  size_t msg_len,
  const unsigned char *s_prime,
  size_t s_prime_len,
  const unsigned char *p,
  size_t p_len,
  const unsigned char *q,
  size_t q_len
) {
  int r = 0;

  if (ctx == NULL
      || out == NULL
      || out_len == NULL
      || msg == NULL
      || s_prime == NULL
      || p == NULL
      || q == NULL) {
    return 0;
  }

  if (msg_len < 20 || msg_len > 64)
    return 0;

  if (s_prime_len != 32)
    return 0;

  mpz_t msg_n, s_prime_n, p_n, q_n;
  goo_sig_t sig;
  size_t size;
  unsigned char *data = NULL;

  mpz_init(msg_n);
  mpz_init(s_prime_n);
  mpz_init(p_n);
  mpz_init(q_n);

  goo_sig_init(&sig);

  goo_mpz_import(msg_n, msg, msg_len);
  goo_mpz_import(s_prime_n, s_prime, s_prime_len);
  goo_mpz_import(p_n, p, p_len);
  goo_mpz_import(q_n, q, q_len);

  if (!goo_group_sign(ctx, &sig, msg_n, s_prime_n, p_n, q_n))
    goto fail;

  size = goo_sig_size(&sig, ctx->bits);
  data = malloc(size);

  if (data == NULL)
    goto fail;

  if (!goo_sig_export(data, &sig, ctx->bits))
    goto fail;

  *out = data;
  *out_len = size;

  r = 1;
fail:
  mpz_clear(msg_n);
  mpz_clear(s_prime_n);
  mpz_clear(p_n);
  mpz_clear(q_n);
  goo_sig_uninit(&sig);

  if (r == 0)
    goo_free(data);

  return r;
}

int
goo_verify(
  goo_ctx_t *ctx,
  const unsigned char *msg,
  size_t msg_len,
  const unsigned char *sig,
  size_t sig_len,
  const unsigned char *C1,
  size_t C1_len
) {
  if (ctx == NULL || msg == NULL || sig == NULL || C1 == NULL)
    return 0;

  if (msg_len < 20 || msg_len > 64)
    return 0;

  if (C1_len != ctx->size)
    return 0;

  goo_mpz_import(ctx->msg, msg, msg_len);
  goo_mpz_import(ctx->C1, C1, C1_len);

  if (!goo_sig_import(&ctx->sig, sig, sig_len, ctx->bits))
    return 0;

  return goo_group_verify(ctx, ctx->msg, &ctx->sig, ctx->C1);
}

#ifdef GOO_TEST
#include <stdio.h>

static int
goo_hex_cmp(const unsigned char *data, size_t len, const char *expect) {
  mpz_t x, y;

  mpz_init(x);
  mpz_init(y);

  goo_mpz_import(x, data, len);

  assert(mpz_set_str(y, expect, 16) == 0);

  int r = mpz_cmp(x, y);

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

  memset(&key[0], 0xff, 32);

  printf("Testing HMAC...\n");

  goo_hmac_t ctx;
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

  memset(&entropy[0], 0xaa, 64);

  printf("Testing DRBG...\n");

  goo_drbg_t ctx;
  goo_drbg_init(&ctx, &entropy[0], 64);

  goo_drbg_generate(&ctx, &out[0], 32);
  assert(goo_hex_cmp(&out[0], 32, expect1) == 0);

  goo_drbg_generate(&ctx, &out[0], 16);
  assert(goo_hex_cmp(&out[0], 16, expect2) == 0);

  goo_drbg_generate(&ctx, &out[0], 16);
  assert(goo_hex_cmp(&out[0], 16, expect3) == 0);
}

static void
run_rng_test(void) {
  mpz_t x, y;

  printf("Testing RNG...\n");

  mpz_init(x);
  mpz_init(y);

  assert(goo_random_bits(x, 256));
  assert(mpz_sgn(x) > 0);
  assert(goo_mpz_bitlen(x) <= 256);

  assert(goo_random_int(y, x));
  assert(mpz_sgn(y) > 0);
  assert(goo_mpz_bitlen(y) <= 256);
  assert(mpz_cmp(y, x) < 0);

  mpz_clear(x);
  mpz_clear(y);
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
  assert(mpz_cmp_ui(x, 540405817) == 0);
  goo_prng_random_bits(&prng, x, 31);
  assert(mpz_cmp_ui(x, 1312024779) == 0);
  goo_prng_random_bits(&prng, x, 31);
  goo_prng_random_int(&prng, y, x);
  assert(mpz_cmp_ui(y, 665860407) == 0);

  mpz_clear(x);
  mpz_clear(y);
  goo_prng_uninit(&prng);
}

static void
run_util_test(void) {
  // test bitlen and zerobits
  {
    printf("Testing bitlen & zerobits...\n");

    mpz_t n;
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

  // test mask
  {
    printf("Testing mask...\n");

    mpz_t n, t;

    mpz_init(n);
    mpz_init(t);

    mpz_set_ui(n, 0xffff1234);

    goo_mpz_mask(n, n, 16, t);

    assert(mpz_get_ui(n) == 0x1234);

    mpz_clear(n);
    mpz_clear(t);
  }

  // test sqrt
  {
    printf("Testing sqrt...\n");

    assert(goo_dsqrt(1024) == 32);
    assert(goo_dsqrt(1025) == 32);
  }

  // test division
  {
    printf("Testing division...\n");
    mpz_t x, y, z;
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

  // test modulo
  {
    printf("Testing modulo...\n");
    mpz_t x, y, z;
    mpz_init(x);
    mpz_init(y);
    mpz_init(z);

    // Note: This equals 1 with mpz_mod.
    mpz_set_si(x, 3);
    mpz_set_si(y, -2);
    mpz_fdiv_r(z, x, y);
    assert(mpz_get_si(z) == -1);

    // Note: mpz_tdiv_r behaves like mpz_mod.
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

  // test sqrts
  {
    printf("Testing roots...\n");

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

    mpz_init(p);
    mpz_init(q);
    mpz_init(n);

    assert(mpz_set_str(p, p_hex, 16) == 0);
    assert(mpz_set_str(q, q_hex, 16) == 0);

    mpz_mul(n, p, q);

    // test sqrt_modp
    {
      printf("Testing sqrt_modp...\n");

      mpz_t r1;
      mpz_t sr1;

      mpz_init(r1);
      mpz_init(sr1);

      assert(goo_random_int(r1, p));
      mpz_powm_ui(r1, r1, 2, p);

      assert(goo_mpz_sqrtp(sr1, r1, p));

      mpz_powm_ui(sr1, sr1, 2, p);

      assert(mpz_cmp(sr1, r1) == 0);

      mpz_clear(r1);
      mpz_clear(sr1);
    }

    // test sqrt_modn
    {
      printf("Testing sqrt_modn...\n");

      mpz_t r2;
      mpz_t sr2;

      mpz_init(r2);
      mpz_init(sr2);

      assert(goo_random_int(r2, n));
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

  // https://github.com/golang/go/blob/aadaec5/src/math/big/int_test.go#L1590
  static const int symbols[17][3] = {
    {0, 1, 1},
    {0, -1, 1},
    {1, 1, 1},
    {1, -1, 1},
    {0, 5, 0},
    {1, 5, 1},
    {2, 5, -1},
    {-2, 5, -1},
    {2, -5, -1},
    {-2, -5, 1},
    {3, 5, -1},
    {5, 5, 0},
    {-5, 5, 0},
    {6, 5, 1},
    {6, -5, 1},
    {-6, 5, 1},
    {-6, -5, -1}
  };

  // test jacobi
  {
    printf("Testing jacobi...\n");

    for (int i = 0; i < 17; i++) {
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
}

static void
run_primes_test(void) {
  // https://github.com/golang/go/blob/aadaec5/src/math/big/prime_test.go
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

    // https://golang.org/issue/638
    "18699199384836356663",

    "98920366548084643601728869055592650835572950"
    "932266967461790948584315647051443",

    "94560208308847015747498523884063394671606671"
    "904944666360068158221458669711639",

    // https://primes.utm.edu/lists/small/small3.html
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

    // ECC primes: https://tools.ietf.org/html/draft-ladd-safecurves-02
    // Curve1174: 2^251-9

    "36185027886661311069865932815214971204146870"
    "20801267626233049500247285301239",

    // Curve25519: 2^255-19

    "57896044618658097711785492504343953926634992"
    "332820282019728792003956564819949",

    // E-382: 2^382-105

    "98505015490986198030697600250359034512699348"
    "17616361666987073351061430442874302652853566"
    "563721228910201656997576599",

    // Curve41417: 2^414-17

    "42307582002575910332922579714097346549017899"
    "70971399803421752289756197063912392613281210"
    "9468141778230245837569601494931472367",

    // E-521: 2^521-1

    "68647976601306097149819007990813932172694353"
    "00143305409394463459185543183397656052122559"
    "64066145455497729631139148085803712198799971"
    "6643812574028291115057151"
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

    // Arnault, "Rabin-Miller Primality Test: Composite Numbers Which Pass It",
    // Mathematics of Computation, 64(209) (January 1995), pp. 335-361.

    // Strong pseudoprime to prime bases 2 through 29.
    "1195068768795265792518361315725116351898245581",

    // Strong pseudoprime to all prime bases up to 200.
    "8038374574536394912570796143419421081388376882"
    "8755814583748891752229742737653336521865023361"
    "6396004545791504202360320876656996676098728404"
    "3965408232928738791850869166857328267761771029"
    "3896977394701670823042868710999743997654414484"
    "5341155872450633409279022275296229414984230688"
    "1685404326457534018329786111298960644845216191"
    "652872597534901",

    // Extra-strong Lucas pseudoprimes.
    // https://oeis.org/A217719
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

#define GOO_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

  unsigned char key[32];
  unsigned char zero[32];

  assert(goo_random(key, 32));

  memset(&zero[0], 0x00, 32);

  printf("Testing primes...\n");

  for (int i = 0; i < (int)GOO_ARRAY_SIZE(primes); i++) {
    mpz_t p;
    mpz_init(p);

    assert(mpz_set_str(p, primes[i], 10) == 0);
    assert(goo_is_prime_div(p));
    assert(goo_is_prime_mr(p, key, 16 + 1, 1));
    assert(goo_is_prime_mr(p, key, 1, 1));
    assert(goo_is_prime_mr(p, key, 1, 0));
    assert(goo_is_prime_lucas(p));
    assert(goo_is_prime(p, key));

    mpz_clear(p);
  }

  printf("Testing composites...\n");

  for (int i = 0; i < (int)GOO_ARRAY_SIZE(composites); i++) {
    mpz_t p;
    mpz_init(p);

    assert(mpz_set_str(p, composites[i], 10) == 0);

    if (i == 6 || i == 7 || (i >= 43 && i <= 49) || i == 54) {
      assert(goo_is_prime_div(p));
    } else {
      // We actually catch a surpising
      // number of composites here.
      assert(!goo_is_prime_div(p));
    }

    // MR with a deterministic key.
    assert(!goo_is_prime_mr(p, zero, 16 + 1, 1));
    assert(!goo_is_prime_mr(p, zero, 4, 1));
    assert(!goo_is_prime_mr(p, zero, 4, 0));

    if (i >= 8 && i <= 42) {
      // Lucas pseudoprime.
      assert(goo_is_prime_lucas(p));
    } else {
      assert(!goo_is_prime_lucas(p));
    }

    // No composite should ever pass
    // Baillie-PSW, random or otherwise.
    assert(!goo_is_prime(p, zero));
    assert(!goo_is_prime(p, key));

    mpz_clear(p);
  }

#undef GOO_ARRAY_SIZE

  // test next_prime
  {
    printf("Testing next_prime...\n");

    mpz_t n;
    mpz_init(n);
    mpz_set_ui(n, 4);

    assert(goo_next_prime(n, n, zero, 512));

    assert(mpz_get_ui(n) == 5);

    mpz_clear(n);
  }
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

  printf("Testing group ops...\n");

  mpz_t n;
  goo_group_t *goo;

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

    assert(goo->combs[1].g.points_per_add == 7);
    assert(goo->combs[1].g.adds_per_shift == 4);
    assert(goo->combs[1].g.shifts == 151);
    assert(goo->combs[1].g.bits_per_window == 604);
    assert(goo->combs[1].g.bits == 4228);
    assert(goo->combs[1].g.points_per_subcomb == 127);
    assert(goo->combs[1].g.size == 508);

    assert(goo->combs[1].h.points_per_add == 7);
    assert(goo->combs[1].h.adds_per_shift == 4);
    assert(goo->combs[1].h.shifts == 151);
    assert(goo->combs[1].h.bits_per_window == 604);
    assert(goo->combs[1].h.bits == 4228);
    assert(goo->combs[1].h.points_per_subcomb == 127);
    assert(goo->combs[1].h.size == 508);
  }

  // test pow2
  {
    printf("Testing pow2...\n");

    mpz_t b1, b2, e1, e2;
    mpz_t b1_inv, b2_inv;
    mpz_t r1, r2;

    mpz_init(b1);
    mpz_init(b2);
    mpz_init(e1);
    mpz_init(e2);

    mpz_init(b1_inv);
    mpz_init(b2_inv);

    mpz_init(r1);
    mpz_init(r2);

    assert(goo_random_bits(b1, 2048));
    assert(goo_random_bits(b2, 2048));
    assert(goo_random_bits(e1, 128));
    assert(goo_random_bits(e2, 128));

    assert(goo_group_inv2(goo, b1_inv, b2_inv, b1, b2));

    assert(goo_group_pow2_slow(goo, r1, b1, b1_inv, e1, b2, b2_inv, e2));
    assert(goo_group_pow2(goo, r2, b1, b1_inv, e1, b2, b2_inv, e2));

    assert(mpz_cmp(r1, r2) == 0);

    mpz_clear(b1);
    mpz_clear(b2);
    mpz_clear(e1);
    mpz_clear(e2);
    mpz_clear(b1_inv);
    mpz_clear(b2_inv);
    mpz_clear(r1);
    mpz_clear(r2);
  }

  // test powgh
  {
    printf("Testing powgh...\n");

    mpz_t e1, e2;
    mpz_t r1, r2;

    mpz_init(e1);
    mpz_init(e2);

    mpz_init(r1);
    mpz_init(r2);

    assert(goo_random_bits(e1, 2048 + GOO_CHAL_BITS + 2 - 1));
    assert(goo_random_bits(e2, 2048 + GOO_CHAL_BITS + 2 - 1));

    assert(goo_group_powgh_slow(goo, r1, e1, e2));
    assert(goo_group_powgh(goo, r2, e1, e2));

    assert(mpz_cmp(r1, r2) == 0);

    mpz_clear(e1);
    mpz_clear(e2);
    mpz_clear(r1);
    mpz_clear(r2);
  }

  // test inv2
  {
    printf("Testing inv2...\n");

    mpz_t e1, e2;
    mpz_t e1_s, e2_s;
    mpz_t e1_si, e2_si;
    mpz_t r1, r2;

    mpz_init(e1);
    mpz_init(e2);
    mpz_init(e1_s);
    mpz_init(e2_s);
    mpz_init(e1_si);
    mpz_init(e2_si);

    mpz_init(r1);
    mpz_init(r2);

    assert(goo_random_bits(e1, 2048));
    assert(goo_random_bits(e2, 2048));

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

  // test inv7
  {
    printf("Testing inv7...\n");

    mpz_t evals[7];
    mpz_t einvs[7];

    for (int i = 0; i < 7; i++) {
      mpz_init(evals[i]);
      mpz_init(einvs[i]);

      assert(goo_random_bits(evals[i], 2048));
    }

    assert(goo_group_inv7(goo,
      einvs[0], einvs[1], einvs[2], einvs[3], einvs[4], einvs[5], einvs[6],
      evals[0], evals[1], evals[2], evals[3], evals[4], evals[5], evals[6]));

    for (int i = 0; i < 7; i++) {
      mpz_mul(evals[i], evals[i], einvs[i]);
      mpz_mod(evals[i], evals[i], goo->n);

      goo_group_reduce(goo, evals[i], evals[i]);

      assert(mpz_cmp_ui(evals[i], 1) == 0);

      mpz_clear(evals[i]);
      mpz_clear(einvs[i]);
    }
  }

  mpz_clear(n);
  goo_group_uninit(goo);
  goo_free(goo);
}

static void
run_combspec_test(void) {
  goo_combspec_t spec;

  printf("Testing combspec...\n");

  assert(goo_combspec_init(&spec, GOO_CHAL_BITS, GOO_MAX_COMB_SIZE));

  long bits = spec.bits_per_window * spec.points_per_add;
  long points_per_subcomb = (1 << spec.points_per_add) - 1;

  assert(spec.points_per_add == 8);
  assert(spec.adds_per_shift == 2);
  assert(spec.shifts == 8);
  assert(spec.bits_per_window == 16);
  assert(bits == 128);
  assert(points_per_subcomb == 255);
  assert(spec.size == 510);

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

  mpz_t n;
  goo_group_t *goo;

  mpz_init(n);
  goo = goo_malloc(sizeof(goo_group_t));

  assert(mpz_set_str(n, mod_hex, 16) == 0);
  assert(goo_group_init(goo, n, 2, 3, 0));

  assert(goo->combs[0].g.points_per_add == 8);
  assert(goo->combs[0].g.adds_per_shift == 2);
  assert(goo->combs[0].g.shifts == 8);
  assert(goo->combs[0].g.bits_per_window == 16);
  assert(goo->combs[0].g.bits == 128);
  assert(goo->combs[0].g.points_per_subcomb == 255);
  assert(goo->combs[0].g.size == 510);

  assert(goo->combs[0].h.points_per_add == 8);
  assert(goo->combs[0].h.adds_per_shift == 2);
  assert(goo->combs[0].h.shifts == 8);
  assert(goo->combs[0].h.bits_per_window == 16);
  assert(goo->combs[0].h.bits == 128);
  assert(goo->combs[0].h.points_per_subcomb == 255);
  assert(goo->combs[0].h.size == 510);

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
  printf("Testing signing/verifying...\n");

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

  mpz_t p, q, n;
  mpz_t mod_n;
  goo_group_t *goo;
  mpz_t s_prime, C1;
  mpz_t msg;
  goo_sig_t sig;

  mpz_init(p);
  mpz_init(q);
  mpz_init(n);
  mpz_init(mod_n);

  goo = goo_malloc(sizeof(goo_group_t));

  mpz_init(s_prime);
  mpz_init(C1);
  mpz_init(msg);
  goo_sig_init(&sig);

  assert(mpz_set_str(p, p_hex, 16) == 0);
  assert(mpz_set_str(q, q_hex, 16) == 0);

  mpz_mul(n, p, q);

  assert(mpz_set_str(mod_n, mod_hex, 16) == 0);

  assert(goo_group_init(goo, mod_n, 2, 3, 4096));

  assert(goo_group_generate(goo, s_prime));
  assert(goo_group_challenge(goo, C1, s_prime, n));

  mpz_set_ui(msg, 0xdeadbeef);

  assert(goo_group_validate(goo, s_prime, C1, p, q));
  assert(goo_group_sign(goo, &sig, msg, s_prime, p, q));
  assert(goo_group_verify(goo, msg, &sig, C1));

  mpz_clear(p);
  mpz_clear(q);
  mpz_clear(n);
  mpz_clear(mod_n);
  mpz_clear(s_prime);
  mpz_clear(C1);
  mpz_clear(msg);
  goo_sig_uninit(&sig);
  goo_group_uninit(goo);
  goo_free(goo);
}

void
goo_test(void) {
  run_hmac_test();
  run_drbg_test();
  run_rng_test();
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
