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
#include <stdint.h>
#include <limits.h>

#ifdef _WIN32
/* For SecureZeroMemory (actually defined in winbase.h). */
#include <windows.h>
#endif

#include "internal.h"
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

static void
goo_free(void *ptr) {
  if (ptr != NULL)
    free(ptr);
}

/*
 * Helpers
 */

static void
goo_cleanse(void *ptr, size_t len) {
#if defined(_WIN32)
  /* https://github.com/jedisct1/libsodium/blob/3b26a5c/src/libsodium/sodium/utils.c#L112 */
  SecureZeroMemory(ptr, len);
#elif defined(__GNUC__)
  /* https://github.com/torvalds/linux/blob/37d4e84/include/linux/string.h#L233 */
  /* https://github.com/torvalds/linux/blob/37d4e84/include/linux/compiler-gcc.h#L21 */
  memset(ptr, 0, len);
  __asm__ __volatile__("": :"r"(ptr) :"memory");
#else
  /* http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html */
  static void *(*const volatile memset_ptr)(void *, int, size_t) = memset;
  (memset_ptr)(ptr, 0, len);
#endif
}

static void
goo_swap(unsigned long *x, unsigned long *y) {
  unsigned long z = *x;
  *x = *y;
  *y = z;
}

static uint32_t
safe_equal(uint32_t x, uint32_t y) {
  return ((x ^ y) - 1) >> 31;
}

static uint32_t
safe_select(uint32_t x, uint32_t y, uint32_t v) {
  return (x & (v - 1)) | (y & ~(v - 1));
}

static uint32_t
safe_equal_bytes(const unsigned char *x, const unsigned char *y, size_t len) {
  uint32_t v = 0;
  size_t i;

  for (i = 0; i < len; i++)
    v |= x[i] ^ y[i];

  return (v - 1) >> 31;
}

/*
 * GMP helpers
 */

#define goo_mpz_import(ret, data, len) \
  mpz_import((ret), (len), 1, sizeof((data)[0]), 0, 0, (data))

#define goo_mpz_export(data, size, n) \
  mpz_export((data), (size), 1, sizeof((data)[0]), 0, 0, (n))

#define goo_mpz_bytelen(n) ((goo_mpz_bitlen((n)) + 7) / 8)

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
    return out;

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

#ifndef GOO_HAS_GMP
/* `mpz_jacobi` is not implemented in mini-gmp. */
/* https://github.com/golang/go/blob/aadaec5/src/math/big/int.go#L754 */
static int
mpz_jacobi(const mpz_t x, const mpz_t y) {
  mpz_t a, b, c;
  unsigned long s, bmod8;
  int j;

  /* Undefined behavior. */
  /* if y == 0 or y mod 2 == 0 */
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

static void
goo_mpz_cleanse(mpz_t n) {
#ifdef GOO_HAS_GMP
  /* Using the public API. */
  const mp_limb_t *orig = mpz_limbs_read(n);
  size_t size = mpz_size(n);
  mp_limb_t *limbs = mpz_limbs_modify(n, (mp_size_t)size);

  /* Zero the limbs. */
  goo_cleanse(limbs, size * sizeof(mp_limb_t));

  /* Ensure the integer remains in a valid state. */
  mpz_limbs_finish(n, 0);

  /* Sanity checks. */
  assert(limbs == orig);
  assert(mpz_limbs_read(n) == orig);
  assert(mpz_sgn(n) == 0);
#else
  /* Using the internal API. */
  mpz_ptr x = n;
  goo_cleanse(x->_mp_d, x->_mp_alloc * sizeof(mp_limb_t));
  x->_mp_size = 0;
#endif
}

static void
goo_mpz_clear(mpz_t n) {
  goo_mpz_cleanse(n);
  mpz_clear(n);
}

/*
 * Hashing
 */

static int
goo_hash_int(goo_sha256_t *ctx,
             const mpz_t n,
             size_t size,
             unsigned char *slab) {
  size_t len = goo_mpz_bytelen(n);
  size_t pos;

  if (len > size)
    return 0;

  if (len > GOO_MAX_RSA_BYTES)
    return 0;

  pos = size - len;

  memset(slab, 0x00, pos);

  if (len != 0)
    goo_mpz_export(slab + pos, NULL, n);

  goo_sha256_update(ctx, slab, size);

  return 1;
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
goo_prng_seed(goo_prng_t *prng,
              const unsigned char *key,
              const unsigned char *iv) {
  unsigned char entropy[64];

  memcpy(&entropy[0], iv, 32);
  memcpy(&entropy[32], key, 32);

  goo_drbg_init(&prng->ctx, entropy, sizeof(entropy));

  mpz_set_ui(prng->save, 0);
  prng->total = 0;
}

static int
goo_prng_seed_sign(goo_prng_t *prng,
                   const mpz_t p,
                   const mpz_t q,
                   const unsigned char *s_prime,
                   const unsigned char *msg,
                   size_t msg_len,
                   unsigned char *slab) {
  int r = 0;
  goo_sha256_t ctx;
  unsigned char key[GOO_SHA256_HASH_SIZE];

  goo_sha256_init(&ctx);

  if (!goo_hash_int(&ctx, p, GOO_MAX_RSA_BYTES, slab))
    goto fail;

  if (!goo_hash_int(&ctx, q, GOO_MAX_RSA_BYTES, slab))
    goto fail;

  goo_sha256_update(&ctx, s_prime, 32);
  goo_sha256_update(&ctx, msg, msg_len);
  goo_sha256_final(&ctx, key);

  goo_prng_seed(prng, key, GOO_PRNG_SIGN);

  r = 1;
fail:
  goo_cleanse(slab, GOO_MAX_RSA_BYTES);
  goo_cleanse(&ctx, sizeof(goo_sha256_t));
  goo_cleanse(key, sizeof(key));
  return r;
}

static void
goo_prng_generate(goo_prng_t *prng, void *out, size_t len) {
  goo_drbg_generate(&prng->ctx, out, len);
}

static void
goo_prng_random_bits(goo_prng_t *prng, mpz_t ret, unsigned long bits) {
  unsigned long total = prng->total;
  unsigned char out[GOO_SHA256_HASH_SIZE];
  unsigned long left;

  /* ret = save */
  mpz_set(ret, prng->save);

  while (total < bits) {
    /* ret = ret << 256 */
    mpz_mul_2exp(ret, ret, sizeof(out) * 8);

    /* tmp = random 256 bit integer */
    goo_prng_generate(prng, out, sizeof(out));
    goo_mpz_import(prng->tmp, out, sizeof(out));

    /* ret = ret | tmp */
    mpz_ior(ret, ret, prng->tmp);
    total += sizeof(out) * 8;
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
goo_prng_random_num(goo_prng_t *prng, unsigned long mod) {
  unsigned char raw[4];
  uint32_t max = (uint32_t)mod;
  uint32_t x, r;

  if (max == 0)
    return 0;

  /* http://www.pcg-random.org/posts/bounded-rands.html */
  do {
    goo_prng_generate(prng, raw, sizeof(raw));

    x = ((uint32_t)raw[0] << 24)
      | ((uint32_t)raw[1] << 16)
      | ((uint32_t)raw[2] << 8)
      | ((uint32_t)raw[3] << 0);

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
  unsigned long a, b;

  if (x <= 1)
    return x;

  while (y != 0) {
    len += 1;
    y >>= 1;
  }

  a = 1 << ((len >> 1) + 1);

  for (;;) {
    assert(a != 0);

    b = x / a;
    b += a;
    b >>= 1;

    if (b >= a)
      return a;

    a = b;
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

  /* if p <= 0 or p mod 2 == 0 */
  if (mpz_sgn(p) <= 0 || mpz_even_p(p))
    goto fail;

  /* if x < 0 or x >= p */
  if (mpz_sgn(x) < 0 || mpz_cmp(x, p) >= 0) {
    /* x = x mod p */
    mpz_mod(x, x, p);
  }

  /* if p mod 4 == 3 */
  if ((mpz_getlimbn(p, 0) & 3) == 3) {
    /* b = x^((p + 1) / 4) mod p */
    mpz_add_ui(e, p, 1);
    mpz_tdiv_q_2exp(e, e, 2);
    mpz_powm(b, x, e, p);

    /* g = b^2 mod p */
    mpz_mul(g, b, b);
    mpz_mod(g, g, p);

    /* g != x */
    if (mpz_cmp(g, x) != 0)
      goto fail;

    /* ret = b */
    mpz_set(ret, b);

    goto succeed;
  }

  /* if p mod 8 == 5 */
  if ((mpz_getlimbn(p, 0) & 7) == 5) {
    /* t = x * 2 mod p */
    mpz_mul_2exp(t, x, 1);
    mpz_mod(t, t, p);

    /* a = t^((p - 5) / 8) mod p */
    mpz_tdiv_q_2exp(e, p, 3);
    mpz_powm(a, t, e, p);

    /* b = (a^2 * t - 1) * x * a mod p */
    mpz_mul(b, a, a);
    mpz_mod(b, b, p);
    mpz_mul(b, b, t);
    mpz_mod(b, b, p);
    mpz_sub_ui(b, b, 1);
    mpz_mod(b, b, p);
    mpz_mul(b, b, x);
    mpz_mod(b, b, p);
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

    goto succeed;
  }

  /* if p == 1 */
  if (mpz_cmp_ui(p, 1) == 0)
    goto fail;

  switch (mpz_jacobi(x, p)) {
    case -1:
      goto fail;
    case 0:
      mpz_set_ui(ret, 0);
      goto succeed;
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

  /* while n^((p - 1) / 2) != -1 mod p */
  while (mpz_jacobi(n, p) != -1) {
    /* n = n + 1 */
    mpz_add_ui(n, n, 1);
  }

  /* y = x^((s + 1) / 2) mod p */
  mpz_add_ui(y, s, 1);
  mpz_tdiv_q_2exp(y, y, 1);
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

    /* t = g^(2^(k - m - 1)) mod p */
    mpz_set_ui(t, 1);
    mpz_mul_2exp(t, t, k - m - 1);
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
succeed:
  r = 1;
fail:
  goo_mpz_clear(x);
  goo_mpz_clear(e);
  goo_mpz_clear(t);
  goo_mpz_clear(a);
  goo_mpz_clear(s);
  goo_mpz_clear(n);
  goo_mpz_clear(y);
  goo_mpz_clear(b);
  goo_mpz_clear(g);
  return r;
}

static int
goo_mpz_sqrtpq(mpz_t ret, const mpz_t x, const mpz_t p, const mpz_t q) {
  /* Compute x^(1 / 2) in F(p * q). */
  int r = 0;
  mpz_t sp, sq, mp, mq, u, v;

  mpz_init(sp);
  mpz_init(sq);
  mpz_init(mp);
  mpz_init(mq);
  mpz_init(u);
  mpz_init(v);

  /* sp = x^(1 / 2) in F(p) */
  if (!goo_mpz_sqrtm(sp, x, p))
    goto fail;

  /* sq = x^(1 / 2) in F(q) */
  if (!goo_mpz_sqrtm(sq, x, q))
    goto fail;

  /* (mp, mq) = bezout coefficients for egcd(p, q) */
  mpz_gcdext(u, mp, mq, p, q);

  /* u = sq * mp * p */
  mpz_mul(u, sq, mp);
  mpz_mul(u, u, p);

  /* v = sp * mq * q */
  mpz_mul(v, sp, mq);
  mpz_mul(v, v, q);

  /* u = u + v */
  mpz_add(u, u, v);

  /* v = p * q */
  mpz_mul(v, p, q);

  /* ret = u mod v */
  mpz_mod(ret, u, v);

  r = 1;
fail:
  goo_mpz_clear(sp);
  goo_mpz_clear(sq);
  goo_mpz_clear(mp);
  goo_mpz_clear(mq);
  goo_mpz_clear(u);
  goo_mpz_clear(v);
  return r;
}

/*
 * Primes
 */

static int
goo_is_prime_div(const mpz_t n) {
  size_t i;

  /* if n <= 1 */
  if (mpz_cmp_ui(n, 1) <= 0)
    return 0;

  /* if n mod 2 == 0 */
  if (mpz_even_p(n)) {
    /* if n == 2 */
    if (mpz_cmp_ui(n, 2) == 0)
      return 1;
    return 0;
  }

  for (i = 0; i < GOO_TEST_PRIMES_LEN; i++) {
    /* if n == test_primes[i] */
    if (mpz_cmp_ui(n, goo_test_primes[i]) == 0)
      return 1;

    /* if n mod test_primes[i] == 0 */
    if (mpz_fdiv_ui(n, goo_test_primes[i]) == 0)
      return 0;
  }

  return -1;
}

/* https://github.com/golang/go/blob/aadaec5/src/math/big/prime.go#L81 */
/* https://github.com/indutny/miller-rabin/blob/master/lib/mr.js */
static int
goo_is_prime_mr(const mpz_t n,
                const unsigned char *key,
                unsigned long reps,
                int force2) {
  int r = 0;
  mpz_t nm1, nm3, q, x, y;
  unsigned long k, i, j;
  goo_prng_t prng;

  /* if n < 7 */
  if (mpz_cmp_ui(n, 7) < 0) {
    /* n == 2 or n == 3 or n == 5 */
    return mpz_cmp_ui(n, 2) == 0
        || mpz_cmp_ui(n, 3) == 0
        || mpz_cmp_ui(n, 5) == 0;
  }

  /* if n mod 2 == 0 */
  if (mpz_even_p(n))
    return 0;

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
  goo_prng_seed(&prng, key, GOO_PRNG_PRIMALITY);

  for (i = 0; i < reps; i++) {
    if (i == reps - 1 && force2) {
      /* x = 2 */
      mpz_set_ui(x, 2);
    } else {
      /* x = random integer in [2,n-1] */
      goo_prng_random_int(&prng, x, nm3);
      mpz_add_ui(x, x, 2);
    }

    /* y = x^q mod n */
    mpz_powm(y, x, q, n);

    /* if y == 1 or y == -1 mod n */
    if (mpz_cmp_ui(y, 1) == 0 || mpz_cmp(y, nm1) == 0)
      continue;

    for (j = 1; j < k; j++) {
      /* y = y^2 mod n */
      mpz_mul(y, y, y);
      mpz_mod(y, y, n);

      /* if y == -1 mod n */
      if (mpz_cmp(y, nm1) == 0)
        goto next;

      /* if y == 1 mod n */
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
  goo_prng_uninit(&prng);
  return r;
}

/* https://github.com/golang/go/blob/aadaec5/src/math/big/prime.go#L150 */
static int
goo_is_prime_lucas(const mpz_t n, unsigned long limit) {
  int ret = 0;
  unsigned long p, r;
  mpz_t d, s, nm2, vk, vk1, t1, t2, t3;
  long i, t;
  int j;

  mpz_init(d);
  mpz_init(s);
  mpz_init(nm2);
  mpz_init(vk);
  mpz_init(vk1);
  mpz_init(t1);
  mpz_init(t2);
  mpz_init(t3);

  /* if n <= 1 */
  if (mpz_cmp_ui(n, 1) <= 0)
    goto fail;

  /* if n mod 2 == 0 */
  if (mpz_even_p(n)) {
    /* if n == 2 */
    if (mpz_cmp_ui(n, 2) == 0)
      goto succeed;
    goto fail;
  }

  /* p = 3 */
  p = 3;

  /* d = 1 */
  mpz_set_ui(d, 1);

  for (;;) {
    if (p > 10000) {
      /* Thought to be impossible. */
      goto fail;
    }

    if (limit != 0 && p > limit) {
      /* Enforce a limit to prevent DoS'ing. */
      goto fail;
    }

    /* d = p * p - 4 */
    mpz_set_ui(d, p * p - 4);

    j = mpz_jacobi(d, n);

    /* if d is not square mod n */
    if (j == -1)
      break;

    /* if d == 0 mod n */
    if (j == 0) {
      /* if n == p + 2 */
      if (mpz_cmp_ui(n, p + 2) == 0)
        goto succeed;
      goto fail;
    }

    if (p == 40) {
      /* if floor(n^(1 / 2))^2 == n */
      if (mpz_perfect_square_p(n))
        goto fail;
    }

    p += 1;
  }

  /* s = n + 1 */
  mpz_add_ui(s, n, 1);

  /* r = s factors of 2 */
  r = goo_mpz_zerobits(s);

  /* nm2 = n - 2 */
  mpz_sub_ui(nm2, n, 2);

  /* vk = 2 */
  mpz_set_ui(vk, 2);

  /* vk1 = p */
  mpz_set_ui(vk1, p);

  /* s >>= r */
  mpz_tdiv_q_2exp(s, s, r);

  for (i = (long)goo_mpz_bitlen(s); i >= 0; i--) {
    /* if floor(s / 2^i) mod 2 == 1 */
    if (mpz_tstbit(s, i)) {
      /* vk = (vk * vk1 + n - p) mod n */
      /* vk1 = (vk1^2 + nm2) mod n */
      mpz_mul(t1, vk, vk1);
      mpz_add(t1, t1, n);
      mpz_sub_ui(t1, t1, p);
      mpz_mod(vk, t1, n);
      mpz_mul(t1, vk1, vk1);
      mpz_add(t1, t1, nm2);
      mpz_mod(vk1, t1, n);
    } else {
      /* vk1 = (vk * vk1 + n - p) mod n */
      /* vk = (vk^2 + nm2) mod n */
      mpz_mul(t1, vk, vk1);
      mpz_add(t1, t1, n);
      mpz_sub_ui(t1, t1, p);
      mpz_mod(vk1, t1, n);
      mpz_mul(t1, vk, vk);
      mpz_add(t1, t1, nm2);
      mpz_mod(vk, t1, n);
    }
  }

  /* if vk == 2 or vk == nm2 */
  if (mpz_cmp_ui(vk, 2) == 0 || mpz_cmp(vk, nm2) == 0) {
    /* t3 = abs(vk * p - vk1 * 2) mod n */
    mpz_mul_ui(t1, vk, p);
    mpz_mul_2exp(t2, vk1, 1);

    if (mpz_cmp(t1, t2) < 0)
      mpz_swap(t1, t2);

    mpz_sub(t1, t1, t2);
    mpz_mod(t3, t1, n);

    /* if t3 == 0 */
    if (mpz_sgn(t3) == 0)
      goto succeed;
  }

  for (t = 0; t < (long)r - 1; t++) {
    /* if vk == 0 */
    if (mpz_sgn(vk) == 0)
      goto succeed;

    /* if vk == 2 */
    if (mpz_cmp_ui(vk, 2) == 0)
      goto fail;

    /* vk = (vk^2 - 2) mod n */
    mpz_mul(t1, vk, vk);
    mpz_sub_ui(t1, t1, 2);
    mpz_mod(vk, t1, n);
  }

  goto fail;
succeed:
  ret = 1;
fail:
  mpz_clear(d);
  mpz_clear(s);
  mpz_clear(nm2);
  mpz_clear(vk);
  mpz_clear(vk1);
  mpz_clear(t1);
  mpz_clear(t2);
  mpz_clear(t3);
  return ret;
}

static int
goo_is_prime(const mpz_t p, const unsigned char *key) {
  int ret = goo_is_prime_div(p);

  if (ret != -1)
    return ret;

  if (!goo_is_prime_mr(p, key, 16 + 1, 1))
    return 0;

  if (!goo_is_prime_lucas(p, 50))
    return 0;

  return 1;
}

static int
goo_next_prime(mpz_t ret,
               const mpz_t p,
               const unsigned char *key,
               unsigned long max) {
  unsigned long inc = 0;

  mpz_set(ret, p);

  if (mpz_even_p(ret)) {
    mpz_add_ui(ret, ret, 1);
    inc += 1;
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
  size_t GOO_MOD_BYTES = (bits + 7) / 8;
  size_t len = 0;

  (void)sig;

  len += GOO_MOD_BYTES; /* C2 */
  len += GOO_MOD_BYTES; /* C3 */
  len += 2; /* t */
  len += GOO_CHAL_BYTES; /* chal */
  len += GOO_ELL_BYTES; /* ell */
  len += GOO_MOD_BYTES; /* Aq */
  len += GOO_MOD_BYTES; /* Bq */
  len += GOO_MOD_BYTES; /* Cq */
  len += GOO_MOD_BYTES; /* Dq */
  len += GOO_EXP_BYTES; /* Eq */
  len += GOO_ELL_BYTES * 8; /* z' */
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
  memset(out + pos, 0x00, pad);         \
  pos += pad;                           \
                                        \
  goo_mpz_export(out + pos, NULL, (n)); \
  pos += bytes;                         \
} while (0)

static int
goo_sig_export(unsigned char *out, const goo_sig_t *sig, size_t bits) {
  size_t GOO_MOD_BYTES = (bits + 7) / 8;
  size_t pos = 0;

  goo_write_int(sig->C2, GOO_MOD_BYTES);
  goo_write_int(sig->C3, GOO_MOD_BYTES);
  goo_write_int(sig->t, 2);

  goo_write_int(sig->chal, GOO_CHAL_BYTES);
  goo_write_int(sig->ell, GOO_ELL_BYTES);
  goo_write_int(sig->Aq, GOO_MOD_BYTES);
  goo_write_int(sig->Bq, GOO_MOD_BYTES);
  goo_write_int(sig->Cq, GOO_MOD_BYTES);
  goo_write_int(sig->Dq, GOO_MOD_BYTES);
  goo_write_int(sig->Eq, GOO_EXP_BYTES);

  goo_write_int(sig->z_w, GOO_ELL_BYTES);
  goo_write_int(sig->z_w2, GOO_ELL_BYTES);
  goo_write_int(sig->z_s1, GOO_ELL_BYTES);
  goo_write_int(sig->z_a, GOO_ELL_BYTES);
  goo_write_int(sig->z_an, GOO_ELL_BYTES);
  goo_write_int(sig->z_s1w, GOO_ELL_BYTES);
  goo_write_int(sig->z_sa, GOO_ELL_BYTES);
  goo_write_int(sig->z_s2, GOO_ELL_BYTES);

  out[pos++] = mpz_sgn(sig->Eq) < 0 ? 1 : 0;

  assert(goo_sig_size(sig, bits) == pos);

  return 1;
}

#undef goo_write_int

#define goo_read_int(n, size) do {         \
  goo_mpz_import((n), data + pos, (size)); \
  pos += (size);                           \
} while (0)                                \

static int
goo_sig_import(goo_sig_t *sig,
               const unsigned char *data,
               size_t data_len,
               size_t bits) {
  size_t GOO_MOD_BYTES = (bits + 7) / 8;
  size_t pos = 0;
  unsigned char sign;

  if (data_len != goo_sig_size(sig, bits)) {
    /* Invalid signature size. */
    return 0;
  }

  goo_read_int(sig->C2, GOO_MOD_BYTES);
  goo_read_int(sig->C3, GOO_MOD_BYTES);
  goo_read_int(sig->t, 2);

  goo_read_int(sig->chal, GOO_CHAL_BYTES);
  goo_read_int(sig->ell, GOO_ELL_BYTES);
  goo_read_int(sig->Aq, GOO_MOD_BYTES);
  goo_read_int(sig->Bq, GOO_MOD_BYTES);
  goo_read_int(sig->Cq, GOO_MOD_BYTES);
  goo_read_int(sig->Dq, GOO_MOD_BYTES);
  goo_read_int(sig->Eq, GOO_EXP_BYTES);

  goo_read_int(sig->z_w, GOO_ELL_BYTES);
  goo_read_int(sig->z_w2, GOO_ELL_BYTES);
  goo_read_int(sig->z_s1, GOO_ELL_BYTES);
  goo_read_int(sig->z_a, GOO_ELL_BYTES);
  goo_read_int(sig->z_an, GOO_ELL_BYTES);
  goo_read_int(sig->z_s1w, GOO_ELL_BYTES);
  goo_read_int(sig->z_sa, GOO_ELL_BYTES);
  goo_read_int(sig->z_s2, GOO_ELL_BYTES);

  sign = data[pos++];

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
combspec_size(unsigned long bits) {
  unsigned long max = 0;
  unsigned long ppa;

  for (ppa = 2; ppa < 18; ppa++) {
    unsigned long bpw = (bits + ppa - 1) / ppa;
    unsigned long sqrt = goo_isqrt(bpw);
    unsigned long aps;

    for (aps = 1; aps < sqrt + 2; aps++) {
      unsigned long shifts, ops1, ops2, ops;

      if (bpw % aps != 0)
        continue;

      shifts = bpw / aps;

      assert(shifts != 0);
      assert(aps != 0);

      ops1 = shifts * (aps + 1) - 1;
      ops2 = aps * (shifts + 1) - 1;
      ops = ops1 > ops2 ? ops1 : ops2;

      if (ops > max)
        max = ops;
    }
  }

  return max + 1;
}

static void
combspec_generate(goo_combspec_t **specs,
                  size_t specs_len,
                  unsigned long shifts,
                  unsigned long aps,
                  unsigned long ppa,
                  unsigned long bps) {
  unsigned long ops = shifts * (aps + 1) - 1;
  unsigned long size = ((1 << ppa) - 1) * aps;
  goo_combspec_t *best;

  assert((size_t)ops < specs_len);

  if (specs[ops] == NULL) {
    specs[ops] = goo_malloc(sizeof(goo_combspec_t));
    specs[ops]->size = ULONG_MAX;
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
goo_combspec_init(goo_combspec_t *out,
                  unsigned long bits,
                  unsigned long max_size) {
  int r = 0;
  size_t specs_len, i;
  goo_combspec_t **specs, *ret;
  unsigned long ppa, sm;

  if (bits == 0 || max_size == 0)
    return 0;

  /* We don't have a hash table, so this allocates up to ~70kb. */
  specs_len = combspec_size(bits);
  specs = goo_calloc(specs_len, sizeof(goo_combspec_t *));

  for (ppa = 2; ppa < 18; ppa++) {
    unsigned long bpw = (bits + ppa - 1) / ppa;
    unsigned long sqrt = goo_isqrt(bpw);
    unsigned long aps;

    for (aps = 1; aps < sqrt + 2; aps++) {
      unsigned long shifts;

      if (bpw % aps != 0)
        continue;

      shifts = bpw / aps;

      assert(shifts != 0);
      assert(aps != 0);

      combspec_generate(specs, specs_len, shifts, aps, ppa, bpw);
      combspec_generate(specs, specs_len, aps, shifts, ppa, bpw);
    }
  }

  sm = ULONG_MAX;
  ret = NULL;

  for (i = 0; i < specs_len; i++) {
    goo_combspec_t *spec = specs[i];

    if (spec == NULL)
      continue;

    if (sm <= spec->size)
      continue;

    sm = spec->size;

    if (sm <= max_size) {
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
  unsigned long i, j, skip;
  mpz_t *items, exp;

  assert((size_t)spec->points_per_add <= sizeof(unsigned long) * 8);

  mpz_init(exp);

  comb->points_per_add = spec->points_per_add;
  comb->adds_per_shift = spec->adds_per_shift;
  comb->shifts = spec->shifts;
  comb->bits_per_window = spec->bits_per_window;
  comb->bits = spec->bits_per_window * spec->points_per_add;
  comb->points_per_subcomb = (1 << spec->points_per_add) - 1;
  comb->size = spec->size;
  comb->items = goo_calloc(comb->size, sizeof(mpz_t));
  comb->wins = goo_calloc(comb->shifts, sizeof(unsigned long *));

  for (i = 0; i < comb->size; i++)
    mpz_init(comb->items[i]);

  for (i = 0; i < comb->shifts; i++)
    comb->wins[i] = goo_calloc(comb->adds_per_shift, sizeof(unsigned long));

  mpz_set(comb->items[0], base);

  items = &comb->items[0];

  /* exp = 1 << bits_per_window */
  mpz_set_ui(exp, 1);
  mpz_mul_2exp(exp, exp, comb->bits_per_window);

  for (i = 1; i < comb->points_per_add; i++) {
    unsigned long x = 1 << i;
    unsigned long y = x >> 1;

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
      unsigned long k = i * skip + j;

      goo_group_pow_slow(group, items[k], items[k - skip], exp);
    }
  }

  mpz_clear(exp);
}

static void
goo_comb_uninit(goo_comb_t *comb) {
  unsigned long i;

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

static void
goo_comb_cleanse(goo_comb_t *comb) {
  unsigned long i;

  for (i = 0; i < comb->shifts; i++)
    goo_cleanse(comb->wins[i], comb->adds_per_shift * sizeof(unsigned long));
}

static int
goo_comb_recode(goo_comb_t *comb, const mpz_t e) {
  unsigned long len = goo_mpz_bitlen(e);
  long i;

  if (len > comb->bits)
    return 0;

  if (mpz_sgn(e) < 0)
    return 0;

  for (i = (long)comb->adds_per_shift - 1; i >= 0; i--) {
    unsigned long j;

    for (j = 0; j < comb->shifts; j++) {
      unsigned long ret = 0;
      unsigned long k;

      for (k = 0; k < comb->points_per_add; k++) {
        unsigned long b = (i + k * comb->adds_per_shift) * comb->shifts + j;

        ret <<= 1;
        ret |= mpz_tstbit(e, (comb->bits - 1) - b);
      }

      comb->wins[j][(comb->adds_per_shift - 1) - i] = ret;
    }
  }

  return 1;
}

/*
 * Group
 */

static void
goo_group_uninit(goo_group_t *group);

static int
goo_group_init(goo_group_t *group,
               const mpz_t n,
               unsigned long g,
               unsigned long h,
               unsigned long bits) {
  size_t i;

  /* Allocate. */
  mpz_init(group->n);
  mpz_init(group->g);
  mpz_init(group->h);
  mpz_init(group->nh);

  goo_prng_init(&group->prng);

  for (i = 0; i < GOO_TABLEN; i++) {
    mpz_init(group->table_p1[i]);
    mpz_init(group->table_n1[i]);
    mpz_init(group->table_p2[i]);
    mpz_init(group->table_n2[i]);
  }

  group->combs_len = 0;

  /* Initialize. */
  mpz_set(group->n, n);
  mpz_set_ui(group->g, g);
  mpz_set_ui(group->h, h);
  mpz_tdiv_q_2exp(group->nh, group->n, 1);

  group->bits = goo_mpz_bitlen(group->n);
  group->size = (group->bits + 7) / 8;
  group->rand_bits = group->bits - 1;

  /* Pre-calculate signature hash prefix. */
  goo_sha256_init(&group->sha);

  if (!goo_hash_int(&group->sha, group->g, 4, group->slab)
      || !goo_hash_int(&group->sha, group->h, 4, group->slab)
      || !goo_hash_int(&group->sha, group->n, group->size, group->slab)) {
    goto fail;
  }

  goo_sha256_final(&group->sha, group->slab);

  goo_sha256_init(&group->sha);
  goo_sha256_update(&group->sha, GOO_HASH_PREFIX, sizeof(GOO_HASH_PREFIX));
  goo_sha256_update(&group->sha, group->slab, GOO_SHA256_HASH_SIZE);

  /* Calculate combs for g^e1 * h^e2 mod n. */
  if (bits != 0) {
    unsigned long big1 = 2 * bits;
    unsigned long big2 = bits + group->rand_bits;
    unsigned long big = big1 > big2 ? big1 : big2;
    unsigned long big_bits = big + GOO_ELL_BITS + 1;
    unsigned long small_bits = group->rand_bits;
    goo_combspec_t big_spec, small_spec;

    if (bits < GOO_MIN_RSA_BITS || bits > GOO_MAX_RSA_BITS)
      goto fail;

    if (!goo_combspec_init(&big_spec, big_bits, GOO_MAX_COMB_SIZE))
      goto fail;

    if (!goo_combspec_init(&small_spec, small_bits, GOO_MAX_COMB_SIZE))
      goto fail;

    goo_comb_init(&group->combs[0].g, group, group->g, &small_spec);
    goo_comb_init(&group->combs[0].h, group, group->h, &small_spec);
    goo_comb_init(&group->combs[1].g, group, group->g, &big_spec);
    goo_comb_init(&group->combs[1].h, group, group->h, &big_spec);

    group->combs_len = 2;
  } else {
    unsigned long tiny_bits = GOO_ELL_BITS;
    goo_combspec_t tiny_spec;

    if (!goo_combspec_init(&tiny_spec, tiny_bits, GOO_MAX_COMB_SIZE))
      goto fail;

    goo_comb_init(&group->combs[0].g, group, group->g, &tiny_spec);
    goo_comb_init(&group->combs[0].h, group, group->h, &tiny_spec);

    group->combs_len = 1;
  }

  return 1;
fail:
  goo_group_uninit(group);
  return 0;
}

static void
goo_group_uninit(goo_group_t *group) {
  size_t i;

  mpz_clear(group->n);
  mpz_clear(group->nh);
  mpz_clear(group->g);
  mpz_clear(group->h);

  goo_prng_uninit(&group->prng);

  for (i = 0; i < GOO_TABLEN; i++) {
    mpz_clear(group->table_p1[i]);
    mpz_clear(group->table_n1[i]);
    mpz_clear(group->table_p2[i]);
    mpz_clear(group->table_n2[i]);
  }

  for (i = 0; i < group->combs_len; i++) {
    goo_comb_uninit(&group->combs[i].g);
    goo_comb_uninit(&group->combs[i].h);
  }

  group->combs_len = 0;
}

static void
goo_group_cleanse(goo_group_t *group) {
  size_t i;

  for (i = 0; i < GOO_TABLEN; i++) {
    goo_mpz_cleanse(group->table_p1[i]);
    goo_mpz_cleanse(group->table_n1[i]);
    goo_mpz_cleanse(group->table_p2[i]);
    goo_mpz_cleanse(group->table_n2[i]);
  }

  goo_cleanse(group->wnaf0, sizeof(group->wnaf0));
  goo_cleanse(group->wnaf1, sizeof(group->wnaf1));
  goo_cleanse(group->wnaf2, sizeof(group->wnaf2));

  for (i = 0; i < group->combs_len; i++) {
    goo_comb_cleanse(&group->combs[i].g);
    goo_comb_cleanse(&group->combs[i].h);
  }

  goo_cleanse(group->slab, sizeof(group->slab));
}

static void
goo_group_reduce(goo_group_t *group, mpz_t ret, const mpz_t b) {
  /* if b > nh */
  if (mpz_cmp(b, group->nh) > 0) {
    /* ret = n - b */
    mpz_sub(ret, group->n, b);
  } else {
    /* ret = b */
    mpz_set(ret, b);
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
  goo_group_mul(group, b12i, b1, b2);

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

#ifdef GOO_TEST
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
#endif

static int
goo_group_powgh(goo_group_t *group, mpz_t ret, const mpz_t e1, const mpz_t e2) {
  /* Compute g^e1 * h*e2 mod n. */
  goo_comb_t *gcomb = NULL;
  goo_comb_t *hcomb = NULL;
  unsigned long bits1 = goo_mpz_bitlen(e1);
  unsigned long bits2 = goo_mpz_bitlen(e2);
  unsigned long bits = bits1 > bits2 ? bits1 : bits2;
  unsigned long i;

  for (i = 0; i < (unsigned long)group->combs_len; i++) {
    if (bits <= group->combs[i].g.bits) {
      gcomb = &group->combs[i].g;
      hcomb = &group->combs[i].h;
      break;
    }
  }

  if (gcomb == NULL || hcomb == NULL)
    return 0;

  if (!goo_comb_recode(gcomb, e1))
    return 0;

  if (!goo_comb_recode(hcomb, e2))
    return 0;

  mpz_set_ui(ret, 1);

  for (i = 0; i < gcomb->shifts; i++) {
    unsigned long *us = gcomb->wins[i];
    unsigned long *vs = hcomb->wins[i];
    unsigned long j;

    if (i != 0)
      goo_group_sqr(group, ret, ret);

    for (j = 0; j < gcomb->adds_per_shift; j++) {
      unsigned long u = us[j];
      unsigned long v = vs[j];

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
  size_t i;

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
goo_group_wnaf(goo_group_t *group,
               long *out,
               const mpz_t exp,
               unsigned long bits) {
  long w = GOO_WINDOW_SIZE;
  long mask = (1 << w) - 1;
  long i;
  mpz_t e;

  (void)group;

  mpz_init(e);
  mpz_set(e, exp);

  for (i = (long)bits - 1; i >= 0; i--) {
    long val = 0;

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

#ifdef GOO_TEST
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
#endif

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
  unsigned char *slab = group->slab;
  size_t GOO_MOD_BYTES = group->size;
  unsigned char sign[GOO_INT_BYTES] = {0, 0, 0, 0};
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

  if (!goo_hash_int(&ctx, C1, GOO_MOD_BYTES, slab)
      || !goo_hash_int(&ctx, C2, GOO_MOD_BYTES, slab)
      || !goo_hash_int(&ctx, C3, GOO_MOD_BYTES, slab)
      || !goo_hash_int(&ctx, t, GOO_INT_BYTES, slab)
      || !goo_hash_int(&ctx, A, GOO_MOD_BYTES, slab)
      || !goo_hash_int(&ctx, B, GOO_MOD_BYTES, slab)
      || !goo_hash_int(&ctx, C, GOO_MOD_BYTES, slab)
      || !goo_hash_int(&ctx, D, GOO_MOD_BYTES, slab)
      || !goo_hash_int(&ctx, E, GOO_EXP_BYTES, slab)) {
    return 0;
  }

  sign[3] = mpz_sgn(E) < 0 ? 1 : 0;

  goo_sha256_update(&ctx, sign, GOO_INT_BYTES);
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

  goo_prng_seed(&group->prng, key, GOO_PRNG_DERIVE);
  goo_prng_random_bits(&group->prng, chal, GOO_CHAL_BITS);
  goo_prng_random_bits(&group->prng, ell, GOO_ELL_BITS);

  return 1;
}

static void
goo_group_expand_sprime(goo_group_t *group, mpz_t s,
                        const unsigned char *s_prime) {
  goo_prng_seed(&group->prng, s_prime, GOO_PRNG_EXPAND);
  goo_prng_random_bits(&group->prng, s, GOO_EXP_BITS);
}

static void
goo_group_random_scalar(goo_group_t *group, goo_prng_t *prng, mpz_t ret) {
  size_t bits = group->rand_bits;

  if (bits > GOO_EXP_BITS)
    bits = GOO_EXP_BITS;

  goo_prng_random_bits(prng, ret, bits);
}

static int
goo_is_valid_prime(const mpz_t p) {
  /* if p mod 2 == 0 */
  if (mpz_even_p(p))
    return 0;

  /* if p < 3 */
  if (mpz_cmp_ui(p, 3) < 0)
    return 0;

  /* if ceil(log2(p)) > 4096 */
  if (goo_mpz_bitlen(p) > GOO_MAX_RSA_BITS)
    return 0;

  return 1;
}

static int
goo_is_valid_modulus(const mpz_t n) {
  size_t bits;

  /* if n <= 0 */
  if (mpz_sgn(n) <= 0)
    return 0;

  bits = goo_mpz_bitlen(n);

  /* if ceil(log2(n)) < 1024 or ceil(log2(n)) > 4096 */
  if (bits < GOO_MIN_RSA_BITS || bits > GOO_MAX_RSA_BITS)
    return 0;

  /* if n mod 2 == 0 */
  if (mpz_even_p(n))
    return 0;

  return 1;
}

static int
goo_is_valid_exponent(const mpz_t e) {
  /* if e < 3 */
  if (mpz_cmp_ui(e, 3) < 0)
    return 0;

  /* if ceil(log2(e)) > 33 */
  if (goo_mpz_bitlen(e) > 33)
    return 0;

  /* if e mod 2 == 0 */
  if (mpz_even_p(e))
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

  if (!goo_is_valid_modulus(n)) {
    /* Invalid RSA public key. */
    goto fail;
  }

  goo_group_expand_sprime(group, s, s_prime);

  /* Commit to the RSA modulus:
   *
   *   C1 = g^n * h^s in G
   */
  if (!goo_group_powgh(group, C1, n, s))
    goto fail;

  goo_group_reduce(group, C1, C1);

  r = 1;
fail:
  goo_mpz_clear(s);
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

  if (!goo_is_valid_modulus(n))
    goto fail;

  goo_group_expand_sprime(group, s, s_prime);

  if (!goo_group_powgh(group, x, n, s))
    goto fail;

  goo_group_reduce(group, x, x);

  if (mpz_cmp(C1, x) != 0)
    goto fail;

  r = 1;
fail:
  goo_mpz_clear(n);
  goo_mpz_clear(s);
  goo_mpz_clear(x);
  goo_group_cleanse(group);
  return r;
}

static int
goo_group_sign(goo_group_t *group,
               goo_sig_t *S,
               const unsigned char *msg,
               size_t msg_len,
               const unsigned char *s_prime,
               const mpz_t p,
               const mpz_t q) {
  int r = 0;
  int found;
  unsigned long primes[GOO_PRIMES_LEN];
  unsigned char key[GOO_SHA256_HASH_SIZE];
  goo_prng_t prng;
  unsigned long i;

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

  if (!goo_is_valid_prime(p) || !goo_is_valid_prime(q)) {
    /* Invalid RSA public key. */
    goto fail;
  }

  mpz_mul(n, p, q);

  if (!goo_is_valid_modulus(n)) {
    /* Invalid RSA public key. */
    goto fail;
  }

  /* Seed the PRNG using the primes and message as entropy. */
  if (!goo_prng_seed_sign(&prng, p, q, s_prime, msg, msg_len, group->slab))
    goto fail;

  /* Find a small quadratic residue prime `t`. */
  found = 0;

  memcpy(primes, goo_primes, sizeof(goo_primes));

  for (i = 0; i < GOO_PRIMES_LEN; i++) {
    /* Fisher-Yates shuffle to choose random `t`. */
    unsigned long j = goo_prng_random_num(&prng, GOO_PRIMES_LEN - i);

    goo_swap(&primes[i], &primes[i + j]);

    mpz_set_ui(*t, primes[i]);

    /* w = t^(1 / 2) in F(p * q) */
    if (goo_mpz_sqrtpq(w, *t, p, q)) {
      found = 1;
      break;
    }
  }

  if (!found) {
    /* No prime quadratic residue less than `1000 mod n`! */
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
    /* `w^2 - t` was not divisible by `n`! */
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
  goo_group_expand_sprime(group, s, s_prime);

  if (!goo_group_powgh(group, C1, n, s))
    goto fail;

  goo_group_reduce(group, C1, C1);

  goo_group_random_scalar(group, &prng, s1);

  if (!goo_group_powgh(group, *C2, w, s1))
    goto fail;

  goo_group_reduce(group, *C2, *C2);

  goo_group_random_scalar(group, &prng, s2);

  if (!goo_group_powgh(group, *C3, a, s2))
    goto fail;

  goo_group_reduce(group, *C3, *C3);

  /* Inverses of `C1` and `C2`. */
  if (!goo_group_inv2(group, C1i, C2i, C1, *C2))
    goto fail;

  /* Eight random 2048-bit integers: */
  /*   r_w, r_w2, r_s1, r_a, r_an, r_s1w, r_sa, r_s2 */
  goo_group_random_scalar(group, &prng, r_w);
  goo_group_random_scalar(group, &prng, r_w2);
  goo_group_random_scalar(group, &prng, r_a);
  goo_group_random_scalar(group, &prng, r_an);
  goo_group_random_scalar(group, &prng, r_s1w);
  goo_group_random_scalar(group, &prng, r_sa);
  goo_group_random_scalar(group, &prng, r_s2);

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
    goo_group_random_scalar(group, &prng, r_s1);

    if (!goo_group_powgh(group, A, r_w, r_s1))
      goto fail;

    goo_group_reduce(group, A, A);

    if (!goo_group_derive(group,
                          *chal, *ell, key, C1, *C2, *C3,
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

  assert(goo_mpz_bitlen(*Eq) <= GOO_EXP_BITS);

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
  goo_mpz_clear(n);
  goo_mpz_clear(s);
  goo_mpz_clear(C1);
  goo_mpz_clear(w);
  goo_mpz_clear(a);
  goo_mpz_clear(s1);
  goo_mpz_clear(s2);
  goo_mpz_clear(t1);
  goo_mpz_clear(t2);
  goo_mpz_clear(t3);
  goo_mpz_clear(t4);
  goo_mpz_clear(t5);
  goo_mpz_clear(C1i);
  goo_mpz_clear(C2i);
  goo_mpz_clear(r_w);
  goo_mpz_clear(r_w2);
  goo_mpz_clear(r_s1);
  goo_mpz_clear(r_a);
  goo_mpz_clear(r_an);
  goo_mpz_clear(r_s1w);
  goo_mpz_clear(r_sa);
  goo_mpz_clear(r_s2);
  goo_mpz_clear(A);
  goo_mpz_clear(B);
  goo_mpz_clear(C);
  goo_mpz_clear(D);
  goo_mpz_clear(E);
  goo_cleanse(&prng, sizeof(goo_prng_t));
  goo_cleanse(primes, sizeof(primes));
  goo_cleanse(&i, sizeof(i));
  goo_cleanse(key, sizeof(key));
  goo_group_cleanse(group);
  return r;
}

static int
goo_group_verify(goo_group_t *group,
                 const unsigned char *msg,
                 size_t msg_len,
                 const goo_sig_t *S,
                 const mpz_t C1) {
  int r = 0;
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

  unsigned char key[GOO_SHA256_HASH_SIZE];
  size_t i;
  int found;

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
  if (mpz_sgn(*ell) == 0 || goo_mpz_bitlen(*ell) > GOO_ELL_BITS)
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
  if (goo_mpz_bitlen(*Eq) > GOO_EXP_BITS)
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

  mpz_mul(E, *Eq, *ell);
  mpz_sub(tmp, *z_w2, *z_an);
  mpz_mod(tmp, tmp, *ell);
  mpz_add(E, E, tmp);
  mpz_mul(tmp, *t, *chal);
  mpz_sub(E, E, tmp);

  /* Recompute `chal` and `ell`. */
  if (!goo_group_derive(group, chal0, ell0, key,
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
  if (!goo_is_prime(*ell, key))
    goto fail;

  r = 1;
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
  return r;
}

/*
 * RSA
 */

static void
goo_mgf1xor(unsigned char *out,
            size_t out_len,
            const unsigned char *seed,
            size_t seed_len) {
  /* [RFC8017] Page 67, Section B.2.1. */
  unsigned char ctr[4] = {0, 0, 0, 0};
  unsigned char digest[GOO_SHA256_HASH_SIZE];
  goo_sha256_t ctx, sha;
  size_t i = 0;
  size_t j;
  int k;

  goo_sha256_init(&ctx);
  goo_sha256_update(&ctx, seed, seed_len);

  while (i < out_len) {
    memcpy(&sha, &ctx, sizeof(goo_sha256_t));
    goo_sha256_update(&sha, ctr, sizeof(ctr));
    goo_sha256_final(&sha, digest);

    j = 0;

    while (i < out_len && j < sizeof(digest))
      out[i++] ^= digest[j++];

    for (k = 3; k >= 0; k--) {
      ctr[k] += 1;

      if (ctr[k] != 0x00)
        break;
    }
  }
}

static int
goo_veil(mpz_t v,
         const mpz_t c,
         const mpz_t n,
         size_t bits,
         goo_prng_t *prng) {
  int r = 0;
  mpz_t v0, vmax, rmax, r0;

  mpz_init(v0);
  mpz_init(vmax);
  mpz_init(rmax);
  mpz_init(r0);

  if (!goo_is_valid_modulus(n))
    goto fail;

  if (bits < goo_mpz_bitlen(n))
    goto fail;

  if (mpz_cmp(c, n) >= 0)
    goto fail;

  /* vmax = 1 << bits */
  mpz_set_ui(vmax, 1);
  mpz_mul_2exp(vmax, vmax, bits);

  /* rmax = (vmax - c + n - 1) / n */
  mpz_sub(rmax, vmax, c);
  mpz_add(rmax, rmax, n);
  mpz_sub_ui(rmax, rmax, 1);
  mpz_fdiv_q(rmax, rmax, n);

  assert(mpz_sgn(rmax) > 0);

  mpz_set(v0, vmax);

  while (mpz_cmp(v0, vmax) >= 0) {
    goo_prng_random_int(prng, r0, rmax);

    /* v = c + r * n */
    mpz_mul(r0, r0, n);
    mpz_add(v0, c, r0);
  }

  mpz_mod(r0, v0, n);

  assert(mpz_cmp(r0, c) == 0);
  assert(goo_mpz_bitlen(v0) <= bits);

  mpz_set(v, v0);

  r = 1;
fail:
  goo_mpz_clear(v0);
  goo_mpz_clear(vmax);
  goo_mpz_clear(rmax);
  goo_mpz_clear(r0);
  return r;
}

static int
goo_unveil(mpz_t m,
           const unsigned char *msg,
           size_t msg_len,
           const mpz_t n,
           size_t bits) {
  if (!goo_is_valid_modulus(n))
    return 0;

  if (msg_len < goo_mpz_bytelen(n))
    return 0;

  goo_mpz_import(m, msg, msg_len);

  if (goo_mpz_bitlen(m) > bits)
    return 0;

  mpz_mod(m, m, n);

  return 1;
}

static int
goo_encrypt_oaep(unsigned char **out,
                 size_t *out_len,
                 const unsigned char *msg,
                 size_t msg_len,
                 const mpz_t n,
                 const mpz_t e,
                 const unsigned char *label,
                 size_t label_len,
                 const unsigned char *entropy) {
  /* [RFC8017] Page 22, Section 7.1.1. */
  int r = 0;
  goo_prng_t prng;
  size_t klen = goo_mpz_bytelen(n);
  size_t mlen = msg_len;
  size_t hlen = GOO_SHA256_HASH_SIZE;
  unsigned char *em = NULL;
  unsigned char *seed, *db;
  unsigned char lhash[GOO_SHA256_HASH_SIZE];
  size_t slen, dlen;
  mpz_t m;

  goo_prng_init(&prng);
  mpz_init(m);

  if (!goo_is_valid_modulus(n))
    goto fail;

  if (!goo_is_valid_exponent(e))
    goto fail;

  if (klen < 2 * hlen + 2)
    goto fail;

  if (msg_len > klen - 2 * hlen - 2)
    goto fail;

  /* EM = 0x00 || (seed) || (Hash(L) || PS || 0x01 || M) */
  em = goo_calloc(klen, sizeof(unsigned char));
  goo_sha256(lhash, label, label_len);
  seed = &em[1];
  slen = hlen;
  db = &em[1 + hlen];
  dlen = klen - (1 + hlen);

  em[0] = 0x00;

  goo_prng_seed(&prng, entropy, GOO_PRNG_ENCRYPT);
  goo_prng_generate(&prng, seed, slen);
  memcpy(&db[0], lhash, sizeof(lhash));
  memset(&db[hlen], 0x00, (dlen - mlen - 1) - hlen);
  db[dlen - mlen - 1] = 0x01;
  memcpy(&db[dlen - mlen], msg, mlen);

  goo_mgf1xor(db, dlen, seed, slen);
  goo_mgf1xor(seed, slen, db, dlen);

  goo_mpz_import(m, em, klen);
  goo_cleanse(em, klen);

  /* c = m^e mod n */
  mpz_powm(m, m, e, n);

  if (!goo_veil(m, m, n, GOO_MAX_RSA_BITS + 8, &prng))
    goto fail;

  *out_len = (GOO_MAX_RSA_BITS + 8 + 7) / 8;
  *out = goo_mpz_pad(NULL, *out_len, m);

  if (*out == NULL)
    goto fail;

  r = 1;
fail:
  goo_prng_uninit(&prng);
  goo_cleanse(&prng, sizeof(goo_prng_t));
  goo_mpz_clear(m);
  goo_free(em);
  return r;
}

static int
goo_decrypt_oaep(unsigned char **out,
                 size_t *out_len,
                 const unsigned char *msg,
                 size_t msg_len,
                 const mpz_t p,
                 const mpz_t q,
                 const mpz_t e,
                 const unsigned char *label,
                 size_t label_len,
                 const unsigned char *entropy) {
  /* [RFC8017] Page 25, Section 7.1.2. */
  int r = 0;
  goo_prng_t prng;
  mpz_t n, t, d, m, s, b, bi;
  unsigned char *em = NULL;
  unsigned char *seed, *db, *rest, *lhash;
  size_t i, klen, slen, dlen, rlen;
  size_t hlen = GOO_SHA256_HASH_SIZE;
  uint32_t zero, lvalid, looking, index, invalid, valid;
  unsigned char expect[GOO_SHA256_HASH_SIZE];

  goo_prng_init(&prng);

  mpz_init(n);
  mpz_init(t);
  mpz_init(d);
  mpz_init(m);
  mpz_init(s);
  mpz_init(b);
  mpz_init(bi);

  if (!goo_is_valid_prime(p) || !goo_is_valid_prime(q))
    goto fail;

  /* n = p * q */
  mpz_mul(n, p, q);

  if (!goo_is_valid_modulus(n))
    goto fail;

  if (!goo_is_valid_exponent(e))
    goto fail;

  /* t = (p - 1) * (q - 1) */
  mpz_sub_ui(t, p, 1);
  mpz_sub_ui(d, q, 1);
  mpz_mul(t, t, d);

  /* d = e^-1 mod t */
  if (!mpz_invert(d, e, t))
    goto fail;

  klen = goo_mpz_bytelen(n);

  if (klen < hlen * 2 + 2)
    goto fail;

  if (!goo_unveil(m, msg, msg_len, n, GOO_MAX_RSA_BITS + 8))
    goto fail;

  /* Seed PRNG with user-provided entropy. */
  goo_prng_seed(&prng, entropy, GOO_PRNG_DECRYPT);

  /* t = n - 1 */
  mpz_sub_ui(t, n, 1);

  /* Generate blinding factor. */
  for (;;) {
    /* s = random integer in [1,n-1] */
    goo_prng_random_int(&prng, s, t);
    mpz_add_ui(s, s, 1);

    /* bi = s^-1 mod n */
    if (!mpz_invert(bi, s, n))
      continue;

    /* b = s^e mod n */
    mpz_powm(b, s, e, n);

    break;
  }

  /* c' = c * b mod n (blind) */
  mpz_mul(m, m, b);
  mpz_mod(m, m, n);

  /* m' = c'^d mod n */
#ifdef GOO_HAS_GMP
  if (mpz_sgn(d) > 0 && mpz_odd_p(n))
    mpz_powm_sec(m, m, d, n);
  else
    mpz_powm(m, m, d, n);
#else
  mpz_powm(m, m, d, n);
#endif

  /* m = m' * bi mod n (unblind) */
  mpz_mul(m, m, bi);
  mpz_mod(m, m, n);

  /* EM = 0x00 || (seed) || (Hash(L) || PS || 0x01 || M) */
  em = goo_mpz_pad(NULL, klen, m);

  if (em == NULL)
    goto fail;

  goo_sha256(expect, label, label_len);
  zero = safe_equal(em[0], 0x00);
  seed = &em[1];
  slen = hlen;
  db = &em[hlen + 1];
  dlen = klen - (hlen + 1);

  goo_mgf1xor(seed, slen, db, dlen);
  goo_mgf1xor(db, dlen, seed, slen);

  lhash = &db[0];
  lvalid = safe_equal_bytes(lhash, expect, hlen);
  rest = &db[hlen];
  rlen = dlen - hlen;

  looking = 1;
  index = 0;
  invalid = 0;

  for (i = 0; i < rlen; i++) {
    uint32_t equals0 = safe_equal(rest[i], 0x00);
    uint32_t equals1 = safe_equal(rest[i], 0x01);

    index = safe_select(index, i, looking & equals1);
    looking = safe_select(looking, 0, equals1);
    invalid = safe_select(invalid, 1, looking & (equals0 ^ 1));
  }

  valid = zero & lvalid & (invalid ^ 1) & (looking ^ 1);

  if (valid == 0)
    goto fail;

  *out_len = rlen - (index + 1);
  *out = goo_malloc(*out_len);
  memcpy(*out, rest + index + 1, *out_len);

  goo_cleanse(em, klen);

  r = 1;
fail:
  goo_prng_uninit(&prng);
  goo_cleanse(&prng, sizeof(goo_prng_t));
  goo_mpz_clear(n);
  goo_mpz_clear(t);
  goo_mpz_clear(d);
  goo_mpz_clear(m);
  goo_mpz_clear(s);
  goo_mpz_clear(b);
  goo_mpz_clear(bi);
  goo_free(em);
  return r;
}

/*
 * API
 */

goo_group_t *
goo_create(const unsigned char *n,
           size_t n_len,
           unsigned long g,
           unsigned long h,
           unsigned long bits) {
  goo_group_t *ctx = goo_malloc(sizeof(goo_group_t));
  goo_group_t *ret = NULL;
  mpz_t n_n;

  mpz_init(n_n);

  if (ctx == NULL || n == NULL)
    goto fail;

  goo_mpz_import(n_n, n, n_len);

  if (!goo_group_init(ctx, n_n, g, h, bits))
    goto fail;

  ret = ctx;
  ctx = NULL;
fail:
  goo_free(ctx);
  mpz_clear(n_n);
  return ret;
}

void
goo_destroy(goo_group_t *ctx) {
  if (ctx != NULL) {
    goo_group_uninit(ctx);
    goo_free(ctx);
  }
}

int
goo_generate(goo_group_t *ctx,
             unsigned char *s_prime,
             const unsigned char *entropy) {
  goo_sha256_t sha;

  (void)ctx;

  if (s_prime == NULL || entropy == NULL)
    return 0;

  /* Hash to mitigate any kind of backtracking */
  /* that may be possible with the global RNG. */
  goo_sha256_init(&sha);
  goo_sha256_update(&sha, GOO_PRNG_GENERATE, sizeof(GOO_PRNG_GENERATE));
  goo_sha256_update(&sha, entropy, 32);
  goo_sha256_final(&sha, s_prime);

  /* Zero the context. */
  goo_cleanse(&sha, sizeof(goo_sha256_t));

  return 1;
}

int
goo_challenge(goo_group_t *ctx,
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

  *C1_len = ctx->size;
  *C1 = goo_mpz_pad(NULL, *C1_len, C1_n);

  if (*C1 == NULL)
    goto fail;

  r = 1;
fail:
  goo_mpz_clear(C1_n);
  goo_mpz_clear(n_n);
  return r;
}

int
goo_validate(goo_group_t *ctx,
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
  goo_mpz_clear(C1_n);
  goo_mpz_clear(p_n);
  goo_mpz_clear(q_n);
  return r;
}

int
goo_sign(goo_group_t *ctx,
         unsigned char **out,
         size_t *out_len,
         const unsigned char *msg,
         size_t msg_len,
         const unsigned char *s_prime,
         const unsigned char *p,
         size_t p_len,
         const unsigned char *q,
         size_t q_len) {
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
      || q == NULL) {
    return 0;
  }

  mpz_init(p_n);
  mpz_init(q_n);
  goo_sig_init(&S);

  goo_mpz_import(p_n, p, p_len);
  goo_mpz_import(q_n, q, q_len);

  if (!goo_group_sign(ctx, &S, msg, msg_len, s_prime, p_n, q_n))
    goto fail;

  size = goo_sig_size(&S, ctx->bits);
  data = goo_malloc(size);

  if (!goo_sig_export(data, &S, ctx->bits))
    goto fail;

  *out = data;
  *out_len = size;
  data = NULL;

  r = 1;
fail:
  goo_mpz_clear(p_n);
  goo_mpz_clear(q_n);
  goo_sig_uninit(&S);
  goo_free(data);
  return r;
}

int
goo_verify(goo_group_t *ctx,
           const unsigned char *msg,
           size_t msg_len,
           const unsigned char *sig,
           size_t sig_len,
           const unsigned char *C1,
           size_t C1_len) {
  int r = 0;
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

  r = 1;
fail:
  goo_sig_uninit(&S);
  mpz_clear(C1_n);
  return r;
}

int
goo_encrypt(goo_group_t *ctx,
            unsigned char **out,
            size_t *out_len,
            const unsigned char *msg,
            size_t msg_len,
            const unsigned char *n,
            size_t n_len,
            const unsigned char *e,
            size_t e_len,
            const unsigned char *label,
            size_t label_len,
            const unsigned char *entropy) {
  int r = 0;
  mpz_t n_n, e_n;

  (void)ctx;

  if (out == NULL
      || out_len == NULL
      || n == NULL
      || e == NULL
      || entropy == NULL) {
    return 0;
  }

  mpz_init(n_n);
  mpz_init(e_n);

  goo_mpz_import(n_n, n, n_len);
  goo_mpz_import(e_n, e, e_len);

  if (!goo_encrypt_oaep(out, out_len, msg, msg_len, n_n,
                        e_n, label, label_len, entropy)) {
    goto fail;
  }

  r = 1;
fail:
  goo_mpz_clear(n_n);
  goo_mpz_clear(e_n);
  return r;
}

int
goo_decrypt(goo_group_t *ctx,
            unsigned char **out,
            size_t *out_len,
            const unsigned char *msg,
            size_t msg_len,
            const unsigned char *p,
            size_t p_len,
            const unsigned char *q,
            size_t q_len,
            const unsigned char *e,
            size_t e_len,
            const unsigned char *label,
            size_t label_len,
            const unsigned char *entropy) {
  int r = 0;
  mpz_t p_n, q_n, e_n;

  (void)ctx;

  if (out == NULL
      || out_len == NULL
      || msg == NULL
      || p == NULL
      || q == NULL
      || e == NULL
      || entropy == NULL) {
    return 0;
  }

  mpz_init(p_n);
  mpz_init(q_n);
  mpz_init(e_n);

  goo_mpz_import(p_n, p, p_len);
  goo_mpz_import(q_n, q, q_len);
  goo_mpz_import(e_n, e, e_len);

  if (!goo_decrypt_oaep(out, out_len, msg, msg_len, p_n, q_n,
                        e_n, label, label_len, entropy)) {
    goto fail;
  }

  r = 1;
fail:
  goo_mpz_clear(p_n);
  goo_mpz_clear(q_n);
  goo_mpz_clear(e_n);
  return r;
}
