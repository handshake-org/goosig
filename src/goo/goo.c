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

#define goo_print_hex(data, len) do { \
  mpz_t n;                            \
  mpz_init(n);                        \
  goo_mpz_import(n, (data), (len));   \
  goo_mpz_print(n);                   \
  mpz_clear(n);                       \
} while (0)

#define goo_mpz_bytesize(n) \
  (goo_mpz_bitlen((n)) + 7) / 8

static inline size_t
goo_mpz_bitlen(const mpz_t n) {
  size_t bits = mpz_sizeinbase(n, 2);

  if (bits == 1 && mpz_cmp_ui(n, 0) == 0)
    bits = 0;

  return bits;
}

static inline unsigned char *
goo_mpz_pad(void *out, size_t size, const mpz_t n) {
  size_t len = goo_mpz_bytesize(n);

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
  if (size == 0) {
    realloc(ptr, size);
    return NULL;
  }

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
 * PRNG
 */

static void
goo_prng_init(goo_prng_t *prng) {
  memset((void *)prng, 0x00, sizeof(goo_prng_t));

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
  unsigned char entropy[64 + sizeof(goo_pers) - 1];

  memcpy(&entropy[0], key, 32);
  memset(&entropy[32], 0x00, 32);
  memcpy(&entropy[64], &goo_pers[0], sizeof(goo_pers) - 1);

  goo_drbg_init(&prng->ctx, entropy, sizeof(entropy));

  mpz_set_ui(prng->save, 0);
}

static void
goo_prng_nextrand(goo_prng_t *prng, unsigned char out[32]) {
  goo_drbg_generate(&prng->ctx, &out[0], 32);
}

static void
goo_prng_getrandbits(goo_prng_t *prng, mpz_t r, unsigned long nbits) {
  mpz_set(r, prng->save);

  unsigned long b = goo_mpz_bitlen(r);
  unsigned char out[32];

  while (b < nbits) {
    // r = r << 256
    mpz_mul_2exp(r, r, 256);
    // tmp = nextrand()
    goo_prng_nextrand(prng, &out[0]);
    goo_mpz_import(prng->tmp, &out[0], 32);
    // r = r | tmp
    mpz_ior(r, r, prng->tmp);
    b += 256;
  }

  unsigned long left = b - nbits;

  if (left == 0) {
    mpz_set_ui(prng->save, 0);
    return;
  }

  // save = r & ((1 << left) - 1)
  mpz_set_ui(prng->tmp, 1);
  mpz_mul_2exp(prng->tmp, prng->tmp, left);
  mpz_sub_ui(prng->tmp, prng->tmp, 1);
  mpz_set(prng->save, r);
  mpz_and(prng->save, prng->save, prng->tmp);

  // r >>= left;
  mpz_fdiv_q_2exp(r, r, left);
}

static void
goo_prng_getrandint(goo_prng_t *prng, mpz_t ret, const mpz_t max) {
  // if max <= 0
  if (mpz_cmp_ui(max, 0) <= 0) {
    // ret = 0
    mpz_set_ui(ret, 0);
    return;
  }

  // ret -= 1
  mpz_set(ret, max);
  mpz_sub_ui(ret, ret, 1);

  // bits = bitlen(ret)
  size_t bits = goo_mpz_bitlen(ret);

  // ret += 1
  mpz_add_ui(ret, ret, 1);

  // while ret >= max
  while (mpz_cmp(ret, max) >= 0)
    goo_prng_getrandbits(prng, ret, bits);
}

/*
 * Utils
 */

static size_t
goo_clog2(const mpz_t val) {
  mpz_t t;
  mpz_init_set(t, val);
  mpz_sub_ui(t, t, 1);
  size_t bits = goo_mpz_bitlen(t);
  mpz_clear(t);
  return bits;
}

static unsigned long
goo_zerobits(const mpz_t n) {
  if (mpz_cmp_ui(n, 0) == 0)
    return 0;

  mpz_t x;
  mpz_init(x);

  // x = n
  mpz_set(x, n);

  // if x < 0
  if (mpz_cmp_ui(x, 0) < 0) {
    // x = -x;
    mpz_mul_si(x, x, -1);
  }

  unsigned long i = 0;

  // while x & 1 == 0
  while (mpz_even_p(x)) {
    i += 1;
    // x >>= 1
    mpz_fdiv_q_2exp(x, x, 1);
  }

  mpz_clear(x);

  return i;
}

// https://github.com/golang/go/blob/aadaec5/src/math/big/nat.go#L1335
static void
goo_isqrt(mpz_t r, const mpz_t x) {
  if (mpz_cmp_ui(x, 1) <= 0) {
    mpz_set(r, x);
    return;
  }

  mpz_t z1, z2;
  mpz_init(z1);
  mpz_init(z2);

  unsigned long len = goo_mpz_bitlen(x);

  // See https://members.loria.fr/PZimmermann/mca/pub226.html.
  // z1 = 1 << ((bitlen(x) >> 1) + 1);
  mpz_set_ui(z1, 1);
  mpz_mul_2exp(z1, z1, (len >> 1) + 1);

  for (;;) {
    // z2 = x / z1
    mpz_fdiv_q(z2, x, z1);
    // z2 += z1
    mpz_add(z2, z2, z1);
    // z2 >>= 1
    mpz_fdiv_q_2exp(z2, z2, 1);

    // if z2 >= z1
    if (mpz_cmp(z2, z1) >= 0)
      break;

    // z1 = z2
    mpz_set(z1, z2);
  }

  // Maybe switch to this entirely.
  mpz_sqrt(z2, x);
  assert(mpz_cmp(z1, z2) == 0);

  // r = z1
  mpz_set(r, z1);
  mpz_clear(z1);
  mpz_clear(z2);
}

static int
goo_is_square(const mpz_t n) {
  int r = 0;

  mpz_t x;
  mpz_init(x);

  // x = isqrt(n)
  goo_isqrt(x, n);

  // x = x * x
  mpz_mul(x, x, x);

  // if x == n
  if (mpz_cmp(x, n) == 0)
    goto succeed;

  goto fail;
succeed:
  r = 1;
fail:
  mpz_clear(x);
  return r;
}

static unsigned long
goo_dsqrt(unsigned long x) {
  if (x <= 1)
    return x;

  // Possibly use:
  // (unsigned log)sqrt((double)x)

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

#ifdef GOO_HAS_GMP
#define goo_jacobi mpz_jacobi
#else
// https://github.com/golang/go/blob/aadaec5/src/math/big/int.go#L754
static int
goo_jacobi(const mpz_t x, const mpz_t y) {
  // Undefined behavior.
  // if y == 0 || y & 1 == 0
  if (mpz_cmp_ui(y, 0) == 0 || mpz_even_p(y))
    return 0;

  mpz_t a;
  mpz_t b;
  mpz_t c;
  mpz_t t;
  int j;

  mpz_init(a);
  mpz_init(b);
  mpz_init(c);
  mpz_init(t);
  j = 0;

  // a = x
  mpz_set(a, x);
  // b = y
  mpz_set(b, y);
  j = 1;

  // if b < 0
  if (mpz_cmp_ui(b, 0) < 0) {
    // if a < 0
    if (mpz_cmp_ui(a, 0) < 0)
      j = -1;
    // b = -b
    mpz_mul_si(b, b, -1);
  }

  for (;;) {
    // if b == 1
    if (mpz_cmp_ui(b, 1) == 0)
      break;

    // if a == 0
    if (mpz_cmp_ui(a, 0) == 0) {
      j = 0;
      break;
    }

    // a = a % b
    mpz_mod(a, a, b);

    // if a == 0
    if (mpz_cmp_ui(a, 0) == 0) {
      j = 0;
      break;
    }

    // s = bitlen(a)
    unsigned long s = goo_zerobits(a);

    if (s & 1) {
      // bmod8 = b & 7
      unsigned long bmod8 = mpz_mod_ui(t, b, 8);

      if (bmod8 == 3 || bmod8 == 5)
        j = -j;
    }

    // c = a >> s
    mpz_fdiv_q_2exp(c, a, s);

    // if b & 3 == 3 and c & 3 == 3
    if (mpz_mod_ui(t, b, 4) == 3 && mpz_mod_ui(t, c, 4) == 3)
      j = -j;

    // a = b
    mpz_set(a, b);
    // b = c
    mpz_set(b, c);
  }

  mpz_clear(a);
  mpz_clear(b);
  mpz_clear(c);
  mpz_clear(t);

  return j;
}
#endif

static int
goo_mod_sqrtp(mpz_t ret, const mpz_t n, const mpz_t p) {
  if (mpz_cmp_ui(p, 0) < 0)
    return 0;

  int r = 0;
  unsigned long s;

  mpz_t nn, t, Q, w, y, q, ys;
  mpz_init(nn);
  mpz_init(t);
  mpz_init(Q);
  mpz_init(w);
  mpz_init(y);
  mpz_init(q);
  mpz_init(ys);

  // n = n % p
  mpz_mod(nn, n, p);

  // if n == 0
  if (mpz_cmp_ui(nn, 0) == 0) {
    mpz_set_ui(ret, 0);
    goto succeed;
  }

  if (goo_jacobi(nn, p) == -1)
    goto fail;

  // if p & 3 == 3
  if (mpz_mod_ui(t, p, 4) == 3) {
    // t = (p + 1) >> 2
    // ret = modpow(n, t, p)
    mpz_set(t, p);
    mpz_add_ui(t, t, 1);
    mpz_fdiv_q_2exp(t, t, 2);
    mpz_powm(ret, nn, t, p);
    goto succeed;
  }

  // Factor out 2^s from p - 1.
  // t = p - 1
  mpz_set(t, p);
  mpz_sub_ui(t, t, 1);

  // s = zerobits(t)
  s = goo_zerobits(t);
  // Q = t >> s
  mpz_fdiv_q_2exp(Q, t, s);

  // Find a non-residue mod p.
  // w = 2
  mpz_set_ui(w, 2);

  while (goo_jacobi(w, p) != -1)
    mpz_add_ui(w, w, 1);

  // w = modpow(w, Q, p)
  mpz_powm(w, w, Q, p);
  // y = modpow(n, Q, p)
  mpz_powm(y, nn, Q, p);

  // t = (Q + 1) >> 1
  // q = modpow(n, t, p)
  mpz_set(t, Q);
  mpz_add_ui(t, t, 1);
  mpz_fdiv_q_2exp(t, t, 1);
  mpz_powm(q, nn, t, p);

  for (;;) {
    unsigned long i = 0;

    // ys = s
    mpz_set(ys, y);

    // while i < s and y != 1
    while (i < s && mpz_cmp_ui(y, 1) != 0) {
      // y = modpow(y, 2, p)
      mpz_powm_ui(y, y, 2, p);
      i += 1;
    }

    if (i == 0)
      break;

    if (i == s)
      goto fail;

    // t = 1 << (s - i - 1)
    // w = modpow(w, t, p)
    mpz_set_ui(t, 1);
    mpz_mul_2exp(t, t, s - i - 1);
    mpz_powm(w, w, t, p);

    s = i;

    // q = (q * w) % p
    mpz_mul(q, q, w);
    mpz_mod(q, q, p);

    // w = modpow(w, 2, p)
    mpz_powm_ui(w, w, 2, p);

    // y = (ys * w) % p
    mpz_set(y, ys);
    mpz_mul(y, y, w);
    mpz_mod(y, y, p);
  }

  // t = p >> 1
  mpz_set(t, p);
  mpz_fdiv_q_2exp(t, t, 1);

  // if q > t
  if (mpz_cmp(q, t) > 0) {
    // q = p - q
    mpz_sub(q, p, q);
  }

  // t = (q * q) % p
  mpz_set(t, q);
  mpz_mul(t, t, t);
  mpz_mod(t, t, p);

  // n == t
  assert(mpz_cmp(nn, t) == 0);

  // ret = q
  mpz_set(ret, q);

succeed:
  r = 1;
fail:
  mpz_clear(nn);
  mpz_clear(t);
  mpz_clear(Q);
  mpz_clear(w);
  mpz_clear(y);
  mpz_clear(q);
  mpz_clear(ys);
  return r;
}

static int
goo_mod_sqrtn(mpz_t ret, const mpz_t x, const mpz_t p, const mpz_t q) {
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
  if (!goo_mod_sqrtp(sp, x, p)
      || !goo_mod_sqrtp(sq, x, q)) {
    goto fail;
  }

  // [mp, mq] = euclid_lr(p, q)
  mpz_gcdext(ret, mp, mq, p, q);

  // xx = sq * mp * p
  mpz_set(xx, sq);
  mpz_mul(xx, xx, mp);
  mpz_mul(xx, xx, p);

  // yy = sp * mq * q
  mpz_set(yy, sp);
  mpz_mul(yy, yy, mq);
  mpz_mul(yy, yy, q);

  // xx = xx + y
  mpz_add(xx, xx, yy);

  // yy = p * q
  mpz_set(yy, p);
  mpz_mul(yy, yy, q);

  // ret = xx % yy
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
  int r = 0;
  mpz_t t;
  mpz_init(t);

  for (long i = 0; i < GOO_TEST_PRIMES_LEN; i++) {
    // if n % test_primes[i] == 0
    if (mpz_mod_ui(t, n, goo_test_primes[i]) == 0)
      goto fail;
  }

  r = 1;
fail:
  mpz_clear(t);
  return r;
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
  mpz_set(nm1, n);
  mpz_sub_ui(nm1, nm1, 1);

  // nm3 = nm1 - 2
  mpz_set(nm3, nm1);
  mpz_sub_ui(nm3, nm3, 2);

  // k = zero_bits(nm1)
  k = goo_zerobits(nm1);
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
      goo_prng_getrandint(&prng, x, nm3);
      // x += 2
      mpz_add_ui(x, x, 2);
    }

    // y = modpow(x, q, n)
    mpz_powm(y, x, q, n);

    // if y == 1 || y == nm1
    if (mpz_cmp_ui(y, 1) == 0 || mpz_cmp(y, nm1) == 0)
      continue;

    for (unsigned long j = 1; j < k; j++) {
      // y = modpow(y, 2, n)
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
  int ret = 0;
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

    // d = p * p - 4
    mpz_set_ui(d, p * p - 4);

    int j = goo_jacobi(d, n);

    if (j == -1)
      break;

    if (j == 0) {
      // if n == p + 2
      if (mpz_cmp_ui(n, p + 2) == 0)
        goto succeed;
      goto fail;
    }

    if (p == 40) {
      if (goo_is_square(n))
        goto fail;
    }

    p += 1;
  }

  // Check for Grantham definition of
  // "extra strong Lucas pseudoprime".
  // s = n + 1
  mpz_add_ui(s, n, 1);

  // r = zerobits(s)
  unsigned long r = goo_zerobits(s);

  // nm2 = n - 2
  mpz_sub_ui(nm2, n, 2);

  // s >>= r
  mpz_fdiv_q_2exp(s, s, r);

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
      // vk = t1 % n
      mpz_mod(vk, t1, n);
      // t1 = vk1 * vk1
      mpz_mul(t1, vk1, vk1);
      // t1 += nm2
      mpz_add(t1, t1, nm2);
      // vk1 = t1 % n
      mpz_mod(vk1, t1, n);
    } else {
      // t1 = vk * vk1
      mpz_mul(t1, vk, vk1);
      // t1 += n
      mpz_add(t1, t1, n);
      // t1 -= bp
      mpz_sub_ui(t1, t1, bp);
      // vk1 = t1 % n
      mpz_mod(vk1, t1, n);
      // t1 = vk * vk
      mpz_mul(t1, vk, vk);
      // t1 += nm2
      mpz_add(t1, t1, nm2);
      // vk = t1 % n
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

    // t3 = t1 % n
    mpz_mod(t3, t1, n);

    // if t3 == 0
    if (mpz_cmp_ui(t3, 0) == 0)
      goto succeed;
  }

  for (long t = 0; t < (long)r - 1; t++) {
    if (mpz_cmp_ui(vk, 0) == 0)
      goto succeed;

    if (mpz_cmp_ui(vk, 2) == 0)
      goto fail;

    // t1 = vk * vk
    mpz_mul(t1, vk, vk);
    // t1 -= 2
    mpz_sub_ui(t1, t1, 2);
    // vk = t1 % n
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
  // if p <= 0
  if (mpz_cmp_ui(p, 0) <= 0)
    return 0;

  for (long i = 0; i < GOO_TEST_PRIMES_LEN; i++) {
    // if p == test_primes[i]
    if (mpz_cmp_ui(p, goo_test_primes[i]) == 0)
      return 1;
  }

  if (!goo_is_prime_div(p))
    return 0;

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
  mpz_init(sig->t);
  mpz_init(sig->chal);
  mpz_init(sig->ell);
  mpz_init(sig->Aq);
  mpz_init(sig->Bq);
  mpz_init(sig->Cq);
  mpz_init(sig->Dq);
  mpz_init(sig->z_w);
  mpz_init(sig->z_w2);
  mpz_init(sig->z_s1);
  mpz_init(sig->z_a);
  mpz_init(sig->z_an);
  mpz_init(sig->z_s1w);
  mpz_init(sig->z_sa);
}

static void
goo_sig_uninit(goo_sig_t *sig) {
  mpz_clear(sig->C2);
  mpz_clear(sig->t);
  mpz_clear(sig->chal);
  mpz_clear(sig->ell);
  mpz_clear(sig->Aq);
  mpz_clear(sig->Bq);
  mpz_clear(sig->Cq);
  mpz_clear(sig->Dq);
  mpz_clear(sig->z_w);
  mpz_clear(sig->z_w2);
  mpz_clear(sig->z_s1);
  mpz_clear(sig->z_a);
  mpz_clear(sig->z_an);
  mpz_clear(sig->z_s1w);
  mpz_clear(sig->z_sa);
}

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
  goo_combspec_t *spec,
  int tiny
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

  if (tiny) {
    assert(comb->points_per_add == 8);
    assert(comb->adds_per_shift == 2);
    assert(comb->shifts == 8);
    assert(comb->bits_per_window == 16);
    assert(comb->bits == 128);
    assert(comb->points_per_subcomb == 255);
    assert(comb->size == 510);
  }

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
        ret += (long)mpz_tstbit(e, (comb->bits - 1) - b);
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
goo_group_init(
  goo_group_t *group,
  const unsigned char *n,
  size_t n_len,
  unsigned long g,
  unsigned long h,
  unsigned long modbits
) {
  memset((void *)group, 0x00, sizeof(goo_group_t));

  mpz_init(group->n);
  mpz_init(group->nh);
  mpz_init(group->g);
  mpz_init(group->h);

  // n = n
  goo_mpz_import(group->n, n, n_len);

  // nh = n >> 1
  mpz_fdiv_q_2exp(group->nh, group->n, 1);

  // g = g
  mpz_set_ui(group->g, g);
  // h = h
  mpz_set_ui(group->h, h);

  group->rand_bits = goo_clog2(group->n) - 1;

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
    goo_comb_init(&group->combs[0].g, group, group->g, &small_spec, 0);
    goo_comb_init(&group->combs[0].h, group, group->h, &small_spec, 0);
    goo_comb_init(&group->combs[1].g, group, group->g, &big_spec, 0);
    goo_comb_init(&group->combs[1].h, group, group->h, &big_spec, 0);
  } else {
    long tiny_bits = GOO_CHAL_BITS;

    goo_combspec_t tiny_spec;
    assert(goo_combspec_init(&tiny_spec, tiny_bits, GOO_MAX_COMB_SIZE));

    group->combs_len = 1;
    goo_comb_init(&group->combs[0].g, group, group->g, &tiny_spec, 1);
    goo_comb_init(&group->combs[0].h, group, group->h, &tiny_spec, 1);
  }

  for (long i = 0; i < GOO_TABLEN; i++) {
    mpz_init(group->pctab_p1[i]);
    mpz_init(group->pctab_n1[i]);
    mpz_init(group->pctab_p2[i]);
    mpz_init(group->pctab_n2[i]);
  }

  goo_prng_init(&group->prng);

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
  mpz_init(group->z_w2_m_an);
  mpz_init(group->tmp);
  mpz_init(group->chal_out);
  mpz_init(group->ell_r_out);
  mpz_init(group->elldiff);
  mpz_init(group->C1);
  mpz_init(group->C2);
  mpz_init(group->t);
  mpz_init(group->msg);
  mpz_init(group->chal);
  mpz_init(group->ell);
  mpz_init(group->Aq);
  mpz_init(group->Bq);
  mpz_init(group->Cq);
  mpz_init(group->Dq);
  mpz_init(group->z_w);
  mpz_init(group->z_w2);
  mpz_init(group->z_s1);
  mpz_init(group->z_a);
  mpz_init(group->z_an);
  mpz_init(group->z_s1w);
  mpz_init(group->z_sa);

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
  mpz_clear(group->z_w2_m_an);
  mpz_clear(group->tmp);
  mpz_clear(group->chal_out);
  mpz_clear(group->ell_r_out);
  mpz_clear(group->elldiff);
  mpz_clear(group->C1);
  mpz_clear(group->C2);
  mpz_clear(group->t);
  mpz_clear(group->msg);
  mpz_clear(group->chal);
  mpz_clear(group->ell);
  mpz_clear(group->Aq);
  mpz_clear(group->Bq);
  mpz_clear(group->Cq);
  mpz_clear(group->Dq);
  mpz_clear(group->z_w);
  mpz_clear(group->z_w2);
  mpz_clear(group->z_s1);
  mpz_clear(group->z_a);
  mpz_clear(group->z_an);
  mpz_clear(group->z_s1w);
  mpz_clear(group->z_sa);
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
  // ret = modpow(b, 2, n)
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
  // ret = modpow(b, e, n)
  mpz_powm(ret, b, e, group->n);
}

static void
goo_group_mul(goo_group_t *group, mpz_t ret, const mpz_t m1, const mpz_t m2) {
  // ret = (m1 * m2) % n
  mpz_mul(ret, m1, m2);
  mpz_mod(ret, ret, group->n);
}

static int
goo_group_inv(goo_group_t *group, mpz_t ret, const mpz_t b) {
  // ret = modinverse(b, n)
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
  // b12_inv = modinverse(b1 * b2)
  mpz_mul(group->b12_inv, b1, b2);

  if (!goo_group_inv(group, group->b12_inv, group->b12_inv))
    return 0;

  // r1 = (b2 * b12_inv) % n
  goo_group_mul(group, r1, b2, group->b12_inv);
  // r2 = (b1 * b12_inv) % n
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
  // b12 = (b1 * b2) % n
  goo_group_mul(group, group->b12, b1, b2);
  // b34 = (b3 * b4) % n
  goo_group_mul(group, group->b34, b3, b4);
  // b1234 = (b12 * b34) % n
  goo_group_mul(group, group->b1234, group->b12, group->b34);
  // b12345 = (b1234 * b5) % n
  goo_group_mul(group, group->b12345, group->b1234, b5);

  // b12345_inv = modinverse(b12345);
  if (!goo_group_inv(group, group->b12345_inv, group->b12345))
    return 0;

  // b1234_inv = (b12345_inv * b5) % n
  goo_group_mul(group, group->b1234_inv, group->b12345_inv, b5);
  // b34_inv = (b1234_inv * b12) % n
  goo_group_mul(group, group->b34_inv, group->b1234_inv, group->b12);
  // b12_inv = (b1234_inv * b34) % n
  goo_group_mul(group, group->b12_inv, group->b1234_inv, group->b34);

  // r1 = (b12_inv * b2) % n
  goo_group_mul(group, r1, group->b12_inv, b2);
  // r2 = (b12_inv * b1) % n
  goo_group_mul(group, r2, group->b12_inv, b1);
  // r3 = (b34_inv * b4) % n
  goo_group_mul(group, r3, group->b34_inv, b4);
  // r4 = (b34_inv * b3) % n
  goo_group_mul(group, r4, group->b34_inv, b3);
  // r5 = (b12345_inv * b1234) % n
  goo_group_mul(group, r5, group->b12345_inv, group->b1234);

  return 1;
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

  mpz_set_ui(ret, 1);

  for (long i = 0; i < gcomb->shifts; i++) {
    long *e1vs = gcomb->wins[i];
    long *e2vs = hcomb->wins[i];

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
  // q1 = modpow(g, e1, n)
  mpz_powm(q1, group->g, e1, group->n);
  // q2 = modpow(h, e2, n)
  mpz_powm(q2, group->h, e2, group->n);
  // ret = (q1 * q2) % n
  mpz_mul(ret, q1, q2);
  mpz_mod(ret, ret, group->n);
  mpz_clear(q1);
  mpz_clear(q2);
  return 1;
}

static void
goo_group_wnaf_pc_help(goo_group_t *group, const mpz_t b, mpz_t *out) {
  // bsq = b * b
  goo_group_sqr(group, group->bsq, b);

  // out[0] = b
  mpz_set(out[0], b);

  for (long i = 1; i < GOO_TABLEN; i++) {
    // out[i] = out[i - 1] * bsq
    goo_group_mul(group, out[i], out[i - 1], group->bsq);
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
goo_group_wnaf(goo_group_t *group, const mpz_t e, long *out, long bitlen) {
  long w = GOO_WINDOW_SIZE;

  // r = e
  mpz_set(group->r, e);

  for (long i = bitlen - 1; i >= 0; i--) {
    // val = 0
    mpz_set_ui(group->val, 0);

    // if r & 1
    if (mpz_odd_p(group->r)) {
      // mask = (1 << w) - 1
      mpz_set_ui(group->mask, (1 << w) - 1);
      // val = r & mask
      mpz_and(group->val, group->r, group->mask);
      // if val & (1 << (w - 1))
      if (mpz_tstbit(group->val, w - 1)) {
        // val -= 1 << w
        mpz_sub_ui(group->val, group->val, 1 << w);
      }
      // r = r - val
      mpz_sub(group->r, group->r, group->val);
    }

    // out[i] = val
    // assert(mpz_fits_slong_p(group->val));
    out[i] = mpz_get_si(group->val);

    // r = r >> 1
    mpz_fdiv_q_2exp(group->r, group->r, 1);
  }

  // r == 0
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

static void
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
  // q1 = modpow(b1, e2, n)
  mpz_powm(q1, b1, e1, group->n);
  // q2 = modpow(b2, e2, n)
  mpz_powm(q2, b2, e2, group->n);
  // ret = (q1 * q2) % n
  mpz_mul(ret, q1, q2);
  mpz_mod(ret, ret, group->n);
  mpz_clear(q1);
  mpz_clear(q2);
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
  // ret = pow2(b1, b1_inv, e1, b2, b2_inv, e2)
  if (!goo_group_pow2(group, ret, b1, b1_inv, e1, b2, b2_inv, e2))
    return 0;

  // gh = powgh(e3, e4)
  if (!goo_group_powgh(group, group->gh, e3, e4))
    return 0;

  // ret = ret * gh
  goo_group_mul(group, ret, ret, group->gh);

  // ret = reduce(ret)
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

  goo_mpz_export(&buf[0], &len, n);

  // Sanity check.
  assert(len <= (GOO_MAX_RSA_BITS + 7) / 8);

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
  unsigned char *size = &group->slab[0];
  unsigned char *buf = &group->slab[2];

  goo_sha256_t ctx;
  goo_sha256_init(&ctx);
  goo_sha256_update(&ctx, (void *)goo_prefix, sizeof(goo_prefix) - 1);

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

  goo_sha256_final(&ctx, out);
}

static int
goo_group_fs_chal(
  goo_group_t *group,
  mpz_t chal,
  mpz_t ell,
  unsigned char *k,
  const mpz_t C1,
  const mpz_t C2,
  const mpz_t t,
  const mpz_t A,
  const mpz_t B,
  const mpz_t C,
  const mpz_t D,
  const mpz_t msg,
  int verify
) {
  unsigned char key[32];

  goo_hash_all(&key[0], group, C1, C2, t, A, B, C, D, msg);

  goo_prng_seed(&group->prng, &key[0]);
  goo_prng_getrandbits(&group->prng, chal, GOO_CHAL_BITS);
  goo_prng_getrandbits(&group->prng, ell, GOO_CHAL_BITS);

  if (k != NULL)
    memcpy(k, key, 32);

  if (!verify) {
    // For prover, call next_prime on ell_r to get ell.
    if (!goo_next_prime(ell, ell, key, GOO_ELLDIFF_MAX)) {
      mpz_set_ui(chal, 0);
      mpz_set_ui(ell, 0);
      return 0;
    }
  }

  return 1;
}

static int
goo_group_randbits(goo_group_t *group, mpz_t ret, size_t size) {
  unsigned char key[32];

  if (!goo_random(&key[0], 32))
    return 0;

  goo_prng_seed(&group->prng, &key[0]);
  goo_prng_getrandbits(&group->prng, ret, size);

  return 1;
}

static int
goo_group_expand_sprime(goo_group_t *group, mpz_t s, const mpz_t s_prime) {
  unsigned char key[32];
  size_t bytes = goo_mpz_bytesize(s_prime);

  if (bytes > 32)
    return 0;

  size_t pos = 32 - bytes;

  memset(&key[0], 0x00, pos);
  goo_mpz_export(&key[pos], NULL, s_prime);

  goo_prng_seed(&group->prng, &key[0]);
  goo_prng_getrandbits(&group->prng, s, GOO_EXPONENT_SIZE);

  return 1;
}

static int
goo_group_rand_scalar(goo_group_t *group, mpz_t ret) {
  size_t size = group->rand_bits;

  if (size > GOO_EXPONENT_SIZE)
    size = GOO_EXPONENT_SIZE;

  unsigned char key[32];

  if (!goo_random(&key[0], 32))
    return 0;

  goo_prng_seed(&group->prng, &key[0]);
  goo_prng_getrandbits(&group->prng, ret, size);

  return 1;
}

static int
goo_group_challenge(
  goo_group_t *group,
  mpz_t s_prime,
  mpz_t C1,
  const mpz_t n
) {
  int r = 0;

  mpz_t s;
  mpz_init(s);

  if (mpz_cmp_ui(n, 0) <= 0) {
    // Invalid RSA public key.
    goto fail;
  }

  // s_prime = randbits(256)
  if (!goo_group_randbits(group, s_prime, 256))
    goto fail;

  // s = expand_sprime(s_prime)
  if (!goo_group_expand_sprime(group, s, s_prime))
    goto fail;

  // if s <= 0
  if (mpz_cmp_ui(s, 0) <= 0)
    goto fail;

  // The challenge: a commitment to the RSA modulus.
  // C1 = powgh(n, s)
  if (!goo_group_powgh(group, C1, n, s))
    goto fail;

  // if C1 <= 0
  if (mpz_cmp_ui(C1, 0) <= 0)
    goto fail;

  // C1 = reduce(C1)
  goo_group_reduce(group, C1, C1);

  r = 1;
fail:
  mpz_clear(s);
  return r;
}

static int
goo_group_sign(
  goo_group_t *group,
  goo_sig_t *sig,
  const mpz_t msg,
  const mpz_t s_prime,
  const mpz_t C1,
  const mpz_t n,
  const mpz_t p,
  const mpz_t q
) {
  goo_sig_init(sig);

  mpz_t *C2 = &sig->C2;
  mpz_t *t = &sig->t;
  mpz_t *chal = &sig->chal;
  mpz_t *ell = &sig->ell;
  mpz_t *Aq = &sig->Aq;
  mpz_t *Bq = &sig->Bq;
  mpz_t *Cq = &sig->Cq;
  mpz_t *Dq = &sig->Dq;
  mpz_t *z_w = &sig->z_w;
  mpz_t *z_w2 = &sig->z_w2;
  mpz_t *z_s1 = &sig->z_s1;
  mpz_t *z_a = &sig->z_a;
  mpz_t *z_an = &sig->z_an;
  mpz_t *z_s1w = &sig->z_s1w;
  mpz_t *z_sa = &sig->z_sa;

  mpz_t *s = &group->Aq;
  mpz_t *w = &group->Bq;
  mpz_t *a = &group->Cq;
  mpz_t *s1 = &group->Dq;

  mpz_t *x = &group->Aq_inv;
  mpz_t *y = &group->Bq_inv;
  mpz_t *z = &group->Cq_inv;
  mpz_t *xx = &group->chal_out;
  mpz_t *yy = &group->ell_r_out;

  mpz_t *C1_inv = &group->C1_inv;
  mpz_t *C2_inv = &group->C2_inv;

  mpz_t *r_w = &group->z_w;
  mpz_t *r_w2 = &group->z_w2;
  mpz_t *r_s1 = &group->z_s1;
  mpz_t *r_a = &group->z_a;
  mpz_t *r_an = &group->z_an;
  mpz_t *r_s1w = &group->z_s1w;
  mpz_t *r_sa = &group->z_sa;

  mpz_t *A = &group->A;
  mpz_t *B = &group->B;
  mpz_t *C = &group->C;
  mpz_t *D = &group->D;

  int r = 0;

  // if s_prime <= 0 or C1 <= 0 or n <= 0 or p <= 0 or q <= 0
  if (mpz_cmp_ui(s_prime, 0) <= 0
      || mpz_cmp_ui(C1, 0) <= 0
      || mpz_cmp_ui(n, 0) <= 0
      || mpz_cmp_ui(p, 0) <= 0
      || mpz_cmp_ui(q, 0) <= 0) {
    goto fail;
  }

  // x = p * q
  mpz_mul(*x, p, q);

  // if x != n
  if (mpz_cmp(*x, n) != 0) {
    // Invalid RSA private key.
    goto fail;
  }

  // s = expand_sprime(s_prime)
  if (!goo_group_expand_sprime(group, *s, s_prime))
    goto fail;

  // x = powgh(n, s)
  if (!goo_group_powgh(group, *x, n, *s))
    goto fail;

  goo_group_reduce(group, *x, *x);

  // if C1 != x
  if (mpz_cmp(C1, *x) != 0) {
    // C1 does not commit to our RSA modulus with opening s.
    goto fail;
  }

  // Preliminaries: compute values P needs to run the ZKPOK.
  // Find `t`.
  int found = 0;

  for (long i = 0; i < GOO_PRIMES_LEN; i++) {
    // t = small_primes[i]
    mpz_set_ui(*t, goo_primes[i]);

    // w = mod_sqrtn(t, p, q)
    if (goo_mod_sqrtn(*w, *t, p, q)) {
      found = 1;
      break;
    }
  }

  if (!found) {
    // No prime quadratic residue less than 1000 mod N!
    goto fail;
  }

  // a = (w ** 2 - t) / n
  mpz_set(*a, *w);
  mpz_pow_ui(*a, *a, 2);
  mpz_sub(*a, *a, *t);
  mpz_fdiv_q(*a, *a, n);

  // x = a * n
  mpz_set(*x, *a);
  mpz_mul(*x, *x, n);

  // y = w ** 2 - t
  mpz_set(*y, *w);
  mpz_pow_ui(*y, *y, 2);
  mpz_sub(*y, *y, *t);

  // if x != y
  if (mpz_cmp(*x, *y) != 0) {
    // w^2 - t was not divisible by N!
    goto fail;
  }

  // Commitment to `w`.
  // s1 = rand_scalar()
  // C2 = powgh(w, s1)
  if (!goo_group_rand_scalar(group, *s1)
      || !goo_group_powgh(group, *C2, *w, *s1)) {
    goto fail;
  }

  goo_group_reduce(group, *C2, *C2);

  // Inverses of `C1` and `C2`.
  // [C1_inv, C2_inv] = inv2(C1, C2)
  if (!goo_group_inv2(group, *C1_inv, *C2_inv, C1, *C2))
    goto fail;

  // P's first message: commit to randomness.
  // P's randomness (except for r_s1; see "V's message", below).
  // [r_w, r_w2, r_a, r_an, r_s1w, r_sa] = rand_scalar(7)
  if (!goo_group_rand_scalar(group, *r_w)
      || !goo_group_rand_scalar(group, *r_w2)
      || !goo_group_rand_scalar(group, *r_a)
      || !goo_group_rand_scalar(group, *r_an)
      || !goo_group_rand_scalar(group, *r_s1w)
      || !goo_group_rand_scalar(group, *r_sa)) {
    goto fail;
  }

  // Prevent D from being negative.
  if (mpz_cmp(*r_w2, *r_an) < 0) {
    // [r_w2, r_an] = [r_an, r_w2]
    mpz_swap(*r_w2, *r_an);
  }

  // P's first message (except for A; see "V's message", below).
  // B = pow(C2_inv, C2, r_w) * powgh(r_w2, r_s1w)
  goo_group_pow(group, *x, *C2_inv, *C2, *r_w);

  if (!goo_group_powgh(group, *y, *r_w2, *r_s1w))
    goto fail;

  goo_group_mul(group, *B, *x, *y);
  goo_group_reduce(group, *B, *B);

  // C = pow(C1_inv, C1, r_a) * powgh(r_an, r_sa)
  goo_group_pow(group, *x, *C1_inv, C1, *r_a);

  if (!goo_group_powgh(group, *y, *r_an, *r_sa))
    goto fail;

  goo_group_mul(group, *C, *x, *y);
  goo_group_reduce(group, *C, *C);

  // D = r_w2 - r_an
  mpz_sub(*D, *r_w2, *r_an);

  // V's message: random challenge and random prime.
  while (r == 0 || goo_mpz_bitlen(*ell) != 128) {
    // Randomize the signature until Fiat-Shamir
    // returns an admissable ell. Note that it's
    // not necessary to re-start the whole
    // signature! Just pick a new r_s1, which
    // only requires re-computing A.
    // r_s1 = rand_scalar()
    // A = powgh(r_w, r_s1)
    if (!goo_group_rand_scalar(group, *r_s1)
        || !goo_group_powgh(group, *A, *r_w, *r_s1)) {
      goto fail;
    }

    goo_group_reduce(group, *A, *A);

    // [chal, ell] = fs_chal(C1, C2, t, A, B, C, D, msg)
    r = goo_group_fs_chal(group,
                          *chal, *ell, NULL, C1, *C2,
                          *t, *A, *B, *C, *D, msg, 0);
  }

  // P's second message: compute quotient message.
  // Compute z' = c*(w, w2, s1, a, an, s1w, sa)
  //            + (r_w, r_w2, r_s1, r_a, r_an, r_s1w, r_sa)
  // z_w = chal * w + r_w
  mpz_mul(*z_w, *chal, *w);
  mpz_add(*z_w, *z_w, *r_w);
  // z_w2 = chal * w * w + r_w2
  mpz_mul(*z_w2, *chal, *w);
  mpz_mul(*z_w2, *z_w2, *w);
  mpz_add(*z_w2, *z_w2, *r_w2);
  // z_s1 = chal * s1 + r_s1
  mpz_mul(*z_s1, *chal, *s1);
  mpz_add(*z_s1, *z_s1, *r_s1);
  // z_a = chal * a + r_a
  mpz_mul(*z_a, *chal, *a);
  mpz_add(*z_a, *z_a, *r_a);
  // z_an = chal * a * n + r_an
  mpz_mul(*z_an, *chal, *a);
  mpz_mul(*z_an, *z_an, n);
  mpz_add(*z_an, *z_an, *r_an);
  // z_s1w = chal * s1 * w + r_s1w
  mpz_mul(*z_s1w, *chal, *s1);
  mpz_mul(*z_s1w, *z_s1w, *w);
  mpz_add(*z_s1w, *z_s1w, *r_s1w);
  // z_sa = chal * s * a + r_sa
  mpz_mul(*z_sa, *chal, *s);
  mpz_mul(*z_sa, *z_sa, *a);
  mpz_add(*z_sa, *z_sa, *r_sa);

  // Compute quotient commitments.

  // Aq = powgh(z_w / ell, z_s1 / ell)
  mpz_fdiv_q(*x, *z_w, *ell);
  mpz_fdiv_q(*y, *z_s1, *ell);

  if (!goo_group_powgh(group, *Aq, *x, *y))
    goto fail;

  goo_group_reduce(group, *Aq, *Aq);

  // Bq = pow(C2_inv, C2, z_w / ell) * powgh(z_w2 / ell, z_s1w / ell)
  mpz_fdiv_q(*x, *z_w, *ell);
  mpz_fdiv_q(*y, *z_w2, *ell);
  mpz_fdiv_q(*z, *z_s1w, *ell);
  goo_group_pow(group, *xx, *C2_inv, *C2, *x);

  if (!goo_group_powgh(group, *yy, *y, *z))
    goto fail;

  goo_group_mul(group, *Bq, *xx, *yy);
  goo_group_reduce(group, *Bq, *Bq);

  // Cq = pow(C1_inv, C2, z_a / ell) * powgh(z_an / ell, z_sa / ell)
  mpz_fdiv_q(*x, *z_a, *ell);
  mpz_fdiv_q(*y, *z_an, *ell);
  mpz_fdiv_q(*z, *z_sa, *ell);
  goo_group_pow(group, *xx, *C1_inv, *C2, *x);

  if (!goo_group_powgh(group, *yy, *y, *z))
    goto fail;

  goo_group_mul(group, *Cq, *xx, *yy);
  goo_group_reduce(group, *Cq, *Cq);

  // Dq = (z_w2 - z_an) / ell
  mpz_sub(*Dq, *z_w2, *z_an);
  mpz_fdiv_q(*Dq, *Dq, *ell);

  assert(mpz_cmp_ui(*Dq, 0) >= 0);
  assert(goo_mpz_bitlen(*Dq) <= 2048);

  mpz_mod(*z_w, *z_w, *ell);
  mpz_mod(*z_w2, *z_w2, *ell);
  mpz_mod(*z_s1, *z_s1, *ell);
  mpz_mod(*z_a, *z_a, *ell);
  mpz_mod(*z_an, *z_an, *ell);
  mpz_mod(*z_s1w, *z_s1w, *ell);
  mpz_mod(*z_sa, *z_sa, *ell);

  // z_prime: (z_w, z_w2, z_s1, z_a, z_an, z_s1w, z_sa).
  // Signature: (chal, ell, Aq, Bq, Cq, Dq, z_prime).

  return 1;
fail:
  goo_sig_uninit(sig);
  return 0;
}

static int
goo_group_verify(
  goo_group_t *group,

  // msg
  const mpz_t msg,

  // pubkey
  const mpz_t C1,
  const mpz_t C2,
  const mpz_t t,

  // sigma
  const mpz_t chal,
  const mpz_t ell,
  const mpz_t Aq,
  const mpz_t Bq,
  const mpz_t Cq,
  const mpz_t Dq,

  // z_prime
  const mpz_t z_w,
  const mpz_t z_w2,
  const mpz_t z_s1,
  const mpz_t z_a,
  const mpz_t z_an,
  const mpz_t z_s1w,
  const mpz_t z_sa
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
  mpz_t *z_w2_m_an = &group->z_w2_m_an;
  mpz_t *tmp = &group->tmp;
  mpz_t *chal_out = &group->chal_out;
  mpz_t *ell_r_out = &group->ell_r_out;
  mpz_t *elldiff = &group->elldiff;

  // Sanity check.
  if (mpz_cmp_ui(C1, 0) <= 0
      || mpz_cmp_ui(C2, 0) <= 0
      || mpz_cmp_ui(t, 0) <= 0
      || mpz_cmp_ui(chal, 0) <= 0
      || mpz_cmp_ui(ell, 0) <= 0
      || mpz_cmp_ui(Aq, 0) <= 0
      || mpz_cmp_ui(Bq, 0) <= 0
      || mpz_cmp_ui(Cq, 0) <= 0
      || mpz_cmp_ui(Dq, 0) <= 0
      || mpz_cmp_ui(z_w, 0) <= 0
      || mpz_cmp_ui(z_w2, 0) <= 0
      || mpz_cmp_ui(z_s1, 0) <= 0
      || mpz_cmp_ui(z_a, 0) <= 0
      || mpz_cmp_ui(z_an, 0) <= 0
      || mpz_cmp_ui(z_s1w, 0) <= 0
      || mpz_cmp_ui(z_sa, 0) <= 0) {
    return 0;
  }

  if (goo_mpz_bitlen(ell) != 128)
    return 0;

  unsigned char key[32];

  // `t` must be one of the small primes in our list.
  int found = 0;

  for (long i = 0; i < GOO_PRIMES_LEN; i++) {
    // if t == primes[i]
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

  // Compute inverses of C1, C2, Aq, Bq, Cq.
  // [C1_inv, C2_inv, Aq_inv, Bq_inv, Cq_inv] = inv5(C1, C2, Aq, Bq, Cq)
  if (!goo_group_inv5(group, *C1_inv, *C2_inv, *Aq_inv,
                      *Bq_inv, *Cq_inv, C1, C2, Aq, Bq, Cq)) {
    return 0;
  }

  // Step 1: reconstruct A, B, C, and D from signature.
  // A = recon(Aq, Aq_inv, ell, C2_inv, C2, chal, z_w, z_s1)
  if (!goo_group_recon(group, *A, Aq, *Aq_inv, ell,
                       *C2_inv, C2, chal, z_w, z_s1)) {
    return 0;
  }

  // B = recon(Bq, Bq_inv, ell, C2_inv, C2, z_w, z_w2, z_s1w)
  if (!goo_group_recon(group, *B, Bq, *Bq_inv, ell,
                       *C2_inv, C2, z_w, z_w2, z_s1w)) {
    return 0;
  }

  // C = recon(Cq, Cq_inv, ell, C1_inv, C1, z_a, z_an, z_sa)
  if (!goo_group_recon(group, *C, Cq, *Cq_inv, ell,
                       *C1_inv, C1, z_a, z_an, z_sa)) {
    return 0;
  }

  // Make sure sign of (z_w2 - z_an) is positive.
  // z_w2_m_an = z_w2 - z_an
  mpz_sub(*z_w2_m_an, z_w2, z_an);

  // D = Dq * ell + z_w2_m_an - t * chal
  mpz_mul(*D, Dq, ell);
  mpz_add(*D, *D, *z_w2_m_an);
  mpz_mul(*tmp, t, chal);
  mpz_sub(*D, *D, *tmp);

  // if z_w2_m_an < 0
  if (mpz_cmp_ui(*z_w2_m_an, 0) < 0) {
    // D += ell
    mpz_add(*D, *D, ell);
  }

  if (mpz_cmp_ui(*D, 0) < 0)
    return 0;

  // Step 2: recompute implicitly claimed V message, viz., chal and ell.
  // [chal_out, ell_r_out, key] = fs_chal(C1, C2, t, A, B, C, D, msg)
  goo_group_fs_chal(group, *chal_out, *ell_r_out, &key[0],
                    C1, C2, t, *A, *B, *C, *D, msg, 1);

  // Final checks.
  // chal has to match
  // AND 0 <= (ell_r_out - ell) <= elldiff_max
  // AND ell is prime
  // elldiff = ell - ell_r_out
  mpz_sub(*elldiff, ell, *ell_r_out);

  // if chal != chal_out
  //   or elldiff < 0
  //   or elldiff > ELLDIFF_MAX
  //   or !is_prime(ell)
  if (mpz_cmp(chal, *chal_out) != 0
      || mpz_cmp_ui(*elldiff, 0) < 0
      || mpz_cmp_ui(*elldiff, GOO_ELLDIFF_MAX) > 0
      || !goo_is_prime(ell, &key[0])) {
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
  if (ctx == NULL || n == NULL)
    return 0;

  if (modbits != 0) {
    if (modbits < GOO_MIN_RSA_BITS || modbits > GOO_MAX_RSA_BITS)
      return 0;
  }

  return goo_group_init(ctx, n, n_len, g, h, modbits);
}

void
goo_uninit(goo_ctx_t *ctx) {
  if (ctx != NULL)
    goo_group_uninit(ctx);
}

int
goo_challenge(
  goo_ctx_t *ctx,
  unsigned char **s_prime,
  size_t *s_prime_len,
  unsigned char **C1,
  size_t *C1_len,
  const unsigned char *n,
  size_t n_len
) {
  int r = 0;

  if (ctx == NULL
      || s_prime == NULL
      || s_prime_len == NULL
      || C1 == NULL
      || C1_len == NULL
      || n == NULL) {
    return 0;
  }

  // if (n_len < GOO_MIN_RSA_BITS / 8 || n_len > GOO_MAX_RSA_BITS / 8)
  //   return 0;

  mpz_t nn, spn;
  mpz_init(nn);
  mpz_init(spn);

  goo_mpz_import(nn, n, n_len);

  if (!goo_group_challenge(ctx, spn, ctx->C1, nn))
    goto fail;

  *s_prime_len = 32;
  *s_prime = goo_mpz_pad(NULL, *s_prime_len, spn);

  if (*s_prime == NULL)
    goto fail;

  *C1_len = goo_mpz_bytesize(ctx->n);
  *C1 = goo_mpz_pad(NULL, *C1_len, ctx->C1);

  if (*C1 == NULL) {
    free(*s_prime);
    goto fail;
  }

  r = 1;
fail:
  mpz_clear(nn);
  mpz_clear(spn);
  return r;
}

#define goo_write_item(n, size) do {     \
  size_t bytes = goo_mpz_bytesize((n));  \
  if (bytes > (size)) {                  \
    free(data);                          \
    goto fail;                           \
  }                                      \
  size_t pad = (size) - bytes;           \
  memset(&data[pos], 0x00, pad);         \
  pos += pad;                            \
  goo_mpz_export(&data[pos], NULL, (n)); \
  pos += bytes;                          \
} while (0)

#define goo_write_final() \
  assert(pos == len)

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
) {
  int r = 0;

  if (ctx == NULL
      || out == NULL
      || out_len == NULL
      || msg == NULL
      || s_prime == NULL
      || C1 == NULL
      || n == NULL
      || p == NULL
      || q == NULL) {
    return 0;
  }

  if (msg_len < 20 || msg_len > 128)
    return 0;

  if (s_prime_len != 32)
    return 0;

  if (C1_len != goo_mpz_bytesize(ctx->n))
    return 0;

  // if (n_len < GOO_MIN_RSA_BITS / 8 || n_len > GOO_MAX_RSA_BITS / 8)
  //   return 0;

  mpz_t spn, nn, pn, qn;

  mpz_init(spn);
  mpz_init(nn);
  mpz_init(pn);
  mpz_init(qn);

  goo_mpz_import(ctx->msg, msg, msg_len);
  goo_mpz_import(spn, s_prime, s_prime_len);
  goo_mpz_import(ctx->C1, C1, C1_len);
  goo_mpz_import(nn, n, n_len);
  goo_mpz_import(pn, p, p_len);
  goo_mpz_import(qn, q, q_len);

  goo_sig_t sig;

  if (!goo_group_sign(ctx, &sig, ctx->msg,
                      spn, ctx->C1, nn, pn, qn)) {
    goto fail;
  }

  size_t modbytes = (goo_mpz_bitlen(ctx->n) + 7) / 8;
  size_t chalbytes = (GOO_CHAL_BITS + 7) / 8;

  size_t pos = 0;
  size_t len = 0;

  len += modbytes; // C2
  len += 2; // t
  len += chalbytes; // chal
  len += chalbytes; // ell
  len += modbytes; // Aq
  len += modbytes; // Bq
  len += modbytes; // Cq
  len += 2048 / 8; // Dq
  len += chalbytes * 7; // z_prime

  unsigned char *data = malloc(len);

  if (data == NULL)
    goto fail;

  goo_write_item(sig.C2, modbytes);
  goo_write_item(sig.t, 2);

  goo_write_item(sig.chal, chalbytes);
  goo_write_item(sig.ell, chalbytes);
  goo_write_item(sig.Aq, modbytes);
  goo_write_item(sig.Bq, modbytes);
  goo_write_item(sig.Cq, modbytes);
  goo_write_item(sig.Dq, 2048 / 8);

  goo_write_item(sig.z_w, chalbytes);
  goo_write_item(sig.z_w2, chalbytes);
  goo_write_item(sig.z_s1, chalbytes);
  goo_write_item(sig.z_a, chalbytes);
  goo_write_item(sig.z_an, chalbytes);
  goo_write_item(sig.z_s1w, chalbytes);
  goo_write_item(sig.z_sa, chalbytes);

  goo_write_final();

  *out = data;
  *out_len = len;

  r = 1;
fail:
  goo_sig_uninit(&sig);
  mpz_clear(spn);
  mpz_clear(nn);
  mpz_clear(pn);
  mpz_clear(qn);
  return r;
}

#define goo_read_item(n, size) do {       \
  if (pos + (size) > sig_len)             \
    return 0;                             \
                                          \
  goo_mpz_import((n), &sig[pos], (size)); \
  pos += (size);                          \
} while (0)                               \

#define goo_read_final() do {     \
  assert(pos <= sig_len);         \
                                  \
  /* non-minimal serialization */ \
  if (pos != sig_len)             \
    return 0;                     \
} while (0)                       \

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

  if (msg_len < 20 || msg_len > 128)
    return 0;

  if (C1_len != goo_mpz_bytesize(ctx->n))
    return 0;

  goo_mpz_import(ctx->msg, msg, msg_len);
  goo_mpz_import(ctx->C1, C1, C1_len);

  size_t pos = 0;

  size_t modbytes = (goo_mpz_bitlen(ctx->n) + 7) / 8;
  size_t chalbytes = (GOO_CHAL_BITS + 7) / 8;

  goo_read_item(ctx->C2, modbytes);
  goo_read_item(ctx->t, 2);

  goo_read_item(ctx->chal, chalbytes);
  goo_read_item(ctx->ell, chalbytes);
  goo_read_item(ctx->Aq, modbytes);
  goo_read_item(ctx->Bq, modbytes);
  goo_read_item(ctx->Cq, modbytes);
  goo_read_item(ctx->Dq, 2048 / 8);

  goo_read_item(ctx->z_w, chalbytes);
  goo_read_item(ctx->z_w2, chalbytes);
  goo_read_item(ctx->z_s1, chalbytes);
  goo_read_item(ctx->z_a, chalbytes);
  goo_read_item(ctx->z_an, chalbytes);
  goo_read_item(ctx->z_s1w, chalbytes);
  goo_read_item(ctx->z_sa, chalbytes);

  goo_read_final();

  return goo_group_verify(
    ctx,

    // msg
    ctx->msg,

    // pubkey
    ctx->C1,
    ctx->C2,
    ctx->t,

    // sigma
    ctx->chal,
    ctx->ell,
    ctx->Aq,
    ctx->Bq,
    ctx->Cq,
    ctx->Dq,

    // z_prime
    ctx->z_w,
    ctx->z_w2,
    ctx->z_s1,
    ctx->z_a,
    ctx->z_an,
    ctx->z_s1w,
    ctx->z_sa
  );
}
