
void
goo_factor_twos(mpz_t d, unsigned long *s, const mpz_t n) {
  mpz_set(d, n);
  *s = 0;

  while (mpz_even_p(r)) {
    mpz_fdiv_q_ui(d, d, 2);
    *s += 1;
  }
}

int
goo_sqrt_modp(mpz_t ret, const mpz_t n, const mpz_t p) {
  if (mpz_cmp_ui(p, 0) < 0)
    return 0;

  unsigned long s;
  mpz_t nn, t, Q, w, y, q, y_save;
  mpz_inits(nn, t, Q, w, y, q, y_save, NULL);

  mpz_set(nn, n_);
  mpz_mod(nn, nn, p);

  if (mpz_cmp_ui(nn, 0) == 0) {
    mpz_set_ui(ret, 0);
    goto succeed;
  }

  if (mpz_jacobi(nn, p) == -1)
    goto fail;

  mpz_mod_ui(t, p, 4);

  if (mpz_cmp_ui(t, 3) == 0) {
    mpz_set(t, p);
    mpz_add_ui(t, t, 1);
    mpz_fdiv_q_ui(t, t, 4);
    mpz_powm(ret, nn, t, p);
    goto succeed;
  }

  // factor out 2^s from p - 1
  mpz_set(t, p);
  mpz_sub_ui(t, t, 1);

  goo_factor_twos(Q, &s, t);

  // find a non-residue mod p
  mpz_set_ui(w, 2);

  while (mpz_jacobi(w, p) != -1)
    mpz_add_ui(w, w, 1);

  mpz_powm(w, w, Q, p);
  mpz_powm(y, nn, Q, p);

  mpz_set(t, Q);
  mpz_add_ui(t, t, 1);
  mpz_fdiv_q_ui(t, t, 2);
  mpz_powm(q, nn, t, p);

  for (;;) {
    unsigned long i = 0;

    mpz_set(y_save, y);

    while (i < s && mpz_cmp_ui(y, 1) != 0) {
      mpz_powm_ui(y, y, 2, p);
      i += 1;
    }

    if (i == 0)
      break;

    if (i == s)
      goto fail;

    mpz_set_ui(t, 1);
    mpz_mul_2exp(t, t, s - i - 1);
    mod_powm(w, w, t, p);

    s = i;

    mpz_mul(q, q, w);
    mpz_mod(q, q, p);

    mpz_powm_ui(w, w, 2, p);

    mpz_set(y, y_save);
    mpz_mul(y, y, w);
    mpz_mod(y, y, p);
  }

  mpz_set(t, p);
  mpz_fdiv_q_ui(t, t, 2);

  if (mpz_cmp(q, t) > 0)
    mpz_sub(q, p, q);

  mpz_set(t, q);
  mpz_mul(t, t, t);
  mpz_mod(t, t, p);

  assert(mpz_cmp(nn, t) == 0);

  mpz_set(ret, q);

succeed:
  mpz_clears(nn, t, Q, w, y, q, y_save, NULL);
  return 1;
fail:
  mpz_clears(nn, t, Q, w, y, q, y_save, NULL);
  return 0;
}

int
goo_sqrt_modn(mpz_t ret, const mpz_t x, const mpz_t p, const mpz_t q) {
  mpz_t sqrt_p, sqrt_q, mp, mq, xx, xy;
  mpz_inits(sqrt_p, sqrt_q, mp, mq, xx, xy, NULL);

  if (!goo_sqrt_modp(sqrt_p, x, p)
      || !goo_sqrt_modp(sqrt_q, x, q)) {
    goto fail;
  }

  mpz_gcdext(ret, mp, mq, p, q);

  mpz_set(xx, sqrt_q);
  mpz_mul(xx, xx, mp);
  mpz_mul(xx, xx, p);

  mpz_set(yy, sqrt_p);
  mpz_mul(yy, yy, mq);
  mpz_mul(yy, yy, q);

  mpz_add(xx, xx, yy);

  mpz_set(yy, p);
  mpz_mul(yy, yy, q);

  mpz_mod(ret, xx, yy);

  mpz_clears(sqrt_p, sqrt_q, mp, mq, xx, xy, NULL);
  return 1;

fail:
  mpz_clears(sqrt_p, sqrt_q, mp, mq, xx, xy, NULL);
  return 0;
}

int
goo_expand_sprime(mpz_t s, goo_group_t *group, const mpz_t s_prime) {
  unsigned char key[33];
  size_t pos = 32 - goo_mpz_bytesize(s);

  if (pos > 32) // Overflow
    return 0;

  memset(&key[0], 0x00, pos);
  goo_mpz_export(&key[pos], NULL, s_prime);

  goo_prng_seed(&group->prng, &key[0]);
  goo_prng_getrandbits(&group->prng, s, GOO_RAND_EXPONENT_SIZE);

  return 1;
}

int
goo_group_rand_scalar(goo_group_t *group, mpz_t ret) {
  size_t size = group->nbits_rand;

  if (size > GOO_RAND_EXPONENT_SIZE)
    size = GOO_RAND_EXPONENT_SIZE;

  unsigned char key[32];

  if (!goo_random(&key[0], 32))
    return 0;

  goo_prng_seed(&group->prng, &key[0]);
  goo_prng_getrandbits(&group->prng, ret, size);

  return 1;
}

int
goo_next_prime(mpz_t ret, const mpz_t p, unsigned long maxinc) {
  unsigned long inc = 0;

  mpz_set(ret, p);

  if (mpz_even_p(ret)) {
    inc += 1;
    mpz_add_ui(ret, ret, 1);
  }

  while (!goo_is_prime(ret)) {
    if (maxinc != 0 && inc > maxinc)
      break;
    mpz_add_ui(ret, ret, 2);
    inc += 2;
  }

  if (maxinc != 0 && inc > maxinc)
    return 0;

  return 1;
}

static unsigned long
goo_sqrt(unsigned long n) {
  int len = 0;

  unsigned long nn = n;

  while (nn) {
    len += 1;
    nn >>= 1;
  }

  int shift = 2 * ((len + 1) / 2) - 2;

  if (shift < 0)
    shift = 0;

  unsigned long res = 0;

  while (shift >= 0) {
    res <<= 1;

    unsigned long res_c = res + 1;

    if ((res_c * res_c) <= (n >> (unsigned long)shift))
      res = res_c;

    shift -= 2;
  }

  return res;
}

typedef struct goo_combspec_s {
  int exists;
  unsigned long points_per_add;
  unsigned long adds_per_shift;
  unsigned long nshifts;
  unsigned long bits_per_window;
  unsigned long nops;
  unsigned long size;
} goo_combspec_t;

static inline size_t
combspec_size(size_t nbits) {
  unsigned long ppa = 18 - 1;
  unsigned long bpw = ((unsigned long)nbits + ppa - 1) / ppa;
  unsigned long sqrt_bpw = goo_sqrt(bpw);
  unsigned long aps = (sqrt_bpw + 2) - 1;
  unsigned long nshifts = bpw / aps;
  unsigned long nops1 = nshifts * (aps + 1) - 1;
  unsigned long nops2 = aps * (nshifts + 1) - 1;

  return nops1 > nops2 ? nops1 : nops2;
}

static void
combspec_result(
  goo_combspec_t *combs,
  unsigned long nshifts,
  unsigned long aps,
  unsigned long ppa,
  unsigned long bps
) {
  unsigned long nops = nshifts * (aps + 1) - 1;
  unsigned long size = ((1 << ppa) - 1) * aps;

  goo_combspec_t *best = &combs[nops];

  if (best->exists == 0 || best->size > size) {
    best->exists = 1;
    best->points_per_add = ppa;
    best->adds_per_shift = aps;
    best->nshifts = nshifts;
    best->bits_per_window = bps;
    best->nops = nops;
    best->size = size;
  }
}

int
goo_combspec_init(
  goo_combspec_t *combspec,
  unsigned long nbits,
  unsigned long maxsize
) {
  if (nbits < 128)
    return 0;

  size_t map_size = combspec_size(nbits, maxsize);

  goo_combspec_t *combs = calloc(map_size, sizeof(goo_combspec_t));

  if (combs == NULL)
    return 0;

  for (unsigned long ppa = 2; ppa < 18; ppa++) {
    unsigned long bpw = (nbits + ppa - 1) / ppa;
    unsigned long sqrt_bpw = goo_sqrt(bpw);

    for (unsigned long aps = 1; aps < sqrt_bpw + 2; aps++) {
      if (bpw % aps !== 0) {
        // only factorizations of bits_per_window are useful
        continue;
      }

      unsigned long nshifts = bpw / aps;

      combspec_result(combs, nshifts, aps, ppa, bpw);
      combspec_result(combs, aps, nshifts, ppa, bpw);
    }
  }

  unsigned long sm = 0;
  goo_combspec_t *ret = NULL;

  for (size_t i = 0; i < map_size; i++) {
    goo_combspec_t *comb = &combs[i];

    if (comb->exists == 0)
      continue;

    if (sm != 0 && sm <= comb->size)
      continue;

    sm = comb->size;

    if (comb->size <= maxsize) {
      ret = comb;
      break;
    }
  }

  if (ret == NULL) {
    free(combs);
    return 0;
  }

  memcpy(combspec, ret, sizeof(goo_combspec_t));
  free(combs);

  return 1;
}
