'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const util = require('./util');
const Defs = require('./defs');
const {CombMixin, WnafMixin, RandMixin} = require('./mixins');

class RSAGroupOps extends RandMixin { // XXX maybe change inheritance chain
  // NOTE you should use an RSA modulus whose factorization is unknown!
  //    In other words, *don't* just generate a modulus! defs.py provides
  //    a few candidates for you to try.
  constructor(Gdesc, modbits = null, prng = null) {
    assert(Gdesc && typeof Gdesc.modulus === 'bigint');
    assert(modbits == null || (modbits >>> 0) === modbits);
    assert(prng == null || (prng && typeof prng.getrandbits === 'function'));

    super();

    this.n = Gdesc.modulus;
    this.nOver2 = this.n / 2n;
    this.g = Gdesc.g;
    this.h = Gdesc.h;
    this.id = 1n;
    this.desc = [this.n, this.g, this.h];

    this.init_rand(util.clog2(this.n) - 1, prng);
    this.init_wnaf(false);
    this.init_comb(Defs.max_rsa_comb_size, modbits);
  }

  reduce(b) {
    // compute the representative of (Z/n)/{1,-1}, i.e., min(|b|, n-|b|)
    if b > self.nOver2:
      return self.n - b
    return b
  }

  is_reduced(b) {
    return b <= self.nOver2
  }

  sqr(b) {
    return pow(b, 2, self.n)
  }

  mul(m1, m2) {
    return (m1 * m2) % self.n
  }

  // @lutil.overrides(_WnafMixin)
  pow(b, bInv, e) {
    return pow(b, e, self.n)
  }

  inv(b) {
    return lutil.invert_modp(b, self.n)
  }

  inv2(b1, b2) {
    b12Inv = self.inv(b1 * b2)
    return ((b2 * b12Inv) % self.n, (b1 * b12Inv) % self.n)
  }

  inv5(b1, b2, b3, b4, b5) {
    b12 = (b1 * b2) % self.n
    b34 = (b3 * b4) % self.n
    b1234 = (b12 * b34) % self.n
    b12345 = (b1234 * b5) % self.n

    b12345Inv = self.inv(b12345)
    b1234Inv = (b12345Inv * b5) % self.n
    b34Inv = (b1234Inv * b12) % self.n
    b12Inv = (b1234Inv * b34) % self.n

    return ((b12Inv * b2) % self.n, (b12Inv * b1) % self.n, (b34Inv * b4) % self.n, (b34Inv * b3) % self.n, (b12345Inv * b1234) % self.n)
  }
}

class ClassGroupOps extends RandMixin { // XXX maybe change inheritence chain
  constructor(Gdesc, modbits = null, prng = null) {
    assert(Gdesc && typeof Gdesc.modulus === 'bigint');
    assert(modbits == null || (modbits >>> 0) === modbits);
    assert(prng == null || (prng && typeof prng.getrandbits === 'function');

    super();

    this.D = Gdesc.disc
    assert this.D < 0 and this.D % 4 == 1 and lprimes.is_prime(-this.D)
    this.g = Gdesc.g
    this.h = Gdesc.h
    this.id = Gdesc.id
    this.L = Gdesc.L
    assert this.L ** 4 <= -this.D and (this.L + 1) ** 4 > -this.D
    this.desc = (this.D, this.g, this.h)

    // number of random bits for exponents; NOTE should we halve this?
    this.init_rand(util.clog2(this.D) - 1, prng);
    this.init_wnaf(true);
    this.init_comb(Defs.max_bqf_comb_size, modbits);
  }

  // Algorithm 5.4.2 of Cohen's "A Course in Computational Algebraic Number Theory"
  static reduce(f) {
    (a, b, c) = f

    while True:
      if -a < b <= a:
        if a > c:
          b = -b
          (a, c) = (c, a)
        else:
          if a == c and b < 0:
            b = -b
          return (a, b, c)

      (q, r) = divmod(b, 2*a)
      if r > a:
        r -= 2 * a
        q += 1

      c = c - ((b + r) * q) / 2
      b = r
  }

  reduce(f) {
    return this.constructor.reduce(f);
  }

  static is_reduced(f) {
    (a, b, c) = f
    return (-a < b <= a < c) or (0 <= b <= a == c)
  }

  is_reduced(f) {
    return this.constructor.is_reduced(f);
  }

  // NUCOMP of Daniel Shanks
  // Adapted from
  //   Jacobson, M.J. and van der Poorten, A.J., "Computational Aspects of NUCOMP." Proc. ANTS 2002.
  mul(m1, m2) {
    if m1[0] == 1:
      return m2
    if m2[0] == 1:
      return m1

    // unpack, swapping m1 and m2 if w1 < w2
    ((u1, v1, w1), (u2, v2, w2)) = (m2, m1) if m1[2] < m2[2] else (m1, m2)

    // Step 1
    s = (v1 + v2) / 2
    m = v2 - s

    // Step 2
    (c, b, F) = lutil.ext_euclid_lr(u1, u2)
    assert u1 * c + u2 * b == F

    // Steps 2--4
    if s % F == 0:
      G = F
      Bx = m * b
      By = u1 / G
    else:
      (y, G) = lutil.ext_euclid_l(s, F)
      assert (G - y *s) % F == 0
      H = F / G
      By = u1 / G
      // Step 4
      l1 = (b * (w1 % H)) % H
      l2 = (c * (w2 % H)) % H
      l = (y * (l1 + l2)) % H
      Bx = b * m / H + l * By / H
    Cy = u2 / G
    Dy = s / G

    // Step 5 (truncated Euclidean division)
    (bx, by) = (Bx % By, By)
    (x, y, z) = (1, 0, 0)
    while bx != 0 and abs(by) > self.L:
      ((q, bx), by) = (divmod(by, bx), bx)
      (y, x) = (x, y - q * x)
      z += 1
    (by, y) = (-by, -y) if z % 2 == 1 else (by, y)
    (ax, ay) = (G * x, G * y)

    // Steps 6--7
    if z == 0:
      // Step 6
      Q1 = Cy * bx
      (cx, dx) = ((Q1 - m) / By, (bx * Dy - w2) / By)
      ret = (by * Cy, v2 - 2 * Q1, bx * cx - G * dx)
    else:
      // Step 7
      (cx, dx) = ((Cy * bx - m * x) / By, (Dy * bx - w2 * x) / By)
      (Q1, Q3) = (by * cx, y * dx)
      (Q2, Q4) = (Q1 + m, Q3 + Dy)
      dy = Q4 / x
      cy = Q2 / bx if bx != 0 else (cx * dy - w1) / dx
      ret = (by * cy - ay * dy, G * (Q3 + Q4) - Q1 - Q2, bx * cx - ax * dx)

    assert self.discrim(ret) == self.D
    return self.reduce(ret)
  }

  // NUCOMP of Daniel Shanks
  // Adapted from
  //   Jacobson, M.J. and van der Poorten, A.J., "Computational Aspects of NUCOMP." Proc. ANTS 2002.
  sqr(m) {
    if m[0] == 1:
      return m
    (u, v, w) = m

    // Step 1
    (y, G) = lutil.ext_euclid_l(v, u)
    (By, Dy) = (u / G, v / G)

    // Step 2
    Bx = (y * w) % By

    // Step 3
    (bx, by) = (Bx, By)
    (x, y, z) = (1, 0, 0)
    while bx != 0 and abs(by) > self.L:
      ((q, bx), by) = (divmod(by, bx), bx)
      (y, x) = (x, y - q * x)
      z += 1
    (by, y) = (-by, -y) if z % 2 == 1 else (by, y)
    (ax, ay) = (G * x, G * y)

    // Steps 4--5
    if z == 0:
      // Step 4
      dx = (bx * Dy - w) / By
      (u3, w3) = (by ** 2, bx ** 2)
      ret = (u3, v - (bx + by) ** 2 + u3 + w3, w3 - G * dx)
    else:
      // Step 5
      dx = (bx * Dy - w * x) / By
      Q1 = dx * y
      dy = Q1 + Dy
      v3 = G * (dy + Q1)
      dy = dy / x
      (u3, w3) = (by ** 2, bx ** 2)
      ret = (u3 - ay * dy, v3 - (bx + by) ** 2 + u3 + w3, w3 - ax * dx)

    assert self.discrim(ret) == self.D
    return self.reduce(ret)
  }

  static discrim(m) {
    (a, b, c) = m
    return b * b - 4 * a * c
  }

  discrim(m) {
    return this.constructor.discrim(m);
  }

  static inv(m) {
    (a, b, c) = m
    return (a, -b, c)
  }

  inv(m) {
    return this.constructor.inv(m);
  }

  inv2(m1, m2) {
    return [this.inv(m1), this.inv(m2)];
  }

  inv5(m1, m2, m3, m4, m5) {
    return [this.inv(m1), this.inv(m2), this.inv(m3), this.inv(m4), this.inv(m5)];
  }
}

exports.RSAGroupOps = RSAGroupOps;
exports.ClassGroupOps = ClassGroupOps;
