'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const BigMath = require('./bigmath');
const util = require('./util');
const defs = require('./defs');
const primes = require('./primes');
const {RandMixin} = require('./mixins');
const {umod, modPow, divmod, abs} = BigMath;

class RSAGroupOps extends RandMixin {
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
    this.init_comb(defs.max_rsa_comb_size, modbits);
  }

  is_element(x) {
    return typeof x === 'bigint';
  }

  equals(x, y) {
    assert(typeof x === 'bigint');
    assert(typeof y === 'bigint');
    return x === y;
  }

  reduce(b) {
    assert(typeof b === 'bigint');

    // compute the representative of (Z/n)/{1,-1}, i.e., min(|b|, n-|b|)
    if (b > this.nOver2)
      return this.n - b;

    return b;
  }

  is_reduced(b) {
    assert(typeof b === 'bigint');

    return b <= this.nOver2;
  }

  sqr(b) {
    return modPow(b, 2n, this.n);
  }

  mul(m1, m2) {
    assert(typeof m1 === 'bigint');
    assert(typeof m2 === 'bigint');

    return umod(m1 * m2, this.n);
  }

  pow(b, bInv, e) {
    return modPow(b, e, this.n);
  }

  inv(b) {
    return util.invert_modp(b, this.n);
  }

  inv2(b1, b2) {
    assert(typeof b1 === 'bigint');
    assert(typeof b2 === 'bigint');

    const b12Inv = this.inv(b1 * b2);

    return [
      umod(b2 * b12Inv, this.n),
      umod(b1 * b12Inv, this.n)
    ];
  }

  inv5(b1, b2, b3, b4, b5) {
    assert(typeof b1 === 'bigint');
    assert(typeof b2 === 'bigint');
    assert(typeof b3 === 'bigint');
    assert(typeof b4 === 'bigint');
    assert(typeof b5 === 'bigint');

    const b12 = umod(b1 * b2, this.n);
    const b34 = umod(b3 * b4, this.n);
    const b1234 = umod(b12 * b34, this.n);
    const b12345 = umod(b1234 * b5, this.n);

    const b12345Inv = this.inv(b12345);
    const b1234Inv = umod(b12345Inv * b5, this.n);
    const b34Inv = umod(b1234Inv * b12, this.n);
    const b12Inv = umod(b1234Inv * b34, this.n);

    return [
      umod(b12Inv * b2, this.n),
      umod(b12Inv * b1, this.n),
      umod(b34Inv * b4, this.n),
      umod(b34Inv * b3, this.n),
      umod(b12345Inv * b1234, this.n)
    ];
  }
}

class ClassGroupOps extends RandMixin {
  constructor(Gdesc, modbits = null, prng = null) {
    assert(Gdesc && typeof Gdesc.disc === 'bigint');
    assert(modbits == null || (modbits >>> 0) === modbits);
    assert(prng == null || (prng && typeof prng.getrandbits === 'function'));

    super();

    assert(Gdesc.disc < 0n && umod(Gdesc.disc, 4n) === 1n && primes.is_prime(-Gdesc.disc));
    assert(Gdesc.L ** 4n <= -Gdesc.disc && (Gdesc.L + 1n) ** 4n > -Gdesc.disc);

    this.D = Gdesc.disc;
    this.g = Gdesc.g;
    this.h = Gdesc.h;
    this.id = Gdesc.id;
    this.L = Gdesc.L;
    this.desc = [this.D, this.g, this.h];

    // number of random bits for exponents; NOTE should we halve this?
    this.init_rand(util.clog2(this.D) - 1, prng);
    this.init_wnaf(true);
    this.init_comb(defs.max_bqf_comb_size, modbits);
  }

  is_element(x) {
    return Array.isArray(x)
        && x.length === 3
        && typeof x[0] === 'bigint'
        && typeof x[1] === 'bigint'
        && typeof x[2] === 'bigint';
  }

  equals(x, y) {
    assert(this.is_element(x));
    assert(this.is_element(y));

    return x[0] === y[0]
        && x[1] === y[1]
        && x[2] === y[2];
  }

  // Algorithm 5.4.2 of Cohen's "A Course in Computational Algebraic Number Theory"
  reduce(f) {
    assert(this.is_element(f));

    let [a, b, c] = f;

    for (;;) {
      if (-a < b && b <= a) {
        if (a > c) {
          b = -b;
          [a, c] = [c, a];
        } else {
          if (a === c && b < 0n)
            b = -b;
          return [a, b, c];
        }
      }

      let [q, r] = divmod(b, 2n * a);

      if (r > a) {
        r -= 2n * a;
        q += 1n;
      }

      c = c - ((b + r) * q) / 2n;
      b = r;
    }
  }

  is_reduced(f) {
    assert(this.is_element(f));

    const [a, b, c] = f;

    return (-a < b && b <= a && a < c)
        || (0n <= b && b <= a && a === c);
  }

  // NUCOMP of Daniel Shanks
  // Adapted from
  //   Jacobson, M.J. and van der Poorten, A.J., "Computational Aspects of NUCOMP." Proc. ANTS 2002.
  mul(m1, m2) {
    assert(this.is_element(m1));
    assert(this.is_element(m2));

    if (m1[0] === 1n)
      return m2;

    if (m2[0] === 1n)
      return m1;

    // unpack, swapping m1 and m2 if w1 < w2
    const [[u1, v1, w1], [u2, v2, w2]] = m1[2] < m2[2] ? [m2, m1] : [m1, m2];

    // Step 1
    const s = (v1 + v2) / 2n;
    const m = v2 - s;

    // Step 2
    const [c, b, F] = util.ext_euclid_lr(u1, u2);

    assert(u1 * c + u2 * b === F);

    // Steps 2--4
    let G, Bx, By;
    if (umod(s, F) === 0n) {
      G = F;
      Bx = m * b;
      By = u1 / G;
    } else {
      let y;
      [y, G] = util.ext_euclid_l(s, F);
      assert(umod((G - y * s), F) === 0n);
      const H = F / G;
      By = u1 / G;
      // Step 4
      const l1 = umod(b * umod(w1, H), H);
      const l2 = umod(c * umod(w2, H), H);
      const l = umod(y * (l1 + l2), H);
      Bx = b * m / H + l * By / H;
    }

    const Cy = u2 / G;
    const Dy = s / G;

    // Step 5 (truncated Euclidean division)
    let [bx, by] = [umod(Bx, By), By];
    let [x, y, z] = [1n, 0n, 0n];
    let q;

    while (bx !== 0n && abs(by) > this.L) {
      [[q, bx], by] = [divmod(by, bx), bx];
      [y, x] = [x, y - q * x];
      z += 1n;
    }

    [by, y] = umod(z, 2n) === 1n ? [-by, -y] : [by, y];

    const [ax, ay] = [G * x, G * y];

    // Steps 6--7
    let ret;
    if (z === 0n) {
      // Step 6
      const Q1 = Cy * bx;
      const [cx, dx] = [(Q1 - m) / By, (bx * Dy - w2) / By];
      ret = [by * Cy, v2 - 2n * Q1, bx * cx - G * dx];
    } else {
      // Step 7
      const [cx, dx] = [(Cy * bx - m * x) / By, (Dy * bx - w2 * x) / By];
      const [Q1, Q3] = [by * cx, y * dx];
      const [Q2, Q4] = [Q1 + m, Q3 + Dy];
      const dy = Q4 / x;
      const cy = bx !== 0n ? Q2 / bx : (cx * dy - w1) / dx;
      ret = [by * cy - ay * dy, G * (Q3 + Q4) - Q1 - Q2, bx * cx - ax * dx];
    }

    assert(this.equals(this.discrim(ret), this.D));

    return this.reduce(ret);
  }

  // NUCOMP of Daniel Shanks
  // Adapted from
  //   Jacobson, M.J. and van der Poorten, A.J., "Computational Aspects of NUCOMP." Proc. ANTS 2002.
  sqr(m) {
    assert(this.is_element(m));

    if (m[0] === 1n)
      return m;

    const [u, v, w] = m;

    // Step 1
    const [y_, G] = util.ext_euclid_l(v, u);
    const [By, Dy] = [u / G, v / G];

    // Step 2
    const Bx = umod(y_ * w, By);

    // Step 3
    let [bx, by] = [Bx, By];
    let [x, y, z] = [1n, 0n, 0n];
    let q;

    while (bx !== 0n && abs(by) > this.L) {
      [[q, bx], by] = [divmod(by, bx), bx];
      [y, x] = [x, y - q * x];
      z += 1n;
    }

    [by, y] = umod(z, 2n) === 1n ? [-by, -y] : [by, y];

    const [ax, ay] = [G * x, G * y];

    let ret;

    // Steps 4--5
    if (z === 0n) {
      // Step 4
      const dx = (bx * Dy - w) / By;
      const [u3, w3] = [by ** 2n, bx ** 2n];
      ret = [u3, v - (bx + by) ** 2n + u3 + w3, w3 - G * dx];
    } else {
      // Step 5
      const dx = (bx * Dy - w * x) / By;
      const Q1 = dx * y;
      let dy = Q1 + Dy;
      const v3 = G * (dy + Q1);
      dy = dy / x;
      const [u3, w3] = [by ** 2n, bx ** 2n];
      ret = [u3 - ay * dy, v3 - (bx + by) ** 2n + u3 + w3, w3 - ax * dx];
    }

    assert(this.equals(this.discrim(ret), this.D));

    return this.reduce(ret);
  }

  discrim(m) {
    assert(this.is_element(m));

    const [a, b, c] = m;

    return b * b - 4n * a * c;
  }

  inv(m) {
    assert(this.is_element(m));
    const [a, b, c] = m;
    return [a, -b, c];
  }

  inv2(m1, m2) {
    return [this.inv(m1), this.inv(m2)];
  }

  inv5(m1, m2, m3, m4, m5) {
    return [
      this.inv(m1),
      this.inv(m2),
      this.inv(m3),
      this.inv(m4),
      this.inv(m5)
    ];
  }
}

exports.RSAGroupOps = RSAGroupOps;
exports.ClassGroupOps = ClassGroupOps;
