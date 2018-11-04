/*!
 * util.js - utils for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Parts of this software are based on kwantam/libGooPy:
 *   Copyright (c) 2018, Dan Boneh, Riad S. Wahby (Apache License).
 *
 * Resources:
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/util.py
 */

'use strict';

const assert = require('bsert');
const random = require('bcrypto/lib/random');
const RNG = require('./rng');
const BigMath = require('./bigmath');

/*
 * Util
 */

const util = {
  rand: new RNG({
    generate: size => random.randomBytes(size)
  }),

  randomBits(bits) {
    return this.rand.randomBits(bits);
  },

  randomInt(max) {
    return this.rand.randomInt(max);
  },

  clog2(val) {
    assert(typeof val === 'bigint');
    return BigMath.bitLength(val - 1n);
  },

  modInverseP(val, prime) {
    assert(typeof val === 'bigint');
    assert(typeof prime === 'bigint');
    assert(prime > 0n);

    if (BigMath.mod(val, prime) === 0n)
      return null;

    const [inv, d] = this.euclidL(BigMath.mod(val, prime), prime);

    if (d !== 1n)
      return null;

    assert(BigMath.mod((inv * val - 1n), prime) === 0n);

    return BigMath.mod(inv, prime);
  },

  gcd(a, b) {
    assert(typeof a === 'bigint');
    assert(typeof b === 'bigint');

    while (b !== 0n)
      [a, b] = [b, BigMath.mod(a, b)];

    return a;
  },

  euclidL(a, b) {
    assert(typeof a === 'bigint');
    assert(typeof b === 'bigint');

    let t = 1n;
    let t_ = 0n;
    let r = a;
    let r_ = b;
    let q;

    while (r !== 0n) {
      [[q, r], r_] = [BigMath.divmod(r_, r), r];
      [t_, t] = [t, t_ - q * t];
    }

    return [t_, r_];
  },

  euclidLR(a, b) {
    assert(typeof a === 'bigint');
    assert(typeof b === 'bigint');

    let r = a;
    let r_ = b;
    let i = 0;

    const storage = [];

    // Compute gcd, store quotients.
    while (r_ !== 0n) {
      [[storage[i], r_], r] = [BigMath.divmod(r, r_), r_];
      i += 1;
    }

    // Use quotients to reconstruct Bezout coefficients.
    let s = 1n;
    let t = -1n;

    for (let j = i - 2; j >= (i & 1); j -= 2) {
      s = s - t * storage[j + 1];
      t = t - s * storage[j];
    }

    if (i & 1) {
      s = s - t * storage[0];
      [s, t] = [t, s];
    }

    if (r < 0n) {
      // Make sure gcd is positive.
      r = -r;
      s = -s;
      t = -s;
    }

    if (BigMath.abs(a) !== r && BigMath.abs(b) !== r) {
      // Reduce bezout coefficients.
      const tm = BigMath.abs(BigMath.div(a, r));
      const sm = BigMath.abs(BigMath.div(b, r));

      t = BigMath.mod(t, tm) - (t < 0n ? tm : 0n);
      s = BigMath.mod(s, sm) - (s < 0n ? sm : 0n);
    }

    assert(a * s + b * t === r);

    return [s, t, r];
  },

  // https://github.com/golang/go/blob/aadaec5/src/math/big/int.go#L754
  jacobi(x, y) {
    assert(typeof x === 'bigint');
    assert(typeof y === 'bigint');

    if (y === 0n || (y & 1n) === 0n)
      throw new Error('jacobi: `y` must be odd.');

    // See chapter 2, section 2.4:
    // http://yacas.sourceforge.net/Algo.book.pdf
    let a = x;
    let b = y;
    let j = 1;

    if (b < 0n) {
      if (a < 0n)
        j = -1;
      b = -b;
    }

    for (;;) {
      if (b === 1n)
        return j;

      if (a === 0n)
        return 0;

      a = BigMath.mod(a, b);

      if (a === 0n)
        return 0;

      const s = BigMath.zeroBits(a);

      if (s & 1) {
        const bmod8 = b & 7n;

        if (bmod8 === 3n || bmod8 === 5n)
          j = -j;
      }

      const c = a >> BigInt(s);

      if ((b & 3n) === 3n && (c & 3n) === 3n)
        j = -j;

      a = b;
      b = c;
    }
  },

  // https://github.com/golang/go/blob/aadaec5/src/math/big/nat.go#L1335
  isqrt(x) {
    assert(typeof x === 'bigint');

    if (x <= 1n)
      return x;

    // See https://members.loria.fr/PZimmermann/mca/pub226.html.
    let z1 = 1n;

    z1 <<= BigInt((BigMath.bitLength(x) >>> 1) + 1);

    for (;;) {
      let z2 = x / z1;
      z2 += z1;
      z2 >>= 1n;

      if (z2 >= z1)
        return z1;

      z1 = z2;
    }
  },

  dsqrt(n) {
    assert((n >>> 0) === n);
    return Number(this.isqrt(BigInt(n)));
  },

  // Tonelli-Shanks
  modSqrtP(n, p) {
    assert(typeof n === 'bigint');
    assert(typeof p === 'bigint');
    assert(p > 0n);

    n = BigMath.mod(n, p);

    if (n === 0n)
      return 0n;

    if (this.jacobi(n, p) === -1)
      return null;

    if ((p & 3n) === 3n)
      return BigMath.modPow(n, (p + 1n) >> 2n, p);

    // Factor out 2^s from p - 1.
    let s = BigInt(BigMath.zeroBits(p - 1n));

    const Q = (p - 1n) >> s;

    // Find a non-residue mod p.
    let w = 2n;
    let y, q;

    while (this.jacobi(w, p) !== -1)
      w += 1n;

    w = BigMath.modPow(w, Q, p);
    y = BigMath.modPow(n, Q, p);
    q = BigMath.modPow(n, (Q + 1n) >> 1n, p);

    for (;;) {
      const ysave = y;

      let i = 0n;

      while (i < s && y !== 1n) {
        y = BigMath.modPow(y, 2n, p);
        i += 1n;
      }

      if (i === 0n)
        break;

      if (i === s)
        return null;

      w = BigMath.modPow(w, 1n << (s - i - 1n), p);
      s = i;
      q = BigMath.mod(q * w, p);
      w = BigMath.modPow(w, 2n, p);
      y = BigMath.mod(ysave * w, p);
    }

    if (q > (p >> 1n))
      q = p - q;

    assert(n === BigMath.mod(q * q, p));

    return q;
  },

  modSqrtN(x, p, q) {
    assert(typeof x === 'bigint');
    assert(typeof p === 'bigint');
    assert(typeof q === 'bigint');

    const sqrtP = this.modSqrtP(x, p);
    const sqrtQ = this.modSqrtP(x, q);

    if (sqrtP == null || sqrtQ == null)
      return null;

    const [mP, mQ] = this.euclidLR(p, q);

    return BigMath.mod(sqrtQ * mP * p + sqrtP * mQ * q, p * q);
  }
};

/*
 * Expose
 */

module.exports = util;
