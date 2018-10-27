'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const BigMath = require('./bigmath');
const {
  umod,
  bitLength,
  divmod,
  abs,
  max,
  modPow
} = BigMath;

const storage = [];

for (let i = 0; i < 65536; i++)
  storage.push(0n);

const utils = {
  clog2(val) {
    if (typeof val === 'number')
      val = BigInt(Math.ceil(val));
    assert(typeof val === 'bigint');
    return bitLength(val - 1n);
  },

  invert_modp(val, prime) {
    assert(typeof val === 'bigint');
    assert(typeof prime === 'bigint');
    assert(prime >= 0n);

    if (umod(val, prime) === 0n)
      return null;

    const [inv, d] = this.ext_euclid_l(umod(val, prime), prime);

    if (d !== 1n)
      return null;

    assert(umod((inv * val - 1n), prime) === 0n);

    return umod(inv, prime);
  },

  gcd(a, b) {
    assert(typeof a === 'bigint');
    assert(typeof b === 'bigint');

    while (b !== 0n)
      [a, b] = [b, umod(a, b)];

    return a;
  },

  ext_euclid_l(a, b) {
    assert(typeof a === 'bigint');
    assert(typeof b === 'bigint');

    let [t, t_, r, r_] = [1n, 0n, a, b];
    let q;

    while (r !== 0n) {
      [[q, r], r_] = [divmod(r_, r), r];
      [t_, t] = [t, t_ - q * t];
    }

    return [t_, r_];
  },

  ext_euclid_lr(a, b) {
    assert(typeof a === 'bigint');
    assert(typeof b === 'bigint');

    let [r, r_] = [a, b];
    let idx = 0;

    // compute gcd, store quotients
    while (r_ !== 0n) {
      [[storage[idx], r_], r] = [divmod(r, r_), r_];
      idx += 1;
    }

    // use quotients to reconstruct Bezout coefficients
    let [s, t, imod] = [1n, -1n, idx % 2];

    // for jdx in reversed(range(imod, idx, 2)):
    for (let jdx = idx - 2; jdx >= imod; jdx -= 2) {
      s = s - t * storage[jdx + 1];
      t = t - s * storage[jdx];
    }

    if (imod === 1) {
      s = s - t * storage[0];
      [s, t] = [t, s];
    }

    if (r < 0n) {
      // make sure gcd is positive
      [r, s, t] = [-r, -s, -t];
    }

    if (abs(a) !== r && abs(b) !== r) {
      // reduce bezout coefficients
      const tmod = abs(a / r);
      const smod = abs(b / r);
      t = umod(t, tmod) - (t < 0n ? tmod : 0n);
      s = umod(s, smod) - (s < 0n ? smod : 0n);
    }

    assert(a * s + b * t === r);

    return [s, t, r];
  },

  // read left to right bits
  *num_to_bits(n, pad = 0) {
    assert(typeof n === 'bigint');
    assert((pad >>> 0) === pad);

    let len = bitLength(n);

    if (len === 0)
      len = 1;

    assert(n.toString(2).length === len);

    if (pad !== 0) {
      assert(pad >= len);

      let pre = pad - len;

      while (pre--)
        yield 0;
    }

    let pos = BigInt(len);

    while (pos--) {
      if ((n >> pos) & 1n)
        yield 1;
      else
        yield 0;
    }
  },

  jacobi(a, n) {
    assert(typeof a === 'bigint');
    assert(typeof n === 'bigint');

    if (n <= 0n || n % 2n === 0n)
      throw new Error('Jacobi symbol (a/n) is undefined for negative, zero, and even n');

    let negate = false;

    a = umod(a, n);

    while (a !== 0n) {
      while (a % 2n === 0n) {
        a = a / 2n;
        if (n % 8n === 3n || n % 8n === 5n)
          negate = !negate;
      }

      if (a % 4n === 3n && n % 4n === 3n)
        negate = !negate;

      [n, a] = [a, n];

      a = umod(a, n);
    }

    if (n === 1n)
      return negate ? -1 : 1;

    return 0;
  },

  // essentially https://en.wikipedia.org/wiki/Integer_square_root
  isqrt(n) {
    assert(typeof n === 'bigint');

    if (n < 0n)
      throw new Error('isqrt called with negative input');

    const len = BigInt(bitLength(n));

    let shift = max(0n, 2n * ((len + 1n) / 2n) - 2n);
    let res = 0n;

    while (shift >= 0n) {
      res <<= 1n;

      const res_c = res + 1n;

      if ((res_c * res_c) <= (n >> shift))
        res = res_c;

      shift -= 2n;
    }

    return res;
  },

  dsqrt(n) {
    assert((n >>> 0) === n);
    return Number(this.isqrt(BigInt(n)));
  },

  factor_twos(n) {
    assert(typeof n === 'bigint');

    let d = n;
    let s = 0n;

    while (umod(d, 2n) === 0n) {
      d /= 2n;
      s += 1n;
    }

    return [d, s];
  },

  // tonelli-shanks
  sqrt_modp(n, p) {
    assert(typeof n === 'bigint');
    assert(typeof p === 'bigint');
    assert(p >= 0n);

    n = umod(n, p);

    if (n === 0n)
      return 0n;

    if (this.jacobi(n, p) === -1)
      return null;

    if (p % 4n === 3n)
      return modPow(n, (p + 1n) / 4n, p);

    // factor out 2^s from p - 1
    let [Q, s] = this.factor_twos(p - 1n);

    // find a non-residue mod p
    let w = 2n;
    let y, q;

    while (this.jacobi(w, p) !== -1)
      w += 1n;

    w = modPow(w, Q, p);
    y = modPow(n, Q, p);
    q = modPow(n, (Q + 1n) / 2n, p);

    for (;;) {
      const y_save = y;

      let i = 0n;

      while (i < s && y !== 1n) {
        y = modPow(y, 2n, p);
        i += 1n;
      }

      if (i === 0n)
        break;

      if (i === s)
        return null;

      w = modPow(w, 1n << (s - i - 1n), p);
      s = i;
      q = umod(q * w, p);
      w = modPow(w, 2n, p);
      y = umod(y_save * w, p);
    }

    if (q > (p / 2n))
      q = p - q;

    assert(n === umod(q * q, p));

    return q;
  },

  sqrt_modn(x, p, q) {
    assert(typeof x === 'bigint');
    assert(typeof p === 'bigint');
    assert(typeof q === 'bigint');

    const sqrtP = this.sqrt_modp(x, p);
    const sqrtQ = this.sqrt_modp(x, q);

    if (sqrtP == null || sqrtQ == null)
      return null;

    const [mP, mQ] = this.ext_euclid_lr(p, q);

    return umod(sqrtQ * mP * p + sqrtP * mQ * q, p * q);
  },

  iterator(iterable) {
    assert(iterable);

    if (typeof iterable === 'function') {
      const iter = iterable();
      assert(typeof iter.next === 'function');
      return iter;
    }

    if (typeof iterable.next !== 'function') {
      assert(typeof iterable[Symbol.iterator] === 'function');
      return iterable[Symbol.iterator]();
    }

    return iterable;
  },

  next(iterable, def) {
    const iter = this.iterator(iterable);
    const it = iter.next();

    if (iter.done) {
      if (def !== undefined)
        return def;
      throw new Error('Iterator is done.');
    }

    return it.value;
  },

  *enumerate(iterable) {
    const iter = this.iterator(iterable);

    let i = 0;

    for (const item of iter) {
      yield [i, item];
      i += 1;
    }
  },

  list(iterable) {
    const iter = this.iterator(iterable);

    const items = [];

    for (const item of iter)
      items.push(item);

    return items;
  },

  *cycle(iterable) {
    const iter = this.iterator(iterable);
    const saved = [];

    for (const item of iter) {
      yield item;
      saved.push(item);
    }

    while (saved.length) {
      for (const item of saved)
        yield item;
    }
  },

  *chain(...args) {
    for (const iter of args) {
      for (const item of iter)
        yield item;
    }
  },

  *zip(...args) {
    const iters = [];

    for (const iterable of args)
      iters.push(this.iterator(iterable));

    while (iters.length) {
      const result = [];

      for (const iter of iters) {
        const it = iter.next();

        if (it.done)
          return;

        result.push(it.value);
      }

      yield result;
    }
  }
};

module.exports = utils;
