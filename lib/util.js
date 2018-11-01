'use strict';

const assert = require('bsert');
const random = require('bcrypto/lib/random');
const RNG = require('./rng');
const BigMath = require('./bigmath');

/*
 * Constants
 */

const storage = [];

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
    assert(prime >= 0n);

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

    let [t, t_, r, r_] = [1n, 0n, a, b];
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

    if (storage.length === 0) {
      for (let i = 0; i < 65536; i++)
        storage.push(0n);
    }

    let [r, r_] = [a, b];
    let idx = 0;

    // Compute gcd, store quotients.
    while (r_ !== 0n) {
      [[storage[idx], r_], r] = [BigMath.divmod(r, r_), r_];
      idx += 1;
    }

    // Use quotients to reconstruct Bezout coefficients.
    let [s, t, imod] = [1n, -1n, idx % 2];

    for (let jdx = idx - 2; jdx >= imod; jdx -= 2) {
      s = s - t * storage[jdx + 1];
      t = t - s * storage[jdx];
    }

    if (imod === 1) {
      s = s - t * storage[0];
      [s, t] = [t, s];
    }

    if (r < 0n) {
      // Make sure gcd is positive.
      [r, s, t] = [-r, -s, -t];
    }

    if (BigMath.abs(a) !== r && BigMath.abs(b) !== r) {
      // Reduce bezout coefficients.
      const tmod = BigMath.abs(a / r);
      const smod = BigMath.abs(b / r);

      t = BigMath.mod(t, tmod) - (t < 0n ? tmod : 0n);
      s = BigMath.mod(s, smod) - (s < 0n ? smod : 0n);
    }

    assert(a * s + b * t === r);

    return [s, t, r];
  },

  // Read left to right bits.
  *numToBits(n, pad = 0) {
    assert(typeof n === 'bigint');
    assert((pad >>> 0) === pad);

    let len = BigMath.bitLength(n);

    if (len === 0)
      len = 1;

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
      throw new Error('Cannot compute jacobi symbol.');

    let negate = false;

    a = BigMath.mod(a, n);

    while (a !== 0n) {
      while (a % 2n === 0n) {
        a = a / 2n;
        if (n % 8n === 3n || n % 8n === 5n)
          negate = !negate;
      }

      if (a % 4n === 3n && n % 4n === 3n)
        negate = !negate;

      [n, a] = [a, n];

      a = BigMath.mod(a, n);
    }

    if (n === 1n)
      return negate ? -1 : 1;

    return 0;
  },

  // Essentially https://en.wikipedia.org/wiki/Integer_square_root
  isqrt(n) {
    assert(typeof n === 'bigint');

    if (n < 0n)
      throw new Error('isqrt called with negative input');

    const len = BigInt(BigMath.bitLength(n));

    let shift = BigMath.max(0n, 2n * ((len + 1n) / 2n) - 2n);
    let res = 0n;

    while (shift >= 0n) {
      res <<= 1n;

      const resc = res + 1n;

      if ((resc * resc) <= (n >> shift))
        res = resc;

      shift -= 2n;
    }

    return res;
  },

  dsqrt(n) {
    assert((n >>> 0) === n);
    return Number(this.isqrt(BigInt(n)));
  },

  factorTwos(n) {
    assert(typeof n === 'bigint');

    let d = n;
    let s = 0n;

    while (BigMath.mod(d, 2n) === 0n) {
      d /= 2n;
      s += 1n;
    }

    return [d, s];
  },

  // Tonelli-Shanks
  modSqrtP(n, p) {
    assert(typeof n === 'bigint');
    assert(typeof p === 'bigint');
    assert(p >= 0n);

    n = BigMath.mod(n, p);

    if (n === 0n)
      return 0n;

    if (this.jacobi(n, p) === -1)
      return null;

    if (p % 4n === 3n)
      return BigMath.modPow(n, (p + 1n) / 4n, p);

    // Factor out 2^s from p - 1.
    let [Q, s] = this.factorTwos(p - 1n);

    // Find a non-residue mod p.
    let w = 2n;
    let y, q;

    while (this.jacobi(w, p) !== -1)
      w += 1n;

    w = BigMath.modPow(w, Q, p);
    y = BigMath.modPow(n, Q, p);
    q = BigMath.modPow(n, (Q + 1n) / 2n, p);

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

    if (q > (p / 2n))
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
  },

  primeProdAndCarmichael(bits) {
    assert((bits >>> 0) === bits);

    let prod = 1n;
    let carm = 1n;

    for (const np of this.primesSkip(1)) {
      const [prod_, carm_] = [prod, carm];

      prod *= np;
      carm = (carm * (np - 1n)) / util.gcd(carm, np - 1n);

      if (BigMath.bitLength(prod) > bits)
        return [prod_, carm_];
    }

    throw new Error('Unreachable.');
  },

  findMinDelta(m, maxmult) {
    assert(typeof m === 'bigint');
    assert(typeof maxmult === 'bigint');

    let mindelta = 1n;
    let iii = 1n;

    for (let i = 1n; i < maxmult; i++) {
      const mm = m * i;
      const len = BigInt(BigMath.bitLength(mm));
      const delta = ((1n << len) - mm) / (1n << len);

      if (delta < mindelta) {
        iii = i;
        mindelta = delta;
      }
    }

    return iii;
  },

  fouqueTibouchiOptions(bits, fix) {
    assert((bits >>> 0) === bits);
    assert((fix >>> 0) === fix);

    const [m, lamm] = this.primeProdAndCarmichael(bits - fix);
    const mmult = this.findMinDelta(m, 1024n);
    const amax = (1n << BigInt(bits)) / m;
    const amult = this.findMinDelta(amax, 1024n);

    return [m, mmult, lamm, amax, amult];
  },

  // From Fouque and Tibouchi,
  // "Close to uniform prime number generation with fewer random bits."
  // https://eprint.iacr.org/2011/418

  fouqueTibouchi(opts, rng) {
    assert(Array.isArray(opts));
    assert(rng && typeof rng.randomInt === 'function');

    const [m, mmult, lamm, amax, amult] = opts;
    const mlimit = m * mmult;
    const alimit = amax * amult;

    for (;;) {
      let u = 1n;
      let b = 0n;

      while (u !== 0n) {
        const r = BigMath.mod(rng.randomInt(mlimit) * u / mmult, m);

        b = BigMath.mod(b + r, m);
        u = 1n - BigMath.modPow(b, lamm, m);
        u = u < 0n ? u + m : u;
      }

      let p = 2n;
      let i = 0n;
      let cont = false;

      while (!this.isPrime(p, null)) {
        if (i > amax / 10n) {
          // Did we choose a "bad" b?
          cont = true;
          break;
        }

        i += 1n;

        const a = rng.randomInt(alimit) / amult;

        p = (a * m + b) | 1n;
      }

      if (!cont)
        return p;
    }
  }
};

/*
 * Expose
 */

module.exports = util;
