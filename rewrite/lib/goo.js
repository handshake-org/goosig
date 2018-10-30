'use strict';

/* eslint camelcase: "off" */

const assert = require('bsert');
const SHA256 = require('bcrypto/lib/sha256');
const DRBG = require('bcrypto/lib/drbg');
const rsa = require('bcrypto/lib/rsa');
const BigMath = require('./bigmath');
const constants = require('./constants');
const primes = require('./primes');
const RNG = require('./rng');
const Signature = require('./signature');
const util = require('./util');

/*
 * Constants
 */

const SLAB = Buffer.alloc(2, 0x00);

/*
 * Goo
 */

class Goo {
  constructor(n, g, h, modBits = null) {
    assert(Buffer.isBuffer(n));
    assert((g >>> 0) === g);
    assert((h >>> 0) === h);
    assert(modBits == null || (modBits >>> 0) === modBits);

    this.n = BigMath.decode(n);
    this.nh = this.n / 2n;
    this.g = BigInt(g);
    this.h = BigInt(h);

    this.randBits = util.clog2(this.n) - 1;
    this.e1bits = new Int32Array(constants.EXPONENT_SIZE * 2 + 2);
    this.e2bits = new Int32Array(constants.EXPONENT_SIZE * 2 + 2);
    this.combs = [];

    this.init(constants.MAX_COMB_SIZE, modBits);
  }

  init(maxCombSize, modBits) {
    assert((maxCombSize >>> 0) === maxCombSize);
    assert(modBits == null || (modBits >>> 0) === modBits);

    if (modBits != null) {
      const big = Math.max(2 * modBits, modBits + this.randBits);
      const bigBits = big + constants.CHAL_BITS + 1;
      const bigSpec = Comb.generate(bigBits, maxCombSize);
      const smallBits = this.randBits;
      const smallSpec = Comb.generate(smallBits, maxCombSize);

      this.combs = [
        [
          new Comb(this, this.g, smallSpec),
          new Comb(this, this.h, smallSpec)
        ],
        [
          new Comb(this, this.g, bigSpec),
          new Comb(this, this.h, bigSpec)
        ]
      ];
    } else {
      const tinyBits = constants.CHAL_BITS;
      const tinySpec = Comb.generate(tinyBits, maxCombSize);

      this.combs = [
        [
          new Comb(this, this.g, tinySpec),
          new Comb(this, this.h, tinySpec)
        ]
      ];
    }
  }

  randomScalar() {
    const size = Math.min(constants.EXPONENT_SIZE, this.randBits);
    return util.randomBits(size);
  }

  wnafPCHelp(b, winSize) {
    assert(typeof b === 'bigint');
    assert((winSize >>> 0) === winSize);
    assert(winSize >= 2);

    const len = 2 ** (winSize - 2);
    const table = new Array(len);
    const sqr = this.sqr(b);

    table[0] = b;

    for (let i = 1; i < len; i++)
      table[i] = this.mul(table[i - 1], sqr);

    return table;
  }

  oneMul(ret, w, pctabP, pctabN) {
    assert(typeof ret === 'bigint');
    assert(typeof w === 'number');
    assert(Array.isArray(pctabP));
    assert(Array.isArray(pctabN));

    if (w > 0)
      ret = this.mul(ret, pctabP[(w - 1) >>> 1]);
    else if (w < 0)
      ret = this.mul(ret, pctabN[(-1 - w) >>> 1]);

    return ret;
  }

  precompWnaf(b, bInv, winsize) {
    return [
      this.wnafPCHelp(b, winsize),
      this.wnafPCHelp(bInv, winsize)
    ];
  }

  wnaf(r, ws, out, bitlen) {
    assert(typeof r === 'bigint');
    assert(typeof ws === 'number');
    assert(out instanceof Int32Array);
    assert((bitlen >>> 0) === bitlen);
    assert(bitlen <= out.length);

    const w = BigInt(ws);

    for (let i = bitlen - 1; i >= 0; i--) {
      let val = 0n;

      if (r % 2n) {
        val = r & ((1n << w) - 1n);
        if (val & (1n << (w - 1n)))
          val -= 1n << w;
        r -= val;
      }

      out[i] = Number(val);

      r = r >> 1n;
    }

    assert(r === 0n);

    return out;
  }

  reduce(b) {
    assert(typeof b === 'bigint');

    if (b > this.nh)
      return this.n - b;

    return b;
  }

  isReduced(b) {
    assert(typeof b === 'bigint');

    return b <= this.nh;
  }

  sqr(b) {
    return BigMath.modPow(b, 2n, this.n);
  }

  mul(m1, m2) {
    assert(typeof m1 === 'bigint');
    assert(typeof m2 === 'bigint');

    return BigMath.mod(m1 * m2, this.n);
  }

  pow(b, bInv, e) {
    return BigMath.modPow(b, e, this.n);
  }

  powWnaf(b, bInv, e) {
    assert(typeof b === 'bigint');

    const ws = constants.WINDOW_SIZE;
    const [pctabP, pctabN] = this.precompWnaf(b, bInv, ws);
    const totlen = BigMath.bitLength(e) + 1;
    const ebits = this.wnaf(e, ws, this.e1bits, totlen);

    let ret = 1n;

    for (let i = 0; i < totlen; i++) {
      const w = ebits[i];

      if (ret !== 1n)
        ret = this.sqr(ret);

      ret = this.oneMul(ret, w, pctabP, pctabN);
    }

    return ret;
  }

  pow2Slow(b1, b1Inv, e1, b2, b2Inv, e2) {
    const q1 = BigMath.modPow(b1, e1, this.n);
    const q2 = BigMath.modPow(b2, e2, this.n);
    return BigMath.mod(q1 * q2, this.n);
  }

  pow2(b1, b1Inv, e1, b2, b2Inv, e2) {
    assert(typeof b1 === 'bigint');
    assert(typeof b2 === 'bigint');

    const ws = constants.WINDOW_SIZE;
    const [pctabP1, pctabN1] = this.precompWnaf(b1, b1Inv, ws);
    const [pctabP2, pctabN2] = this.precompWnaf(b2, b2Inv, ws);

    const totlen = Math.max(BigMath.bitLength(e1), BigMath.bitLength(e2)) + 1;
    const e1bits = this.wnaf(e1, ws, this.e1bits, totlen);
    const e2bits = this.wnaf(e2, ws, this.e2bits, totlen);

    let ret = 1n;

    for (let i = 0; i < totlen; i++) {
      const w1 = e1bits[i];
      const w2 = e2bits[i];

      if (ret !== 1n)
        ret = this.sqr(ret);

      ret = this.oneMul(ret, w1, pctabP1, pctabN1);
      ret = this.oneMul(ret, w2, pctabP2, pctabN2);
    }

    return ret;
  }

  powghSlow(e1, e2) {
    const q1 = BigMath.modPow(this.g, e1, this.n);
    const q2 = BigMath.modPow(this.h, e2, this.n);
    return BigMath.mod(q1 * q2, this.n);
  }

  powgh(e1, e2) {
    assert(typeof e1 === 'bigint');
    assert(typeof e2 === 'bigint');

    const loge = Math.max(BigMath.bitLength(e1), BigMath.bitLength(e2));

    let gcomb = null;
    let hcomb = null;

    for (const pair of this.combs) {
      if (loge <= pair[0].bits) {
        [gcomb, hcomb] = pair;
        break;
      }
    }

    if (!gcomb || !hcomb)
      throw new Error('got unexpectedly large exponent in powgh');

    const e1e = gcomb.toCombExp(e1);
    const e2e = hcomb.toCombExp(e2);

    let ret = 1n;

    for (let i = 0; i < e1e.length; i++) {
      const e1vs = e1e[i];
      const e2vs = e2e[i];

      if (ret !== 1n)
        ret = this.sqr(ret);

      for (let j = 0; j < e1vs.length; j++) {
        const e1v = e1vs[j];
        const e2v = e2vs[j];

        if (e1v !== 0) {
          const g = gcomb.items[j * gcomb.pointsPerSubcomb + e1v - 1];
          ret = this.mul(ret, g);
        }

        if (e2v !== 0) {
          const h = hcomb.items[j * hcomb.pointsPerSubcomb + e2v - 1];
          ret = this.mul(ret, h);
        }
      }
    }

    return ret;
  }

  inv(b) {
    const r = util.modInverseP(b, this.n);

    if (r == null)
      throw new Error('Could not find inverse.');

    return r;
  }

  inv2(b1, b2) {
    assert(typeof b1 === 'bigint');
    assert(typeof b2 === 'bigint');

    const b12Inv = this.inv(b1 * b2);

    return [
      BigMath.mod(b2 * b12Inv, this.n),
      BigMath.mod(b1 * b12Inv, this.n)
    ];
  }

  inv5(b1, b2, b3, b4, b5) {
    assert(typeof b1 === 'bigint');
    assert(typeof b2 === 'bigint');
    assert(typeof b3 === 'bigint');
    assert(typeof b4 === 'bigint');
    assert(typeof b5 === 'bigint');

    const b12 = BigMath.mod(b1 * b2, this.n);
    const b34 = BigMath.mod(b3 * b4, this.n);
    const b1234 = BigMath.mod(b12 * b34, this.n);
    const b12345 = BigMath.mod(b1234 * b5, this.n);

    const b12345Inv = this.inv(b12345);
    const b1234Inv = BigMath.mod(b12345Inv * b5, this.n);
    const b34Inv = BigMath.mod(b1234Inv * b12, this.n);
    const b12Inv = BigMath.mod(b1234Inv * b34, this.n);

    return [
      BigMath.mod(b12Inv * b2, this.n),
      BigMath.mod(b12Inv * b1, this.n),
      BigMath.mod(b34Inv * b4, this.n),
      BigMath.mod(b34Inv * b3, this.n),
      BigMath.mod(b12345Inv * b1234, this.n)
    ];
  }

  fsChal(C1, C2, t, A, B, C, D, msg, verify) {
    assert(typeof C1 === 'bigint');
    assert(typeof C2 === 'bigint');
    assert(typeof t === 'bigint');
    assert(typeof A === 'bigint');
    assert(typeof B === 'bigint');
    assert(typeof C === 'bigint');
    assert(typeof D === 'bigint');
    assert(typeof msg === 'bigint');
    assert(typeof verify === 'boolean');

    const key = hashAll([
      this.n,
      this.g,
      this.h,
      C1,
      C2,
      t,
      A,
      B,
      C,
      D,
      msg
    ]);

    const prng = new PRNG(key);
    const chal = prng.randomBits(constants.CHAL_BITS);

    let ell = prng.randomBits(constants.CHAL_BITS);

    if (!verify) {
      // For prover, call nextPrime on ell_r to get ell.
      ell = primes.nextPrime(ell, BigInt(constants.ELLDIFF_MAX));
    }

    return [chal, ell];
  }

  expandSprime(s_prime) {
    const rng = new PRNG(BigMath.encode(s_prime, 32));
    return rng.randomBits(constants.EXPONENT_SIZE);
  }

  veil(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(key instanceof rsa.RSAKey);

    const C0_pre = BigMath.decode(msg);
    const n = BigMath.decode(key.n);

    // Make a ciphertext C0 indistinguishable from
    // a random (MAX_RSA_BITS + 8)-bit integer.
    const ctlim = 1n << (BigInt(constants.MAX_RSA_BITS) + 8n);

    // Ceiling of (ctlim - C0_pre) / n,
    // ensuring C0_pre + n * rlim >= ctlim.
    const rlim = (ctlim - C0_pre + n - 1n) / n;

    let C0 = ctlim;

    while (C0 >= ctlim) {
      const c0_rand = util.randomInt(rlim);

      C0 = C0_pre + c0_rand * n;
    }

    assert(BigMath.mod(C0, n) === C0_pre);

    return BigMath.encode(C0, (constants.MAX_RSA_BITS + 7) >>> 3);
  }

  unveil(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(key instanceof rsa.RSAKey);

    const C0 = BigMath.decode(msg);
    const n = BigMath.decode(key.n);
    const C0_pre = BigMath.mod(C0, n);

    return BigMath.encode(C0_pre, key.size());
  }

  challenge(key) {
    assert(key instanceof rsa.RSAKey);

    const n = BigMath.decode(key.n);
    const s_prime = util.randomBits(256);
    const s = this.expandSprime(s_prime);

    // The challenge: a commitment to the RSA modulus.
    const C1 = this.reduce(this.powgh(n, s));

    const bytes = BigMath.byteLength(this.n);

    return [BigMath.encode(s_prime, 32), BigMath.encode(C1, bytes)];
  }

  sign(msg, s_prime, C1, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(s_prime));
    assert(Buffer.isBuffer(C1));
    assert(key instanceof rsa.RSAPrivateKey);

    return this._sign(BigMath.decode(msg),
                      BigMath.decode(s_prime),
                      BigMath.decode(C1),
                      BigMath.decode(key.n),
                      BigMath.decode(key.p),
                      BigMath.decode(key.q));
  }

  _sign(msg, s_prime, C1, n, p, q) {
    assert(typeof s_prime === 'bigint');
    assert(typeof C1 === 'bigint');
    assert(typeof msg === 'bigint');
    assert(typeof n === 'bigint');
    assert(typeof p === 'bigint');
    assert(typeof q === 'bigint');

    const s = this.expandSprime(s_prime);

    if (C1 !== this.reduce(this.powgh(n, s)))
      throw new Error('C1 does not commit to our RSA modulus with opening s.');

    // Preliminaries: compute values P needs to run the ZKPOK.
    // Find `t`.
    let w = null;
    let t = null;

    for (t of primes.smallPrimes) {
      w = util.modSqrtN(t, p, q);

      if (w != null)
        break;
    }

    if (w == null || t == null)
      throw new Error('No prime quadratic residue less than 1000 mod N!');

    const a = (w ** 2n - t) / n;

    if (a * n !== w ** 2n - t)
      throw new Error('w^2 - t was not divisible by N!');

    // Commitment to `w`.
    const s1 = this.randomScalar();
    const C2 = this.reduce(this.powgh(w, s1));

    // Inverses of `C1` and `C2`.
    const [C1Inv, C2Inv] = this.inv2(C1, C2);

    // P's first message: commit to randomness.
    // P's randomness (except for r_s1; see "V's message", below).
    let [r_w, r_w2, r_a, r_an, r_s1w, r_sa] = [
      this.randomScalar(),
      this.randomScalar(),
      this.randomScalar(),
      this.randomScalar(),
      this.randomScalar(),
      this.randomScalar()
    ];

    // Prevent D from being negative.
    if (r_w2 < r_an)
      [r_w2, r_an] = [r_an, r_w2];

    // P's first message (except for A; see "V's message", below).
    const B = this.reduce(this.mul(this.pow(C2Inv, C2, r_w),
                                   this.powgh(r_w2, r_s1w)));
    const C = this.reduce(this.mul(this.pow(C1Inv, C1, r_a),
                                   this.powgh(r_an, r_sa)));
    const D = r_w2 - r_an;

    // V's message: random challenge and random prime.
    let chal = null;
    let ell = null;
    let r_s1, A;

    while (ell == null || BigMath.bitLength(ell) !== 128) {
      // Randomize the signature until Fiat-Shamir
      // returns an admissable ell. Note that it's
      // not necessary to re-start the whole
      // signature! Just pick a new r_s1, which
      // only requires re-computing A.
      r_s1 = this.randomScalar();
      A = this.reduce(this.powgh(r_w, r_s1));
      [chal, ell] = this.fsChal(C1, C2, t, A, B, C, D, msg, false);
    }

    // P's second message: compute quotient message.
    // Compute z' = c*(w, w2, s1, a, an, s1w, sa)
    //            + (r_w, r_w2, r_s1, r_a, r_an, r_s1w, r_sa)
    const z_w = chal * w + r_w;
    const z_w2 = chal * w * w + r_w2;
    const z_s1 = chal * s1 + r_s1;
    const z_a = chal * a + r_a;
    const z_an = chal * a * n + r_an;
    const z_s1w = chal * s1 * w + r_s1w;
    const z_sa = chal * s * a + r_sa;

    // Compute quotient commitments.
    const Aq = this.reduce(this.powgh(z_w / ell, z_s1 / ell));
    const Bq = this.reduce(this.mul(this.pow(C2Inv, C2, z_w / ell),
                                    this.powgh(z_w2 / ell, z_s1w / ell)));
    const Cq = this.reduce(this.mul(this.pow(C1Inv, C2, z_a / ell),
                                    this.powgh(z_an / ell, z_sa / ell)));
    const Dq = (z_w2 - z_an) / ell;

    // Compute z'.
    const z_prime = [];

    for (const z_foo of [z_w, z_w2, z_s1, z_a, z_an, z_s1w, z_sa])
      z_prime.push(BigMath.mod(z_foo, ell));

    // z_prime: (z_w, z_w2, z_s1, z_a, z_an, z_s1w, z_sa).
    // Signature: (chal, ell, Aq, Bq, Cq, Dq, z_prime).
    return new Signature({ C2,
                           t,
                           chal,
                           ell,
                           Aq,
                           Bq,
                           Cq,
                           Dq,
                           z_prime }).encode();
  }

  verify(msg, sig, C1) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(C1));

    const m = BigMath.decode(msg);
    const s = Signature.decode(sig);
    const c = BigMath.decode(C1);

    return this._verify(m, s, c);
  }

  _verify(msg, sig, C1) {
    assert(typeof msg === 'bigint');
    assert(sig instanceof Signature);
    assert(typeof C1 === 'bigint');

    const {C2, t} = sig;
    const {chal, ell, Aq, Bq, Cq, Dq} = sig;
    const {zp_w, zp_w2, zp_s1, zp_a, zp_an, zp_s1w, zp_sa} = sig;

    // Make sure that the public key is valid.
    // `t` must be one of the small primes in our list.
    if (primes.smallPrimes.indexOf(t) === -1)
      return false;

    // All group elements must be the "canonical"
    // element of the quotient group (Z/n)/{1,-1}.
    for (const b of [C1, C2, Aq, Bq, Cq]) {
      if (!this.isReduced(b))
        return false;
    }

    // Compute inverses of C1, C2, Aq, Bq, Cq.
    //
    // Note:
    // Since we're inverting C1 and C2, we can
    // get inverses of Aq, Bq, Cq for ~free. This
    // lets us use signed-digit exponentiation below,
    // which is much faster.
    const [C1Inv, C2Inv, AqInv, BqInv, CqInv] = this.inv5(C1, C2, Aq, Bq, Cq);

    // Step 1: reconstruct A, B, C, and D from signature.
    const A = this.reduce(this.mul(this.pow2(Aq, AqInv, ell, C2Inv, C2, chal),
                                   this.powgh(zp_w, zp_s1)));
    const B = this.reduce(this.mul(this.pow2(Bq, BqInv, ell, C2Inv, C2, zp_w),
                                   this.powgh(zp_w2, zp_s1w)));
    const C = this.reduce(this.mul(this.pow2(Cq, CqInv, ell, C1Inv, C1, zp_a),
                                   this.powgh(zp_an, zp_sa)));

    // Make sure sign of (zp_w2 - zp_an) is positive.
    const zp_w2_m_an = zp_w2 - zp_an;

    let D = Dq * ell + zp_w2_m_an - t * chal;

    if (zp_w2_m_an < 0n)
      D += ell;

    // Step 2: recompute implicitly claimed V message, viz., chal and ell.
    const [chal_out, ell_r_out] = this.fsChal(C1, C2, t, A, B, C, D, msg, true);

    // Final checks.
    // chal has to match
    // AND 0 <= (ell_r_out - ell) <= ELLDIFF_MAX
    // AND ell is prime
    const elldiff = ell - ell_r_out;

    if (chal !== chal_out
        || elldiff < 0n
        || elldiff > BigInt(constants.ELLDIFF_MAX)
        || !primes.isPrime(ell)) {
      return false;
    }

    return true;
  }

  toJSON() {
    return {
      n: BigMath.encodeHex(this.n),
      g: Number(this.g),
      h: Number(this.h),
      combs: this.combs.map((combs) => {
        return combs.map(comb => comb.toJSON());
      })
    };
  }
}

/*
 * Static
 */

Goo.AOL = constants.AOL;
Goo.RSA617 = constants.RSA617;
Goo.RSA2048 = constants.RSA2048;
Goo.DEFAULT_G = constants.DEFAULT_G;
Goo.DEFAULT_H = constants.DEFAULT_H;
Goo.MAX_RSA_BITS = constants.MAX_RSA_BITS;
Goo.EXPONENT_SIZE = constants.EXPONENT_SIZE;
Goo.WINDOW_SIZE = constants.WINDOW_SIZE;
Goo.MAX_COMB_SIZE = constants.MAX_COMB_SIZE;
Goo.CHAL_BITS = constants.CHAL_BITS;
Goo.ELLDIFF_MAX = constants.ELLDIFF_MAX;
Goo.HASH_PREFIX = constants.HASH_PREFIX;
Goo.DRBG_PERS = constants.DRBG_PERS;
Goo.NONCE = constants.NONCE;

/*
 * Comb
 */

class Comb {
  constructor(goo, base, spec) {
    this.pointsPerAdd = 0;
    this.addsPerShift = 0;
    this.shifts = 0;
    this.bitsPerWindow = 0;
    this.bits = 0;
    this.pointsPerSubcomb = 0;
    this.items = [];
    this.ebits = new Uint8Array(0);
    this.wins = [];

    this.init(goo, base, spec);
  }

  init(goo, base, spec) {
    assert(goo && typeof goo.mul === 'function');
    assert(typeof base === 'bigint');
    assert(Array.isArray(spec));
    assert(spec.length === 6);
    assert((spec[0] >>> 0) === spec[0]);
    assert((spec[1] >>> 0) === spec[1]);
    assert((spec[2] >>> 0) === spec[2]);
    assert((spec[3] >>> 0) === spec[3]);
    assert((spec[4] >>> 0) === spec[4]);
    assert((spec[5] >>> 0) === spec[5]);

    const [ppa, aps, shifts, bpw, , size] = spec;
    const skip = 2 ** ppa - 1;
    const window = 1n << BigInt(bpw);
    const powval = 1n << BigInt(shifts);

    this.pointsPerAdd = ppa;
    this.addsPerShift = aps;
    this.shifts = shifts;
    this.bitsPerWindow = bpw;
    this.bits = bpw * ppa;
    this.pointsPerSubcomb = skip;

    // Allocate space.
    this.items = [];

    for (let i = 0; i < size; i++)
      this.items.push(0n);

    // Compute bottom comb.
    this.items[0] = base;

    for (let i = 1; i < ppa; i++) {
      const x = 2 ** i;
      const y = x >>> 1;

      this.items[x - 1] = goo.pow(this.items[y - 1], null, window);

      for (let j = x + 1; j < 2 * x; j++)
        this.items[j - 1] = goo.mul(this.items[j - x - 1], this.items[x - 1]);
    }

    for (let i = 1; i < aps; i++) {
      for (let j = 0; j < skip; j++) {
        const k = i * skip + j;
        const n = this.items[k - skip];

        this.items[k] = goo.pow(n, null, powval);
      }
    }

    this.ebits = new Uint8Array(this.bits);

    for (let i = 0; i < this.shifts; i++)
      this.wins.push(new Int32Array(this.addsPerShift));
  }

  toCombExp(e) {
    assert(typeof e === 'bigint');

    let i = 0;
    let len = BigMath.bitLength(e);

    if (len === 0)
      len = 1;

    assert(this.bits >= len);

    let pre = this.bits - len;

    while (pre--)
      this.ebits[i++] = 0;

    let pos = BigInt(len);

    while (pos--) {
      if ((e >> pos) & 1n)
        this.ebits[i++] = 1;
      else
        this.ebits[i++] = 0;
    }

    for (let i = this.addsPerShift - 1; i >= 0; i--) {
      for (let j = 0; j < this.shifts; j++) {
        let ret = 0;
        for (let k = 0; k < this.pointsPerAdd; k++) {
          const b = (i + k * this.addsPerShift) * this.shifts + j;
          ret *= 2;
          // ret += Number((e >> BigInt((this.bits - 1) - b)) & 1n);
          ret += this.ebits[b];
        }
        this.wins[j][(this.addsPerShift - 1) - i] = ret;
      }
    }

    return this.wins;
  }

  toJSON() {
    return {
      pointsPerAdd: this.pointsPerAdd,
      addsPerShift: this.addsPerShift,
      shifts: this.shifts,
      bitsPerWindow: this.bitsPerWindow,
      bits: this.bits,
      pointsPerSubcomb: this.pointsPerSubcomb,
      size: this.items.length,
      items: this.items.map(item => BigMath.encodeHex(item))
    };
  }

  static generate(bits, maxSize) {
    assert((bits >>> 0) === bits);
    assert((maxSize >>> 0) === maxSize);

    // An "optimal" comb for a given #ops is
    // the one that uses the least storage
    // for a given storage size is the one
    // that uses the least ops.
    const combs = new Map();

    const genComb = (shifts, aps, ppa, bpw) => {
      // Note:
      // This assumes add/mull and double/square have the same cost;
      // you might adjust this to get a better optimization result!
      const ops = shifts * (aps + 1) - 1;
      const size = (2 ** ppa - 1) * aps;
      const item = [ppa, aps, shifts, bpw, ops, size];
      const best = combs.get(ops);

      if (best == null || best[5] > size)
        combs.set(ops, item);
    };

    for (let ppa = 2; ppa < 18; ppa++) {
      const bpw = ((bits + ppa - 1) / ppa) >>> 0;
      const sqrt = util.dsqrt(bpw);

      for (let aps = 1; aps < sqrt + 2; aps++) {
        if (bpw % aps !== 0) {
          // Only factorizations of
          // bpw are useful.
          continue;
        }

        const shifts = (bpw / aps) >>> 0;

        genComb(shifts, aps, ppa, bpw);
        genComb(aps, shifts, ppa, bpw);
      }
    }

    const keys = [];

    for (const key of combs.keys())
      keys.push(key);

    keys.sort((a, b) => a - b);

    let ret = null;
    let sm = null;

    for (const ops of keys) {
      const comb = combs.get(ops);

      if (sm != null && sm <= comb[5])
        continue;

      sm = comb[5];

      if (sm <= maxSize) {
        ret = comb;
        break;
      }
    }

    if (!ret)
      throw new Error('Could not calculate comb.');

    return ret;
  }
}

/*
 * PRNG
 */

class PRNG extends RNG {
  constructor(key) {
    super(new DRBG(SHA256, key, constants.DRBG_NONCE, constants.DRBG_PERS));
  }
}

/*
 * Helpers
 */

function hashAll(items) {
  assert(Array.isArray(items));

  const ctx = new SHA256();
  const size = SLAB;

  ctx.init();
  ctx.update(constants.HASH_PREFIX);

  for (const item of items) {
    // Commit to integer size.
    let len = BigMath.byteLength(item);
    assert(len <= 0x7fff);

    // Commit to sign.
    if (item < 0n)
      len |= 0x8000;

    size[0] = len;
    size[1] = len >>> 8;

    ctx.update(size);
    ctx.update(BigMath.encode(item));
  }

  return ctx.final();
}

/*
 * Expose
 */

module.exports = Goo;
