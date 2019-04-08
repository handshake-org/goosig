/*!
 * goo.js - groups of unknown order for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Parts of this software are based on kwantam/libGooPy:
 *   Copyright (c) 2018, Dan Boneh, Riad S. Wahby (Apache License).
 *   https://github.com/kwantam/GooSig
 *
 * Resources:
 *   https://github.com/kwantam/GooSig/blob/master/protocol.txt
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/group_ops.py
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/group_mixins.py
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/tokengen.py
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/sign.py
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/verify.py
 */

/* eslint camelcase: "off" */
/* eslint valid-typeof: "off" */

'use strict';

const assert = require('bsert');
const BN = require('bcrypto/lib/bn.js');
const SHA256 = require('bcrypto/lib/sha256');
const constants = require('../internal/constants');
const primes = require('./primes');
const PRNG = require('./prng');
const rsa = require('../internal/rsa');
const Signature = require('./signature');
const util = require('./util');

/*
 * Goo
 */

class Goo {
  constructor(n, g, h, modBits) {
    if (modBits == null)
      modBits = 0;

    assert(Buffer.isBuffer(n));
    assert((g >>> 0) === g);
    assert((h >>> 0) === h);
    assert((modBits >>> 0) === modBits);

    this.n = BN.decode(n);
    this.red = BN.red(this.n);
    this.bits = this.n.bitLength();
    this.size = (this.bits + 7) >>> 3;
    this.nh = this.n.ushrn(1);
    this.nhRed = this.nh.toRed(this.red);
    this.zero = BN.from(0).toRed(this.red);
    this.one = BN.from(1).toRed(this.red);
    this.g = BN.fromNumber(g).toRed(this.red);
    this.h = BN.fromNumber(h).toRed(this.red);
    this.nRaw = this.n.encode('be');
    this.gRaw = this.g.fromRed().encode('be', 4);
    this.hRaw = this.h.fromRed().encode('be', 4);
    this.randBits = this.n.bitLength() - 1;
    this.e1bits = new Int32Array(constants.CHAL_BITS + 1);
    this.e2bits = new Int32Array(constants.CHAL_BITS + 1);
    this.combs = [];

    this.init(constants.MAX_COMB_SIZE, modBits);
  }

  init(maxCombSize, modBits) {
    assert((maxCombSize >>> 0) === maxCombSize);
    assert((modBits >>> 0) === modBits);

    if (modBits !== 0) {
      if (modBits < constants.MIN_RSA_BITS
          || modBits > constants.MAX_RSA_BITS) {
        throw new Error('Invalid modulus bits.');
      }

      const big = Math.max(2 * modBits, modBits + this.randBits);
      const bigBits = big + constants.CHAL_BITS + 1;
      const bigSpec = Comb.generate(bigBits, maxCombSize);
      const smallBits = this.randBits;
      const smallSpec = Comb.generate(smallBits, maxCombSize);

      this.combs = [
        {
          g: new Comb(this, this.g, smallSpec),
          h: new Comb(this, this.h, smallSpec)
        },
        {
          g: new Comb(this, this.g, bigSpec),
          h: new Comb(this, this.h, bigSpec)
        }
      ];
    } else {
      const tinyBits = constants.CHAL_BITS;
      const tinySpec = Comb.generate(tinyBits, maxCombSize);

      this.combs = [
        {
          g: new Comb(this, this.g, tinySpec),
          h: new Comb(this, this.h, tinySpec)
        }
      ];
    }
  }

  randomScalar() {
    const bits = Math.min(constants.EXPONENT_SIZE, this.randBits);
    return util.randomBitsNZ(bits);
  }

  wnafPCHelp(b, winSize) {
    assert(BN.isBN(b));
    assert((winSize >>> 0) === winSize);
    assert(winSize >= 2);

    const len = 2 ** (winSize - 2);
    const table = new Array(len);
    const sqr = b.redSqr();

    table[0] = b;

    for (let i = 1; i < len; i++)
      table[i] = table[i - 1].redMul(sqr);

    return table;
  }

  oneMul(ret, w, pctabP, pctabN) {
    assert(BN.isBN(ret));
    assert(typeof w === 'number');
    assert(Array.isArray(pctabP));
    assert(Array.isArray(pctabN));

    if (w > 0)
      ret = ret.redIMul(pctabP[(w - 1) >>> 1]);
    else if (w < 0)
      ret = ret.redIMul(pctabN[(-1 - w) >>> 1]);

    return ret;
  }

  precompWnaf(b, bInv, winsize) {
    return [
      this.wnafPCHelp(b, winsize),
      this.wnafPCHelp(bInv, winsize)
    ];
  }

  wnaf(exp, ws, out, bitlen) {
    assert(BN.isBN(exp));
    assert(typeof ws === 'number');
    assert(out instanceof Int32Array);
    assert((bitlen >>> 0) === bitlen);
    assert(bitlen <= out.length);

    const e = exp.clone();

    for (let i = bitlen - 1; i >= 0; i--) {
      let val = 0;

      if (e.isOdd()) {
        val = e.andln((1 << ws) - 1);

        if (val & (1 << (ws - 1)))
          val -= 1 << ws;

        e.isubn(val);
      }

      out[i] = val;

      e.iushrn(1);
    }

    assert(e.isZero());

    return out;
  }

  reduce(b) {
    assert(BN.isBN(b));
    assert(b.red === this.red);

    if (b.gt(this.nhRed))
      return b.redNeg();

    return b;
  }

  isReduced(b) {
    assert(BN.isBN(b));
    assert(!b.red); // Scalars only.
    return b.lte(this.nh);
  }

  sqr(b) {
    assert(BN.isBN(b));
    return b.redSqr();
  }

  mul(m1, m2) {
    assert(BN.isBN(m1));
    return m1.redMul(m2);
  }

  pow(b, bInv, e) {
    assert(BN.isBN(b));
    return b.redPow(e);
  }

  powWnaf(b, bInv, e) {
    assert(BN.isBN(b));

    if (bInv == null)
      return this.pow(b, bInv, e);

    const ws = constants.WINDOW_SIZE;
    const [pctabP, pctabN] = this.precompWnaf(b, bInv, ws);
    const totlen = e.bitLength() + 1;

    if (totlen > constants.CHAL_BITS + 1)
      throw new Error('Got unexpectedly large exponent in pow.');

    const ebits = this.wnaf(e, ws, this.e1bits, totlen);

    let ret = this.one.clone();

    for (let i = 0; i < totlen; i++) {
      const w = ebits[i];

      if (!ret.eq(this.one))
        ret = ret.redISqr();

      ret = this.oneMul(ret, w, pctabP, pctabN);
    }

    return ret;
  }

  pow2Slow(b1, b1Inv, e1, b2, b2Inv, e2) {
    assert(BN.isBN(b1));
    assert(BN.isBN(b2));

    const q1 = b1.redPow(e1);
    const q2 = b2.redPow(e2);

    return q1.redIMul(q2);
  }

  pow2(b1, b1Inv, e1, b2, b2Inv, e2) {
    assert(BN.isBN(e1));
    assert(BN.isBN(e2));

    const ws = constants.WINDOW_SIZE;
    const [pctabP1, pctabN1] = this.precompWnaf(b1, b1Inv, ws);
    const [pctabP2, pctabN2] = this.precompWnaf(b2, b2Inv, ws);

    const totlen = Math.max(e1.bitLength(), e2.bitLength()) + 1;

    if (totlen > constants.CHAL_BITS + 1)
      throw new Error('Got unexpectedly large exponent in pow2.');

    const e1bits = this.wnaf(e1, ws, this.e1bits, totlen);
    const e2bits = this.wnaf(e2, ws, this.e2bits, totlen);

    let ret = this.one.clone();

    for (let i = 0; i < totlen; i++) {
      const w1 = e1bits[i];
      const w2 = e2bits[i];

      if (!ret.eq(this.one))
        ret = ret.redISqr();

      ret = this.oneMul(ret, w1, pctabP1, pctabN1);
      ret = this.oneMul(ret, w2, pctabP2, pctabN2);
    }

    return ret;
  }

  powghSlow(e1, e2) {
    const q1 = this.g.redPow(e1);
    const q2 = this.h.redPow(e2);
    return q1.redIMul(q2);
  }

  powgh(e1, e2) {
    assert(BN.isBN(e1));
    assert(BN.isBN(e2));

    const loge = Math.max(e1.bitLength(), e2.bitLength());

    let gcomb = null;
    let hcomb = null;

    for (const item of this.combs) {
      if (loge <= item.g.bits) {
        gcomb = item.g;
        hcomb = item.h;
        break;
      }
    }

    if (!gcomb || !hcomb)
      throw new Error('Got unexpectedly large exponent in powgh.');

    const e1e = gcomb.toCombExp(e1);
    const e2e = hcomb.toCombExp(e2);

    let ret = this.one.clone();

    for (let i = 0; i < e1e.length; i++) {
      const e1vs = e1e[i];
      const e2vs = e2e[i];

      if (!ret.eq(this.one))
        ret = ret.redISqr();

      for (let j = 0; j < e1vs.length; j++) {
        const e1v = e1vs[j];
        const e2v = e2vs[j];

        if (e1v !== 0) {
          const g = gcomb.items[j * gcomb.pointsPerSubcomb + e1v - 1];
          ret = ret.redIMul(g);
        }

        if (e2v !== 0) {
          const h = hcomb.items[j * hcomb.pointsPerSubcomb + e2v - 1];
          ret = ret.redIMul(h);
        }
      }
    }

    return ret;
  }

  inv(b) {
    assert(BN.isBN(b));
    return b.redInvm();
  }

  inv2(b1, b2) {
    assert(BN.isBN(b1));
    assert(BN.isBN(b2));

    const b12Inv = b1.redMul(b2).redInvm();

    return [
      b2.redMul(b12Inv),
      b1.redMul(b12Inv)
    ];
  }

  inv7(b1, b2, b3, b4, b5, b6, b7) {
    assert(BN.isBN(b1));
    assert(BN.isBN(b2));
    assert(BN.isBN(b3));
    assert(BN.isBN(b4));
    assert(BN.isBN(b5));
    assert(BN.isBN(b6));
    assert(BN.isBN(b7));

    const b12 = b1.redMul(b2);
    const b34 = b3.redMul(b4);
    const b56 = b5.redMul(b6);
    const b1234 = b12.redMul(b34);
    const b123456 = b1234.redMul(b56);
    const b1234567 = b123456.redMul(b7);

    const b1234567Inv = b1234567.redInvm();
    const b123456Inv = b1234567Inv.redMul(b7);
    const b1234Inv = b123456Inv.redMul(b56);
    const b56Inv = b123456Inv.redMul(b1234);
    const b34Inv = b1234Inv.redMul(b12);
    const b12Inv = b1234Inv.redMul(b34);

    return [
      b12Inv.redMul(b2),
      b12Inv.redIMul(b1),
      b34Inv.redMul(b4),
      b34Inv.redIMul(b3),
      b56Inv.redMul(b6),
      b56Inv.redIMul(b5),
      b1234567Inv.redIMul(b123456)
    ];
  }

  fsChal(C1, C2, C3, t, A, B, C, D, E, msg, verify) {
    assert(BN.isBN(C1));
    assert(BN.isBN(C2));
    assert(BN.isBN(C3));
    assert(BN.isBN(t));
    assert(BN.isBN(A));
    assert(BN.isBN(B));
    assert(BN.isBN(C));
    assert(BN.isBN(D));
    assert(BN.isBN(E));
    assert(BN.isBN(msg));
    assert(typeof verify === 'boolean');

    const modBytes = this.size;
    const expBytes = (constants.EXPONENT_SIZE + 7) >>> 3;

    if (C1.isNeg()
        || C2.isNeg()
        || C3.isNeg()
        || t.isNeg()
        || A.isNeg()
        || B.isNeg()
        || C.isNeg()
        || D.isNeg()
        || E.isNeg()
        || msg.isNeg()) {
      throw new RangeError('Negative parameters.');
    }

    const ctx = new SHA256();

    ctx.init();
    ctx.update(constants.HASH_PREFIX);
    ctx.update(this.nRaw);
    ctx.update(this.gRaw);
    ctx.update(this.hRaw);
    ctx.update(C1.fromRed().encode('be', modBytes));
    ctx.update(C2.fromRed().encode('be', modBytes));
    ctx.update(C3.fromRed().encode('be', modBytes));
    ctx.update(t.encode('be', 4));
    ctx.update(A.fromRed().encode('be', modBytes));
    ctx.update(B.fromRed().encode('be', modBytes));
    ctx.update(C.fromRed().encode('be', modBytes));
    ctx.update(D.fromRed().encode('be', modBytes));
    ctx.update(E.encode('be', expBytes));
    ctx.update(msg.encode('be', 64));

    const key = ctx.final();
    const prng = new PRNG(key);
    const chal = prng.randomBitsNZ(constants.CHAL_BITS);

    let ell = prng.randomBitsNZ(constants.CHAL_BITS);

    if (!verify) {
      // For prover, call nextPrime on ell_r to get ell.
      ell = primes.nextPrime(ell, key, constants.ELLDIFF_MAX);
    }

    return [chal, ell, key];
  }

  expandSprime(s_prime) {
    const rng = new PRNG(s_prime.encode('be', 32));
    return rng.randomBitsNZ(constants.EXPONENT_SIZE);
  }

  generate() {
    const s_prime = this._generate();
    return s_prime.encode('be', 32);
  }

  _generate() {
    const s_prime = util.randomBitsNZ(256);
    return s_prime;
  }

  challenge(s_prime, key) {
    assert(Buffer.isBuffer(s_prime));

    if (s_prime.length !== 32)
      throw new Error('Invalid seed length.');

    if (!isSanePublicKey(key))
      throw new Error('Invalid RSA public key.');

    const s_prime_n = BN.decode(s_prime);
    const n_n = BN.decode(key.n);
    const C1 = this._challenge(s_prime_n, n_n);

    return C1.encode('be', this.size);
  }

  _challenge(s_prime, n) {
    assert(BN.isBN(s_prime));
    assert(BN.isBN(n));

    if (s_prime.cmpn(0) <= 0)
      throw new Error('Invalid parameters.');

    if (n.cmpn(0) <= 0)
      throw new Error('Invalid RSA public key.');

    // The challenge: a commitment to the RSA modulus.
    const s = this.expandSprime(s_prime);
    const C1 = this.reduce(this.powgh(n, s));

    if (C1.cmp(this.zero) <= 0)
      throw new Error('Invalid C1 value.');

    return C1.fromRed();
  }

  encrypt(msg, key) {
    return rsa.encrypt(msg, key);
  }

  decrypt(ct, key) {
    return rsa.decrypt(ct, key);
  }

  validate(s_prime, C1, key) {
    assert(Buffer.isBuffer(s_prime));
    assert(Buffer.isBuffer(C1));

    if (s_prime.length !== 32)
      return false;

    if (C1.length !== this.size)
      return false;

    if (!isSanePrivateKey(key))
      return false;

    try {
      return this._validate(BN.decode(s_prime),
                            BN.decode(C1),
                            BN.decode(key.p),
                            BN.decode(key.q));
    } catch (e) {
      return false;
    }
  }

  _validate(s_prime, C1, p, q) {
    assert(BN.isBN(s_prime));
    assert(BN.isBN(C1));
    assert(BN.isBN(p));
    assert(BN.isBN(q));

    if (s_prime.cmpn(0) <= 0
        || C1.cmpn(0) <= 0
        || p.cmpn(0) <= 0
        || q.cmpn(0) <= 0) {
      return false;
    }

    const n = p.mul(q);
    const bits = n.bitLength();

    if (bits < constants.MIN_RSA_BITS
        || bits > constants.MAX_RSA_BITS) {
      return false;
    }

    const s = this.expandSprime(s_prime);
    const x = this.reduce(this.powgh(n, s));

    if (x.cmp(this.zero) <= 0)
      return false;

    return C1.eq(x.fromRed());
  }

  sign(msg, s_prime, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(s_prime));

    if (msg.length < 20 || msg.length > 64)
      throw new Error('Invalid message size.');

    if (s_prime.length !== 32)
      throw new Error('Invalid s_prime length.');

    if (!isSanePrivateKey(key))
      throw new Error('Invalid RSA private key.');

    const sig = this._sign(BN.decode(msg),
                           BN.decode(s_prime),
                           BN.decode(key.p),
                           BN.decode(key.q));

    return sig.encode(this.bits);
  }

  _sign(msg, s_prime, p, q) {
    assert(BN.isBN(msg));
    assert(BN.isBN(s_prime));
    assert(BN.isBN(p));
    assert(BN.isBN(q));

    if (msg.cmpn(0) <= 0
        || s_prime.cmpn(0) <= 0
        || p.cmpn(0) <= 0
        || q.cmpn(0) <= 0) {
      throw new Error('Invalid parameters.');
    }

    // The challenge: a commitment to the RSA modulus.
    const n = p.mul(q);
    const bits = n.bitLength();

    if (bits < constants.MIN_RSA_BITS
        || bits > constants.MAX_RSA_BITS) {
      throw new Error('Invalid RSA private key.');
    }

    // Preliminaries: compute values P needs to run the ZKPOK.
    // Find `t`.
    let w = null;
    let t = null;

    const smalls = [...primes.smallPrimes]; // You're killing me, smalls.

    for (let i = 0; i < smalls.length; i++) {
      // Partial in-place Fisher-Yates shuffle to choose random t.
      // Note: randomNum() is _exclusive_ of endpoints!
      const j = util.randomNum(smalls.length - i);

      [smalls[i], smalls[i + j]] = [smalls[i + j], smalls[i]];

      try {
        t = BN.from(smalls[i]);
        w = t.sqrtpq(p, q);
      } catch (e) {
        continue;
      }

      break;
    }

    if (w == null)
      throw new Error('No prime quadratic residue less than 1000 mod N!');

    assert(w.cmpn(0) > 0);

    const a = w.sqr().isub(t).div(n);

    assert(!a.isNeg());

    if (!a.mul(n).eq(w.sqr().isub(t)))
      throw new Error('w^2 - t was not divisible by N!');

    // Commitment to `n`.
    const s = this.expandSprime(s_prime);
    const C1 = this.reduce(this.powgh(n, s));

    // Commitment to `w`.
    const s1 = this.randomScalar();
    const C2 = this.reduce(this.powgh(w, s1));

    // Commitment to `a`.
    const s2 = this.randomScalar();
    const C3 = this.reduce(this.powgh(a, s2));

    if (C1.cmp(this.zero) <= 0
        || C2.cmp(this.zero) <= 0
        || C3.cmp(this.zero) <= 0) {
      throw new Error('Invalid C1, C2, or C3 value.');
    }

    // Inverses of `C1` and `C2`.
    const [C1Inv, C2Inv] = this.inv2(C1, C2);

    // P's first message: commit to randomness.
    // P's randomness (except for r_s1; see "V's message", below).
    let [r_w, r_w2, r_a, r_an, r_s1w, r_sa, r_s2] = [
      this.randomScalar(),
      this.randomScalar(),
      this.randomScalar(),
      this.randomScalar(),
      this.randomScalar(),
      this.randomScalar(),
      this.randomScalar()
    ];

    // Prevent E from being negative.
    if (r_w2.cmp(r_an) < 0)
      [r_w2, r_an] = [r_an, r_w2];

    // P's first message (except for A; see "V's message", below).
    const B = this.reduce(this.powgh(r_a, r_s2));
    const C = this.reduce(this.mul(this.pow(C2Inv, C2, r_w),
                                   this.powgh(r_w2, r_s1w)));
    const D = this.reduce(this.mul(this.pow(C1Inv, C1, r_a),
                                   this.powgh(r_an, r_sa)));
    const E = r_w2.sub(r_an);

    assert(!E.isNeg());

    // V's message: random challenge and random prime.
    let chal = null;
    let ell = null;
    let r_s1, A;

    while (ell == null || ell.bitLength() !== 128) {
      // Randomize the signature until Fiat-Shamir
      // returns an admissable ell. Note that it's
      // not necessary to re-start the whole
      // signature! Just pick a new r_s1, which
      // only requires re-computing A.
      r_s1 = this.randomScalar();
      A = this.reduce(this.powgh(r_w, r_s1));
      [chal, ell] = this.fsChal(C1, C2, C3, t, A, B, C, D, E, msg, false);
    }

    if (A.cmp(this.zero) <= 0
        || B.cmp(this.zero) <= 0
        || C.cmp(this.zero) <= 0
        || D.cmp(this.zero) <= 0
        || E.cmpn(0) <= 0) {
      throw new Error('Invalid A, B, C, D, or E value.');
    }

    // P's second message: compute quotient message.
    // Compute z' = c*(w, w2, s1, a, an, s1w, sa, s2)
    //            + (r_w, r_w2, r_s1, r_a, r_an, r_s1w, r_sa, r_s2)
    const z_w = chal.mul(w).iadd(r_w);
    const z_w2 = chal.mul(w).imul(w).iadd(r_w2);
    const z_s1 = chal.mul(s1).iadd(r_s1);
    const z_a = chal.mul(a).iadd(r_a);
    const z_an = chal.mul(a).imul(n).iadd(r_an);
    const z_s1w = chal.mul(s1).imul(w).iadd(r_s1w);
    const z_sa = chal.mul(s).imul(a).iadd(r_sa);
    const z_s2 = chal.mul(s2).iadd(r_s2);

    // Compute quotient commitments.
    const Aq = this.reduce(this.powgh(z_w.div(ell), z_s1.div(ell)));
    const Bq = this.reduce(this.powgh(z_a.div(ell), z_s2.div(ell)));
    const Cq = this.reduce(this.mul(this.pow(C2Inv, C2, z_w.div(ell)),
                                    this.powgh(z_w2.div(ell), z_s1w.div(ell))));
    const Dq = this.reduce(this.mul(this.pow(C1Inv, C2, z_a.div(ell)),
                                    this.powgh(z_an.div(ell), z_sa.div(ell))));
    const Eq = z_w2.sub(z_an).div(ell);

    if (Eq.isNeg() || Eq.bitLength() > constants.EXPONENT_SIZE)
      throw new Error(`Invalid Eq: (${z_w2} - ${z_an}) / ${ell} = ${Eq}.`);

    if (Aq.cmp(this.zero) <= 0
        || Bq.cmp(this.zero) <= 0
        || Cq.cmp(this.zero) <= 0
        || Dq.cmp(this.zero) <= 0
        || Eq.cmpn(0) <= 0) {
      throw new Error('Invalid Aq, Bq, Cq, Dq, or Eq value.');
    }

    // Compute z'.
    const z_prime = [];

    for (const z_foo of [z_w, z_w2, z_s1, z_a, z_an, z_s1w, z_sa, z_s2])
      z_prime.push(z_foo.umod(ell));

    for (const z_foo of z_prime) {
      if (z_foo.cmpn(0) <= 0)
        throw new Error('Invalid z_prime value.');
    }

    // z_prime: (z_w, z_w2, z_s1, z_a, z_an, z_s1w, z_sa, z_s2).
    // Signature: (chal, ell, Aq, Bq, Cq, Dq, Eq, z_prime).
    return new Signature({ C2: C2.fromRed(),
                           C3: C3.fromRed(),
                           t,
                           chal,
                           ell,
                           Aq: Aq.fromRed(),
                           Bq: Bq.fromRed(),
                           Cq: Cq.fromRed(),
                           Dq: Dq.fromRed(),
                           Eq,
                           z_prime });
  }

  verify(msg, sig, C1) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(C1));

    if (msg.length < 20 || msg.length > 64)
      return false;

    if (C1.length !== this.size)
      return false;

    const m = BN.decode(msg);
    const c = BN.decode(C1);

    let s;

    try {
      s = Signature.decode(sig, this.bits);
    } catch (e) {
      return false;
    }

    try {
      return this._verify(m, s, c);
    } catch (e) {
      return false;
    }
  }

  _verify(msg, sig, C1) {
    assert(BN.isBN(msg));
    assert(sig instanceof Signature);
    assert(BN.isBN(C1));

    let {C2, C3, t} = sig;
    let {chal, ell, Aq, Bq, Cq, Dq, Eq} = sig;
    const {z_w, z_w2, z_s1, z_a, z_an, z_s1w, z_sa, z_s2} = sig;

    if (C1.cmpn(0) <= 0
        || C2.cmpn(0) <= 0
        || C3.cmpn(0) <= 0
        || t.cmpn(0) <= 0
        || chal.cmpn(0) <= 0
        || ell.cmpn(0) <= 0
        || Aq.cmpn(0) <= 0
        || Bq.cmpn(0) <= 0
        || Cq.cmpn(0) <= 0
        || Dq.cmpn(0) <= 0
        || Eq.cmpn(0) <= 0
        || z_w.cmpn(0) <= 0
        || z_w2.cmpn(0) <= 0
        || z_s1.cmpn(0) <= 0
        || z_a.cmpn(0) <= 0
        || z_an.cmpn(0) <= 0
        || z_s1w.cmpn(0) <= 0
        || z_sa.cmpn(0) <= 0
        || z_s2.cmpn(0) <= 0) {
      throw new Error('Invalid parameters.');
    }

    if (ell.bitLength() > 128)
      throw new Error('Invalid ell value.');

    // Make sure that the public key is valid.
    // `t` must be one of the small primes in our list.
    if (primes.smallPrimes.indexOf(t.toNumber()) === -1)
      throw new Error('Invalid small prime.');

    // All group elements must be the "canonical"
    // element of the quotient group (Z/n)/{1,-1}.
    for (const b of [C1, C2, C3, Aq, Bq, Cq, Dq]) {
      if (!this.isReduced(b))
        throw new Error('Non-reduced parameters.');
    }

    // Switch to reduction context.
    C1 = C1.toRed(this.red);
    C2 = C2.toRed(this.red);
    C3 = C3.toRed(this.red);
    Aq = Aq.toRed(this.red);
    Bq = Bq.toRed(this.red);
    Cq = Cq.toRed(this.red);
    Dq = Dq.toRed(this.red);

    // Compute inverses of C1, C2, C3, Aq, Bq, Cq, Dq.
    //
    // Note:
    // Since we're inverting C1, C2, and C3, we can
    // get inverses of Aq, Bq, Cq, and Dq for ~free.
    // This lets us use signed-digit exponentiation
    // below, which is much faster.
    const [C1Inv, C2Inv, C3Inv,
           AqInv, BqInv, CqInv, DqInv] = this.inv7(C1, C2, C3, Aq, Bq, Cq, Dq);

    // Step 1: reconstruct A, B, C, D, and E from signature.
    const A = this.reduce(this.mul(this.pow2(Aq, AqInv, ell, C2Inv, C2, chal),
                                   this.powgh(z_w, z_s1)));
    const B = this.reduce(this.mul(this.pow2(Bq, BqInv, ell, C3Inv, C3, chal),
                                   this.powgh(z_a, z_s2)));
    const C = this.reduce(this.mul(this.pow2(Cq, CqInv, ell, C2Inv, C2, z_w),
                                   this.powgh(z_w2, z_s1w)));
    const D = this.reduce(this.mul(this.pow2(Dq, DqInv, ell, C1Inv, C1, z_a),
                                   this.powgh(z_an, z_sa)));

    // Make sure sign of (z_w2 - z_an) is positive.
    const z_w2_m_an = z_w2.sub(z_an);
    const E = Eq.mul(ell).iadd(z_w2_m_an.sub(t.mul(chal)));

    if (z_w2_m_an.cmpn(0) < 0)
      E.iadd(ell);

    if (E.isNeg())
      throw new Error(`Negative E value: ${E}.`);

    // Step 2: recompute implicitly claimed V message, viz., chal and ell.
    const [chal_out, ell_r_out, key] =
      this.fsChal(C1, C2, C3, t, A, B, C, D, E, msg, true);

    // Final checks.
    // chal has to match
    // AND 0 <= (ell_r_out - ell) <= ELLDIFF_MAX
    // AND ell is prime
    const elldiff = ell.sub(ell_r_out);

    if (!chal.eq(chal_out)
        || elldiff.cmpn(0) < 0
        || elldiff.cmpn(constants.ELLDIFF_MAX) > 0
        || !primes.isPrime(ell, key)) {
      throw new Error('Invalid chal/ell values.');
    }

    return true;
  }

  toJSON() {
    return {
      n: this.n.toJSON(),
      nh: this.nh.toJSON(),
      g: this.g.toNumber(),
      h: this.h.toNumber(),
      randBits: this.randBits,
      combs: this.combs.map((combs) => {
        return {
          g: combs.g.toJSON(),
          h: combs.h.toJSON()
        };
      })
    };
  }

  static encrypt(msg, key, bits) {
    return rsa.encrypt(msg, key, bits);
  }

  static decrypt(ct, key, bits) {
    return rsa.decrypt(ct, key, bits);
  }
}

/*
 * Static
 */

Goo.native = 0;
Goo.AOL1 = constants.AOL1;
Goo.AOL2 = constants.AOL2;
Goo.RSA2048 = constants.RSA2048;
Goo.RSA617 = constants.RSA617;

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
    this.wins = [];

    if (goo != null)
      this.init(goo, base, spec);
  }

  init(goo, base, spec) {
    assert(goo && typeof goo.mul === 'function');
    assert(BN.isBN(base));
    assert(Array.isArray(spec));
    assert(spec.length === 6);
    assert((spec[0] >>> 0) === spec[0]);
    assert((spec[1] >>> 0) === spec[1]);
    assert((spec[2] >>> 0) === spec[2]);
    assert((spec[3] >>> 0) === spec[3]);
    assert((spec[4] >>> 0) === spec[4]);
    assert((spec[5] >>> 0) === spec[5]);

    const [ppa, aps, shifts, bpw, , size] = spec;
    const skip = BN.pow(2, ppa).isubn(1);
    const window = BN.shift(1, bpw);
    const powval = BN.shift(1, shifts);

    this.pointsPerAdd = ppa;
    this.addsPerShift = aps;
    this.shifts = shifts;
    this.bitsPerWindow = bpw;
    this.bits = bpw * ppa;
    this.pointsPerSubcomb = skip;

    // Allocate space.
    this.items = [];

    for (let i = 0; i < size; i++)
      this.items.push(BN.from(0));

    // Compute bottom comb.
    this.items[0] = base.clone();

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

    for (let i = 0; i < this.shifts; i++)
      this.wins.push(new Int32Array(this.addsPerShift));
  }

  toCombExp(e) {
    assert(BN.isBN(e));

    for (let i = this.addsPerShift - 1; i >= 0; i--) {
      for (let j = 0; j < this.shifts; j++) {
        let ret = 0;

        for (let k = 0; k < this.pointsPerAdd; k++) {
          const b = (i + k * this.addsPerShift) * this.shifts + j;

          ret *= 2;
          ret += e.testn((this.bits - 1) - b);
        }

        this.wins[j][(this.addsPerShift - 1) - i] = ret;
      }
    }

    return this.wins;
  }

  toJSON() {
    return {
      base: this.items[0].toJSON(),
      pointsPerAdd: this.pointsPerAdd,
      addsPerShift: this.addsPerShift,
      shifts: this.shifts,
      bitsPerWindow: this.bitsPerWindow,
      bits: this.bits,
      pointsPerSubcomb: this.pointsPerSubcomb,
      size: this.items.length,
      items: this.items.map(item => item.toJSON())
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert((json.pointsPerAdd >>> 0) === json.pointsPerAdd);
    assert((json.addsPerShift >>> 0) === json.addsPerShift);
    assert((json.shifts >>> 0) === json.shifts);
    assert((json.bitsPerWindow >>> 0) === json.bitsPerWindow);
    assert((json.bits >>> 0) === json.bits);
    assert((json.pointsPerSubcomb >>> 0) === json.pointsPerSubcomb);
    assert((json.size >>> 0) === json.size);
    assert(Array.isArray(json.items));

    this.pointsPerAdd = json.pointsPerAdd;
    this.addsPerShift = json.addsPerShift;
    this.shifts = json.shifts;
    this.bitsPerWindow = json.bitsPerWindow;
    this.bits = json.bits;
    this.pointsPerSubcomb = json.pointsPerSubcomb;

    for (const item of json.items)
      this.items.push(BN.fromJSON(item));

    return this;
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

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

/*
 * Helpers
 */

function isSanePublicKey(key) {
  assert(key && typeof key === 'object');

  const klen = util.countBits(key.n);

  return klen >= constants.MIN_RSA_BITS
      && klen <= constants.MAX_RSA_BITS;
}

function isSanePrivateKey(key) {
  assert(key && typeof key === 'object');

  const plen = util.countBits(key.p);
  const qlen = util.countBits(key.q);

  return plen <= constants.MAX_RSA_BITS
      && qlen <= constants.MAX_RSA_BITS;
}

/*
 * Expose
 */

module.exports = Goo;
