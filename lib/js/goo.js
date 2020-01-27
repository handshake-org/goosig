/*!
 * goo.js - groups of unknown order for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
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

'use strict';

const assert = require('bsert');
const BN = require('bcrypto/lib/bn.js');
const rng = require('bcrypto/lib/random');
const SHA256 = require('bcrypto/lib/sha256');
const rsa = require('bcrypto/lib/rsa');
const constants = require('../internal/constants');
const primes = require('./primes');
const PRNG = require('./prng');
const internal = require('../internal/rsa');
const Signature = require('./signature');

/*
 * Goo
 */

class Goo {
  constructor(n, g, h, bits) {
    if (bits == null)
      bits = 0;

    assert(Buffer.isBuffer(n));
    assert((g >>> 0) === g);
    assert((h >>> 0) === h);
    assert((bits >>> 0) === bits);

    this.n = BN.decode(n);
    this.red = BN.red(this.n);
    this.g = new BN(g).toRed(this.red);
    this.h = new BN(h).toRed(this.red);
    this.nh = this.n.ushrn(1);

    this.bits = this.n.bitLength();
    this.size = (this.bits + 7) >>> 3;
    this.randBits = this.bits - 1;

    this.groupHash = SHA256.multi(this.g.fromRed().encode('be', 4),
                                  this.h.fromRed().encode('be', 4),
                                  this.n.encode('be'));

    this.zero = new BN(0).toRed(this.red);
    this.one = new BN(1).toRed(this.red);

    this.wnaf0 = new Int32Array(constants.MAX_RSA_BITS + 1);
    this.wnaf1 = new Int32Array(constants.ELL_BITS + 1);
    this.wnaf2 = new Int32Array(constants.ELL_BITS + 1);
    this.combs = [];

    this.init(bits);
  }

  init(bits) {
    assert((bits >>> 0) === bits);

    if (bits !== 0) {
      if (bits < constants.MIN_RSA_BITS
          || bits > constants.MAX_RSA_BITS) {
        throw new Error('Invalid modulus bits.');
      }

      const big = Math.max(2 * bits, bits + this.randBits);
      const bigBits = big + constants.ELL_BITS + 1;
      const bigSpec = CombSpec.generate(bigBits, constants.MAX_COMB_SIZE);
      const smallBits = this.randBits;
      const smallSpec = CombSpec.generate(smallBits, constants.MAX_COMB_SIZE);

      this.combs = [
        {
          g: new Comb(this.g, smallSpec),
          h: new Comb(this.h, smallSpec)
        },
        {
          g: new Comb(this.g, bigSpec),
          h: new Comb(this.h, bigSpec)
        }
      ];
    } else {
      const tinyBits = constants.ELL_BITS;
      const tinySpec = CombSpec.generate(tinyBits, constants.MAX_COMB_SIZE);

      this.combs = [
        {
          g: new Comb(this.g, tinySpec),
          h: new Comb(this.h, tinySpec)
        }
      ];
    }
  }

  randomScalar(rng) {
    assert(rng instanceof PRNG);

    const bits = Math.min(constants.EXP_BITS, this.randBits);

    return rng.randomBits(bits);
  }

  oneMul(ret, w, p, n) {
    if (w > 0)
      ret = ret.redMul(p[(w - 1) >>> 1]);
    else if (w < 0)
      ret = ret.redMul(n[(-1 - w) >>> 1]);

    return ret;
  }

  precompWNAF(b, bi, winSize) {
    return [
      this.precompTable(b, winSize),
      this.precompTable(bi, winSize)
    ];
  }

  precompTable(b, winSize) {
    assert(BN.isBN(b));
    assert((winSize >>> 0) === winSize);
    assert(winSize >= 2);

    const len = 2 ** (winSize - 2);
    const table = new Array(len);
    const b2 = b.redSqr();

    table[0] = b;

    for (let i = 1; i < len; i++)
      table[i] = table[i - 1].redMul(b2);

    return table;
  }

  wnaf(out, exp, ws, bits) {
    assert(out instanceof Int32Array);
    assert(BN.isBN(exp));
    assert((ws >>> 0) === ws);
    assert((bits >>> 0) === bits);
    assert(bits <= out.length);

    const e = exp.clone();

    for (let i = bits - 1; i >= 0; i--) {
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

    if (b.redIsHigh())
      return b.redNeg();

    return b;
  }

  sqr(b) {
    assert(BN.isBN(b));
    return b.redSqr();
  }

  mul(m1, m2) {
    assert(BN.isBN(m1));
    return m1.redMul(m2);
  }

  powSlow(b, e) {
    // Compute b^e mod n (slowly).
    assert(BN.isBN(b));
    return b.redPow(e);
  }

  pow(b, bi, e) {
    // Compute b^e mod n.
    const ws = constants.WINDOW_SIZE;
    const [p, n] = this.precompWNAF(b, bi, ws);
    const bits = e.bitLength() + 1;

    if (bits > constants.MAX_RSA_BITS + 1)
      throw new Error('Exponent is too large.');

    this.wnaf(this.wnaf0, e, ws, bits);

    let ret = this.one.clone();

    for (let i = 0; i < bits; i++) {
      const w = this.wnaf0[i];

      if (i !== 0)
        ret = ret.redSqr();

      ret = this.oneMul(ret, w, p, n);
    }

    return ret;
  }

  pow2Slow(b1, e1, b2, e2) {
    // Compute b1^e1 * b2^e2 mod n (slowly).
    assert(BN.isBN(b1));
    assert(BN.isBN(b2));

    const q1 = b1.redPow(e1);
    const q2 = b2.redPow(e2);

    return q1.redMul(q2);
  }

  pow2(b1, b1i, e1, b2, b2i, e2) {
    // Compute b1^e1 * b2^e2 mod n.
    const ws = constants.WINDOW_SIZE;
    const [p1, n1] = this.precompWNAF(b1, b1i, ws);
    const [p2, n2] = this.precompWNAF(b2, b2i, ws);
    const bits = Math.max(e1.bitLength(), e2.bitLength()) + 1;

    if (bits > constants.ELL_BITS + 1)
      throw new Error('Exponent is too large.');

    this.wnaf(this.wnaf1, e1, ws, bits);
    this.wnaf(this.wnaf2, e2, ws, bits);

    let ret = this.one.clone();

    for (let i = 0; i < bits; i++) {
      const w1 = this.wnaf1[i];
      const w2 = this.wnaf2[i];

      if (i !== 0)
        ret = ret.redSqr();

      ret = this.oneMul(ret, w1, p1, n1);
      ret = this.oneMul(ret, w2, p2, n2);
    }

    return ret;
  }

  powghSlow(e1, e2) {
    // Compute g^e1 * h*e2 mod n (slowly).
    const q1 = this.g.redPow(e1);
    const q2 = this.h.redPow(e2);
    return q1.redMul(q2);
  }

  powgh(e1, e2) {
    // Compute g^e1 * h*e2 mod n.
    assert(BN.isBN(e1));
    assert(BN.isBN(e2));

    const bits = Math.max(e1.bitLength(), e2.bitLength());

    let gcomb = null;
    let hcomb = null;

    for (const item of this.combs) {
      if (bits <= item.g.bits) {
        gcomb = item.g;
        hcomb = item.h;
        break;
      }
    }

    if (!gcomb || !hcomb)
      throw new Error('Exponent is too large.');

    const E1 = gcomb.recode(e1);
    const E2 = hcomb.recode(e2);

    let ret = this.one.clone();

    for (let i = 0; i < E1.length; i++) {
      const us = E1[i];
      const vs = E2[i];

      if (i !== 0)
        ret = ret.redSqr();

      for (let j = 0; j < us.length; j++) {
        const u = us[j];
        const v = vs[j];

        if (u !== 0) {
          const g = gcomb.items[j * gcomb.pointsPerSubcomb + u - 1];
          ret = ret.redMul(g);
        }

        if (v !== 0) {
          const h = hcomb.items[j * hcomb.pointsPerSubcomb + v - 1];
          ret = ret.redMul(h);
        }
      }
    }

    return ret;
  }

  inv(b) {
    assert(BN.isBN(b));
    return b.redInvert();
  }

  inv2(b1, b2) {
    assert(BN.isBN(b1));
    assert(BN.isBN(b2));

    const b12i = b1.redMul(b2).redInvert();

    return [
      b2.redMul(b12i),
      b1.redMul(b12i)
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
    const b1234567i = b1234567.redInvert();
    const b123456i = b1234567i.redMul(b7);
    const b1234i = b123456i.redMul(b56);
    const b56i = b123456i.redMul(b1234);
    const b34i = b1234i.redMul(b12);
    const b12i = b1234i.redMul(b34);

    return [
      b12i.redMul(b2),
      b12i.redMul(b1),
      b34i.redMul(b4),
      b34i.redMul(b3),
      b56i.redMul(b6),
      b56i.redMul(b5),
      b1234567i.redMul(b123456)
    ];
  }

  recover(b1, b1i, e1, b2, b2i, e2, e3, e4) {
    // Compute b1^e1 * g^e3 * h^e4 / b2^e2 mod n.

    // a = b1^e1 / b2^e2 mod n
    const a = this.pow2(b1, b1i, e1, b2i, b2, e2);

    // b = g^e3 * h^e4 mod n
    const b = this.powgh(e3, e4);

    // r = a * b mod n
    const r = a.redMul(b);

    // r = n - r if r > n / 2
    return this.reduce(r);
  }

  derive(C1, C2, C3, t, A, B, C, D, E, msg) {
    assert(BN.isBN(C1));
    assert(BN.isBN(C2));
    assert(BN.isBN(C3));
    assert(BN.isBN(t));
    assert(BN.isBN(A));
    assert(BN.isBN(B));
    assert(BN.isBN(C));
    assert(BN.isBN(D));
    assert(BN.isBN(E));
    assert(Buffer.isBuffer(msg));

    const ctx = new SHA256();

    ctx.init();
    ctx.update(constants.HASH_PREFIX);
    ctx.update(this.groupHash);
    ctx.update(C1.fromRed().encode('be', this.size));
    ctx.update(C2.fromRed().encode('be', this.size));
    ctx.update(C3.fromRed().encode('be', this.size));
    ctx.update(t.encode('be', 4));
    ctx.update(A.fromRed().encode('be', this.size));
    ctx.update(B.fromRed().encode('be', this.size));
    ctx.update(C.fromRed().encode('be', this.size));
    ctx.update(D.fromRed().encode('be', this.size));
    ctx.update(E.encode('be', constants.EXP_BYTES));
    ctx.update(Buffer.from([0, 0, 0, E.isNeg() ? 1 : 0]));
    ctx.update(msg);

    const key = ctx.final();
    const prng = new PRNG(key, constants.PRNG_DERIVE);
    const chal = prng.randomBits(constants.CHAL_BITS);
    const ell = prng.randomBits(constants.ELL_BITS);

    return [chal, ell, key];
  }

  expandSprime(s_prime) {
    const prng = new PRNG(s_prime, constants.PRNG_EXPAND);
    return prng.randomBits(constants.EXP_BITS);
  }

  generate() {
    return this.constructor.generate();
  }

  challenge(s_prime, key) {
    assert(Buffer.isBuffer(s_prime));
    assert(Buffer.isBuffer(key));

    if (s_prime.length !== 32)
      throw new Error('Invalid seed length.');

    const k = rsa.publicKeyExport(key);
    const n = BN.decode(k.n);
    const C1 = this._challenge(s_prime, n);

    return C1.encode('be', this.size);
  }

  _challenge(s_prime, n) {
    const bits = n.bitLength();

    if (bits < constants.MIN_RSA_BITS
        || bits > constants.MAX_RSA_BITS) {
      throw new Error('Invalid RSA public key.');
    }

    // Commit to the RSA modulus:
    //   C1 = g^n * h^s in G
    const s = this.expandSprime(s_prime);
    const C1 = this.reduce(this.powgh(n, s));

    return C1.fromRed();
  }

  encrypt(msg, key, size) {
    return this.constructor.encrypt(msg, key, size);
  }

  decrypt(ct, key, size) {
    return this.constructor.decrypt(ct, key, size);
  }

  validate(s_prime, C1, key) {
    assert(Buffer.isBuffer(s_prime));
    assert(Buffer.isBuffer(C1));
    assert(Buffer.isBuffer(key));

    if (s_prime.length !== 32)
      return false;

    if (C1.length !== this.size)
      return false;

    let k;
    try {
      k = rsa.privateKeyExport(key);
    } catch (e) {
      return false;
    }

    const C = BN.decode(C1);
    const p = BN.decode(k.p);
    const q = BN.decode(k.q);

    try {
      return this._validate(s_prime, C, p, q);
    } catch (e) {
      return false;
    }
  }

  _validate(s_prime, C1, p, q) {
    const n = p.mul(q);
    const bits = n.bitLength();

    if (bits < constants.MIN_RSA_BITS
        || bits > constants.MAX_RSA_BITS) {
      return false;
    }

    if (C1.cmp(this.nh) > 0)
      return false;

    // Validate the private key with:
    //   n = p * q
    //   x = g^n * h^s in G
    //   C1 == x
    const s = this.expandSprime(s_prime);
    const x = this.reduce(this.powgh(n, s));

    return C1.eq(x.fromRed());
  }

  sign(msg, s_prime, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(s_prime));
    assert(Buffer.isBuffer(key));

    if (s_prime.length !== 32)
      throw new Error('Invalid s_prime length.');

    const k = rsa.privateKeyExport(key);
    const p = BN.decode(k.p);
    const q = BN.decode(k.q);
    const S = this._sign(msg, s_prime, p, q);

    return S.encode(this.bits);
  }

  _sign(msg, s_prime, p, q) {
    const n = p.mul(q);
    const bits = n.bitLength();

    if (bits < constants.MIN_RSA_BITS
        || bits > constants.MAX_RSA_BITS) {
      throw new Error('Invalid RSA private key.');
    }

    // Seed the PRNG using the primes and message as entropy.
    const rng = PRNG.fromSign(p, q, s_prime, msg);

    // Find a small quadratic residue prime `t`.
    const smalls = [...primes.smallPrimes];

    let w = null;
    let t = null;

    for (let i = 0; i < smalls.length; i++) {
      // Fisher-Yates shuffle to choose random `t`.
      const j = rng.randomNum(smalls.length - i);

      [smalls[i], smalls[i + j]] = [smalls[i + j], smalls[i]];

      // w = t^(1 / 2) in F(p * q)
      try {
        t = new BN(smalls[i]);
        w = t.sqrtpq(p, q);
      } catch (e) {
        continue;
      }

      break;
    }

    if (w == null)
      throw new Error('No prime quadratic residue less than `1000 mod n`!');

    assert(w.sign() > 0);

    // a = (w^2 - t) / n
    const a = w.sqr().isub(t).div(n);

    assert(a.sign() >= 0);

    // `w` and `a` must satisfy `w^2 = t + a * n`.
    if (a.mul(n).cmp(w.sqr().isub(t)) !== 0)
      throw new Error('`w^2 - t` was not divisible by `n`!');

    // Commit to `n`, `w`, and `a` with:
    //
    //   C1 = g^n * h^s in G
    //   C2 = g^w * h^s1 in G
    //   C3 = g^a * h^s2 in G
    //
    // Where `s`, `s1`, and `s2` are
    // random 2048-bit integers.
    const s = this.expandSprime(s_prime);
    const C1 = this.reduce(this.powgh(n, s));
    const s1 = this.randomScalar(rng);
    const C2 = this.reduce(this.powgh(w, s1));
    const s2 = this.randomScalar(rng);
    const C3 = this.reduce(this.powgh(a, s2));

    // Inverses of `C1` and `C2`.
    const [C1i, C2i] = this.inv2(C1, C2);

    // Eight random 2048-bit integers:
    //   r_w, r_w2, r_s1, r_a, r_an, r_s1w, r_sa, r_s2
    const r_w = this.randomScalar(rng);
    const r_w2 = this.randomScalar(rng);
    const r_a = this.randomScalar(rng);
    const r_an = this.randomScalar(rng);
    const r_s1w = this.randomScalar(rng);
    const r_sa = this.randomScalar(rng);
    const r_s2 = this.randomScalar(rng);

    // Compute:
    //
    //   A = g^r_w * h^r_s1 in G
    //   B = g^r_a * h^r_s2 in G
    //   C = g^r_w2 * h^r_s1w / C2^r_w in G
    //   D = g^r_an * h^r_sa / C1^r_a in G
    //   E = r_w2 - r_an
    //
    // `A` must be recomputed until a prime
    // `ell` is found within range.
    const B = this.reduce(this.powgh(r_a, r_s2));
    const C = this.reduce(this.mul(this.pow(C2i, C2, r_w),
                                   this.powgh(r_w2, r_s1w)));
    const D = this.reduce(this.mul(this.pow(C1i, C1, r_a),
                                   this.powgh(r_an, r_sa)));
    const E = r_w2.sub(r_an);

    let ell = new BN(0);
    let r_s1, A, chal, key;

    while (ell.bitLength() !== constants.ELL_BITS) {
      r_s1 = this.randomScalar(rng);
      A = this.reduce(this.powgh(r_w, r_s1));
      [chal, ell, key] = this.derive(C1, C2, C3, t, A, B, C, D, E, msg);
      ell = primes.nextPrime(ell, key, constants.ELLDIFF_MAX);
    }

    // Compute the integer vector `z`:
    //
    //   z_w = chal * w + r_w
    //   z_w2 = chal * w^2 + r_w2
    //   z_s1 = chal * s1 + r_s1
    //   z_a = chal * a + r_a
    //   z_an = chal * a * n + r_an
    //   z_s1w = chal * s1 * w + r_s1w
    //   z_sa = chal * s * a + r_sa
    //   z_s2 = chal * s2 + r_s2
    const z_w = chal.mul(w).iadd(r_w);
    const z_w2 = chal.mul(w).imul(w).iadd(r_w2);
    const z_s1 = chal.mul(s1).iadd(r_s1);
    const z_a = chal.mul(a).iadd(r_a);
    const z_an = chal.mul(a).imul(n).iadd(r_an);
    const z_s1w = chal.mul(s1).imul(w).iadd(r_s1w);
    const z_sa = chal.mul(s).imul(a).iadd(r_sa);
    const z_s2 = chal.mul(s2).iadd(r_s2);

    // Compute quotient commitments:
    //
    //   Aq = g^(z_w / ell) * h^(z_s1  / ell) in G
    //   Bq = g^(z_a / ell) * h^(z_s2  / ell) in G
    //   Cq = g^(z_w2 / ell) * h^(z_s1w / ell) / C2^(z_w / ell) in G
    //   Dq = g^(z_an / ell) * h^(z_sa  / ell) / C1^(z_a / ell) in G
    //   Eq = (z_w2 - z_an) / ell
    const Aq = this.reduce(this.powgh(z_w.div(ell), z_s1.div(ell)));
    const Bq = this.reduce(this.powgh(z_a.div(ell), z_s2.div(ell)));
    const Cq = this.reduce(this.mul(this.pow(C2i, C2, z_w.div(ell)),
                                    this.powgh(z_w2.div(ell), z_s1w.div(ell))));
    const Dq = this.reduce(this.mul(this.pow(C1i, C1, z_a.div(ell)),
                                    this.powgh(z_an.div(ell), z_sa.div(ell))));
    const Eq = z_w2.sub(z_an).div(ell);

    assert(Eq.bitLength() <= constants.EXP_BITS);

    // Compute `z' = (z mod ell)`.
    z_w.imod(ell);
    z_w2.imod(ell);
    z_s1.imod(ell);
    z_a.imod(ell);
    z_an.imod(ell);
    z_s1w.imod(ell);
    z_sa.imod(ell);
    z_s2.imod(ell);

    // S = (C2, C3, t, chal, ell, Aq, Bq, Cq, Dq, Eq, z')
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
                           z_w,
                           z_w2,
                           z_s1,
                           z_a,
                           z_an,
                           z_s1w,
                           z_sa,
                           z_s2 });
  }

  verify(msg, sig, C1) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(C1));

    if (C1.length !== this.size)
      return false;

    let S;
    try {
      S = Signature.decode(sig, this.bits);
    } catch (e) {
      return false;
    }

    const C = BN.decode(C1);

    try {
      return this._verify(msg, S, C);
    } catch (e) {
      return false;
    }
  }

  _verify(msg, S, C1) {
    assert(Buffer.isBuffer(msg));
    assert(S instanceof Signature);
    assert(BN.isBN(C1));

    let {C2, C3, t, chal, ell, Aq, Bq, Cq, Dq, Eq,
         z_w, z_w2, z_s1, z_a, z_an, z_s1w, z_sa, z_s2} = S;

    // `t` must be one of the small primes in our list.
    if (!primes.smallPrimes.includes(t.toNumber()))
      throw new Error('Invalid small prime.');

    // `chal` must be in range.
    if (chal.bitLength() > constants.CHAL_BITS)
      throw new Error('Invalid chal value.');

    // `ell` must be in range.
    if (ell.isZero() || ell.bitLength() > constants.ELL_BITS)
      throw new Error('Invalid ell value.');

    // All group elements must be the canonical
    // element of the quotient group (Z/n)/{1,-1}.
    if (C1.cmp(this.nh) > 0
        || C2.cmp(this.nh) > 0
        || C3.cmp(this.nh) > 0
        || Aq.cmp(this.nh) > 0
        || Bq.cmp(this.nh) > 0
        || Cq.cmp(this.nh) > 0
        || Dq.cmp(this.nh) > 0) {
      throw new Error('Non-reduced parameters.');
    }

    // `Eq` must be in range.
    if (Eq.bitLength() > constants.EXP_BITS)
      throw new Error('Invalid Eq value.');

    // `z'` must be within range.
    if (z_w.cmp(ell) >= 0
        || z_w2.cmp(ell) >= 0
        || z_s1.cmp(ell) >= 0
        || z_a.cmp(ell) >= 0
        || z_an.cmp(ell) >= 0
        || z_s1w.cmp(ell) >= 0
        || z_sa.cmp(ell) >= 0
        || z_s2.cmp(ell) >= 0) {
      throw new Error('Invalid z_prime value.');
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
    const [C1i, C2i, C3i, Aqi, Bqi, Cqi, Dqi] =
      this.inv7(C1, C2, C3, Aq, Bq, Cq, Dq);

    // Reconstruct A, B, C, D, and E from signature:
    //
    //   A = Aq^ell * g^z_w * h^z_s1 / C2^chal in G
    //   B = Bq^ell * g^z_a * h^z_s2 / C3^chal in G
    //   C = Cq^ell * g^z_w2 * h^z_s1w / C2^z_w in G
    //   D = Dq^ell * g^z_an * h^z_sa / C1^z_a in G
    //   E = Eq * ell + ((z_w2 - z_an) mod ell) - t * chal
    const A = this.recover(Aq, Aqi, ell, C2, C2i, chal, z_w, z_s1);
    const B = this.recover(Bq, Bqi, ell, C3, C3i, chal, z_a, z_s2);
    const C = this.recover(Cq, Cqi, ell, C2, C2i, z_w, z_w2, z_s1w);
    const D = this.recover(Dq, Dqi, ell, C1, C1i, z_a, z_an, z_sa);
    const E = Eq.mul(ell).iadd(z_w2.sub(z_an).imod(ell)).isub(t.mul(chal));

    // Recompute `chal` and `ell`.
    const [chal0, ell0, key] = this.derive(C1, C2, C3, t, A, B, C, D, E, msg);

    // `chal` must be equal to the computed value.
    if (chal.cmp(chal0) !== 0)
      throw new Error('Invalid chal value.');

    // `ell` must be in the interval [ell',ell'+512].
    const ell1 = ell0.addn(constants.ELLDIFF_MAX);

    if (ell.cmp(ell0) < 0 || ell.cmp(ell1) > 0)
      throw new Error('Invalid ell value (out of range).');

    // `ell` must be prime.
    if (!primes.isPrime(ell, key))
      throw new Error('Invalid ell value (composite).');

    return true;
  }

  toJSON() {
    return {
      n: this.n.toJSON(),
      nh: this.nh.toJSON(),
      g: this.g.fromRed().toNumber(),
      h: this.h.fromRed().toNumber(),
      combs: this.combs.map((combs) => {
        return {
          g: combs.g.toJSON(),
          h: combs.h.toJSON()
        };
      })
    };
  }

  static generate() {
    // Hash to mitigate any kind of backtracking
    // that may be possible with the global RNG.
    return SHA256.multi(constants.PRNG_GENERATE, rng.randomBytes(32));
  }

  static encrypt(msg, key, size) {
    return internal.encrypt(msg, key, size);
  }

  static decrypt(ct, key, size) {
    return internal.decrypt(ct, key, size);
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
  constructor(base, spec) {
    this.pointsPerAdd = 0;
    this.addsPerShift = 0;
    this.shifts = 0;
    this.bitsPerWindow = 0;
    this.bits = 0;
    this.pointsPerSubcomb = 0;
    this.size = 0;
    this.items = [];
    this.wins = [];

    if (base != null)
      this.init(base, spec);
  }

  init(base, spec) {
    assert(BN.isBN(base));
    assert(spec instanceof CombSpec);
    assert(spec.pointsPerAdd < 32);

    this.pointsPerAdd = spec.pointsPerAdd;
    this.addsPerShift = spec.addsPerShift;
    this.shifts = spec.shifts;
    this.bitsPerWindow = spec.bitsPerWindow;
    this.bits = spec.bitsPerWindow * spec.pointsPerAdd;
    this.pointsPerSubcomb = (1 << spec.pointsPerAdd) - 1;
    this.size = spec.size;
    this.items = new Array(this.size);
    this.wins = new Array(this.shifts);

    for (let i = 0; i < this.size; i++)
      this.items[i] = new BN(0);

    for (let i = 0; i < this.shifts; i++)
      this.wins[i] = new Int32Array(this.addsPerShift);

    this.items[0] = base.clone();

    const win = BN.shift(1, this.bitsPerWindow);

    for (let i = 1; i < this.pointsPerAdd; i++) {
      const x = 1 << i;
      const y = x >>> 1;

      this.items[x - 1] = this.items[y - 1].redPow(win);

      for (let j = x + 1; j < 2 * x; j++)
        this.items[j - 1] = this.items[j - x - 1].redMul(this.items[x - 1]);
    }

    const pow = BN.shift(1, this.shifts);

    for (let i = 1; i < this.addsPerShift; i++) {
      for (let j = 0; j < this.pointsPerSubcomb; j++) {
        const k = i * this.pointsPerSubcomb + j;

        this.items[k] = this.items[k - this.pointsPerSubcomb].redPow(pow);
      }
    }
  }

  recode(e) {
    assert(BN.isBN(e));

    for (let i = this.addsPerShift - 1; i >= 0; i--) {
      for (let j = 0; j < this.shifts; j++) {
        let ret = 0;

        for (let k = 0; k < this.pointsPerAdd; k++) {
          const b = (i + k * this.addsPerShift) * this.shifts + j;

          ret <<= 1;
          ret |= e.testn((this.bits - 1) - b);
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
      size: this.size,
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
    assert(Array.isArray(json.items));

    this.pointsPerAdd = json.pointsPerAdd;
    this.addsPerShift = json.addsPerShift;
    this.shifts = json.shifts;
    this.bitsPerWindow = json.bitsPerWindow;
    this.bits = json.bits;
    this.pointsPerSubcomb = json.pointsPerSubcomb;
    this.size = json.items.length;

    for (const item of json.items)
      this.items.push(BN.fromJSON(item));

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

/*
 * CombSpec
 */

class CombSpec {
  constructor(ppa, aps, shifts, bpw, size) {
    this.pointsPerAdd = ppa;
    this.addsPerShift = aps;
    this.shifts = shifts;
    this.bitsPerWindow = bpw;
    this.size = size;
  }

  toJSON() {
    return {
      pointsPerAdd: this.pointsPerAdd,
      addsPerShift: this.addsPerShift,
      shifts: this.shifts,
      bitsPerWindow: this.bitsPerWindow,
      size: this.size
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert((json.pointsPerAdd >>> 0) === json.pointsPerAdd);
    assert((json.addsPerShift >>> 0) === json.addsPerShift);
    assert((json.shifts >>> 0) === json.shifts);
    assert((json.bitsPerWindow >>> 0) === json.bitsPerWindow);
    assert((json.size >>> 0) === json.size);

    this.pointsPerAdd = json.pointsPerAdd;
    this.addsPerShift = json.addsPerShift;
    this.shifts = json.shifts;
    this.bitsPerWindow = json.bitsPerWindow;
    this.size = json.size;

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  static generate(bits, maxSize) {
    assert((bits >>> 0) === bits);
    assert((maxSize >>> 0) === maxSize);
    assert(bits > 0 && maxSize > 0);

    const specs = new Map();

    const generate = (shifts, aps, ppa, bpw) => {
      const ops = shifts * (aps + 1) - 1;
      const size = (2 ** ppa - 1) * aps;
      const best = specs.get(ops);

      assert(ops >= 0);

      if (best == null || best.size > size) {
        const spec = new this(ppa, aps, shifts, bpw, size);

        specs.set(ops, spec);
      }
    };

    for (let ppa = 2; ppa < 18; ppa++) {
      const bpw = ((bits + ppa - 1) / ppa) >>> 0;
      const sqrt = Math.sqrt(bpw) >>> 0;

      for (let aps = 1; aps < sqrt + 2; aps++) {
        if ((bpw % aps) !== 0)
          continue;

        const shifts = (bpw / aps) >>> 0;

        assert(shifts > 0);

        generate(shifts, aps, ppa, bpw);
        generate(aps, shifts, ppa, bpw);
      }
    }

    const keys = [];

    for (const key of specs.keys())
      keys.push(key);

    keys.sort((a, b) => a - b);

    let sm = -1 >>> 0;

    for (const ops of keys) {
      const spec = specs.get(ops);

      if (sm <= spec.size)
        continue;

      sm = spec.size;

      if (sm <= maxSize)
        return spec;
    }

    throw new Error('Could not calculate comb.');
  }
}

/*
 * Expose
 */

module.exports = Goo;
