'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const bm = require('./bigmath');
const {RSAGroupOps} = require('./ops');
const {Grsa2048} = require('./consts');
const Defs = require('./defs');
const primes = require('./primes');
const prng = require('./prng');
const util = require('./util');

class GooSigner {
  constructor(p, q, gops = null) {
    assert(typeof p === 'bigint');
    assert(typeof q === 'bigint');
    assert(gops == null || typeof gops.powgh === 'function');

    this.p = p;
    this.q = q;
    this.n = this.p * this.q;

    // encryption and decryption with Signer's key
    this.lam = (p - 1n) * (q - 1n) / util.gcd(p - 1n, q - 1n);

    for (const e of primes.primes_skip(1)) {
      if (e > 1000n)
        throw new Error('cannot find suitable secret key');

      const d = util.invert_modp(e, this.lam);

      if (d != null) {
        this.e = e;
        this.d = d;
        break;
      }
    }

    assert((this.d * this.e) % this.lam === 1n);

    if (gops == null) {
      const modbits = util.clog2(p) + util.clog2(q);
      gops = new RSAGroupOps(Grsa2048, modbits);
    }

    this.gops = gops;

    assert(primes.is_prime(p));
    assert(primes.is_prime(q));
  }

  encrypt(m) {
    //  NOTE this is not real RSA encryption! You should use RSA-OAEP or the like.
    return bm.modPow(m, this.e, this.n);
  }

  decrypt(c) {
    //  NOTE this is not real RSA decryption! You should use RSA-OAEP or the like.
    return bm.modPow(c, this.d, this.n);
  }

  sign(C1, s, msg) {
    assert(typeof C1 === 'bigint');
    assert(typeof s === 'bigint');
    assert(typeof msg === 'bigint');

    //  NOTE one assumes that s will have been encrypted to our public key.
    //     This function expects that s has already been decrypted.
    assert(C1 == this.gops.reduce(this.gops.powgh(this.n, s)),
          'C1 does not appear to commit to our RSA modulus with opening s');

    //
    //  Preliminaries: compute values P needs to run the ZKPOK
    //
    //  find t
    let t = null;

    for (const t of Defs.primes) {
      const w = util.sqrt_modn(t, this.p, this.q)
      if (w != null)
        break
    }

    if (w == null || t == null)
      throw new Error('did not find a prime quadratic residue less than 1000 mod N!');

    const a = (w ** 2n - t) / this.n;
    assert(a * this.n == w ** 2n - t, 'w^2 - t was not divisible by N!');

    //  commitment to w
    const s1 = this.gops.rand_scalar();
    const C2 = this.gops.reduce(this.gops.powgh(w, s1));

    //  inverses of C1 and C2
    const [C1Inv, C2Inv] = this.gops.inv2(C1, C2);

    //
    //  P's first message: commit to randomness
    //
    //  P's randomness
    const [r_w, r_w2, r_s1, r_a, r_an, r_s1w, r_sa] = [
      this.gops.rand_scalar(),
      this.gops.rand_scalar(),
      this.gops.rand_scalar(),
      this.gops.rand_scalar(),
      this.gops.rand_scalar(),
      this.gops.rand_scalar(),
      this.gops.rand_scalar()
    ];

    //  P's first message
    const A = this.gops.reduce(this.gops.powgh(r_w, r_s1));
    const B = this.gops.reduce(this.gops.mul(this.gops.pow(C2Inv, C2, r_w), this.gops.powgh(r_w2, r_s1w)));
    const C = this.gops.reduce(this.gops.mul(this.gops.pow(C1Inv, C1, r_a), this.gops.powgh(r_an, r_sa)));
    const D = r_w2 - r_an;

    //
    //  V's message: random challenge and random prime
    //
    const [chal, ell] = prng.fs_chal(this.gops.desc, C1, C2, t, A, B, C, D, msg);

    //
    //  P's second message: compute quotient message
    //
    //  compute z' = c*(w, w2, s1, a, an, s1w, sa) + (r_w, r_w2, r_s1, r_a, r_an, r_s1w, r_sa)
    const z_w = chal * w + r_w;
    const z_w2 = chal * w * w + r_w2;
    const z_s1 = chal * s1 + r_s1;
    const z_a = chal * a + r_a;
    const z_an = chal * a * this.n + r_an;
    const z_s1w = chal * s1 * w + r_s1w;
    const z_sa = chal * s * a + r_sa;

    //  compute quotient commitments
    const Aq = this.gops.reduce(this.gops.powgh(z_w / ell, z_s1 / ell));
    const Bq = this.gops.reduce(this.gops.mul(this.gops.pow(C2Inv, C2, z_w / ell), this.gops.powgh(z_w2 / ell, z_s1w / ell)));
    const Cq = this.gops.reduce(this.gops.mul(this.gops.pow(C1Inv, C2, z_a / ell), this.gops.powgh(z_an / ell, z_sa / ell)));
    const Dq = (z_w2 - z_an) / ell;

    //  compute z'
    const z_prime = [];

    for (const z_foo of [z_w, z_w2, z_s1, z_a, z_an, z_s1w, z_sa])
      z_prime.push(z_foo % ell);

    //
    //  signature: (chal, ell, Aq, Bq, Cq, Dq, z_prime)
    //
    const sigma = [chal, ell, Aq, Bq, Cq, Dq, z_prime];

    return [C2, t, sigma];
  }

  sign_simple(C1, C2, msg) {
    assert(typeof C1 === 'bigint');
    assert(typeof C2 === 'bigint');
    assert(typeof msg === 'bigint');

    //
    //  Preliminaries
    //
    //  decrypt C2 to get s
    const s = this.decrypt(C2);
    assert(C1 == this.gops.reduce(this.gops.powgh(this.n, s)),
          'C1 does not appear to commit to our RSA modulus with opening s');

    //
    //  P's first message: commit to randomness
    //
    //  P's randomness
    const [r_n, r_s] = [
      this.gops.rand_scalar(),
      this.gops.rand_scalar()
    ];

    //  P's first message
    const A = this.gops.reduce(this.gops.powgh(r_n, r_s));

    //
    //  V's message: random challenge and random prime
    //
    const [chal, ell] = prng.fs_chal(this.gops.desc, C1, C2, A, msg);

    //
    //  P's second message: compute quotient message
    //
    //  compute z' = c*(n, s) + (r_n, r_s)
    const z_n = chal * this.n + r_n;
    const z_s = chal * s + r_s;

    //  compute quotient commitments
    const Aq = this.gops.reduce(this.gops.powgh(z_n / ell, z_s / ell));

    //  compute z'
    const z_prime = [
      z_n % ell,
      z_s % ell
    ];

    //
    //  signature: (chal, ell, Aq, z_prime)
    //
    return [chal, ell, Aq, z_prime];
  }
}

module.exports = GooSigner;
