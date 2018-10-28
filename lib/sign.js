'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const BigMath = require('./bigmath');
const {RSAGroupOps} = require('./ops');
const {Grsa2048} = require('./consts');
const defs = require('./defs');
const prng = require('./prng');
const RSAKey = require('./rsa');
const util = require('./util');
const {umod, decode, bitLength} = BigMath;

class GooSigner {
  constructor(key, gops = null) {
    assert(key instanceof RSAKey);
    assert(gops == null || typeof gops.powgh === 'function');

    if (gops == null) {
      const modbits = util.clog2(key.n);
      gops = new RSAGroupOps(Grsa2048, modbits);
    }

    this.key = key;
    this.gops = gops;
  }

  sign(C0, C1, msg) {
    if (typeof msg === 'string')
      msg = Buffer.from(msg, 'binary');

    if (Buffer.isBuffer(msg))
      msg = decode(msg);

    assert(typeof C0 === 'bigint');
    assert(this.gops.is_element(C1));
    assert(typeof msg === 'bigint');

    const C0dec = this.key.decrypt(C0);
    const s_prime = C0dec & ((1n << 256n) - 1n);
    const hC1 = C0dec >> 256n;
    const s = prng.expand_sprime(s_prime);

    assert(this.gops.equals(C1, this.gops.reduce(this.gops.powgh(this.key.n, s))),
          'C1 does not appear to commit to our RSA modulus with opening s');
    assert(hC1 === decode(prng.hash_all(C1)));

    //
    //  Preliminaries: compute values P needs to run the ZKPOK
    //
    //  find t
    let w = null;
    let t = null;

    for (t of defs.primes) {
      w = util.sqrt_modn(t, this.key.p, this.key.q);
      if (w != null)
        break;
    }

    if (w == null || t == null)
      throw new Error('did not find a prime quadratic residue less than 1000 mod N!');

    const a = (w ** 2n - t) / this.key.n;
    assert(a * this.key.n === w ** 2n - t, 'w^2 - t was not divisible by N!');

    //  commitment to w
    const s1 = this.gops.rand_scalar();
    const C2 = this.gops.reduce(this.gops.powgh(w, s1));

    //  inverses of C1 and C2
    const [C1Inv, C2Inv] = this.gops.inv2(C1, C2);

    //
    //  P's first message: commit to randomness
    //
    //  P's randomness (except for r_s1; see "V's message", below)
    let [r_w, r_w2, r_a, r_an, r_s1w, r_sa] = [
      this.gops.rand_scalar(),
      this.gops.rand_scalar(),
      this.gops.rand_scalar(),
      this.gops.rand_scalar(),
      this.gops.rand_scalar(),
      this.gops.rand_scalar()
    ];

    // Prevent D from being negative
    if (r_w2 < r_an)
      [r_w2, r_an] = [r_an, r_w2];

    //  P's first message (except for A; see "V's message", below)
    const B = this.gops.reduce(this.gops.mul(this.gops.pow(C2Inv, C2, r_w), this.gops.powgh(r_w2, r_s1w)));
    const C = this.gops.reduce(this.gops.mul(this.gops.pow(C1Inv, C1, r_a), this.gops.powgh(r_an, r_sa)));
    const D = r_w2 - r_an;

    //
    //  V's message: random challenge and random prime
    //
    let chal = null;
    let ell = null;
    let r_s1, A;

    while (ell == null || bitLength(ell) !== 128) {
      // randomize the signature until Fiat-Shamir returns an admissable ell
      // NOTE it's not necessary to re-start the whole signature!
      //      Just pick a new r_s1, which only requires re-computing A.
      r_s1 = this.gops.rand_scalar();
      A = this.gops.reduce(this.gops.powgh(r_w, r_s1));
      [chal, ell] = prng.fs_chal(false, this.gops.desc, C1, C2, t, A, B, C, D, msg);
    }

    //
    //  P's second message: compute quotient message
    //
    //  compute z' = c*(w, w2, s1, a, an, s1w, sa) + (r_w, r_w2, r_s1, r_a, r_an, r_s1w, r_sa)
    const z_w = chal * w + r_w;
    const z_w2 = chal * w * w + r_w2;
    const z_s1 = chal * s1 + r_s1;
    const z_a = chal * a + r_a;
    const z_an = chal * a * this.key.n + r_an;
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
      z_prime.push(umod(z_foo, ell));

    //
    //  signature: (chal, ell, Aq, Bq, Cq, Dq, z_prime)
    //
    const sigma = [chal, ell, Aq, Bq, Cq, Dq, z_prime];

    return [C2, t, sigma];
  }
}

module.exports = GooSigner;
