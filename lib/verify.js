'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const bm = require('./bigmath');
const {RSAGroupOps} = require('./ops');
const {Grsa2048} = require('./consts');
const Defs = require('./defs');
const prng = require('./prng');

class GooVerifier {
  constructor(gops = null) {
    if (gops == null)
      gops = new RSAGroupOps(Grsa2048, null);
    this.gops = gops;
  }

  verify(pubkey, msg, sigma) {
    assert(Array.isArray(pubkey));
    assert(typeof msg === 'bigint');
    assert(Array.isArray(sigma));
    assert(pubkey.length === 3);
    assert(sigma.length === 7);

    const [C1, C2, t] = pubkey;
    const [chal, ell, Aq, Bq, Cq, Dq, z_prime] = sigma;

    assert(typeof C1 === 'bigint');
    assert(typeof C2 === 'bigint');
    assert(typeof t === 'bigint');
    assert(typeof chal === 'bigint');
    assert(typeof ell === 'bigint');
    assert(typeof Aq === 'bigint');
    assert(typeof Bq === 'bigint');
    assert(typeof Cq === 'bigint');
    assert(typeof Dq === 'bigint');
    assert(Array.isArray(z_prime));
    assert(z_prime.length === 7);

    const [zp_w, zp_w2, zp_s1, zp_a, zp_an, zp_s1w, zp_sa] = z_prime;

    assert(typeof zp_w === 'bigint');
    assert(typeof zp_w2 === 'bigint');
    assert(typeof zp_s1 === 'bigint');
    assert(typeof zp_a === 'bigint');
    assert(typeof zp_an === 'bigint');
    assert(typeof zp_s1w === 'bigint');
    assert(typeof zp_sa === 'bigint');

    // make sure that the public key is valid
    if (Defs.primes.indexOf(t) === -1) {
      // t must be one of the small primes in our list
      return false;
    }

    for (const b of [C1, C2, Aq, Bq, Cq]) {
      if (!this.gops.is_reduced(b)) {
        // all group elements must be the "canonical" element of the quotient group (Z/n)/{1,-1}
        return false;
      }
    }

    // compute inverses of C1, C2, Aq, Bq, Cq
    // NOTE: Since we're inverting C1 and C2, we can get inverses of Aq, Bq, Cq for ~free.
    //     This lets us use signed-digit exponentiation below, which is much faster.
    const [C1Inv, C2Inv, AqInv, BqInv, CqInv] = this.gops.inv5(C1, C2, Aq, Bq, Cq);

    //
    // Step 1: reconstruct A, B, C, and D from signature
    //
    const A = this.gops.reduce(this.gops.mul(this.gops.pow2(Aq, AqInv, ell, C2Inv, C2, chal), this.gops.powgh(zp_w, zp_s1)));
    const B = this.gops.reduce(this.gops.mul(this.gops.pow2(Bq, BqInv, ell, C2Inv, C2, zp_w), this.gops.powgh(zp_w2, zp_s1w)));
    const C = this.gops.reduce(this.gops.mul(this.gops.pow2(Cq, CqInv, ell, C1Inv, C1, zp_a), this.gops.powgh(zp_an, zp_sa)));

    // make sure sign of (zp_w2 - zp_an) is positive
    const zp_w2_m_an = zp_w2 - zp_an;
    const D = Dq * ell + zp_w2_m_an - t * chal;
    if (zp_w2_m_an < 0n)
      D += ell;

    //
    // Step 2: recompute implicitly claimed V message, viz., chal and ell
    //
    const [chal_out, ell_out] = prng.fs_chal(this.gops.desc, C1, C2, t, A, B, C, D, msg);

    // final check
    if (chal !== chal_out || ell !== ell_out)
      return false;

    return true;
  }

  verify_simple(pubkey, msg, sigma) {
    assert(Array.isArray(pubkey));
    assert(typeof msg === 'bigint');
    assert(Array.isArray(sigma));
    assert(pubkey.length === 2);
    assert(sigma.length === 4);

    const [C1, C2] = pubkey;
    const [chal, ell, Aq, z_prime] = sigma;

    assert(typeof C1 === 'bigint');
    assert(typeof C2 === 'bigint');
    assert(typeof chal === 'bigint');
    assert(typeof ell === 'bigint');
    assert(typeof Aq === 'bigint');
    assert(Array.isArray(z_prime));
    assert(z_prime.length === 2);

    const [zp_n, zp_s] = z_prime;

    assert(typeof zp_n === 'bigint');
    assert(typeof zp_s === 'bigint');

    // make sure that the public key and signature include valid group elements
    for (const b of [C1, Aq]) {
      if (!this.gops.is_reduced(b)) {
        // all group elements must be the "canonical" element of the quotient group (Z/n)/{1,-1}
        return false;
      }
    }

    // compute inverses of C1 and Aq
    // NOTE: As above, can get inverse of Aq for free from inverse of C1 and then
    //     use signed-digit exponentiation.
    const [C1Inv, AqInv] = this.gops.inv2(C1, Aq);

    //
    // Step 1: reconstruct A from signature
    //
    const A = this.gops.reduce(this.gops.mul(this.gops.pow2(Aq, AqInv, ell, C1Inv, C1, chal), this.gops.powgh(zp_n, zp_s)));

    //
    // Step 2: recompute implicitly claimed V message, viz., chal and ell
    //
    const [chal_out, ell_out] = prng.fs_chal(this.gops.desc, C1, C2, A, msg);

    // final check
    if (chal !== chal_out || ell !== ell_out)
      return false

    return true
  }
}

module.exports = GooVerifier;
