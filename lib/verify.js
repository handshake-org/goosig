'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const BigMath = require('./bigmath');
const {RSAGroupOps} = require('./ops');
const {Grsa2048} = require('./consts');
const defs = require('./defs');
const primes = require('./primes');
const prng = require('./prng');
const {decode} = BigMath;

class GooVerifier {
  constructor(gops = null) {
    if (gops == null)
      gops = new RSAGroupOps(Grsa2048, null);
    this.gops = gops;
  }

  verify(pubkey, msg, sigma) {
    if (typeof msg === 'string')
      msg = Buffer.from(msg, 'binary');

    if (Buffer.isBuffer(msg))
      msg = decode(msg);

    assert(Array.isArray(pubkey));
    assert(typeof msg === 'bigint');
    assert(Array.isArray(sigma));
    assert(pubkey.length === 3);
    assert(sigma.length === 7);

    const [C1, C2, t] = pubkey;
    const [chal, ell, Aq, Bq, Cq, Dq, z_prime] = sigma;

    assert(this.gops.is_element(C1));
    assert(this.gops.is_element(C2));
    assert(typeof t === 'bigint');
    assert(typeof chal === 'bigint');
    assert(typeof ell === 'bigint');
    assert(this.gops.is_element(Aq));
    assert(this.gops.is_element(Bq));
    assert(this.gops.is_element(Cq));
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
    if (defs.primes.indexOf(t) === -1) {
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

    let D = Dq * ell + zp_w2_m_an - t * chal;

    if (zp_w2_m_an < 0n)
      D += ell;

    //
    // Step 2: recompute implicitly claimed V message, viz., chal and ell
    //
    const [chal_out, ell_r_out] = prng.fs_chal(true, this.gops.desc, C1, C2, t, A, B, C, D, msg);

    // final checks
    // chal has to match AND 0 <= (ell_r_out - ell) <= elldiff_max AND ell is prime
    const elldiff = ell - ell_r_out;

    if (chal !== chal_out || elldiff < 0n || elldiff > defs.elldiff_max || !primes.is_prime(ell))
      return false;

    return true;
  }
}

module.exports = GooVerifier;
