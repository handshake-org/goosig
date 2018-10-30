'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const BigMath = require('./bigmath');
const {Grsa2048} = require('./consts');
const defs = require('./defs');
const ops = require('./ops');
const prng = require('./prng');
const util = require('./util');
const {umod, decode} = BigMath;

class GooChallenger {
  constructor(gops) {
    if (gops == null)
      gops = new ops.RSAGroupOps(Grsa2048, defs.max_rsa_keysize);
    this.gops = gops;
  }

  create_challenge(rsapubkey) {
    assert(rsapubkey && typeof rsapubkey.n === 'bigint');

    // NOTE: in the real protocol, select a 256-bit s' and expand to 2048-bit s,
    //       e.g., with AESEnc(s', 0), ..., AESEnc(s', 3)
    const s_prime = util.rand.getrandbits(256);
    const s = prng.expand_sprime(s_prime);

    // the challenge: a commitment to the RSA modulus
    const C1 = this.gops.reduce(this.gops.powgh(rsapubkey.n, s));
    const hC1 = decode(prng.hash_all(C1));

    // (Hash(C1) || s_prime), encrypted to the pubkey
    const C0_pre = rsapubkey.encrypt((hC1 << 256n) | s_prime);

    // make a ciphertext C0 indistinguishable from a random (max_rsa_keysize + 8)-bit integer
    const ct_lim = 1n << (BigInt(defs.max_rsa_keysize) + 8n);
    // ceiling of (ct_lim - C0_pre) / rsapubkey.n, ensuring C0_pre + rsapubkey.n * r_lim >= ct_lim
    const r_lim = (ct_lim - C0_pre + rsapubkey.n - 1n) / rsapubkey.n;

    let C0 = ct_lim;

    while (C0 >= ct_lim) {
      const c0_rand = util.rand.randint(0n, r_lim); // NOTE randint returns in [0, r_lim]

      C0 = C0_pre + c0_rand * rsapubkey.n;
    }

    assert(umod(C0, rsapubkey.n) === C0_pre);

    return [C0, C1];
  }
}

module.exports = GooChallenger;
