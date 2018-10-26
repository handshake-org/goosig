/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint max-len: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('./util/assert');
const random = require('bcrypto/lib/random');
const testUtil = require('./util');
const BigMath = require('../lib/bigmath');
const consts = require('../lib/consts');
const ops = require('../lib/ops');
const GooSigner = require('../lib/sign');
const util = require('../lib/util');
const {HashPRNG} = require('../lib/prng');
const GooVerifier = require('../lib/verify');
const {bitLength} = BigMath;

describe('Goo', function() {
  this.timeout(20000);

  // reuse Gops throughout. Notice that you can reuse gops for different
  // Signer modulus as long as the *size* of the Signer's modulus is no
  // larger than the one the gops object was built for.

  // 4096-bit GoUO
  // 4096-bit RSA GoUO, 2048-bit Signer key
  const gops_4_2_p = new ops.RSAGroupOps(consts.Gaol, 2048);
  // 4096-bit RSA GoUO, 4096-bit Signer key
  const gops_4_4_p = new ops.RSAGroupOps(consts.Gaol, 4096);
  // 4096-bit RSA GoUO (verification)
  const gops_4_v = new ops.RSAGroupOps(consts.Gaol, null);

  // 2048-bit GoUO
  // 2048-bit RSA GoUO, 2048-bit Signer key
  const gops_2_2_p = new ops.RSAGroupOps(consts.Grsa2048, 2048);
  // 2048-bit RSA GoUO, 4096-bit Signer key
  const gops_2_4_p = new ops.RSAGroupOps(consts.Grsa2048, 4096);
  // 2048-bit RSA GoUO (verification)
  const gops_2_v = new ops.RSAGroupOps(consts.Grsa2048, null);

  // 2048-bit BQF discriminant
  // 2048-bit BQF GoUO, 2048-bit Signer key
  // const gops_c2_2_p = new ops.ClassGroupOps(consts.Ggoo2048, 2048);
  // 2048-bit BQF GoUO, 4096-bit Signer key
  // const gops_c2_4_p = new ops.ClassGroupOps(consts.Ggoo2048, 4096);
  // 2048-bit BQF GoUO (verification)
  // const gops_c2_v = new ops.ClassGroupOps(consts.Ggoo2048, null);

  // 1024-bit BQF discriminant
  // 1024-bit BQF GoUO, 2048-bit Signer key
  // const gops_c1_2_p = new ops.ClassGroupOps(consts.Ggoo1024, 2048);
  // 1024-bit BQF GoUO, 2048-bit Signer key
  // const gops_c1_4_p = new ops.ClassGroupOps(consts.Ggoo1024, 4096);
  // 1024-bit BQF GoUO, 4096-bit Signer key
  // const gops_c1_v = new ops.ClassGroupOps(consts.Ggoo1024, null);

  // measure times
  const pv_expts = [
    ['4096-bit RSA GoUO, 2048-bit Signer PK', gops_4_2_p, gops_4_v],
    ['4096-bit RSA GoUO, 4096-bit Signer PK', gops_4_4_p, gops_4_v],
    ['2048-bit RSA GoUO, 2048-bit Signer PK', gops_2_2_p, gops_2_v],
    ['2048-bit RSA GoUO, 4096-bit Signer PK', gops_2_4_p, gops_2_v]
    // ['2048-bit BQF GoUO, 2048-bit Signer PK', gops_c2_2_p, gops_c2_v],
    // ['2048-bit BQF GoUO, 4096-bit Signer PK', gops_c2_4_p, gops_c2_v],
    // ['1024-bit BQF GoUO, 2048-bit Signer PK', gops_c1_2_p, gops_c1_v],
    // ['1024-bit BQF GoUO, 4096-bit Signer PK', gops_c1_4_p, gops_c1_v]
  ];

  const pv_plsts = [testUtil.primes_1024, testUtil.primes_2048];
  const rand = new HashPRNG(random.randomBytes(32));

  for (const [idx, [msg, gops_p, gops_v]] of pv_expts.entries()) {
    it(`should sign and verify msg: "${msg}"`, () => {
      // random Signer modulus
      const [p, q] = rand.sample(pv_plsts[idx % 2], 2);
      const prv = new GooSigner(p, q, gops_p);
      const ver = new GooVerifier(gops_v);

      // run the 'complex' proof
      // commit to Signer modulus
      const s = prv.gops.rand_scalar();
      const C1 = prv.gops.reduce(prv.gops.powgh(p * q, s));

      // generate the proof
      const [C2, t, sigma] = prv.sign(C1, s, msg);

      // verify the proof
      const result = ver.verify([C1, C2, t], msg, sigma);

      assert.strictEqual(result, true);
    });

    it(`should sign and verify msg (simple): "${msg}"`, () => {
      // random Signer modulus
      const [p, q] = rand.sample(pv_plsts[idx % 2], 2);
      const prv = new GooSigner(p, q, gops_p);
      const ver = new GooVerifier(gops_v);

      // run the 'simple' proof
      // commit to Signer modulus and encrypt s to PK
      const s_simple = rand.getrandbits(bitLength(prv.n) - 1);
      const C1_simple = prv.gops.reduce(prv.gops.powgh(p * q, s_simple));
      const C2_simple = prv.encrypt(s_simple);

      // generate the proof
      const sigma_simple = prv.sign_simple(C1_simple, C2_simple, msg);

      // verify the proof
      const result = ver.verify_simple([C1_simple, C2_simple], msg, sigma_simple);

      assert.strictEqual(result, true);
    });
  }
});
