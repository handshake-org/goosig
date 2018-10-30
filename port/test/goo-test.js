/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint max-len: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('./util/assert');
const testUtil = require('./util');
const consts = require('../lib/consts');
const GooChallenger = require('../lib/challenge');
const ops = require('../lib/ops');
const GooSigner = require('../lib/sign');
const util = require('../lib/util');
const GooVerifier = require('../lib/verify');
const RSAKey = require('../lib/rsa');

describe('Goo', function() {
  this.timeout(60000);

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
  const gops_c2_2_p = new ops.ClassGroupOps(consts.Ggoo2048, 2048);
  // 2048-bit BQF GoUO, 4096-bit Signer key
  const gops_c2_4_p = new ops.ClassGroupOps(consts.Ggoo2048, 4096);
  // 2048-bit BQF GoUO (verification)
  const gops_c2_v = new ops.ClassGroupOps(consts.Ggoo2048, null);

  // 1024-bit BQF discriminant
  // 1024-bit BQF GoUO, 2048-bit Signer key
  const gops_c1_2_p = new ops.ClassGroupOps(consts.Ggoo1024, 2048);
  // 1024-bit BQF GoUO, 2048-bit Signer key
  const gops_c1_4_p = new ops.ClassGroupOps(consts.Ggoo1024, 4096);
  // 1024-bit BQF GoUO, 4096-bit Signer key
  const gops_c1_v = new ops.ClassGroupOps(consts.Ggoo1024, null);

  // measure times
  const pv_expts = [
    ['4096-bit RSA GoUO, 2048-bit Signer PK', gops_4_2_p, gops_4_v],
    ['4096-bit RSA GoUO, 4096-bit Signer PK', gops_4_4_p, gops_4_v],
    ['2048-bit RSA GoUO, 2048-bit Signer PK', gops_2_2_p, gops_2_v],
    ['2048-bit RSA GoUO, 4096-bit Signer PK', gops_2_4_p, gops_2_v],
    ['2048-bit BQF GoUO, 2048-bit Signer PK', gops_c2_2_p, gops_c2_v],
    ['2048-bit BQF GoUO, 4096-bit Signer PK', gops_c2_4_p, gops_c2_v],
    ['1024-bit BQF GoUO, 2048-bit Signer PK', gops_c1_2_p, gops_c1_v],
    ['1024-bit BQF GoUO, 4096-bit Signer PK', gops_c1_4_p, gops_c1_v]
  ];

  const pv_plsts = [testUtil.primes_1024, testUtil.primes_2048];

  for (const [idx, [msg, gops_p, gops_v]] of pv_expts.entries()) {
    it(`should sign and verify msg: "${msg}"`, () => {
      // random Signer modulus
      const [p, q] = util.rand.sample(pv_plsts[idx % 2], 2);
      const rsakey = new RSAKey(p, q);
      const gen = new GooChallenger(gops_p);
      const prv = new GooSigner(rsakey, gops_p);
      const ver = new GooVerifier(gops_v);

      // generate the challenge token
      const [C0, C1] = gen.create_challenge(rsakey);

      // generate the proof
      const [C2, t, sigma] = prv.sign(C0, C1, msg);

      // verify the proof
      const result = ver.verify([C1, C2, t], msg, sigma);

      assert.strictEqual(result, true);
    });
  }
});
