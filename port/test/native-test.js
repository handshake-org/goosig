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
const NativeGooVerifier = require('../lib/native');
const RSAKey = require('../lib/rsa');

describe('Goo', function() {
  this.timeout(60000);

  // 2048-bit GoUO
  // 2048-bit RSA GoUO, 2048-bit Signer key
  const gops_2_2_p = new ops.RSAGroupOps(consts.Grsa2048, 2048);
  // 2048-bit RSA GoUO, 4096-bit Signer key
  const gops_2_4_p = new ops.RSAGroupOps(consts.Grsa2048, 4096);
  // 2048-bit RSA GoUO (verification)
  const gops_2_v = new ops.RSAGroupOps(consts.Grsa2048, null);

  const native = new NativeGooVerifier(consts.Grsa2048);

  // measure times
  const pv_expts = [
    ['2048-bit RSA GoUO, 2048-bit Signer PK', gops_2_2_p, gops_2_v],
    ['2048-bit RSA GoUO, 4096-bit Signer PK', gops_2_4_p, gops_2_v]
  ];

  const pv_plsts = [testUtil.primes_1024, testUtil.primes_2048];

  const vectors = [];

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

      vectors.push([C1, C2, t, msg, sigma]);

      assert.strictEqual(result, true);
    });
  }

  it('should verify with native interface', () => {
    for (const [C1, C2, t, msg, sigma] of vectors) {
      const result = native.verify([C1, C2, t], msg, sigma);

      assert.strictEqual(result, true);
    }
  });
});
