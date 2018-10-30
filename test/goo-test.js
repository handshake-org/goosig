/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('./util/assert');
const testUtil = require('./util');
const Goo = require('../lib/goo');

describe('Goo', function() {
  this.timeout(60000);

  // 4096-bit GoUO
  // 4096-bit RSA GoUO, 2048-bit Signer key
  const gops_4_2_p = new Goo(Goo.AOL, 2, 3, 2048);
  // 4096-bit RSA GoUO, 4096-bit Signer key
  const gops_4_4_p = new Goo(Goo.AOL, 2, 3, 4096);
  // 4096-bit RSA GoUO (verification)
  const gops_4_v = new Goo(Goo.AOL, 2, 3, null);

  // 2048-bit GoUO
  // 2048-bit RSA GoUO, 2048-bit Signer key
  const gops_2_2_p = new Goo(Goo.RSA2048, 2, 3, 2048);
  // 2048-bit RSA GoUO, 4096-bit Signer key
  const gops_2_4_p = new Goo(Goo.RSA2048, 2, 3, 4096);
  // 2048-bit RSA GoUO (verification)
  const gops_2_v = new Goo(Goo.RSA2048, 2, 3, null);

  // measure times
  const tests = [
    ['4096-bit RSA GoUO, 2048-bit Signer PK', gops_4_2_p, gops_4_v],
    ['4096-bit RSA GoUO, 4096-bit Signer PK', gops_4_4_p, gops_4_v],
    ['2048-bit RSA GoUO, 2048-bit Signer PK', gops_2_2_p, gops_2_v],
    ['2048-bit RSA GoUO, 4096-bit Signer PK', gops_2_4_p, gops_2_v]
  ];

  const primes = [testUtil.primes1024, testUtil.primes2048];

  for (const [i, [name, gops_p, gops_v]] of tests.entries()) {
    it(`should sign and verify msg: "${name}"`, () => {
      const msg = Buffer.from(name, 'binary');

      // Random signer modulus.
      const [p, q] = testUtil.sample(primes[i % 2], 2);
      const key = testUtil.rsaKey(p, q);

      // Generate the challenge token.
      const [s_prime, C1] = gops_p.challenge(key);

      // Generate the proof.
      const sig = gops_v.sign(msg, s_prime, C1, key);

      // Verify the proof.
      const result = gops_v.verify(msg, sig, C1);

      assert.strictEqual(result, true);
    });
  }
});
