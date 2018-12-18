/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const SHA256 = require('bcrypto/lib/sha256');
const testUtil = require('./util');
const Goo = require('../');

describe('API', function() {
  this.timeout(60000);

  const tests = [
    ['2048-bit RSA GoUO, 2048-bit Signer PK', Goo.AOL1, 2, 3, 2048],
    ['2048-bit RSA GoUO, 4096-bit Signer PK', Goo.AOL1, 2, 3, 4096],
    ['4096-bit RSA GoUO, 2048-bit Signer PK', Goo.AOL2, 2, 3, 2048],
    ['4096-bit RSA GoUO, 4096-bit Signer PK', Goo.AOL2, 2, 3, 4096],
    ['2048-bit RSA GoUO, 2048-bit Signer PK', Goo.RSA2048, 2, 3, 2048],
    ['2048-bit RSA GoUO, 4096-bit Signer PK', Goo.RSA2048, 2, 3, 4096],
    ['2048-bit RSA GoUO, 2048-bit Signer PK', Goo.RSA617, 2, 3, 2048],
    ['2048-bit RSA GoUO, 4096-bit Signer PK', Goo.RSA617, 2, 3, 4096]
  ];

  for (const [name, n, g, h, bits] of tests) {
    const goo = new Goo(n, g, h);

    it(`should sign and verify msg: "${name}"`, () => {
      const msg = SHA256.digest(Buffer.from(name, 'binary'));

      // Random signer modulus.
      const key = testUtil.genKey(bits);

      // Generate the challenge token.
      const s_prime = goo.generate();
      const C1 = goo.challenge(s_prime, key);

      // Encrypt to the recipient.
      const ct = goo.encrypt(s_prime, key);

      // Recipient decrypts.
      const pt = goo.decrypt(ct, key);

      assert.bufferEqual(pt, s_prime);

      assert(goo.validate(s_prime, C1, key));

      // Generate the proof.
      const sig = goo.sign(msg, s_prime, key);

      // Verify the proof.
      const result = goo.verify(msg, sig, C1);

      assert.strictEqual(result, true);
    });
  }
});
