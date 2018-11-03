/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('./util/assert');
const rsa = require('bcrypto/lib/rsa');
const SHA256 = require('bcrypto/lib/sha256');
const testUtil = require('./util');
const JS = require('../lib/js/goo');
const Native = require('../lib/native/goo');
const Signature = require('../lib/js/signature');
const vectors = require('./data/vectors.json');

function runTests(name, Goo, Other) {
  describe(name, function() {
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

    const sigs = [];

    for (const [i, [name, n, g, h, bits]] of tests.entries()) {
      it(`should sign and verify msg: "${name}"`, () => {
        const prover = new Goo(n, g, h, bits);
        const verifier = new Goo(n, g, h, null);

        const msg = SHA256.digest(Buffer.from(name, 'binary'));

        // Random signer modulus.
        const key = testUtil.genKey(bits);

        // Generate the challenge token.
        let [s_prime, C1] = prover.challenge(key);

        // Encrypt to the recipient.
        const ct = prover.encrypt(s_prime, C1, key);

        // Recipient decrypts.
        [s_prime, C1] = prover.decrypt(ct, key);

        // Generate the proof.
        const sig = prover.sign(msg, s_prime, C1, key);

        sigs.push([n, g, h, msg, sig, C1]);

        // Verify the proof.
        const result = verifier.verify(msg, sig, C1);

        assert.strictEqual(result, true);
      });
    }

    it('should verify with opposite implementation', () => {
      for (const [n, g, h, msg, sig, C1] of sigs) {
        const goo = new Other(n, g, h, null);
        const result = goo.verify(msg, sig, C1);
        assert.strictEqual(result, true);
      }
    });

    for (const vector of vectors) {
      const name = vector.group;
      const group = Goo[vector.group];
      const groupBits = vector.groupBits;
      const g = vector.g;
      const h = vector.h;
      const bits = vector.bits;
      const key = rsa.privateKeyImportJWK(vector.key);
      const msg = Buffer.from(vector.msg, 'hex');
      const s_prime = Buffer.from(vector.s_prime, 'hex');
      const C1 = Buffer.from(vector.C1, 'hex');
      const ct = Buffer.from(vector.ct, 'hex');
      const sig = Signature.fromJSON(vector.sig).encode(groupBits);
      const str = `${groupBits}-bit RSA GoUO, ${bits}-bit Signer PK (${name})`;

      it(`should verify vector: ${str}`, () => {
        const goo = new Goo(group, g, h, null);
        const result = goo.verify(msg, sig, C1);

        assert.strictEqual(result, true);

        const [s_prime2, C12] = goo.decrypt(ct, key);

        assert.bufferEqual(s_prime2, s_prime);
        assert.bufferEqual(C12, C1);
      });

      it(`should not accept invalid proof: ${str}`, () => {
        const goo = new Goo(group, g, h, null);
        const sig2 = Buffer.from(sig);
        const C12 = Buffer.from(C1);
        const i = (Math.random() * sig2.length) | 0;
        const j = (Math.random() * C12.length) | 0;

        let res1, res2;

        sig2[i] ^= 1;
        res1 = goo.verify(msg, sig2, C12);
        sig2[i] ^= 1;

        assert.strictEqual(res1, false);

        C12[j] ^= 1;
        res2 = goo.verify(msg, sig2, C12);
        C12[j] ^= 1;

        assert.strictEqual(res2, false);
      });
    }
  });
}

runTests('Goo', JS, Native);
runTests('Goo (Native)', Native, JS);
