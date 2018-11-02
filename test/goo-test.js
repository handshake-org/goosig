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

    // 4096-bit GoUO
    // 4096-bit RSA GoUO, 2048-bit Signer key
    const gops_4_2_p = () => new Goo(Goo.AOL2, 2, 3, 2048);
    // 4096-bit RSA GoUO, 4096-bit Signer key
    const gops_4_4_p = () => new Goo(Goo.AOL2, 2, 3, 4096);
    // 4096-bit RSA GoUO (verification)
    const gops_4_v = () => new Goo(Goo.AOL2, 2, 3, null);

    // 2048-bit GoUO
    // 2048-bit RSA GoUO, 2048-bit Signer key
    const gops_2_2_p = () => new Goo(Goo.RSA2048, 2, 3, 2048);
    // 2048-bit RSA GoUO, 4096-bit Signer key
    const gops_2_4_p = () => new Goo(Goo.RSA2048, 2, 3, 4096);
    // 2048-bit RSA GoUO (verification)
    const gops_2_v = () => new Goo(Goo.RSA2048, 2, 3, null);

    const tests = [
      ['4096-bit RSA GoUO, 2048-bit Signer PK', gops_4_2_p, gops_4_v],
      ['4096-bit RSA GoUO, 4096-bit Signer PK', gops_4_4_p, gops_4_v],
      ['2048-bit RSA GoUO, 2048-bit Signer PK', gops_2_2_p, gops_2_v],
      ['2048-bit RSA GoUO, 4096-bit Signer PK', gops_2_4_p, gops_2_v]
    ];

    const primes = [testUtil.primes1024, testUtil.primes2048];

    const created = [];

    for (const [i, [name, gops_p_, gops_v_]] of tests.entries()) {
      it(`should sign and verify msg: "${name}"`, () => {
        const gops_p = gops_p_();
        const gops_v = gops_v_();

        const msg = SHA256.digest(Buffer.from(name, 'binary'));

        // Random signer modulus.
        const [p, q] = testUtil.sample(primes[i % 2], 2);
        const key = testUtil.rsaKey(p, q);

        // Generate the challenge token.
        let [s_prime, C1] = gops_p.challenge(key);

        // Encrypt to the recipient.
        const ct = gops_p.encrypt(s_prime, C1, key);

        // Recipient decrypts.
        [s_prime, C1] = gops_p.decrypt(ct, key);

        // Generate the proof.
        const sig = gops_p.sign(msg, s_prime, C1, key);

        created.push([msg, sig, C1]);

        // Verify the proof.
        const result = gops_v.verify(msg, sig, C1);

        assert.strictEqual(result, true);
      });
    }

    it('should verify with opposite implementation', () => {
      // Native 4096 bit
      const other_4_v = new Other(Goo.AOL2, 2, 3, null);
      // Native 2048 bit
      const other_2_v = new Other(Goo.RSA2048, 2, 3, null);

      for (let i = 0; i < created.length; i++) {
        const group = i < 2 ? other_4_v : other_2_v;
        const [msg, sig, C1] = created[i];
        const result = group.verify(msg, sig, C1);
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
