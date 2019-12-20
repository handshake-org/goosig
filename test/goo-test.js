/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const rng = require('bcrypto/lib/random');
const rsa = require('bcrypto/lib/rsa');
const SHA256 = require('bcrypto/lib/sha256');
const util = require('./util');
const Goo = require('../');
const verify = require('./data/verify.json');
const sign = require('./data/sign.json');

describe('Goo', function() {
  describe('Protocol', () => {
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
      it(`should sign and verify msg: "${name}"`, () => {
        const goo = new Goo(n, g, h, bits);
        const ver = new Goo(n, g, h);
        const msg = Buffer.from(name, 'binary');
        const key = util.genKey(bits);

        // Generate the challenge token.
        const s_prime = goo.generate();
        const C1 = goo.challenge(s_prime, key);

        // Encrypt to the recipient.
        const ct = goo.encrypt(s_prime, key);

        // Recipient decrypts.
        assert.bufferEqual(goo.decrypt(ct, key), s_prime);

        // Validate key.
        assert(goo.validate(s_prime, C1, key));

        // Generate the proof.
        const sig = goo.sign(msg, s_prime, key);

        // Verify the proof.
        assert.strictEqual(ver.verify(msg, sig, C1), true);

        // Ensure our RNG isn't broken.
        assert.notBufferEqual(s_prime, Buffer.alloc(32, 0x00));
      });
    }
  });

  describe('Verify', () => {
    const goo = new Goo(Goo.RSA2048, 2, 3);

    for (const [i, item] of verify.entries()) {
      const msg = Buffer.from(item[0], 'hex');
      const sig = Buffer.from(item[1], 'hex');
      const C1 = Buffer.from(item[2], 'hex');
      const comment = item[3];

      it(`should verify vector #${i + 1} (${comment})`, () => {
        assert.strictEqual(goo.verify(msg, sig, C1), comment === 'valid');
      });
    }
  });

  describe('Sign', () => {
    const goo = new Goo(Goo.RSA2048, 2, 3, 4096);
    const ver = new Goo(Goo.RSA2048, 2, 3);

    for (const [i, item] of sign.entries()) {
      const key = rsa.privateKeyImport(Buffer.from(item[0], 'hex'));
      const msg = Buffer.from(item[1], 'hex');
      const s_prime = Buffer.from(item[2], 'hex');
      const C1 = Buffer.from(item[3], 'hex');
      const ct = Buffer.from(item[4], 'hex');
      const sig = Buffer.from(item[5], 'hex');

      it(`should sign & verify vector #${i + 1}`, () => {
        assert.bufferEqual(goo.challenge(s_prime, key), C1);
        assert.bufferEqual(goo.sign(msg, s_prime, key), sig);
        assert.bufferEqual(goo.decrypt(ct, key), s_prime);
        assert.strictEqual(goo.verify(msg, sig, C1), true);
        assert.strictEqual(ver.verify(msg, sig, C1), true);
      });

      it(`should not accept invalid proof for #${i + 1}`, () => {
        const i = rng.randomRange(0, msg.length);
        const j = rng.randomRange(0, sig.length);
        const k = rng.randomRange(0, C1.length);
        const a = rng.randomRange(0, 8);
        const b = rng.randomRange(0, 8);
        const c = rng.randomRange(0, 8);

        // Flip some bits.
        msg[i] ^= 1 << a;

        assert.strictEqual(goo.verify(msg, sig, C1), false);
        assert.strictEqual(ver.verify(msg, sig, C1), false);

        msg[i] ^= 1 << a;

        sig[j] ^= 1 << b;

        assert.strictEqual(goo.verify(msg, sig, C1), false);
        assert.strictEqual(ver.verify(msg, sig, C1), false);

        sig[j] ^= 1 << b;

        C1[k] ^= 1 << c;

        assert.strictEqual(goo.verify(msg, sig, C1), false);
        assert.strictEqual(ver.verify(msg, sig, C1), false);

        C1[k] ^= 1 << c;

        // Truncate
        assert.strictEqual(goo.verify(msg.slice(0, -1), sig, C1), false);
        assert.strictEqual(ver.verify(msg.slice(0, -1), sig, C1), false);

        assert.strictEqual(goo.verify(msg, sig.slice(0, -1), C1), false);
        assert.strictEqual(ver.verify(msg, sig.slice(0, -1), C1), false);

        assert.strictEqual(goo.verify(msg, sig, C1.slice(0, -1)), false);
        assert.strictEqual(ver.verify(msg, sig, C1.slice(0, -1)), false);

        // Extend
        const concat = (buf) => {
          const ch = rng.randomRange(0, 0x100);
          const byte = Buffer.from([ch]);

          return Buffer.concat([buf, byte]);
        };

        assert.strictEqual(goo.verify(concat(msg), sig, C1), false);
        assert.strictEqual(ver.verify(concat(msg), sig, C1), false);

        assert.strictEqual(goo.verify(msg, concat(sig), C1), false);
        assert.strictEqual(ver.verify(msg, concat(sig), C1), false);

        assert.strictEqual(goo.verify(msg, sig, concat(C1)), false);
        assert.strictEqual(ver.verify(msg, sig, concat(C1)), false);

        // Empty
        assert.strictEqual(goo.verify(Buffer.alloc(0), sig, C1), false);
        assert.strictEqual(ver.verify(Buffer.alloc(0), sig, C1), false);

        assert.strictEqual(goo.verify(msg, Buffer.alloc(0), C1), false);
        assert.strictEqual(ver.verify(msg, Buffer.alloc(0), C1), false);

        assert.strictEqual(goo.verify(msg, sig, Buffer.alloc(0)), false);
        assert.strictEqual(ver.verify(msg, sig, Buffer.alloc(0)), false);

        // Ensure we're still valid.
        assert.strictEqual(goo.verify(msg, sig, C1), true);
        assert.strictEqual(ver.verify(msg, sig, C1), true);
      });
    }
  });
});
