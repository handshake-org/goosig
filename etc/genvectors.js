/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const Path = require('path');
const fs = require('fs');
const rsa = require('bcrypto/lib/rsa');
const random = require('bcrypto/lib/random');
const SHA256 = require('bcrypto/lib/sha256');
const JS = require('../lib/js/goo');
const Native = require('../lib/native/goo');
const Signature = require('../lib/js/signature');

const vectors = [];

for (const Goo of [JS, Native]) {
  const moduli = [
    ['AOL1', Goo.AOL1],
    ['AOL2', Goo.AOL2],
    ['RSA2048', Goo.RSA2048],
    ['RSA617', Goo.RSA617]
  ];

  const sizes = [
    1024,
    2048,
    4096
  ];

  const gh = [
    [2, 3],
    [5, 7]
  ];

  for (const [name, modulus] of moduli) {
    for (const [g, h] of gh) {
      const ver = new Goo(modulus, g, h, null);

      for (const bits of sizes) {
        const goo = new Goo(modulus, g, h, bits);

        console.log('Generating 5 vectors for %s.', name);
        console.log('  g=%d, h=%d, bits=%d', g, h, bits);

        for (let i = 0; i < 5; i++) {
          const msg = SHA256.digest(random.randomBytes(32));
          const key = rsa.privateKeyGenerate(bits);
          const s_prime = goo.generate();
          const C1 = goo.challenge(s_prime, key);
          const ct = goo.encrypt(s_prime, key);
          const sig = goo.sign(msg, s_prime, key);
          const result = ver.verify(msg, sig, C1);

          assert.strictEqual(result, true);

          vectors.push({
            group: name,
            groupBits: goo.bits,
            g: g,
            h: h,
            bits: bits,
            key: rsa.privateKeyExportJWK(key),
            msg: msg.toString('hex'),
            s_prime: s_prime.toString('hex'),
            C1: C1.toString('hex'),
            ct: ct.toString('hex'),
            sig: Signature.decode(sig, goo.bits).toJSON(),
            original: false,
            native: Goo.native ? true : false
          });
        }
      }
    }
  }
}

{
  const path = Path.resolve(__dirname, '..',
                            'test', 'data',
                            'vectors.json');

  const json = JSON.stringify(vectors, null, 2);

  fs.writeFileSync(path, json + '\n');
}
