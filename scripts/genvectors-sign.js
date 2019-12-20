/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const {resolve} = require('path');
const fs = require('fs');
const rsa = require('bcrypto/lib/rsa');
const rng = require('bcrypto/lib/random');
const SHA256 = require('bcrypto/lib/sha256');
const Goo = require('../lib/js/goo');

const goo = new Goo(Goo.RSA2048, 2, 3, 4096);
const vectors = [];

for (const bits of [2048, 4096]) {
  for (let i = 0; i < 5; i++) {
    const msg = SHA256.digest(rng.randomBytes(32));
    const key = rsa.privateKeyGenerate(bits);
    const s_prime = goo.generate();
    const C1 = goo.challenge(s_prime, key);
    const ct = goo.encrypt(s_prime, key);
    const sig = goo.sign(msg, s_prime, key);
    const result = goo.verify(msg, sig, C1);

    assert.strictEqual(result, true);

    vectors.push([
      rsa.privateKeyExport(key).toString('hex'),
      msg.toString('hex'),
      s_prime.toString('hex'),
      C1.toString('hex'),
      ct.toString('hex'),
      sig.toString('hex')
    ]);
  }
}

{
  const path = resolve(__dirname, '..', 'test', 'data', 'sign.json');
  const json = JSON.stringify(vectors, null, 2);

  fs.writeFileSync(path, json + '\n');
}
