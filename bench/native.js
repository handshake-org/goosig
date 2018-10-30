/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint max-len: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('../test/util/assert');
const testUtil = require('../test/util');
const Goo = require('../lib/goo');
const Native = require('../lib/native');

const gops_p = new Goo(Goo.RSA2048, 2, 3, 2048);
const gops_v = new Goo(Goo.RSA2048, 2, 3, null);
const native = new Native(Goo.RSA2048, 2, 3, null);

const msg = Buffer.from('2048-bit RSA GoUO, 2048-bit Signer PK');
const [p, q] = testUtil.sample(testUtil.primes1024, 2);
const key = testUtil.rsaKey(p, q);

// Generate the challenge token.
const [s_prime, C1] = gops_p.challenge(key);

// Generate the proof.
const sig = gops_v.sign(msg, s_prime, C1, key);

// Verify the proof.
const result = gops_v.verify(msg, sig, C1);

assert.strictEqual(result, true);

let start, i;

start = Date.now();

for (i = 0; i < 1000; i++) {
  const result = gops_v.verify(msg, sig, C1);
  assert.strictEqual(result, true);
}

console.log((Date.now() - start) / i);

start = Date.now();

for (i = 0; i < 1000; i++) {
  const result = native.verify(msg, sig, C1);
  assert.strictEqual(result, true);
}

console.log((Date.now() - start) / i);
