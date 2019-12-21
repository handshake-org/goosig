/* eslint camelcase: "off" */

'use strict';

const rsa = require('bcrypto/lib/rsa');
const rng = require('bcrypto/lib/random');
const SHA256 = require('bcrypto/lib/sha256');
const Goo = require('../lib/js/goo');

const goo = new Goo(Goo.RSA2048, 2, 3, 4096);
const msg = SHA256.digest(rng.randomBytes(32));
const key = rsa.privateKeyGenerate(2048);
const s_prime = goo.generate();
const C1 = goo.challenge(s_prime, key);
const sig = goo.sign(msg, s_prime, key);

const json = [
  msg.toString('hex'),
  sig.toString('hex'),
  C1.toString('hex'),
  true,
  'valid'
];

console.log(JSON.stringify(json, null, 2).replace(/^/gm, '  '));
