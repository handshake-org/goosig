/*!
 * rsa.js - RSA IES for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const rsaies = require('bcrypto/lib/rsaies');
const SHA256 = require('bcrypto/lib/sha256');

/*
 * RSA
 */

function encrypt(s_prime, C1, key, bits) {
  assert(Buffer.isBuffer(s_prime));
  assert(s_prime.length === 32);
  assert(Buffer.isBuffer(C1));
  assert((bits >>> 0) === bits);
  assert(C1.length === (bits + 7) >>> 3);

  const msg = Buffer.concat([s_prime, C1]);

  return rsaies.encrypt(SHA256, msg, key, 4096);
}

function decrypt(ct, key, bits) {
  assert((bits >>> 0) === bits);

  const msg = rsaies.decrypt(SHA256, ct, key, 4096);
  const bytes = (bits + 7) >>> 3;

  if (msg.length !== 32 + bytes)
    throw new Error('Invalid ciphertext.');

  const s_prime = msg.slice(0, 32);
  const C1 = msg.slice(32);

  return [s_prime, C1];
}

/*
 * Expose
 */

exports.encrypt = encrypt;
exports.decrypt = decrypt;
