/*!
 * rsa.js - RSA IES for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const rsa = require('bcrypto/lib/rsa');
const SHA256 = require('bcrypto/lib/sha256');
const {MAX_RSA_BITS} = require('./constants');

/*
 * RSA
 */

function encrypt(msg, pub) {
  assert(Buffer.isBuffer(msg));
  assert(msg.length === 32);

  const ct0 = rsa.encryptOAEP(SHA256, msg, pub, null);

  return rsa.veil(ct0, MAX_RSA_BITS, pub);
}

function decrypt(ct, priv) {
  const ct0 = rsa.unveil(ct, MAX_RSA_BITS, priv);
  const msg = rsa.decryptOAEP(SHA256, ct0, priv, null);

  if (msg.length !== 32)
    throw new Error('Invalid ciphertext.');

  return msg;
}

/*
 * Expose
 */

exports.encrypt = encrypt;
exports.decrypt = decrypt;
