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

function encrypt(msg, pub, size = 32) {
  assert(Buffer.isBuffer(msg));
  assert((size >>> 0) === size);
  assert(msg.length === size);

  const ct0 = rsa.encryptOAEP(SHA256, msg, pub, null);

  return rsa.veil(ct0, MAX_RSA_BITS + 8, pub);
}

function decrypt(ct, priv, size = 32) {
  assert((size >>> 0) === size);

  const pub = rsa.publicKeyCreate(priv);
  const ct0 = rsa.unveil(ct, MAX_RSA_BITS + 8, pub);
  const msg = rsa.decryptOAEP(SHA256, ct0, priv, null);

  if (msg.length !== size)
    throw new Error('Invalid ciphertext.');

  return msg;
}

/*
 * Expose
 */

exports.encrypt = encrypt;
exports.decrypt = decrypt;
