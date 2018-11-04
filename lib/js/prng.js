/*!
 * prng.js - prng for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

'use strict';

const SHA256 = require('bcrypto/lib/sha256');
const DRBG = require('bcrypto/lib/drbg');
const constants = require('../internal/constants');
const RNG = require('./rng');

/*
 * PRNG
 */

class PRNG extends RNG {
  constructor(key) {
    super(new DRBG(SHA256, key, constants.DRBG_NONCE, constants.DRBG_PERS));
  }
}

/*
 * Expose
 */

module.exports = PRNG;
