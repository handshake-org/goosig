/*!
 * prng.js - prng for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

'use strict';

const HmacDRBG = require('bcrypto/lib/hmac-drbg');
const SHA256 = require('bcrypto/lib/sha256');
const constants = require('../internal/constants');
const RNG = require('./rng');

/*
 * PRNG
 */

class PRNG extends RNG {
  constructor(key) {
    super(new HmacDRBG(SHA256, key, constants.DRBG_PERS));
  }
}

/*
 * Expose
 */

module.exports = PRNG;
