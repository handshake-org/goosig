'use strict';

/* eslint camelcase: "off" */

const SHA256 = require('bcrypto/lib/sha256');
const DRBG = require('bcrypto/lib/drbg');
const constants = require('./constants');
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
