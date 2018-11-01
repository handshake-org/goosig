'use strict';

/* eslint camelcase: "off" */

const assert = require('bsert');
const goosig = require('bindings')('goosig');
const constants = require('./constants');

/*
 * Goo
 */

class Goo extends goosig.Goo {
  constructor(n, g, h, modBits) {
    super(n, g, h, modBits);
  }

  challenge(key) {
    assert(key && typeof key === 'object');
    return super.challenge(key.n);
  }

  sign(msg, s_prime, C1, key) {
    assert(key && typeof key === 'object');

    return super.sign(msg,
                      s_prime,
                      C1,
                      key.n,
                      key.p,
                      key.q);
  }

  verify(msg, sig, C1) {
    return super.verify(msg, sig, C1);
  }
}

/*
 * Static
 */

Goo.AOL = constants.AOL;
Goo.RSA617 = constants.RSA617;
Goo.RSA2048 = constants.RSA2048;
Goo.DEFAULT_G = constants.DEFAULT_G;
Goo.DEFAULT_H = constants.DEFAULT_H;
Goo.MAX_RSA_BITS = constants.MAX_RSA_BITS;
Goo.EXPONENT_SIZE = constants.EXPONENT_SIZE;
Goo.WINDOW_SIZE = constants.WINDOW_SIZE;
Goo.MAX_COMB_SIZE = constants.MAX_COMB_SIZE;
Goo.CHAL_BITS = constants.CHAL_BITS;
Goo.ELLDIFF_MAX = constants.ELLDIFF_MAX;
Goo.HASH_PREFIX = constants.HASH_PREFIX;
Goo.DRBG_PERS = constants.DRBG_PERS;
Goo.DRBG_NONCE = constants.DRBG_NONCE;

/*
 * Expose
 */

module.exports = Goo;
