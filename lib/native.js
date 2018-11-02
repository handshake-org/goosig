'use strict';

/* eslint camelcase: "off" */

const assert = require('bsert');
const goosig = require('bindings')('goosig');
const constants = require('./constants');
const rsa = require('./rsa');

/*
 * Goo
 */

class Goo extends goosig.Goo {
  constructor(n, g, h, modBits) {
    super(n, g, h, modBits);
    this.bits = countBits(n);
  }

  challenge(key) {
    if (!isSanePublicKey(key))
      throw new Error('Invalid RSA public key.');

    return super.challenge(key.n);
  }

  encrypt(s_prime, C1, key) {
    return rsa.encrypt(s_prime, C1, key, this.bits);
  }

  decrypt(ct, key) {
    return rsa.decrypt(ct, key, this.bits);
  }

  sign(msg, s_prime, C1, key) {
    if (!isSanePublicKey(key))
      throw new Error('Invalid RSA private key.');

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

  static encrypt(s_prime, C1, key, bits) {
    return rsa.encrypt(s_prime, C1, key, bits);
  }

  static decrypt(ct, key, bits) {
    return rsa.decrypt(ct, key, bits);
  }
}

/*
 * Static
 */

Goo.AOL1 = constants.AOL1;
Goo.AOL2 = constants.AOL2;
Goo.RSA2048 = constants.RSA2048;
Goo.RSA617 = constants.RSA617;
Goo.DEFAULT_G = constants.DEFAULT_G;
Goo.DEFAULT_H = constants.DEFAULT_H;
Goo.MIN_RSA_BITS = constants.MIN_RSA_BITS;
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
 * Helpers
 */

function isSanePublicKey(key) {
  assert(key && typeof key === 'object');
  assert(typeof key.bits === 'function');

  const klen = key.bits();

  return klen >= constants.MIN_RSA_BITS
      && klen <= constants.MAX_RSA_BITS;
}

function countBits(buf) {
  assert(Buffer.isBuffer(buf));

  let i = 0;

  for (; i < buf.length; i++) {
    if (buf[i] !== 0x00)
      break;
  }

  let bits = (buf.length - i) * 8;

  if (bits === 0)
    return 0;

  bits -= 8;

  let oct = buf[i];

  while (oct) {
    bits += 1;
    oct >>>= 1;
  }

  return bits;
}

/*
 * Expose
 */

module.exports = Goo;
