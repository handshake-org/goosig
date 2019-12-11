/*!
 * goo.js - groups of unknown order for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Parts of this software are based on kwantam/libGooPy:
 *   Copyright (c) 2018, Dan Boneh, Riad S. Wahby (Apache License).
 *   https://github.com/kwantam/GooSig
 */

/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const binding = require('./binding');
const constants = require('../internal/constants');
const rsa = require('../internal/rsa');

/*
 * Goo
 */

class Goo extends binding.Goo {
  constructor(n, g, h, modBits) {
    super(n, g, h, modBits);
    this.bits = countBits(n);
    this.size = (this.bits + 7) >>> 3;
  }

  generate() {
    return super.generate();
  }

  challenge(s_prime, key) {
    assert(key && typeof key === 'object');
    return super.challenge(s_prime, key.n);
  }

  encrypt(msg, key, size) {
    return rsa.encrypt(msg, key, size);
  }

  decrypt(ct, key, size) {
    return rsa.decrypt(ct, key, size);
  }

  validate(s_prime, C1, key) {
    assert(key && typeof key === 'object');
    return super.validate(s_prime, C1, key.p, key.q);
  }

  sign(msg, s_prime, key) {
    assert(key && typeof key === 'object');
    return super.sign(msg, s_prime, key.p, key.q);
  }

  verify(msg, sig, C1) {
    return super.verify(msg, sig, C1);
  }

  static encrypt(msg, key, size) {
    return rsa.encrypt(msg, key, size);
  }

  static decrypt(ct, key, size) {
    return rsa.decrypt(ct, key, size);
  }
}

/*
 * Static
 */

Goo.native = 2;
Goo.AOL1 = constants.AOL1;
Goo.AOL2 = constants.AOL2;
Goo.RSA2048 = constants.RSA2048;
Goo.RSA617 = constants.RSA617;

/*
 * Helpers
 */

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
