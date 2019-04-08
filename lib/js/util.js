/*!
 * util.js - utils for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Parts of this software are based on kwantam/libGooPy:
 *   Copyright (c) 2018, Dan Boneh, Riad S. Wahby (Apache License).
 *   https://github.com/kwantam/GooSig
 *
 * Resources:
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/util.py
 */

/* eslint valid-typeof: "off" */

'use strict';

const assert = require('bsert');
const BN = require('bcrypto/lib/bn.js');
const rng = require('bcrypto/lib/random');

/*
 * Util
 */

const util = {
  randomBits(bits) {
    return BN.randomBits(rng, bits);
  },

  randomBitsNZ(bits) {
    assert(bits !== 0);

    let num = null;

    do {
      num = BN.randomBits(rng, bits);
    } while (num.isZero());

    return num;
  },

  randomInt(max) {
    return BN.random(rng, 0, max);
  },

  randomNum(num) {
    return rng.randomRange(0, num);
  },

  dsqrt(n) {
    assert((n >>> 0) === n);
    return BN.from(n).isqrt().toNumber();
  },

  countBits(buf) {
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
};

/*
 * Expose
 */

module.exports = util;
