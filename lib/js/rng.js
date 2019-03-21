/*!
 * rng.js - rng for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Parts of this software are based on kwantam/libGooPy:
 *   Copyright (c) 2018, Dan Boneh, Riad S. Wahby (Apache License).
 *   https://github.com/kwantam/GooSig
 *
 * Resources:
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/prng.py
 */

/* eslint valid-typeof: "off" */

'use strict';

const assert = require('bsert');
const BigMath = require('./bigmath');

/*
 * RNG
 */

class RNG {
  constructor(source) {
    assert(source && typeof source.generate === 'function');
    this.source = source;
    this.save = 0n;
  }

  nextRandom() {
    return BigMath.decode(this.source.generate(32));
  }

  randomBits(bits) {
    assert((bits >>> 0) === bits);

    let ret = this.save;
    let b = BigMath.bitLength(ret);

    while (b < bits) {
      ret <<= 256n;
      ret += this.nextRandom();
      b += 256;
    }

    const left = BigInt(b - bits);

    this.save = ret & ((1n << left) - 1n);

    ret >>= left;

    return ret;
  }

  randomInt(max) {
    assert(typeof max === 'bigint');

    const bits = BigMath.bitLength(max - 1n);

    let ret = max;

    while (ret >= max)
      ret = this.randomBits(bits);

    return ret;
  }
}

/*
 * Expose
 */

module.exports = RNG;
