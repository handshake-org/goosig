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
const BN = require('bcrypto/lib/bn.js');

/*
 * RNG
 */

class RNG {
  constructor(source) {
    assert(source && typeof source.generate === 'function');
    this.source = source;
    this.save = BN.from(0);
    this.total = 0;
  }

  nextRandom() {
    return BN.decode(this.source.generate(32));
  }

  randomBits(bits) {
    assert((bits >>> 0) === bits);

    const ret = this.save;

    let total = this.total;

    while (total < bits) {
      ret.iushln(256);
      ret.iadd(this.nextRandom());
      total += 256;
    }

    const left = total - bits;

    this.save = ret.maskn(left);
    this.total = left;

    ret.iushrn(left);

    return ret;
  }

  randomBitsNZ(bits) {
    assert(bits !== 0);

    let num = null;

    do {
      num = this.randomBits(bits);
    } while (num.isZero());

    return num;
  }

  randomInt(max) {
    assert(BN.isBN(max));

    if (max.cmpn(0) <= 0)
      return BN.from(0);

    return BN.random(bits => this.randomBits(bits), 0, max);
  }
}

/*
 * Expose
 */

module.exports = RNG;
