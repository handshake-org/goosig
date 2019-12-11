/*!
 * prng.js - prng for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

'use strict';

const assert = require('bsert');
const BN = require('bcrypto/lib/bn.js');
const HmacDRBG = require('bcrypto/lib/hmac-drbg');
const SHA256 = require('bcrypto/lib/sha256');
const constants = require('../internal/constants');

/*
 * PRNG
 */

class PRNG {
  constructor(key) {
    this.drbg = new HmacDRBG(SHA256, key, constants.DRBG_PERS);
    this.save = new BN(0);
    this.total = 0;
  }

  nextRandom() {
    return BN.decode(this.drbg.generate(32));
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

  randomInt(max) {
    assert(BN.isBN(max));

    if (max.cmpn(0) <= 0)
      return new BN(0);

    return BN.random(bits => this.randomBits(bits), 0, max);
  }
}

/*
 * Expose
 */

module.exports = PRNG;
