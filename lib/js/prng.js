/*!
 * prng.js - prng for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

/* eslint camelcase: 'off' */

'use strict';

const assert = require('bsert');
const BN = require('bcrypto/lib/bn.js');
const HmacDRBG = require('bcrypto/lib/hmac-drbg');
const SHA256 = require('bcrypto/lib/sha256');
const constants = require('../internal/constants');

/*
 * PRNG
 */

class PRNG extends HmacDRBG {
  constructor(entropy, nonce, pers) {
    super(SHA256, entropy, nonce, pers);

    this.save = new BN(0);
    this.total = 0;
  }

  init(entropy, nonce, pers) {
    super.init(entropy, nonce, pers);

    this.save = new BN(0);
    this.total = 0;

    return this;
  }

  randomBits(bits) {
    assert((bits >>> 0) === bits);

    const ret = this.save;

    let total = this.total;

    while (total < bits) {
      const x = BN.decode(this.generate(32));

      ret.iushln(256);
      ret.iadd(x);

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

    if (max.sign() <= 0)
      return new BN(0);

    return BN.random(bits => this.randomBits(bits), 0, max);
  }

  randomNum(max) {
    assert((max >>> 0) === max);

    if (max === 0)
      return 0;

    const top = -max >>> 0;

    let x, r;

    do {
      const data = this.generate(4);

      x = 0;
      x += data[0] * 0x1000000;
      x += data[1] * 0x10000;
      x += data[2] * 0x100;
      x += data[3];

      r = x % max;
    } while (x - r > top);

    return r;
  }

  static fromKey(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === 32);

    return new this(key, constants.DRBG_PERS);
  }

  static fromSign(p, q, s_prime, msg) {
    assert(p instanceof BN);
    assert(q instanceof BN);
    assert(Buffer.isBuffer(s_prime));
    assert(Buffer.isBuffer(msg));

    const x = p.encode('be', constants.MAX_RSA_BYTES);
    const y = q.encode('be', constants.MAX_RSA_BYTES);
    const entropy = SHA256.multi(x, y, s_prime);
    const nonce = SHA256.digest(msg);

    return new this(entropy, nonce);
  }
}

/*
 * Expose
 */

module.exports = PRNG;
