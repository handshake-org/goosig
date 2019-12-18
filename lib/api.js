/*!
 * api.js - groups of unknown order for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Parts of this software are based on kwantam/libGooPy:
 *   Copyright (c) 2018, Dan Boneh, Riad S. Wahby (Apache License).
 *   https://github.com/kwantam/GooSig
 */

/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const {countLeft} = require('bcrypto/lib/encoding/util');
const Goo = require('./goo');
const constants = require('./internal/constants');

/*
 * Constants
 */

const {
  DEFAULT_N,
  DEFAULT_G,
  DEFAULT_H,
  MAX_RSA_BITS
} = constants;

/*
 * API
 */

class API {
  constructor(n = DEFAULT_N, g = DEFAULT_G, h = DEFAULT_H) {
    assert(Buffer.isBuffer(n));
    assert((g >>> 0) === g);
    assert((h >>> 0) === h);

    this.n = n;
    this.g = g;
    this.h = h;
    this.bits = countLeft(n);
    this.size = (this.bits + 7) >>> 3;

    this._p = null;
    this._v = null;
  }

  _prover() {
    if (!this._p)
      this._p = new Goo(this.n, this.g, this.h, MAX_RSA_BITS);
    return this._p;
  }

  _verifier() {
    if (!this._v)
      this._v = new Goo(this.n, this.g, this.h, null);
    return this._v;
  }

  generate() {
    return this.constructor.generate();
  }

  challenge(s_prime, key) {
    return this._prover().challenge(s_prime, key);
  }

  encrypt(msg, key, size) {
    return this.constructor.encrypt(msg, key, size);
  }

  decrypt(ct, key, size) {
    return this.constructor.decrypt(ct, key, size);
  }

  validate(s_prime, C1, key) {
    return this._prover().validate(s_prime, C1, key);
  }

  sign(msg, s_prime, key) {
    return this._prover().sign(msg, s_prime, key);
  }

  verify(msg, sig, C1) {
    return this._verifier().verify(msg, sig, C1);
  }

  static generate() {
    return Goo.generate();
  }

  static encrypt(msg, key, size) {
    return Goo.encrypt(msg, key, size);
  }

  static decrypt(ct, key, size) {
    return Goo.decrypt(ct, key, size);
  }
}

/*
 * Static
 */

API.native = Goo.native;
API.AOL1 = constants.AOL1;
API.AOL2 = constants.AOL2;
API.RSA2048 = constants.RSA2048;
API.RSA617 = constants.RSA617;

/*
 * Expose
 */

module.exports = API;
