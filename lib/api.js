/*!
 * api.js - groups of unknown order for javascript
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
const Goo = require('./goo');
const constants = require('./internal/constants');
const rsa = require('./internal/rsa');

/*
 * Constants
 */

const N = constants.DEFAULT_N;
const G = constants.DEFAULT_G;
const H = constants.DEFAULT_H;
const SIZE = constants.MAX_RSA_BITS;

/*
 * API
 */

class API {
  constructor(n = N, g = G, h = H) {
    assert(Buffer.isBuffer(n));
    assert((g >>> 0) === g);
    assert((h >>> 0) === h);

    this.n = n;
    this.g = g;
    this.h = h;

    this._p = null;
    this._v = null;
  }

  _prover() {
    if (!this._p)
      this._p = new Goo(this.n, this.g, this.h, SIZE);
    return this._p;
  }

  _verifier() {
    if (!this._v)
      this._v = new Goo(this.n, this.g, this.h, null);
    return this._v;
  }

  get bits() {
    return this._verifier().bits;
  }

  get size() {
    return this._verifier().size;
  }

  generate() {
    return this._verifier().generate();
  }

  challenge(s_prime, key) {
    return this._prover().challenge(s_prime, key);
  }

  encrypt(msg, key, size) {
    return rsa.encrypt(msg, key, size);
  }

  decrypt(ct, key, size) {
    return rsa.decrypt(ct, key, size);
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

API.native = Goo.native;
API.AOL1 = constants.AOL1;
API.AOL2 = constants.AOL2;
API.RSA2048 = constants.RSA2048;
API.RSA617 = constants.RSA617;

/*
 * Expose
 */

module.exports = API;
