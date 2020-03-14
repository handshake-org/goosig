/*!
 * goo.js - groups of unknown order for javascript
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
const binding = require('./binding');
const constants = require('../internal/constants');
const rsa = require('bcrypto/lib/rsa');
const internal = require('../internal/rsa');

/*
 * Goo
 */

class Goo {
  constructor(n, g, h, modBits) {
    if (modBits == null)
      modBits = 0;

    assert(Buffer.isBuffer(n));
    assert((g >>> 0) === g);
    assert((h >>> 0) === h);
    assert((modBits >>> 0) === modBits);

    this._handle = binding.goosig_create(n, g, h, modBits);
    this.bits = countLeft(n);
    this.size = (this.bits + 7) >>> 3;
  }

  generate() {
    return binding.goosig_generate(binding.entropy());
  }

  challenge(s_prime, key) {
    assert(this instanceof Goo);
    assert(Buffer.isBuffer(s_prime));

    const {n} = rsa.publicKeyExport(key);

    return binding.goosig_challenge(this._handle, s_prime, n);
  }

  encrypt(msg, key, size) {
    return internal.encrypt(msg, key, size);
  }

  decrypt(ct, key, size) {
    return internal.decrypt(ct, key, size);
  }

  validate(s_prime, C1, key) {
    assert(this instanceof Goo);
    assert(Buffer.isBuffer(s_prime));
    assert(Buffer.isBuffer(C1));
    assert(Buffer.isBuffer(key));

    let k;
    try {
      k = rsa.privateKeyExport(key);
    } catch (e) {
      return false;
    }

    return binding.goosig_validate(this._handle, s_prime, C1, k.p, k.q);
  }

  sign(msg, s_prime, key) {
    assert(this instanceof Goo);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(s_prime));
    assert(Buffer.isBuffer(key));

    const {p, q} = rsa.privateKeyExport(key);

    return binding.goosig_sign(this._handle, msg, s_prime, p, q);
  }

  verify(msg, sig, C1) {
    assert(this instanceof Goo);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(C1));

    return binding.goosig_verify(this._handle, msg, sig, C1);
  }

  static generate() {
    return binding.goosig_generate(binding.entropy());
  }

  static encrypt(msg, key, size) {
    return internal.encrypt(msg, key, size);
  }

  static decrypt(ct, key, size) {
    return internal.decrypt(ct, key, size);
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
 * Expose
 */

module.exports = Goo;
