/*!
 * rng.js - goosig signatures for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const BN = require('bcrypto/lib/bn.js');
const constants = require('../internal/constants');

/*
 * Constants
 */

const {
  EXP_BYTES,
  CHAL_BYTES,
  ELL_BYTES
} = constants;

/*
 * Signature
 */

class Signature {
  constructor(options) {
    this.C2 = new BN(0);
    this.C3 = new BN(0);
    this.t = new BN(0);

    this.chal = new BN(0);
    this.ell = new BN(0);
    this.Aq = new BN(0);
    this.Bq = new BN(0);
    this.Cq = new BN(0);
    this.Dq = new BN(0);
    this.Eq = new BN(0);

    this.z_w = new BN(0);
    this.z_w2 = new BN(0);
    this.z_s1 = new BN(0);
    this.z_a = new BN(0);
    this.z_an = new BN(0);
    this.z_s1w = new BN(0);
    this.z_sa = new BN(0);
    this.z_s2 = new BN(0);

    if (options != null)
      this.init(options);
  }

  init(options) {
    assert(options && typeof options === 'object');
    assert(BN.isBN(options.C2));
    assert(BN.isBN(options.C3));
    assert(BN.isBN(options.t));
    assert(BN.isBN(options.chal));
    assert(BN.isBN(options.ell));
    assert(BN.isBN(options.Aq));
    assert(BN.isBN(options.Bq));
    assert(BN.isBN(options.Cq));
    assert(BN.isBN(options.Dq));
    assert(BN.isBN(options.Eq));
    assert(BN.isBN(options.z_w));
    assert(BN.isBN(options.z_w2));
    assert(BN.isBN(options.z_s1));
    assert(BN.isBN(options.z_a));
    assert(BN.isBN(options.z_an));
    assert(BN.isBN(options.z_s1w));
    assert(BN.isBN(options.z_sa));
    assert(BN.isBN(options.z_s2));

    this.C2 = options.C2;
    this.C3 = options.C3;
    this.t = options.t;
    this.chal = options.chal;
    this.ell = options.ell;
    this.Aq = options.Aq;
    this.Bq = options.Bq;
    this.Cq = options.Cq;
    this.Dq = options.Dq;
    this.Eq = options.Eq;
    this.z_w = options.z_w;
    this.z_w2 = options.z_w2;
    this.z_s1 = options.z_s1;
    this.z_a = options.z_a;
    this.z_an = options.z_an;
    this.z_s1w = options.z_s1w;
    this.z_sa = options.z_sa;
    this.z_s2 = options.z_s2;

    return this;
  }

  getSize(bits) {
    assert((bits >>> 0) === bits);

    const MOD_BYTES = (bits + 7) >>> 3;

    let size = 0;
    size += MOD_BYTES; // C2
    size += MOD_BYTES; // C3
    size += 2; // t
    size += CHAL_BYTES; // chal
    size += ELL_BYTES; // ell
    size += MOD_BYTES; // Aq
    size += MOD_BYTES; // Bq
    size += MOD_BYTES; // Cq
    size += MOD_BYTES; // Dq
    size += EXP_BYTES; // Eq
    size += ELL_BYTES * 8; // z_prime
    size += 1;

    return size;
  }

  encode(bits) {
    assert((bits >>> 0) === bits);

    const MOD_BYTES = (bits + 7) >>> 3;

    return Buffer.concat([
      this.C2.encode('be', MOD_BYTES),
      this.C3.encode('be', MOD_BYTES),
      this.t.encode('be', 2),
      this.chal.encode('be', CHAL_BYTES),
      this.ell.encode('be', ELL_BYTES),
      this.Aq.encode('be', MOD_BYTES),
      this.Bq.encode('be', MOD_BYTES),
      this.Cq.encode('be', MOD_BYTES),
      this.Dq.encode('be', MOD_BYTES),
      this.Eq.encode('be', EXP_BYTES),
      this.z_w.encode('be', ELL_BYTES),
      this.z_w2.encode('be', ELL_BYTES),
      this.z_s1.encode('be', ELL_BYTES),
      this.z_a.encode('be', ELL_BYTES),
      this.z_an.encode('be', ELL_BYTES),
      this.z_s1w.encode('be', ELL_BYTES),
      this.z_sa.encode('be', ELL_BYTES),
      this.z_s2.encode('be', ELL_BYTES),
      Buffer.from([this.Eq.isNeg() ? 1 : 0])
    ]);
  }

  decode(data, bits) {
    assert(Buffer.isBuffer(data));
    assert((bits >>> 0) === bits);

    const MOD_BYTES = (bits + 7) >>> 3;
    const size = this.getSize(bits);

    if (data.length !== size)
      throw new RangeError('Invalid signature size.');

    let off = 0;

    [off, this.C2] = readInt(data, off, MOD_BYTES);
    [off, this.C3] = readInt(data, off, MOD_BYTES);
    [off, this.t] = readInt(data, off, 2);
    [off, this.chal] = readInt(data, off, CHAL_BYTES);
    [off, this.ell] = readInt(data, off, ELL_BYTES);
    [off, this.Aq] = readInt(data, off, MOD_BYTES);
    [off, this.Bq] = readInt(data, off, MOD_BYTES);
    [off, this.Cq] = readInt(data, off, MOD_BYTES);
    [off, this.Dq] = readInt(data, off, MOD_BYTES);
    [off, this.Eq] = readInt(data, off, EXP_BYTES);
    [off, this.z_w] = readInt(data, off, ELL_BYTES);
    [off, this.z_w2] = readInt(data, off, ELL_BYTES);
    [off, this.z_s1] = readInt(data, off, ELL_BYTES);
    [off, this.z_a] = readInt(data, off, ELL_BYTES);
    [off, this.z_an] = readInt(data, off, ELL_BYTES);
    [off, this.z_s1w] = readInt(data, off, ELL_BYTES);
    [off, this.z_sa] = readInt(data, off, ELL_BYTES);
    [off, this.z_s2] = readInt(data, off, ELL_BYTES);

    const sign = data[off++];

    assert(off === size);

    if (sign > 1)
      throw new Error('Non-minimal serialization.');

    if (sign)
      this.Eq.ineg();

    return this;
  }

  toJSON() {
    return {
      C2: this.C2.toJSON(),
      C3: this.C3.toJSON(),
      t: this.t.toJSON(),
      chal: this.chal.toJSON(),
      ell: this.ell.toJSON(),
      Aq: this.Aq.toJSON(),
      Bq: this.Bq.toJSON(),
      Cq: this.Cq.toJSON(),
      Dq: this.Dq.toJSON(),
      Eq: this.Eq.toJSON(),
      z_w: this.z_w.toJSON(),
      z_w2: this.z_w2.toJSON(),
      z_s1: this.z_s1.toJSON(),
      z_a: this.z_a.toJSON(),
      z_an: this.z_an.toJSON(),
      z_s1w: this.z_s1w.toJSON(),
      z_sa: this.z_sa.toJSON(),
      z_s2: this.z_s2.toJSON()
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');

    this.C2 = BN.fromJSON(json.C2);
    this.C3 = BN.fromJSON(json.C3);
    this.t = BN.fromJSON(json.t);
    this.chal = BN.fromJSON(json.chal);
    this.ell = BN.fromJSON(json.ell);
    this.Aq = BN.fromJSON(json.Aq);
    this.Bq = BN.fromJSON(json.Bq);
    this.Cq = BN.fromJSON(json.Cq);
    this.Dq = BN.fromJSON(json.Dq);
    this.Eq = BN.fromJSON(json.Eq);
    this.z_w = BN.fromJSON(json.z_w);
    this.z_w2 = BN.fromJSON(json.z_w2);
    this.z_s1 = BN.fromJSON(json.z_s1);
    this.z_a = BN.fromJSON(json.z_a);
    this.z_an = BN.fromJSON(json.z_an);
    this.z_s1w = BN.fromJSON(json.z_s1w);
    this.z_sa = BN.fromJSON(json.z_sa);
    this.z_s2 = BN.fromJSON(json.z_s2);

    return this;
  }

  format() {
    return {
      C2: this.C2.toString(16),
      C3: this.C2.toString(16),
      t: this.t.toString(16),
      chal: this.chal.toString(16),
      ell: this.ell.toString(16),
      Aq: this.Aq.toString(16),
      Bq: this.Bq.toString(16),
      Cq: this.Cq.toString(16),
      Dq: this.Dq.toString(16),
      Eq: this.Dq.toString(16),
      z_w: this.z_w.toString(16),
      z_w2: this.z_w2.toString(16),
      z_s1: this.z_s1.toString(16),
      z_a: this.z_a.toString(16),
      z_an: this.z_an.toString(16),
      z_s1w: this.z_s1w.toString(16),
      z_sa: this.z_sa.toString(16),
      z_s2: this.z_s2.toString(16)
    };
  }

  static decode(data, bits) {
    return new this().decode(data, bits);
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

/*
 * Helpers
 */

function readInt(data, off, size) {
  const num = BN.decode(data.slice(off, off + size));
  return [off + size, num];
}

/*
 * Expose
 */

module.exports = Signature;
