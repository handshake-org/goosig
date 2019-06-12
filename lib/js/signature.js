/*!
 * rng.js - goosig signatures for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

/* eslint camelcase: "off" */
/* eslint valid-typeof: "off" */

'use strict';

const assert = require('bsert');
const BN = require('bcrypto/lib/bn.js');
const constants = require('../internal/constants');

/*
 * Signature
 */

class Signature {
  constructor(options) {
    this.C2 = BN.from(0);
    this.C3 = BN.from(0);
    this.t = BN.from(0);

    this.chal = BN.from(0);
    this.ell = BN.from(0);
    this.Aq = BN.from(0);
    this.Bq = BN.from(0);
    this.Cq = BN.from(0);
    this.Dq = BN.from(0);
    this.Eq = BN.from(0);

    this.z_w = BN.from(0);
    this.z_w2 = BN.from(0);
    this.z_s1 = BN.from(0);
    this.z_a = BN.from(0);
    this.z_an = BN.from(0);
    this.z_s1w = BN.from(0);
    this.z_sa = BN.from(0);
    this.z_s2 = BN.from(0);

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

  getSize(modBits) {
    assert((modBits >>> 0) === modBits);

    const modBytes = (modBits + 7) >>> 3;
    const expBytes = (constants.EXPONENT_SIZE + 7) >>> 3;
    const chalBytes = (constants.CHAL_BITS + 7) >>> 3;
    const ellBytes = (constants.ELL_BITS + 7) >>> 3;

    let size = 0;
    size += modBytes; // C2
    size += modBytes; // C3
    size += 2; // t
    size += chalBytes; // chal
    size += ellBytes; // ell
    size += modBytes; // Aq
    size += modBytes; // Bq
    size += modBytes; // Cq
    size += modBytes; // Dq
    size += expBytes; // Eq
    size += ellBytes * 8; // z_prime

    return size;
  }

  encode(modBits) {
    assert((modBits >>> 0) === modBits);

    const modBytes = (modBits + 7) >>> 3;
    const expBytes = (constants.EXPONENT_SIZE + 7) >>> 3;
    const chalBytes = (constants.CHAL_BITS + 7) >>> 3;
    const ellBytes = (constants.ELL_BITS + 7) >>> 3;

    return Buffer.concat([
      this.C2.encode('be', modBytes),
      this.C3.encode('be', modBytes),
      this.t.encode('be', 2),
      this.chal.encode('be', chalBytes),
      this.ell.encode('be', ellBytes),
      this.Aq.encode('be', modBytes),
      this.Bq.encode('be', modBytes),
      this.Cq.encode('be', modBytes),
      this.Dq.encode('be', modBytes),
      this.Eq.encode('be', expBytes),
      this.z_w.encode('be', ellBytes),
      this.z_w2.encode('be', ellBytes),
      this.z_s1.encode('be', ellBytes),
      this.z_a.encode('be', ellBytes),
      this.z_an.encode('be', ellBytes),
      this.z_s1w.encode('be', ellBytes),
      this.z_sa.encode('be', ellBytes),
      this.z_s2.encode('be', ellBytes)
    ]);
  }

  decode(data, modBits) {
    assert(Buffer.isBuffer(data));
    assert((modBits >>> 0) === modBits);

    const modBytes = (modBits + 7) >>> 3;
    const expBytes = (constants.EXPONENT_SIZE + 7) >>> 3;
    const chalBytes = (constants.CHAL_BITS + 7) >>> 3;
    const ellBytes = (constants.ELL_BITS + 7) >>> 3;
    const size = this.getSize(modBits);

    assert(data.length === size);

    let off = 0;

    this.C2 = BN.decode(data.slice(off, off + modBytes));
    off += modBytes;

    this.C3 = BN.decode(data.slice(off, off + modBytes));
    off += modBytes;

    this.t = BN.decode(data.slice(off, off + 2));
    off += 2;

    this.chal = BN.decode(data.slice(off, off + chalBytes));
    off += chalBytes;

    this.ell = BN.decode(data.slice(off, off + ellBytes));
    off += ellBytes;

    this.Aq = BN.decode(data.slice(off, off + modBytes));
    off += modBytes;

    this.Bq = BN.decode(data.slice(off, off + modBytes));
    off += modBytes;

    this.Cq = BN.decode(data.slice(off, off + modBytes));
    off += modBytes;

    this.Dq = BN.decode(data.slice(off, off + modBytes));
    off += modBytes;

    this.Eq = BN.decode(data.slice(off, off + expBytes));
    off += expBytes;

    this.z_w = BN.decode(data.slice(off, off + ellBytes));
    off += ellBytes;

    this.z_w2 = BN.decode(data.slice(off, off + ellBytes));
    off += ellBytes;

    this.z_s1 = BN.decode(data.slice(off, off + ellBytes));
    off += ellBytes;

    this.z_a = BN.decode(data.slice(off, off + ellBytes));
    off += ellBytes;

    this.z_an = BN.decode(data.slice(off, off + ellBytes));
    off += ellBytes;

    this.z_s1w = BN.decode(data.slice(off, off + ellBytes));
    off += ellBytes;

    this.z_sa = BN.decode(data.slice(off, off + ellBytes));
    off += ellBytes;

    this.z_s2 = BN.decode(data.slice(off, off + ellBytes));
    off += ellBytes;

    assert(off === size);

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

  static decode(data, modBits) {
    return new this().decode(data, modBits);
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

/*
 * Expose
 */

module.exports = Signature;
