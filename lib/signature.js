'use strict';

/* eslint camelcase: "off" */

const assert = require('assert');
const BigMath = require('./bigmath');
const constants = require('./constants');

/*
 * Signature
 */

class Signature {
  constructor(options) {
    this.C2 = 0n;
    this.t = 0n;

    this.chal = 0n;
    this.ell = 0n;
    this.Aq = 0n;
    this.Bq = 0n;
    this.Cq = 0n;
    this.Dq = 0n;

    this.z_w = 0n;
    this.z_w2 = 0n;
    this.z_s1 = 0n;
    this.z_a = 0n;
    this.z_an = 0n;
    this.z_s1w = 0n;
    this.z_sa = 0n;

    if (options != null)
      this.init(options);
  }

  init(options) {
    assert(options && typeof options === 'object');
    assert(typeof options.C2 === 'bigint');
    assert(typeof options.t === 'bigint');
    assert(typeof options.chal === 'bigint');
    assert(typeof options.ell === 'bigint');
    assert(typeof options.Aq === 'bigint');
    assert(typeof options.Bq === 'bigint');
    assert(typeof options.Cq === 'bigint');
    assert(typeof options.Dq === 'bigint');
    assert(Array.isArray(options.z_prime));
    assert(options.z_prime.length === 7);
    assert(typeof options.z_prime[0] === 'bigint');
    assert(typeof options.z_prime[1] === 'bigint');
    assert(typeof options.z_prime[2] === 'bigint');
    assert(typeof options.z_prime[3] === 'bigint');
    assert(typeof options.z_prime[4] === 'bigint');
    assert(typeof options.z_prime[5] === 'bigint');
    assert(typeof options.z_prime[6] === 'bigint');

    this.C2 = options.C2;
    this.t = options.t;
    this.chal = options.chal;
    this.ell = options.ell;
    this.Aq = options.Aq;
    this.Bq = options.Bq;
    this.Cq = options.Cq;
    this.Dq = options.Dq;
    this.z_w = options.z_prime[0];
    this.z_w2 = options.z_prime[1];
    this.z_s1 = options.z_prime[2];
    this.z_a = options.z_prime[3];
    this.z_an = options.z_prime[4];
    this.z_s1w = options.z_prime[5];
    this.z_sa = options.z_prime[6];

    return this;
  }

  getSize(modBits) {
    assert((modBits >>> 0) === modBits);

    const modBytes = (modBits + 7) >>> 3;
    const chalBytes = (constants.CHAL_BITS + 7) >>> 3;

    let size = 0;
    size += modBytes; // C2
    size += 2; // t
    size += chalBytes; // chal
    size += chalBytes; // ell
    size += modBytes; // Aq
    size += modBytes; // Bq
    size += modBytes; // Cq
    size += 2048 / 8; // Dq
    size += chalBytes * 7; // z_prime

    return size;
  }

  encode(modBits) {
    assert((modBits >>> 0) === modBits);

    const modBytes = (modBits + 7) >>> 3;
    const chalBytes = (constants.CHAL_BITS + 7) >>> 3;
    const size = this.getSize(modBits);
    const data = Buffer.allocUnsafe(size);

    let pos = 0;

    pos = BigMath.write(data, this.C2, pos, modBytes);
    pos = BigMath.write(data, this.t, pos, 2);
    pos = BigMath.write(data, this.chal, pos, chalBytes);
    pos = BigMath.write(data, this.ell, pos, chalBytes);
    pos = BigMath.write(data, this.Aq, pos, modBytes);
    pos = BigMath.write(data, this.Bq, pos, modBytes);
    pos = BigMath.write(data, this.Cq, pos, modBytes);
    pos = BigMath.write(data, this.Dq, pos, 2048 / 8);
    pos = BigMath.write(data, this.z_w, pos, chalBytes);
    pos = BigMath.write(data, this.z_w2, pos, chalBytes);
    pos = BigMath.write(data, this.z_s1, pos, chalBytes);
    pos = BigMath.write(data, this.z_a, pos, chalBytes);
    pos = BigMath.write(data, this.z_an, pos, chalBytes);
    pos = BigMath.write(data, this.z_s1w, pos, chalBytes);
    pos = BigMath.write(data, this.z_sa, pos, chalBytes);

    assert(pos === data.length);

    return data;
  }

  decode(data, modBits) {
    assert(Buffer.isBuffer(data));
    assert((modBits >>> 0) === modBits);

    const modBytes = (modBits + 7) >>> 3;
    const chalBytes = (constants.CHAL_BITS + 7) >>> 3;
    const size = this.getSize(modBits);

    assert(data.length === size);

    let off = 0;

    this.C2 = BigMath.read(data, off, modBytes);
    off += modBytes;

    this.t = BigMath.read(data, off, 2);
    off += 2;

    this.chal = BigMath.read(data, off, chalBytes);
    off += chalBytes;

    this.ell = BigMath.read(data, off, chalBytes);
    off += chalBytes;

    this.Aq = BigMath.read(data, off, modBytes);
    off += modBytes;

    this.Bq = BigMath.read(data, off, modBytes);
    off += modBytes;

    this.Cq = BigMath.read(data, off, modBytes);
    off += modBytes;

    this.Dq = BigMath.read(data, off, 2048 / 8);
    off += 2048 / 8;

    this.z_w = BigMath.read(data, off, chalBytes);
    off += chalBytes;

    this.z_w2 = BigMath.read(data, off, chalBytes);
    off += chalBytes;

    this.z_s1 = BigMath.read(data, off, chalBytes);
    off += chalBytes;

    this.z_a = BigMath.read(data, off, chalBytes);
    off += chalBytes;

    this.z_an = BigMath.read(data, off, chalBytes);
    off += chalBytes;

    this.z_s1w = BigMath.read(data, off, chalBytes);
    off += chalBytes;

    this.z_sa = BigMath.read(data, off, chalBytes);
    off += chalBytes;

    assert(off === size);

    return this;
  }

  toJSON() {
    return {
      C2: BigMath.encodeHex(this.C2),
      t: BigMath.encodeHex(this.t),
      chal: BigMath.encodeHex(this.chal),
      ell: BigMath.encodeHex(this.ell),
      Aq: BigMath.encodeHex(this.Aq),
      Bq: BigMath.encodeHex(this.Bq),
      Cq: BigMath.encodeHex(this.Cq),
      Dq: BigMath.encodeHex(this.Dq),
      z_w: BigMath.encodeHex(this.z_w),
      z_w2: BigMath.encodeHex(this.z_w2),
      z_s1: BigMath.encodeHex(this.z_s1),
      z_a: BigMath.encodeHex(this.z_a),
      z_an: BigMath.encodeHex(this.z_an),
      z_s1w: BigMath.encodeHex(this.z_s1w),
      z_sa: BigMath.encodeHex(this.z_sa)
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    this.C2 = BigMath.decodeHex(json.C2);
    this.t = BigMath.decodeHex(json.t);
    this.chal = BigMath.decodeHex(json.chal);
    this.ell = BigMath.decodeHex(json.ell);
    this.Aq = BigMath.decodeHex(json.Aq);
    this.Bq = BigMath.decodeHex(json.Bq);
    this.Cq = BigMath.decodeHex(json.Cq);
    this.Dq = BigMath.decodeHex(json.Dq);
    this.z_w = BigMath.decodeHex(json.z_w);
    this.z_w2 = BigMath.decodeHex(json.z_w2);
    this.z_s1 = BigMath.decodeHex(json.z_s1);
    this.z_a = BigMath.decodeHex(json.z_a);
    this.z_an = BigMath.decodeHex(json.z_an);
    this.z_s1w = BigMath.decodeHex(json.z_s1w);
    this.z_sa = BigMath.decodeHex(json.z_sa);
    return this;
  }

  format() {
    return {
      C2: this.C2.toString(16),
      t: this.t.toString(16),
      chal: this.chal.toString(16),
      ell: this.ell.toString(16),
      Aq: this.Aq.toString(16),
      Bq: this.Bq.toString(16),
      Cq: this.Cq.toString(16),
      Dq: this.Dq.toString(16),
      z_w: this.z_w.toString(16),
      z_w2: this.z_w2.toString(16),
      z_s1: this.z_s1.toString(16),
      z_a: this.z_a.toString(16),
      z_an: this.z_an.toString(16),
      z_s1w: this.z_s1w.toString(16),
      z_sa: this.z_sa.toString(16)
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