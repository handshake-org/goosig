'use strict';

/* eslint camelcase: "off" */

const assert = require('assert');
const bio = require('bufio');
const BigMath = require('./bigmath');

/*
 * Signature
 */

class Signature extends bio.Struct {
  constructor(options) {
    super();

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

  getSize() {
    let size = 0;
    size += sizeInt(this.C2);
    size += sizeInt(this.t);
    size += sizeInt(this.chal);
    size += sizeInt(this.ell);
    size += sizeInt(this.Aq);
    size += sizeInt(this.Bq);
    size += sizeInt(this.Cq);
    size += sizeInt(this.Dq);
    size += sizeInt(this.z_w);
    size += sizeInt(this.z_w2);
    size += sizeInt(this.z_s1);
    size += sizeInt(this.z_a);
    size += sizeInt(this.z_an);
    size += sizeInt(this.z_s1w);
    size += sizeInt(this.z_sa);
    return size;
  }

  write(bw) {
    writeInt(bw, this.C2);
    writeInt(bw, this.t);
    writeInt(bw, this.chal);
    writeInt(bw, this.ell);
    writeInt(bw, this.Aq);
    writeInt(bw, this.Bq);
    writeInt(bw, this.Cq);
    writeInt(bw, this.Dq);
    writeInt(bw, this.z_w);
    writeInt(bw, this.z_w2);
    writeInt(bw, this.z_s1);
    writeInt(bw, this.z_a);
    writeInt(bw, this.z_an);
    writeInt(bw, this.z_s1w);
    writeInt(bw, this.z_sa);
    return bw;
  }

  read(br) {
    this.C2 = readInt(br);
    this.t = readInt(br);
    this.chal = readInt(br);
    this.ell = readInt(br);
    this.Aq = readInt(br);
    this.Bq = readInt(br);
    this.Cq = readInt(br);
    this.Dq = readInt(br);
    this.z_w = readInt(br);
    this.z_w2 = readInt(br);
    this.z_s1 = readInt(br);
    this.z_a = readInt(br);
    this.z_an = readInt(br);
    this.z_s1w = readInt(br);
    this.z_sa = readInt(br);
    return this;
  }

  getJSON() {
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
}

function sizeInt(num) {
  return 2 + BigMath.size(num);
}

function writeInt(bw, num) {
  assert(bw && typeof bw.writeU8 === 'function');
  assert(typeof num === 'bigint');

  assert(num >= 0n);

  const size = BigMath.size(num);
  assert(size <= 768);

  bw.writeU16(size);

  BigMath.writeBW(bw, num);
}

function readInt(br) {
  assert(br && typeof br.readU8 === 'function');

  const size = br.readU16();
  assert(size <= 768);

  return BigMath.readBR(br, size);
}

/*
 * Expose
 */

module.exports = Signature;
