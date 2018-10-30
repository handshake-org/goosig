/* eslint camelcase: "off" */

'use strict';

const assert = require('assert');
const bio = require('bufio');
const BigMath = require('./bigmath');

const ELEMENT = [0n, 0n, 0n];

class Challenge extends bio.Struct {
  constructor(C0, C1) {
    super();

    assert(C0 == null || typeof C0 === 'bigint');
    assert(C1 == null || typeof C1 === 'bigint');

    this.C0 = C0 || 0n;
    this.C1 = C1 || 0n;
  }

  getSize() {
    let size = 0;
    size += sizeInt(this.C0);
    size += sizeInt(this.C1);
    return size;
  }

  write(bw) {
    writeInt(bw, this.C0);
    writeInt(bw, this.C1);
    return bw;
  }

  read(br) {
    this.C0 = readInt(br);
    this.C1 = readInt(br);
    return this;
  }

  getJSON() {
    return {
      C0: BigMath.encodeHex(this.C0),
      C1: BigMath.encodeHex(this.C1)
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    this.C0 = BigMath.decodeHex(json.C0);
    this.C1 = BigMath.decodeHex(json.C1);
    return this;
  }

  format() {
    return {
      C0: this.C0.toString(16),
      C1: this.C1.toString(16)
    };
  }
}

class Proof extends bio.Struct {
  constructor(key, sigma) {
    super();

    assert(key == null || (key instanceof PublicKey));
    assert(sigma == null || (sigma instanceof Sigma));

    this.key = key || new PublicKey();
    this.sigma = sigma || new Sigma();
  }

  getSize() {
    let size = 0;
    size += this.key.getSize();
    size += this.sigma.getSize();
    return size;
  }

  write(bw) {
    this.key.write(bw);
    this.sigma.write(bw);
    return bw;
  }

  read(br) {
    this.key.read(br);
    this.sigma.read(br);
    return this;
  }

  getJSON() {
    return {
      key: this.key.getJSON(),
      sigma: this.sigma.getJSON()
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    this.key.fromJSON(json.key);
    this.sigma.fromJSON(json.sigma);
    return this;
  }

  format() {
    return {
      key: this.key,
      sigma: this.sigma
    };
  }
}

class PublicKey extends bio.Struct {
  constructor(C1, C2, t) {
    super();

    assert(C1 == null || typeof C1 === 'bigint');
    assert(C2 == null || typeof C2 === 'bigint');
    assert(t == null || typeof t === 'bigint');

    this.C1 = C1 || 0n;
    this.C2 = C2 || 0n;
    this.t = t || 0n;
  }

  getSize() {
    let size = 0;
    size += sizeInt(this.C1);
    size += sizeInt(this.C2);
    size += sizeInt(this.t);
    return size;
  }

  write(bw) {
    writeInt(bw, this.C1);
    writeInt(bw, this.C2);
    writeInt(bw, this.t);
    return bw;
  }

  read(br) {
    this.C1 = readInt(br);
    this.C2 = readInt(br);
    this.t = readInt(br);
    return this;
  }

  getJSON() {
    return {
      C1: BigMath.encodeHex(this.C1),
      C2: BigMath.encodeHex(this.C2),
      t: BigMath.encodeHex(this.t)
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    this.C1 = BigMath.decodeHex(json.C1);
    this.C2 = BigMath.decodeHex(json.C2);
    this.t = BigMath.decodeHex(json.t);
    return this;
  }

  format() {
    return {
      C1: this.C1.toString(16),
      C2: this.C2.toString(16),
      t: this.t.toString(16)
    };
  }
}

class Sigma extends bio.Struct {
  constructor(chal, ell, Aq, Bq, Cq, Dq, z_prime) {
    super();

    assert(chal == null || typeof chal === 'bigint');
    assert(ell == null || typeof ell === 'bigint');
    assert(Aq == null || typeof Aq === 'bigint');
    assert(Bq == null || typeof Bq === 'bigint');
    assert(Cq == null || typeof Cq === 'bigint');
    assert(Dq == null || typeof Dq === 'bigint');
    assert(z_prime == null || (z_prime instanceof ZPrime));

    this.chal = chal || 0n;
    this.ell = ell || 0n;
    this.Aq = Aq || 0n;
    this.Bq = Bq || 0n;
    this.Cq = Cq || 0n;
    this.Dq = Dq || 0n;
    this.z_prime = z_prime || new ZPrime();
  }

  getSize() {
    let size = 0;
    size += sizeInt(this.chal);
    size += sizeInt(this.ell);
    size += sizeInt(this.Aq);
    size += sizeInt(this.Bq);
    size += sizeInt(this.Cq);
    size += sizeInt(this.Dq);
    size += this.z_prime.getSize();
    return size;
  }

  write(bw) {
    writeInt(bw, this.chal);
    writeInt(bw, this.ell);
    writeInt(bw, this.Aq);
    writeInt(bw, this.Bq);
    writeInt(bw, this.Cq);
    writeInt(bw, this.Dq);
    this.z_prime.write(bw);
    return bw;
  }

  read(br) {
    this.chal = readInt(br);
    this.ell = readInt(br);
    this.Aq = readInt(br);
    this.Bq = readInt(br);
    this.Cq = readInt(br);
    this.Dq = readInt(br);
    this.z_prime.read(br);
    return this;
  }

  getJSON() {
    return {
      chal: BigMath.encodeHex(this.chal),
      ell: BigMath.encodeHex(this.ell),
      Aq: BigMath.encodeHex(this.Aq),
      Bq: BigMath.encodeHex(this.Bq),
      Cq: BigMath.encodeHex(this.Cq),
      Dq: BigMath.encodeHex(this.Dq),
      z_prime: this.z_prime.getJSON()
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    this.chal = BigMath.decodeHex(json.chal);
    this.ell = BigMath.decodeHex(json.ell);
    this.Aq = BigMath.decodeHex(json.Aq);
    this.Bq = BigMath.decodeHex(json.Bq);
    this.Cq = BigMath.decodeHex(json.Cq);
    this.Dq = BigMath.decodeHex(json.Dq);
    this.z_prime.fromJSON(json.z_prime);
    return this;
  }

  format() {
    return {
      chal: this.chal.toString(16),
      ell: this.ell.toString(16),
      Aq: this.Aq.toString(16),
      Bq: this.Bq.toString(16),
      Cq: this.Cq.toString(16),
      Dq: this.Dq.toString(16),
      z_prime: this.z_prime
    };
  }
}

class ZPrime extends bio.Struct {
  constructor(z_w, z_w2, z_s1, z_a, z_an, z_s1w, z_sa) {
    super();

    assert(z_w == null || typeof z_w === 'bigint');
    assert(z_w2 == null || typeof z_w2 === 'bigint');
    assert(z_s1 == null || typeof z_s1 === 'bigint');
    assert(z_a == null || typeof z_a === 'bigint');
    assert(z_an == null || typeof z_an === 'bigint');
    assert(z_s1w == null || typeof z_s1w === 'bigint');
    assert(z_sa == null || typeof z_sa === 'bigint');

    this.z_w = 0n || z_w;
    this.z_w2 = 0n || z_w2;
    this.z_s1 = 0n || z_s1;
    this.z_a = 0n || z_a;
    this.z_an = 0n || z_an;
    this.z_s1w = 0n || z_s1w;
    this.z_sa = 0n || z_sa;
  }

  getSize() {
    let size = 0;
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

class ClassChallenge extends bio.Struct {
  constructor(C0, C1) {
    super();

    assert(C0 == null || typeof C0 === 'bigint');
    assert(C1 == null || isElement(C1));

    this.C0 = C0 || 0n;
    this.C1 = C1 || ELEMENT;
  }

  getSize() {
    let size = 0;
    size += sizeInt(this.C0);
    size += sizeElement(this.C1);
    return size;
  }

  write(bw) {
    writeInt(bw, this.C0);
    writeElement(bw, this.C1);
    return bw;
  }

  read(br) {
    this.C0 = readInt(br);
    this.C1 = readElement(br);
    return this;
  }

  getJSON() {
    return {
      C0: BigMath.encodeHex(this.C0),
      C1: toJSONEl(this.C1)
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    this.C0 = BigMath.decodeHex(json.C0);
    this.C1 = fromJSONEl(json.C1);
    return this;
  }

  format() {
    return {
      C0: this.C0.toString(16),
      C1: toStringEl(this.C1)
    };
  }
}

class ClassProof extends bio.Struct {
  constructor(key, sigma) {
    super();

    assert(key == null || (key instanceof ClassPublicKey));
    assert(sigma == null || (sigma instanceof ClassSigma));

    this.key = key || new PublicKey();
    this.sigma = sigma || new Sigma();
  }

  getSize() {
    let size = 0;
    size += this.key.getSize();
    size += this.sigma.getSize();
    return size;
  }

  write(bw) {
    this.key.write(bw);
    this.sigma.write(bw);
    return bw;
  }

  read(br) {
    this.key.read(br);
    this.sigma.read(br);
    return this;
  }

  getJSON() {
    return {
      key: this.key.getJSON(),
      sigma: this.sigma.getJSON()
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    this.key.fromJSON(json.key);
    this.sigma.fromJSON(json.sigma);
    return this;
  }

  format() {
    return {
      key: this.key,
      sigma: this.sigma
    };
  }
}

class ClassPublicKey extends bio.Struct {
  constructor(C1, C2, t) {
    super();

    assert(C1 == null || isElement(C1));
    assert(C2 == null || isElement(C2));
    assert(t == null || typeof t === 'bigint');

    this.C1 = C1 || ELEMENT;
    this.C2 = C2 || ELEMENT;
    this.t = t || 0n;
  }

  getSize() {
    let size = 0;
    size += sizeElement(this.C1);
    size += sizeElement(this.C2);
    size += sizeInt(this.t);
    return size;
  }

  write(bw) {
    writeElement(bw, this.C1);
    writeElement(bw, this.C2);
    writeInt(bw, this.t);
    return bw;
  }

  read(br) {
    this.C1 = readElement(br);
    this.C2 = readElement(br);
    this.t = readInt(br);
    return this;
  }

  getJSON() {
    return {
      C1: toJSONEl(this.C1),
      C2: toJSONEl(this.C2),
      t: BigMath.encodeHex(this.t)
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    this.C1 = fromJSONEl(json.C1);
    this.C2 = fromJSONEl(json.C2);
    this.t = BigMath.decodeHex(json.t);
    return this;
  }

  format() {
    return {
      C1: toStringEl(this.C1),
      C2: toStringEl(this.C2),
      t: this.t.toString(16)
    };
  }
}

class ClassSigma extends bio.Struct {
  constructor(chal, ell, Aq, Bq, Cq, Dq, z_prime) {
    super();

    assert(chal == null || typeof chal === 'bigint');
    assert(ell == null || typeof ell === 'bigint');
    assert(Aq == null || isElement(Aq));
    assert(Bq == null || isElement(Bq));
    assert(Cq == null || isElement(Cq));
    assert(Dq == null || typeof Dq === 'bigint');
    assert(z_prime == null || (z_prime instanceof ZPrime));

    this.chal = chal || 0n;
    this.ell = ell || 0n;
    this.Aq = Aq || ELEMENT;
    this.Bq = Bq || ELEMENT;
    this.Cq = Cq || ELEMENT;
    this.Dq = Dq || 0n;
    this.z_prime = z_prime || new ZPrime();
  }

  getSize() {
    let size = 0;
    size += sizeInt(this.chal);
    size += sizeInt(this.ell);
    size += sizeElement(this.Aq);
    size += sizeElement(this.Bq);
    size += sizeElement(this.Cq);
    size += sizeInt(this.Dq);
    size += this.z_prime.getSize();
    return size;
  }

  write(bw) {
    writeInt(bw, this.chal);
    writeInt(bw, this.ell);
    writeElement(bw, this.Aq);
    writeElement(bw, this.Bq);
    writeElement(bw, this.Cq);
    writeInt(bw, this.Dq);
    this.z_prime.write(bw);
    return bw;
  }

  read(br) {
    this.chal = readInt(br);
    this.ell = readInt(br);
    this.Aq = readElement(br);
    this.Bq = readElement(br);
    this.Cq = readElement(br);
    this.Dq = readInt(br);
    this.z_prime.read(br);
    return this;
  }

  getJSON() {
    return {
      chal: BigMath.encodeHex(this.chal),
      ell: BigMath.encodeHex(this.ell),
      Aq: toJSONEl(this.Aq),
      Bq: toJSONEl(this.Bq),
      Cq: toJSONEl(this.Cq),
      Dq: BigMath.encodeHex(this.Dq),
      z_prime: this.z_prime.getJSON()
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    this.chal = BigMath.decodeHex(json.chal);
    this.ell = BigMath.decodeHex(json.ell);
    this.Aq = fromJSONEl(json.Aq);
    this.Bq = fromJSONEl(json.Bq);
    this.Cq = fromJSONEl(json.Cq);
    this.Dq = BigMath.decodeHex(json.Dq);
    this.z_prime.fromJSON(json.z_prime);
    return this;
  }

  format() {
    return {
      chal: this.chal.toString(16),
      ell: this.ell.toString(16),
      Aq: toStringEl(this.Aq),
      Bq: toStringEl(this.Bq),
      Cq: toStringEl(this.Cq),
      Dq: this.Dq.toString(16),
      z_prime: this.z_prime
    };
  }
}

function sizeInt(num) {
  return 2 + BigMath.size(num);
}

function writeInt(bw, num, allowNeg = false) {
  assert(bw && typeof bw.writeU8 === 'function');
  assert(typeof num === 'bigint');
  assert(typeof allowNeg === 'boolean');

  if (allowNeg && num < 0n) {
    bw.writeU16(0x8000 | BigMath.size(num));
  } else {
    assert(num >= 0n);
    bw.writeU16(BigMath.size(num));
  }

  BigMath.writeBW(bw, num);
}

function readInt(br, allowNeg = false) {
  assert(br && typeof br.readU8 === 'function');
  assert(typeof allowNeg === 'boolean');

  let size = br.readU16();
  let neg = false;

  if (size & 0x8000) {
    if (!allowNeg)
      throw new Error('Invalid size.');
    neg = true;
    size &= ~0x8000;
  }

  let num = BigMath.readBR(br, size);

  if (neg)
    num = -num;

  return num;
}

function sizeElement(x) {
  assert(isElement(x));
  let size = 0;
  size += sizeInt(x[0]);
  size += sizeInt(x[1]);
  size += sizeInt(x[2]);
  return size;
}

function writeElement(bw, x) {
  assert(isElement(x));
  writeInt(bw, x[0], true);
  writeInt(bw, x[1], true);
  writeInt(bw, x[2], true);
  return bw;
}

function readElement(br) {
  return [
    readInt(br, true),
    readInt(br, true),
    readInt(br, true)
  ];
}

function isElement(x) {
  return Array.isArray(x)
      && x.length === 3
      && typeof x[0] === 'bigint'
      && typeof x[1] === 'bigint'
      && typeof x[2] === 'bigint';
}

function toStringEl(x) {
  assert(isElement(x));
  return [
    x[0].toString(16),
    x[1].toString(16),
    x[2].toString(16)
  ];
}

function toJSONEl(x) {
  assert(isElement(x));
  return [
    BigMath.encodeHex(x[0]),
    BigMath.encodeHex(x[1]),
    BigMath.encodeHex(x[2])
  ];
}

function fromJSONEl(x) {
  assert(Array.isArray(x));
  assert(x.length === 3);
  return [
    BigMath.decodeHex(x[0]),
    BigMath.decodeHex(x[1]),
    BigMath.decodeHex(x[2])
  ];
}

exports.Challenge = Challenge;
exports.Proof = Proof;
exports.PublicKey = PublicKey;
exports.Sigma = Sigma;
exports.ZPrime = ZPrime;
exports.ClassChallenge = ClassChallenge;
exports.ClassProof = ClassProof;
exports.ClassPublicKey = ClassPublicKey;
exports.ClassSigma = ClassSigma;
