/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const testUtil = require('./util');
const BN = require('bcrypto/lib/bn.js');
const rng = require('bcrypto/lib/random');
const constants = require('../lib/internal/constants');
const Goo = require('../lib/js/goo');

describe('Group Ops', function() {
  let t1 = null;
  let t2 = null;

  it('open contexts', () => {
    const {n} = testUtil.genKey(2048);

    t1 = new Goo(Goo.RSA2048, 2, 3, 2048);
    t2 = new Goo(n, 5, 7, 2048);
  });

  it('should compute pow_wnaf (t1)', () => {
    const b = BN.randomBits(rng, 2048).toRed(t1.red);
    const e = BN.randomBits(rng, 4096);
    const r1 = b.redPow(e);
    const bi = t1.inv(b);
    const r2 = t1.pow(b, bi, e);

    assert.strictEqual(r1.fromRed().toString(), r2.fromRed().toString());
  });

  it('should compute pow_wnaf (t2)', () => {
    const b = BN.randomBits(rng, 2048).toRed(t2.red);
    const e = BN.randomBits(rng, 4096);
    const r1 = b.redPow(e);
    const bi = t2.inv(b);
    const r2 = t2.pow(b, bi, e);

    assert.strictEqual(r1.fromRed().toString(), r2.fromRed().toString());
  });

  it('should compute pow2_wnaf (t1)', () => {
    const b1 = BN.randomBits(rng, 2048).toRed(t1.red);
    const b2 = BN.randomBits(rng, 2048).toRed(t1.red);
    const e1 = BN.randomBits(rng, 128);
    const e2 = BN.randomBits(rng, 128);

    const p1 = b1.redPow(e1);
    const p2 = b2.redPow(e2);
    const r1 = p1.redMul(p2);

    const [b1i, b2i] = t1.inv2(b1, b2);
    const r2 = t1.pow2(b1, b1i, e1, b2, b2i, e2);

    assert.strictEqual(r1.fromRed().toString(), r2.fromRed().toString());
  });

  it('should compute pow2_wnaf (t2)', () => {
    const b1 = BN.randomBits(rng, 2048).toRed(t2.red);
    const b2 = BN.randomBits(rng, 2048).toRed(t2.red);
    const e1 = BN.randomBits(rng, 128);
    const e2 = BN.randomBits(rng, 128);

    const p1 = b1.redPow(e1);
    const p2 = b2.redPow(e2);
    const r1 = p1.redMul(p2);

    const [b1i, b2i] = t2.inv2(b1, b2);
    const r2 = t2.pow2(b1, b1i, e1, b2, b2i, e2);

    assert.strictEqual(r1.fromRed().toString(), r2.fromRed().toString());
  });

  it('should compute powgh (t1)', () => {
    const e1 = BN.randomBits(rng, 2 * 2048 + constants.ELL_BITS + 2 - 1); // -1
    const e2 = BN.randomBits(rng, 2 * 2048 + constants.ELL_BITS + 2 - 1); // -1

    const p1 = new BN(2).powm(e1, t1.n);
    const p2 = new BN(3).powm(e2, t1.n);
    const r1 = p1.mul(p2).mod(t1.n);

    const r2 = t1.powgh(e1, e2);

    assert.strictEqual(r1.fromRed().toString(), r2.fromRed().toString());
  });

  it('should compute powgh (t2)', () => {
    const e1 = BN.randomBits(rng, 2 * 2048 + constants.ELL_BITS + 2 - 1); // -1
    const e2 = BN.randomBits(rng, 2 * 2048 + constants.ELL_BITS + 2 - 1); // -1

    const e1_s = e1.ushrn(2048 + constants.ELL_BITS);
    const e2_s = e2.ushrn(2048 + constants.ELL_BITS);

    const p1 = new BN(5).powm(e1_s, t2.n);
    const p2 = new BN(7).powm(e2_s, t2.n);
    const r1 = p1.mul(p2).mod(t2.n);

    const r2 = t2.powgh(e1_s, e2_s);

    assert.strictEqual(r1.fromRed().toString(), r2.fromRed().toString());
  });

  it('should compute inv2 (t1)', () => {
    const e1 = BN.randomBits(rng, 2048).toRed(t1.red);
    const e2 = BN.randomBits(rng, 2048).toRed(t1.red);

    const [e1i, e2i] = t1.inv2(e1, e2);
    const r1 = e1.redMul(e1i);
    const r2 = e2.redMul(e2i);

    assert.strictEqual(t1.reduce(r1).fromRed().toString(), '1');
    assert.strictEqual(t1.reduce(r2).fromRed().toString(), '1');
  });

  it('should compute inv2 (t2)', () => {
    const e1 = BN.randomBits(rng, 2048).toRed(t2.red);
    const e2 = BN.randomBits(rng, 2048).toRed(t2.red);

    const e1_s = e1.ushrn(1536);
    const e2_s = e2.ushrn(1536);

    const [e1_si, e2_si] = t2.inv2(e1_s, e2_s);
    const r1 = e1_s.redMul(e1_si);
    const r2 = e2_s.redMul(e2_si);

    assert.strictEqual(t2.reduce(r1).fromRed().toString(), '1');
    assert.strictEqual(t2.reduce(r2).fromRed().toString(), '1');
  });

  it('should compute inv7 (t1)', () => {
    const exps = [
      BN.randomBits(rng, 2048).toRed(t1.red),
      BN.randomBits(rng, 2048).toRed(t1.red),
      BN.randomBits(rng, 2048).toRed(t1.red),
      BN.randomBits(rng, 2048).toRed(t1.red),
      BN.randomBits(rng, 2048).toRed(t1.red),
      BN.randomBits(rng, 2048).toRed(t1.red),
      BN.randomBits(rng, 2048).toRed(t1.red)
    ];

    const invs = t1.inv7(...exps);

    for (const [e, ei] of testUtil.zip(exps, invs)) {
      const r = e.redMul(ei);
      assert.strictEqual(t1.reduce(r).fromRed().toString(), '1');
    }
  });

  it('should compute inv7 (t2)', () => {
    const exps = [
      BN.randomBits(rng, 2048).toRed(t2.red),
      BN.randomBits(rng, 2048).toRed(t2.red),
      BN.randomBits(rng, 2048).toRed(t2.red),
      BN.randomBits(rng, 2048).toRed(t2.red),
      BN.randomBits(rng, 2048).toRed(t2.red),
      BN.randomBits(rng, 2048).toRed(t2.red),
      BN.randomBits(rng, 2048).toRed(t2.red)
    ];

    const invs = t2.inv7(...exps);

    for (const [e, ei] of testUtil.zip(exps, invs)) {
      const r = e.redMul(ei);
      assert.strictEqual(t2.reduce(r).fromRed().toString(), '1');
    }
  });
});
