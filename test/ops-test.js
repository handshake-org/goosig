/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const util = require('./util');
const BN = require('bcrypto/lib/bn.js');
const rng = require('bcrypto/lib/random');
const constants = require('../lib/internal/constants');
const Goo = require('../lib/js/goo');

describe('Group Ops', function() {
  let t0 = null;
  let t1 = null;
  let t2 = null;

  it('should open contexts', () => {
    const {n} = util.genKey(2048);

    t0 = new Goo(Goo.RSA2048, 2, 3, 0);
    t1 = new Goo(Goo.RSA2048, 2, 3, 2048);
    t2 = new Goo(n, 5, 7, 2048);
  });

  it('should have computed combs (t0)', () => {
    assert.strictEqual(t0.combs.length, 1);

    const g0 = t0.combs[0].g.toJSON();
    const h0 = t0.combs[0].h.toJSON();

    delete g0.items;
    delete h0.items;

    assert.deepStrictEqual(g0, {
      pointsPerAdd: 7,
      addsPerShift: 4,
      shifts: 5,
      bitsPerWindow: 20,
      bits: 140,
      pointsPerSubcomb: 127,
      size: 508
    });

    assert.deepStrictEqual(h0, {
      pointsPerAdd: 7,
      addsPerShift: 4,
      shifts: 5,
      bitsPerWindow: 20,
      bits: 140,
      pointsPerSubcomb: 127,
      size: 508
    });
  });

  it('should have computed combs (t1)', () => {
    assert.strictEqual(t1.combs.length, 2);

    const g0 = t1.combs[0].g.toJSON();
    const h0 = t1.combs[0].h.toJSON();
    const g1 = t1.combs[1].g.toJSON();
    const h1 = t1.combs[1].h.toJSON();

    delete g0.items;
    delete h0.items;
    delete g1.items;
    delete h1.items;

    assert.deepStrictEqual(g0, {
      pointsPerAdd: 8,
      addsPerShift: 2,
      shifts: 128,
      bitsPerWindow: 256,
      bits: 2048,
      pointsPerSubcomb: 255,
      size: 510
    });

    assert.deepStrictEqual(h0, {
      pointsPerAdd: 8,
      addsPerShift: 2,
      shifts: 128,
      bitsPerWindow: 256,
      bits: 2048,
      pointsPerSubcomb: 255,
      size: 510
    });

    assert.deepStrictEqual(g1, {
      pointsPerAdd: 8,
      addsPerShift: 2,
      shifts: 265,
      bitsPerWindow: 530,
      bits: 4240,
      pointsPerSubcomb: 255,
      size: 510
    });

    assert.deepStrictEqual(h1, {
      pointsPerAdd: 8,
      addsPerShift: 2,
      shifts: 265,
      bitsPerWindow: 530,
      bits: 4240,
      pointsPerSubcomb: 255,
      size: 510
    });
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
    const e1 = BN.randomBits(rng, 2 * 2048 + constants.ELL_BITS + 1);
    const e2 = BN.randomBits(rng, 2 * 2048 + constants.ELL_BITS + 1);
    const p1 = new BN(2).powm(e1, t1.n);
    const p2 = new BN(3).powm(e2, t1.n);
    const r1 = p1.mul(p2).mod(t1.n);
    const r2 = t1.powgh(e1, e2);

    assert.strictEqual(r1.toString(), r2.fromRed().toString());
  });

  it('should compute powgh (t2)', () => {
    const e1 = BN.randomBits(rng, 2049);
    const e2 = BN.randomBits(rng, 2049);
    const p1 = new BN(5).powm(e1, t2.n);
    const p2 = new BN(7).powm(e2, t2.n);
    const r1 = p1.mul(p2).mod(t2.n);
    const r2 = t2.powgh(e1, e2);

    assert.strictEqual(r1.toString(), r2.fromRed().toString());
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
    const e1 = BN.randomBits(rng, 512).toRed(t2.red);
    const e2 = BN.randomBits(rng, 512).toRed(t2.red);
    const [e1_si, e2_si] = t2.inv2(e1, e2);
    const r1 = e1.redMul(e1_si);
    const r2 = e2.redMul(e2_si);

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

    for (let i = 0; i < 7; i++) {
      const [e, ei] = [exps[i], invs[i]];
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

    for (let i = 0; i < 7; i++) {
      const [e, ei] = [exps[i], invs[i]];
      const r = e.redMul(ei);

      assert.strictEqual(t2.reduce(r).fromRed().toString(), '1');
    }
  });
});
