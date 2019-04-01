/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const testUtil = require('./util');
const BN = require('bcrypto/lib/bn.js');
const constants = require('../lib/internal/constants');
const Goo = require('../lib/js/goo');
const util = require('../lib/js/util');

describe('Group Ops', function() {
  this.timeout(60000);

  let t1 = null;
  let t2 = null;

  it('open contexts', () => {
    const {n} = testUtil.genKey(2048);

    t1 = new Goo(Goo.RSA2048, 2, 3, 2048);
    t2 = new Goo(n, 5, 7, 2048);
  });

  it('should compute pow2_wnaf (t1)', () => {
    const b1 = util.randomBits(2048).toRed(t1.red);
    const b2 = util.randomBits(2048).toRed(t1.red);
    const e1 = util.randomBits(128);
    const e2 = util.randomBits(128);

    const p1 = b1.redPow(e1);
    const p2 = b2.redPow(e2);
    const r1 = p1.redMul(p2);

    const [b1Inv, b2Inv] = t1.inv2(b1, b2);
    const r2 = t1.pow2(b1, b1Inv, e1, b2, b2Inv, e2);

    assert.strictEqual(r1.toString(), r2.toString());
  });

  it('should compute pow2_wnaf (t2)', () => {
    const b1 = util.randomBits(2048).toRed(t2.red);
    const b2 = util.randomBits(2048).toRed(t2.red);
    const e1 = util.randomBits(128);
    const e2 = util.randomBits(128);

    const p1 = b1.redPow(e1);
    const p2 = b2.redPow(e2);
    const r1 = p1.redMul(p2);

    const [b1Inv, b2Inv] = t2.inv2(b1, b2);
    const r2 = t2.pow2(b1, b1Inv, e1, b2, b2Inv, e2);

    assert.strictEqual(r1.toString(), r2.toString());
  });

  it('should compute powgh (t1)', () => {
    const e1 = util.randomBits(2 * 2048 + constants.CHAL_BITS + 2 - 1); // -1
    const e2 = util.randomBits(2 * 2048 + constants.CHAL_BITS + 2 - 1); // -1

    const p1 = new BN(2).powm(e1, t1.n);
    const p2 = new BN(3).powm(e2, t1.n);
    const r1 = p1.mul(p2).umod(t1.n);

    const r2 = t1.powgh(e1, e2);

    assert.strictEqual(r1.toString(), r2.toString());
  });

  it('should compute powgh (t2)', () => {
    const e1 = util.randomBits(2 * 2048 + constants.CHAL_BITS + 2 - 1); // -1
    const e2 = util.randomBits(2 * 2048 + constants.CHAL_BITS + 2 - 1); // -1

    const e1_s = e1.ushrn(2048 + constants.CHAL_BITS);
    const e2_s = e2.ushrn(2048 + constants.CHAL_BITS);

    const p1 = new BN(5).powm(e1_s, t2.n);
    const p2 = new BN(7).powm(e2_s, t2.n);
    const r1 = p1.mul(p2).umod(t2.n);

    const r2 = t2.powgh(e1_s, e2_s);

    assert.strictEqual(r1.toString(), r2.toString());
  });

  it('should compute inv2 (t1)', () => {
    const e1 = util.randomBits(2048).toRed(t1.red);
    const e2 = util.randomBits(2048).toRed(t1.red);

    const [e1Inv, e2Inv] = t1.inv2(e1, e2);
    const r1 = e1.redMul(e1Inv);
    const r2 = e2.redMul(e2Inv);

    assert.strictEqual(t1.reduce(r1).toString(), '1');
    assert.strictEqual(t1.reduce(r2).toString(), '1');
  });

  it('should compute inv2 (t2)', () => {
    const e1 = util.randomBits(2048).toRed(t2.red);
    const e2 = util.randomBits(2048).toRed(t2.red);

    const e1_s = e1.ushrn(1536);
    const e2_s = e2.ushrn(1536);

    const [e1_sInv, e2_sInv] = t2.inv2(e1_s, e2_s);
    const r1 = e1_s.redMul(e1_sInv);
    const r2 = e2_s.redMul(e2_sInv);

    assert.strictEqual(t2.reduce(r1).toString(), '1');
    assert.strictEqual(t2.reduce(r2).toString(), '1');
  });

  it('should compute inv7 (t1)', () => {
    const eVals = [
      util.randomBits(2048).toRed(t1.red),
      util.randomBits(2048).toRed(t1.red),
      util.randomBits(2048).toRed(t1.red),
      util.randomBits(2048).toRed(t1.red),
      util.randomBits(2048).toRed(t1.red),
      util.randomBits(2048).toRed(t1.red),
      util.randomBits(2048).toRed(t1.red)
    ];

    const eInvs = t1.inv7(...eVals);

    for (const [e, eInv] of testUtil.zip(eVals, eInvs)) {
      const r = e.redMul(eInv);
      assert.strictEqual(t1.reduce(r).toString(), '1');
    }
  });

  it('should compute inv7 (t2)', () => {
    const eVals = [
      util.randomBits(2048).toRed(t2.red),
      util.randomBits(2048).toRed(t2.red),
      util.randomBits(2048).toRed(t2.red),
      util.randomBits(2048).toRed(t2.red),
      util.randomBits(2048).toRed(t2.red),
      util.randomBits(2048).toRed(t2.red),
      util.randomBits(2048).toRed(t2.red)
    ];

    const eInvs = t2.inv7(...eVals);

    for (const [e, eInv] of testUtil.zip(eVals, eInvs)) {
      const r = e.redMul(eInv);
      assert.strictEqual(t2.reduce(r).toString(), '1');
    }
  });
});
