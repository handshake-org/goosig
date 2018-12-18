/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const testUtil = require('./util');
const BigMath = require('../lib/js/bigmath');
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
    const b1 = util.randomBits(2048);
    const b2 = util.randomBits(2048);
    const e1 = util.randomBits(128);
    const e2 = util.randomBits(128);

    const [b1Inv, b2Inv] = t1.inv2(b1, b2);
    const out = BigMath.mod(BigMath.modPow(b1, e1, t1.n)
                          * BigMath.modPow(b2, e2, t1.n), t1.n);
    const to = t1.pow2(b1, b1Inv, e1, b2, b2Inv, e2);

    assert.strictEqual(out, to);
  });

  it('should compute pow2_wnaf (t2)', () => {
    const b1 = util.randomBits(2048);
    const b2 = util.randomBits(2048);
    const e1 = util.randomBits(128);
    const e2 = util.randomBits(128);

    const [b1Inv, b2Inv] = t2.inv2(b1, b2);
    const out = BigMath.mod(BigMath.modPow(b1, e1, t2.n)
                          * BigMath.modPow(b2, e2, t2.n), t2.n);
    const to = t2.pow2(b1, b1Inv, e1, b2, b2Inv, e2);

    assert.strictEqual(out, to);
  });

  it('should compute powgh (t1)', () => {
    const e1 = util.randomBits(2 * 2048 + constants.CHAL_BITS + 2 - 1); // -1
    const e2 = util.randomBits(2 * 2048 + constants.CHAL_BITS + 2 - 1); // -1

    const out = BigMath.mod(BigMath.modPow(2n, e1, t1.n)
                          * BigMath.modPow(3n, e2, t1.n), t1.n);
    const to = t1.powgh(e1, e2);

    assert.strictEqual(out, to);
  });

  it('should compute powgh (t2)', () => {
    const e1 = util.randomBits(2 * 2048 + constants.CHAL_BITS + 2 - 1); // -1
    const e2 = util.randomBits(2 * 2048 + constants.CHAL_BITS + 2 - 1); // -1

    const e1_s = e1 >> BigInt(2048 + constants.CHAL_BITS);
    const e2_s = e2 >> BigInt(2048 + constants.CHAL_BITS);

    const ml = BigMath.modPow(5n, e1_s, t2.n)
             * BigMath.modPow(7n, e2_s, t2.n);
    const out = BigMath.mod(ml, t2.n);
    const to = t2.powgh(e1_s, e2_s);

    assert.strictEqual(out, to);
  });

  it('should compute inv2 (t1)', () => {
    const e1 = util.randomBits(2048);
    const e2 = util.randomBits(2048);

    const [e1Inv, e2Inv] = t1.inv2(e1, e2);

    assert.strictEqual(t1.reduce(BigMath.mod(e1 * e1Inv, t1.n)), 1n);
    assert.strictEqual(t1.reduce(BigMath.mod(e2 * e2Inv, t1.n)), 1n);
  });

  it('should compute inv2 (t2)', () => {
    const e1 = util.randomBits(2048);
    const e2 = util.randomBits(2048);

    const e1_s = e1 >> 1536n;
    const e2_s = e2 >> 1536n;

    const [e1_sInv, e2_sInv] = t2.inv2(e1_s, e2_s);

    assert.strictEqual(t2.reduce(BigMath.mod(e1_s * e1_sInv, t2.n)), 1n);
    assert.strictEqual(t2.reduce(BigMath.mod(e2_s * e2_sInv, t2.n)), 1n);
  });

  it('should compute inv5 (t1)', () => {
    const eVals = [
      util.randomBits(2048),
      util.randomBits(2048),
      util.randomBits(2048),
      util.randomBits(2048),
      util.randomBits(2048)
    ];

    const eInvs = t1.inv5(...eVals);

    for (const [e, eInv] of testUtil.zip(eVals, eInvs))
      assert.strictEqual(t1.reduce(BigMath.mod(e * eInv, t1.n)), 1n);
  });

  it('should compute inv5 (t2)', () => {
    const eVals = [
      util.randomBits(2048),
      util.randomBits(2048),
      util.randomBits(2048),
      util.randomBits(2048),
      util.randomBits(2048)
    ];

    const eInvs = t2.inv5(...eVals);

    for (const [e, eInv] of testUtil.zip(eVals, eInvs))
      assert.strictEqual(t2.reduce(BigMath.mod(e * eInv, t2.n)), 1n);
  });
});
