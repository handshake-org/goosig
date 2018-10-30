/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('./util/assert');
const random = require('bcrypto/lib/random');
const testUtil = require('./util');
const BigMath = require('../lib/bigmath');
const constants = require('../lib/constants');
const Goo = require('../lib/goo');
const PRNG = require('../lib/prng');
const {mod, modPow} = BigMath;

describe('Group Ops', function() {
  this.timeout(10000);

  const rng = new PRNG(random.randomBytes(32));
  const [p, q] = testUtil.sample(testUtil.primes1024, 2);
  const {n} = testUtil.rsaKey(p, q);

  const t1 = new Goo(Goo.RSA2048, 2, 3, 2048);
  const t2 = new Goo(n, 5, 7, 2048);

  it('should compute pow2_wnaf (t1)', () => {
    const [b1, b2, e1, e2] = [
      rng.randomBits(2048),
      rng.randomBits(2048),
      rng.randomBits(2048),
      rng.randomBits(2048)
    ];

    const [b1Inv, b2Inv] = t1.inv2(b1, b2);
    const out = mod(modPow(b1, e1, t1.n) * modPow(b2, e2, t1.n), t1.n);
    const to = t1.pow2(b1, b1Inv, e1, b2, b2Inv, e2);

    assert.strictEqual(out.toString(), to.toString());
  });

  it('should compute pow2_wnaf (t2)', () => {
    const [b1, b2, e1, e2] = [
      rng.randomBits(2048),
      rng.randomBits(2048),
      rng.randomBits(2048),
      rng.randomBits(2048)
    ];

    const [b1Inv, b2Inv] = t2.inv2(b1, b2);
    const out = mod(modPow(b1, e1, t2.n) * modPow(b2, e2, t2.n), t2.n);
    const to = t2.pow2(b1, b1Inv, e1, b2, b2Inv, e2);

    assert.strictEqual(out.toString(), to.toString());
  });

  it('should compute powgh (t1)', () => {
    const [e1, e2] = [
      rng.randomBits(2 * 2048 + constants.CHAL_BITS + 2 - 1), // XXX -1
      rng.randomBits(2 * 2048 + constants.CHAL_BITS + 2 - 1) // XXX -1
    ];

    const out = mod(modPow(2n, e1, t1.n) * modPow(3n, e2, t1.n), t1.n);
    const to = t1.powgh(e1, e2);

    assert.strictEqual(out.toString(), to.toString());
  });

  it('should compute powgh (t2)', () => {
    const [e1, e2] = [
      rng.randomBits(2 * 2048 + constants.CHAL_BITS + 2 - 1), // XXX -1
      rng.randomBits(2 * 2048 + constants.CHAL_BITS + 2 - 1) // XXX -1
    ];

    const [e1_s, e2_s] = [
      e1 >> (2048n + BigInt(constants.CHAL_BITS)),
      e2 >> (2048n + BigInt(constants.CHAL_BITS))
    ];

    const ml = modPow(5n, e1_s, t2.n) * modPow(7n, e2_s, t2.n);
    const out = mod(ml, t2.n);
    const to = t2.powgh(e1_s, e2_s);

    assert.strictEqual(out.toString(), to.toString());
  });

  it('should compute inv2 (t1)', () => {
    const [e1, e2] = [
      rng.randomBits(2048),
      rng.randomBits(2048)
    ];

    const [e1Inv, e2Inv] = t1.inv2(e1, e2);
    const tpass = t1.reduce(mod(e1 * e1Inv, t1.n)) === 1n
               && t1.reduce(mod(e2 * e2Inv, t1.n)) === 1n;

    assert.strictEqual(tpass, true);
  });

  it('should compute inv2 (t2)', () => {
    const [e1, e2] = [
      rng.randomBits(2048),
      rng.randomBits(2048)
    ];

    const [e1_s, e2_s] = [
      e1 >> 1536n,
      e2 >> 1536n
    ];

    const [e1_sInv, e2_sInv] = t2.inv2(e1_s, e2_s);
    const tpass = t2.reduce(mod(e1_s * e1_sInv, t2.n)) === 1n
               && t2.reduce(mod(e2_s * e2_sInv, t2.n)) === 1n;

    assert.strictEqual(tpass, true);
  });

  it('should compute inv5 (t1)', () => {
    const eVals = [
      rng.randomBits(2048),
      rng.randomBits(2048),
      rng.randomBits(2048),
      rng.randomBits(2048),
      rng.randomBits(2048)
    ];

    const eInvs = t1.inv5(...eVals);

    for (const [e, eInv] of testUtil.zip(eVals, eInvs)) {
      const ok = t1.reduce(mod(e * eInv, t1.n)) === 1n;
      assert.strictEqual(ok, true);
    }
  });

  it('should compute inv5 (t2)', () => {
    const eVals = [
      rng.randomBits(2048),
      rng.randomBits(2048),
      rng.randomBits(2048),
      rng.randomBits(2048),
      rng.randomBits(2048)
    ];

    const eInvs = t2.inv5(...eVals);

    for (const [e, eInv] of testUtil.zip(eVals, eInvs)) {
      const ok = t2.reduce(mod(e * eInv, t2.n)) === 1n;
      assert.strictEqual(ok, true);
    }
  });
});
