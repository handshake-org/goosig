/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint max-len: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('./util/assert');
const random = require('bcrypto/lib/random');
const testUtil = require('./util');
const BigMath = require('../lib/bigmath');
const consts = require('../lib/consts');
const defs = require('../lib/defs');
const ops = require('../lib/ops');
const util = require('../lib/util');
const {HashPRNG} = require('../lib/prng');
const {umod, modPow} = BigMath;

describe('Group Ops', function() {
  this.timeout(10000);

  const rand = new HashPRNG(random.randomBytes(32));
  const [p, q] = rand.sample(testUtil.primes_1024, 2);
  const n = p * q;
  const Grandom = consts.gen_RSA_group_obj(n, 5n, 7n);

  const t1 = new ops.RSAGroupOps(consts.Grsa2048, 2048);
  const t2 = new ops.RSAGroupOps(Grandom, 2048);

  it('should compute pow2_wnaf (t1)', () => {
    const [b1, b2, e1, e2] = [
      rand.getrandbits(2048),
      rand.getrandbits(2048),
      rand.getrandbits(2048),
      rand.getrandbits(2048)
    ];

    const [b1Inv, b2Inv] = t1.inv2(b1, b2);
    const out = umod(modPow(b1, e1, t1.n) * modPow(b2, e2, t1.n), t1.n);
    const to = t1.pow2(b1, b1Inv, e1, b2, b2Inv, e2);

    assert.strictEqual(out.toString(), to.toString());
  });

  it('should compute pow2_wnaf (t2)', () => {
    const [b1, b2, e1, e2] = [
      rand.getrandbits(2048),
      rand.getrandbits(2048),
      rand.getrandbits(2048),
      rand.getrandbits(2048)
    ];

    const [b1Inv, b2Inv] = t2.inv2(b1, b2);
    const out = umod(modPow(b1, e1, t2.n) * modPow(b2, e2, t2.n), t2.n);
    const to = t2.pow2(b1, b1Inv, e1, b2, b2Inv, e2);

    assert.strictEqual(out.toString(), to.toString());
  });

  it('should compute powgh (t1)', () => {
    const [e1, e2] = [
      rand.getrandbits(2 * 2048 + defs.chalbits + 2 - 1), // XXX -1
      rand.getrandbits(2 * 2048 + defs.chalbits + 2 - 1) // XXX -1
    ];

    const out = umod(modPow(2n, e1, t1.n) * modPow(3n, e2, t1.n), t1.n);
    const to = t1.powgh(e1, e2);

    assert.strictEqual(out.toString(), to.toString());
  });

  it('should compute powgh (t2)', () => {
    const [e1, e2] = [
      rand.getrandbits(2 * 2048 + defs.chalbits + 2 - 1), // XXX -1
      rand.getrandbits(2 * 2048 + defs.chalbits + 2 - 1) // XXX -1
    ];

    const [e1_s, e2_s] = [
      e1 >> (2048n + BigInt(defs.chalbits)),
      e2 >> (2048n + BigInt(defs.chalbits))
    ];

    const ml = modPow(5n, e1_s, t2.n) * modPow(7n, e2_s, t2.n);
    const out = umod(ml, t2.n);
    const to = t2.powgh(e1_s, e2_s);

    assert.strictEqual(out.toString(), to.toString());
  });

  it('should compute inv2 (t1)', () => {
    const [e1, e2] = [
      rand.getrandbits(2048),
      rand.getrandbits(2048)
    ];

    const [e1Inv, e2Inv] = t1.inv2(e1, e2);
    const tpass = t1.reduce(umod(e1 * e1Inv, t1.n)) === 1n
               && t1.reduce(umod(e2 * e2Inv, t1.n)) === 1n;

    assert.strictEqual(tpass, true);
  });

  it('should compute inv2 (t2)', () => {
    const [e1, e2] = [
      rand.getrandbits(2048),
      rand.getrandbits(2048)
    ];

    const [e1_s, e2_s] = [
      e1 >> 1536n,
      e2 >> 1536n
    ];

    const [e1_sInv, e2_sInv] = t2.inv2(e1_s, e2_s);
    const tpass = t2.reduce(umod(e1_s * e1_sInv, t2.n)) === 1n
               && t2.reduce(umod(e2_s * e2_sInv, t2.n)) === 1n;

    assert.strictEqual(tpass, true);
  });

  it('should compute inv5 (t1)', () => {
    const eVals = [
      rand.getrandbits(2048),
      rand.getrandbits(2048),
      rand.getrandbits(2048),
      rand.getrandbits(2048),
      rand.getrandbits(2048)
    ];

    const eInvs = t1.inv5(...eVals);

    for (const [e, eInv] of util.zip(eVals, eInvs)) {
      const ok = t1.reduce(umod(e * eInv, t1.n)) === 1n;
      assert.strictEqual(ok, true);
    }
  });

  it('should compute inv5 (t2)', () => {
    const eVals = [
      rand.getrandbits(2048),
      rand.getrandbits(2048),
      rand.getrandbits(2048),
      rand.getrandbits(2048),
      rand.getrandbits(2048)
    ];

    const eInvs = t2.inv5(...eVals);

    for (const [e, eInv] of util.zip(eVals, eInvs)) {
      const ok = t2.reduce(umod(e * eInv, t2.n)) === 1n;
      assert.strictEqual(ok, true);
    }
  });
});
