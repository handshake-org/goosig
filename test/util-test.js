/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint max-len: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('./util/assert');
const random = require('bcrypto/lib/random');
const testUtil = require('./util');
const BigMath = require('../lib/bigmath');
const util = require('../lib/util');
const {HashPRNG} = require('../lib/prng');
const {umod} = BigMath;

describe('Util', function() {
  const rand = new HashPRNG(random.randomBytes(32));
  const [p, q] = rand.sample(testUtil.primes_2048, 2);
  const n = p * q;

  it('should compute invert_modp (p)', () => {
    const r = rand.randrange(p);
    const rInv = util.invert_modp(r, p);

    assert.strictEqual(umod(r * rInv - 1n, p).toString(), 0n.toString());
  });

  it('should compute invert_modp (n)', () => {
    const r2 = rand.randrange(n);
    const r2Inv = util.invert_modp(r2, n);

    assert.strictEqual(umod(r2 * r2Inv - 1n, n).toString(), 0n.toString());
  });

  it('should compute gcd and ext_euclid', () => {
    const r1 = rand.getrandbits(256);
    const r2 = rand.getrandbits(256);
    const d_ = util.gcd(r1, r2);
    const [, , d] = util.ext_euclid_lr(r1, r2);
    const ok1 = d_ === d;

    assert.strictEqual(ok1, true);
  });

  it('should compute ext_euclid (2)', () => {
    const r1 = rand.getrandbits(256);
    const r2 = rand.getrandbits(256);
    const d_ = util.gcd(r1, r2);
    const [r1_e, r2_e, d] = util.ext_euclid_lr(r1, r2);

    const r1d = r1 / d;
    const r2d = r2 / d;
    const [r1d_e, r2d_e, d2] = util.ext_euclid_lr(r1d, r2d);

    const ok1 = d_ === d;
    const ok2 = d === r1 * r1_e + r2 * r2_e
             && d2 === 1n
             && r1d * r1d_e + r2d * r2d_e - 1n === 0n;

    assert.strictEqual(ok1, true);
    assert.strictEqual(ok2, true);
  });

  it('should compute isqrt', () => {
    const r = rand.getrandbits(256);
    const int_sqrtR = util.isqrt(r);
    const ok = int_sqrtR ** 2n <= r && r < (int_sqrtR + 1n) ** 2n;

    assert.strictEqual(ok, true);
  });

  it('should compute sqrt_modp (p)', () => {
    const r1 = umod(rand.randrange(p) ** 2n, p);
    const sqrtR1 = util.sqrt_modp(r1, p);

    assert.strictEqual(umod(sqrtR1 ** 2n, p).toString(), r1.toString());
  });

  it('should compute sqrt_modp (n)', () => {
    const r2 = umod(rand.randrange(n) ** 2n, n);
    const sqrtR2 = util.sqrt_modn(r2, p, q);

    assert.strictEqual(umod(sqrtR2 ** 2n, n).toString(), r2.toString());
  });
});
