/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('./util/assert');
const BN = require('bcrypto/lib/bn.js');
const testUtil = require('./util');
const BigMath = require('../lib/js/bigmath');
const util = require('../lib/js/util');
const {mod, modPow, encode, decode} = BigMath;

function modPowBN(x, y, m) {
  x = new BN(encode(x));
  y = new BN(encode(y));
  m = new BN(encode(m));
  return decode(x.toRed(BN.red(m)).redPow(y).fromRed().toArrayLike(Buffer));
}

function modInverse(x, m) {
  x = new BN(encode(x));
  m = new BN(encode(m));
  return new BN(x.invm(m).toArrayLike(Buffer));
}

describe('Util', function() {
  this.timeout(10000);

  const [p_, q_] = testUtil.sample(testUtil.primes2048, 2);
  const [p, q] = [decode(p_), decode(q_)];
  const n = p * q;

  it('should compute sqrt', () => {
    assert.strictEqual(util.isqrt(1024n).toString(), (32n).toString());
    assert.strictEqual(util.isqrt(1025n).toString(), (32n).toString());
    assert.strictEqual(util.dsqrt(1024), 32);
    assert.strictEqual(util.dsqrt(1025), 32);
  });

  it('should compute mod_pow', () => {
    const x = util.randomBits(768);
    const y = util.randomBits(33);
    const m = util.randomBits(1024);

    for (let i = 0; i < 50; i++) {
      assert.strictEqual(modPow(x, y, m).toString(),
                         modPowBN(x, y, m).toString());
    }
  });

  it('should compute invert_modp (p)', () => {
    const r = util.randomInt(p);
    const rInv = util.modInverseP(r, p);

    assert.strictEqual(mod(r * rInv - 1n, p).toString(), (0n).toString());
    assert.strictEqual(rInv.toString(), modInverse(r, p).toString());
  });

  it('should compute invert_modp (n)', () => {
    const r2 = util.randomInt(n);
    const r2Inv = util.modInverseP(r2, n);

    assert.strictEqual(mod(r2 * r2Inv - 1n, n).toString(), (0n).toString());
    assert.strictEqual(r2Inv.toString(), modInverse(r2, n).toString());
  });

  it('should compute gcd and ext_euclid', () => {
    const r1 = util.randomBits(256);
    const r2 = util.randomBits(256);
    const d_ = util.gcd(r1, r2);
    const [, , d] = util.euclidLR(r1, r2);
    const ok1 = d_ === d;

    assert.strictEqual(ok1, true);
  });

  it('should compute ext_euclid', () => {
    const r1 = util.randomBits(256);
    const r2 = util.randomBits(256);
    const d_ = util.gcd(r1, r2);
    const [r1_e, r2_e, d] = util.euclidLR(r1, r2);

    const r1d = r1 / d;
    const r2d = r2 / d;
    const [r1d_e, r2d_e, d2] = util.euclidLR(r1d, r2d);

    const ok1 = d_ === d;
    const ok2 = d === r1 * r1_e + r2 * r2_e
             && d2 === 1n
             && r1d * r1d_e + r2d * r2d_e - 1n === 0n;

    assert.strictEqual(ok1, true);
    assert.strictEqual(ok2, true);
  });

  it('should compute isqrt', () => {
    const r = util.randomBits(256);
    const int_sqrtR = util.isqrt(r);
    const ok = int_sqrtR ** 2n <= r && r < (int_sqrtR + 1n) ** 2n;

    assert.strictEqual(ok, true);
  });

  it('should compute sqrt_modp', () => {
    const r1 = mod(util.randomInt(p) ** 2n, p);
    const sqrtR1 = util.modSqrtP(r1, p);

    assert.strictEqual(mod(sqrtR1 ** 2n, p).toString(), r1.toString());
  });

  it('should compute sqrt_modn', () => {
    const r2 = mod(util.randomInt(n) ** 2n, n);
    const sqrtR2 = util.modSqrtN(r2, p, q);

    assert.strictEqual(mod(sqrtR2 ** 2n, n).toString(), r2.toString());
  });
});
