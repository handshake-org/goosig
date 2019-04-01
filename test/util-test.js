/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const BN = require('bcrypto/lib/bn.js');
const testUtil = require('./util');
const BigMath = require('../lib/js/bigmath');
const util = require('../lib/js/util');

function modPowBN(x, y, m) {
  x = BigMath.toBN(BN, x);
  y = BigMath.toBN(BN, y);
  m = BigMath.toBN(BN, m);
  x = x.toRed(BN.red(m)).redPow(y);
  return BigMath.fromBN(x.fromRed());
}

function modInverse(x, m) {
  x = BigMath.toBN(BN, x);
  m = BigMath.toBN(BN, m);
  x = x.invm(m);
  return BigMath.fromBN(x);
}

const symbols = [
  [0, 1, 1],
  [0, -1, 1],
  [1, 1, 1],
  [1, -1, 1],
  [0, 5, 0],
  [1, 5, 1],
  [2, 5, -1],
  [-2, 5, -1],
  [2, -5, -1],
  [-2, -5, 1],
  [3, 5, -1],
  [5, 5, 0],
  [-5, 5, 0],
  [6, 5, 1],
  [6, -5, 1],
  [-6, 5, 1],
  [-6, -5, -1]
];

describe('Util', function() {
  this.timeout(10000);

  const MAX_SAFE_INTEGER = BigInt(Number.MAX_SAFE_INTEGER);

  const [p_, q_] = testUtil.sample(testUtil.primes2048, 2);
  const [p, q] = [BigMath.decode(p_), BigMath.decode(q_)];
  const n = p * q;

  it('should do assert.bigInt', () => {
    assert.throws(() => {
      assert.strictEqual(1n, 0n);
    });

    assert.throws(() => {
      assert.notStrictEqual(0n, 0n);
    });
  });

  it('should toNumber and fromNumber', () => {
    assert.strictEqual(BigMath.toNumber(1234567890n), 1234567890);
    assert.strictEqual(BigMath.toNumber(-1234567890n), -1234567890);
    assert.strictEqual(BigMath.toNumber(0x1234567890n), 0x1234567890);
    assert.strictEqual(BigMath.toNumber(-0x1234567890n), -0x1234567890);
    assert.strictEqual(BigMath.fromNumber(1234567890), 1234567890n);
    assert.strictEqual(BigMath.fromNumber(-1234567890), -1234567890n);
    assert.strictEqual(BigMath.fromNumber(0x1234567890), 0x1234567890n);
    assert.strictEqual(BigMath.fromNumber(-0x1234567890), -0x1234567890n);

    assert.throws(() => BigMath.toNumber(-MAX_SAFE_INTEGER - 1n));
    assert.throws(() => BigMath.toNumber(MAX_SAFE_INTEGER + 1n));
    assert.doesNotThrow(() => BigMath.toNumber(-MAX_SAFE_INTEGER));
    assert.doesNotThrow(() => BigMath.toNumber(MAX_SAFE_INTEGER));
  });

  it('should toDouble and toDouble', () => {
    assert.strictEqual(BigMath.toDouble(1234567890n), 1234567890);
    assert.strictEqual(BigMath.toDouble(-1234567890n), -1234567890);
    assert.strictEqual(BigMath.toDouble(0x1234567890n), 0x1234567890);
    assert.strictEqual(BigMath.toDouble(-0x1234567890n), -0x1234567890);
    assert.strictEqual(BigMath.fromDouble(1234567890), 1234567890n);
    assert.strictEqual(BigMath.fromDouble(-1234567890), -1234567890n);
    assert.strictEqual(BigMath.fromDouble(0x1234567890), 0x1234567890n);
    assert.strictEqual(BigMath.fromDouble(-0x1234567890), -0x1234567890n);

    assert.doesNotThrow(() => BigMath.toDouble(-MAX_SAFE_INTEGER - 1n));
    assert.doesNotThrow(() => BigMath.toDouble(MAX_SAFE_INTEGER + 1n));
  });

  it('should toString and fromString', () => {
    assert.strictEqual(BigMath.toString(1234567890n, 10), '1234567890');
    assert.strictEqual(BigMath.toString(-1234567890n, 10), '-1234567890');
    assert.strictEqual(BigMath.fromString('1234567890', 10), 1234567890n);
    assert.strictEqual(BigMath.fromString('-1234567890', 10), -1234567890n);
    assert.strictEqual(BigMath.toString(0x1234567890n, 16), '1234567890');
    assert.strictEqual(BigMath.toString(-0x1234567890n, 16), '-1234567890');
    assert.strictEqual(BigMath.fromString('1234567890', 16), 0x1234567890n);
    assert.strictEqual(BigMath.fromString('-1234567890', 16), -0x1234567890n);

    assert.strictEqual(BigMath.toString(0xabcdef1234n, 16), 'abcdef1234');
    assert.strictEqual(BigMath.toString(-0xabcdef1234n, 16), '-abcdef1234');
    assert.strictEqual(BigMath.fromString('abcdef1234', 16), 0xabcdef1234n);
    assert.strictEqual(BigMath.fromString('-abcdef1234', 16), -0xabcdef1234n);

    assert.strictEqual(BigMath.toString(123456789n, 10, 2), '0123456789');
    assert.strictEqual(BigMath.toString(-123456789n, 10, 2), '-0123456789');
    assert.strictEqual(BigMath.toString(0x123456789n, 16, 2), '0123456789');
    assert.strictEqual(BigMath.toString(-0x123456789n, 16, 2), '-0123456789');
  });

  it('should toJSON and fromJSON', () => {
    assert.strictEqual(BigMath.toJSON(0x1234567890n), '1234567890');
    assert.strictEqual(BigMath.toJSON(-0x1234567890n), '-1234567890');
    assert.strictEqual(BigMath.fromJSON('1234567890'), 0x1234567890n);
    assert.strictEqual(BigMath.fromJSON('-1234567890'), -0x1234567890n);
    assert.strictEqual(BigMath.toJSON(0x123456789n), '0123456789');
    assert.strictEqual(BigMath.toJSON(-0x123456789n), '-0123456789');
    assert.strictEqual(BigMath.fromJSON('0123456789'), 0x123456789n);
    assert.strictEqual(BigMath.fromJSON('-0123456789'), -0x123456789n);
  });

  it('should toBuffer and fromBuffer', () => {
    assert.bufferEqual(BigMath.toBuffer(0x1234567890n),
                       new BN(0x1234567890).toBuffer());
    assert.strictEqual(BigMath.fromBuffer(new BN(0x1234567890).toBuffer()),
                       0x1234567890n);
  });

  it('should toBN and fromBN', () => {
    assert.strictEqual(BigMath.fromBN(new BN(0x1234567890)), 0x1234567890n);
    assert.strictEqual(BigMath.fromBN(new BN(-0x1234567890)), -0x1234567890n);
    assert(BigMath.toBN(BN, 0x1234567890n).eq(new BN(0x1234567890)));
    assert(BigMath.toBN(BN, -0x1234567890n).eq(new BN(-0x1234567890)));
  });

  it('should count bits and zero bits', () => {
    assert.strictEqual(BigMath.zeroBits(0x010001n), 0);
    assert.strictEqual(BigMath.bitLength(0x010001n), 17);
    assert.strictEqual(BigMath.zeroBits(-0x010001n), 0);
    assert.strictEqual(BigMath.bitLength(-0x010001n), 17);
    assert.strictEqual(BigMath.zeroBits(0x20000n), 17);
    assert.strictEqual(BigMath.bitLength(0x20000n), 18);
    assert.strictEqual(BigMath.zeroBits(-0x20000n), 17);
    assert.strictEqual(BigMath.bitLength(-0x20000n), 18);
  });

  it('should compute sqrt', () => {
    assert.strictEqual(util.isqrt(1024n), 32n);
    assert.strictEqual(util.isqrt(1025n), 32n);
    assert.strictEqual(util.dsqrt(1024), 32);
    assert.strictEqual(util.dsqrt(1025), 32);
  });

  it('should compute division', () => {
    assert.strictEqual(3n / -2n, -1n);
    assert.strictEqual(-3n / 2n, -1n);
    assert.strictEqual(BigMath.div(3n, -2n), -2n);
    assert.strictEqual(BigMath.div(-3n, 2n), -2n);
    assert.strictEqual(BigMath.div(4n, -2n), -2n);
    assert.strictEqual(BigMath.div(-4n, 2n), -2n);
  });

  it('should compute modulo', () => {
    assert.strictEqual(3n % -2n, 1n);
    assert.strictEqual(-3n % 2n, -1n);
    assert.strictEqual(BigMath.mod(3n, -2n), -1n);
    assert.strictEqual(BigMath.mod(-3n, 2n), 1n);
    assert.strictEqual(BigMath.mod(4n, -2n), 0n);
    assert.strictEqual(BigMath.mod(-4n, 2n), 0n);
  });

  it('should compute mod_pow', () => {
    for (let i = 0; i < 50; i++) {
      const x = util.randomBits(768);
      const y = util.randomBits(33);
      const m = util.randomBits(1024);

      assert.strictEqual(BigMath.modPow(x, y, m), modPowBN(x, y, m));
    }
  });

  it('should compute invert_modp (p)', () => {
    const r = util.randomInt(p);
    const rInv = util.modInverseP(r, p);

    assert.strictEqual(BigMath.mod(r * rInv - 1n, p), 0n);
    assert.strictEqual(rInv, modInverse(r, p));
  });

  it('should compute invert_modp (n)', () => {
    const r2 = util.randomInt(n);
    const r2Inv = util.modInverseP(r2, n);

    assert.strictEqual(BigMath.mod(r2 * r2Inv - 1n, n), 0n);
    assert.strictEqual(r2Inv, modInverse(r2, n));
  });

  it('should compute gcd and ext_euclid', () => {
    const r1 = util.randomBits(256);
    const r2 = util.randomBits(256);
    const d_ = util.gcd(r1, r2);
    const [, , d] = util.euclidLR(r1, r2);

    assert.strictEqual(d_, d);
  });

  it('should compute ext_euclid', () => {
    const r1 = util.randomBits(256);
    const r2 = util.randomBits(256);
    const d_ = util.gcd(r1, r2);
    const [r1_e, r2_e, d] = util.euclidLR(r1, r2);

    const r1d = r1 / d;
    const r2d = r2 / d;
    const [r1d_e, r2d_e, d2] = util.euclidLR(r1d, r2d);

    assert.strictEqual(d_, d);
    assert.strictEqual(d, r1 * r1_e + r2 * r2_e);
    assert.strictEqual(d2, 1n);
    assert.strictEqual(r1d * r1d_e + r2d * r2d_e - 1n, 0n);
  });

  it('should compute isqrt', () => {
    const r = util.randomBits(256);
    const int_sqrtR = util.isqrt(r);

    assert(int_sqrtR ** 2n <= r);
    assert(r < (int_sqrtR + 1n) ** 2n);
  });

  it('should compute sqrt_modp', () => {
    const r1 = BigMath.mod(util.randomInt(p) ** 2n, p);
    const sqrtR1 = util.modSqrtP(r1, p);

    assert.strictEqual(BigMath.mod(sqrtR1 ** 2n, p), r1);
  });

  it('should compute sqrt_modn', () => {
    const r2 = BigMath.mod(util.randomInt(n) ** 2n, n);
    const sqrtR2 = util.modSqrtN(r2, p, q);

    assert.strictEqual(BigMath.mod(sqrtR2 ** 2n, n), r2);
  });

  for (const [x, y, z] of symbols) {
    it(`should compute jacobi symbol for: ${x}, ${y}`, () => {
      const xx = BigInt(x);
      const yy = BigInt(y);
      const zz = z;

      assert.strictEqual(util.jacobi(xx, yy), zz);
    });
  }
});
