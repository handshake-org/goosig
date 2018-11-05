/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */

'use strict';

const assert = require('./util/assert');
const BigMath = require('../lib/js/bigmath');
const SHA256 = require('bcrypto/lib/sha256');
const Goo = require('../lib/goo');

const hashes = {
  AOL1: '7bd082427ff18b35c8e2cdb2b848d9c139877a273663d1eeea1d2a3d72b01140',
  AOL2: '1c25b6b4a8e3b684dc828c0922b2359399c36b93f3ebaa6b71a1e412555545ba',
  RSA2048: '6ae9d033c1d76c4f535b5ad5c0073933a0b375b4120a75fbb66be814eab1a9ce',
  RSA617: '8a090bf2cdbf9fac321b2ffb48b75d4d196118fc27d7430dca10c1d06085d448'
};

function digitSum(data) {
  assert(Buffer.isBuffer(data));

  // Digit Sum, used by RSA2048
  const num = BigMath.fromBuffer(data);
  const base10 = num.toString(10);

  let sum = 0;
  for (let i = 0; i < base10.length; i++)
    sum += Number(base10[i]);

  return sum;
}

function primeMod(data) {
  assert(Buffer.isBuffer(data));
  // Prime Checksum, used by RSA617
  const num = BigMath.fromBuffer(data);
  return Number(num % 991889n);
}

describe('Moduli', function() {
  it('should define correct moduli', () => {
    assert.strictEqual(SHA256.digest(Goo.AOL1).toString('hex'), hashes.AOL1);
    assert.strictEqual(SHA256.digest(Goo.AOL2).toString('hex'), hashes.AOL2);
    assert.strictEqual(SHA256.digest(Goo.RSA2048).toString('hex'),
                       hashes.RSA2048);
    assert.strictEqual(SHA256.digest(Goo.RSA617).toString('hex'),
                       hashes.RSA617);
    assert.strictEqual(digitSum(Goo.RSA2048), 2738);
    assert.strictEqual(primeMod(Goo.RSA617), 909408);
  });
});
