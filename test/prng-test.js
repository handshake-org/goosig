/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */

'use strict';

const assert = require('./util/assert');
const BigMath = require('../lib/js/bigmath');
const PRNG = require('../lib/js/prng');

describe('PRNG', function() {
  it('should generate deterministically random numbers', () => {
    const key = Buffer.alloc(32, 0xaa);
    const rng = new PRNG(key);
    const x = rng.randomBits(256);

    assert(x > 0n);
    assert(BigMath.bitLength(x) <= 256);

    const y = rng.randomInt(x);

    assert(y > 0n);
    assert(BigMath.bitLength(y) <= 256);
    assert(y < x);

    assert(rng.randomBits(30) === 540405817n);
    assert(rng.randomBits(31) === 1312024779n);
    assert(rng.randomInt(rng.randomBits(31)) === 1679635921n);
  });
});
