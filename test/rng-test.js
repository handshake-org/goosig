/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */

'use strict';

const assert = require('bsert');
const BigMath = require('../lib/js/bigmath');
const util = require('../lib/js/util');

describe('RNG', function() {
  it('should generate random numbers', () => {
    const rng = util.rand;
    const x = rng.randomBits(256);

    assert(x > 0n);
    assert(BigMath.bitLength(x) <= 256);

    const y = rng.randomInt(x);

    assert(y > 0n);
    assert(BigMath.bitLength(y) <= 256);
    assert(y < x);
  });
});
