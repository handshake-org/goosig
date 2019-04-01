/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */

'use strict';

const assert = require('bsert');
const random = require('bcrypto/lib/random');
const RNG = require('../lib/js/rng');

describe('RNG', function() {
  it('should generate random numbers', () => {
    const rng = new RNG({
      generate: size => random.randomBytes(size)
    });

    const x = rng.randomBits(256);

    assert(x.cmpn(0) > 0);
    assert(x.bitLength() <= 256);

    const y = rng.randomInt(x);

    assert(y.cmpn(0) > 0);
    assert(y.bitLength() <= 256);
    assert(y.cmp(x) < 0);
  });
});
