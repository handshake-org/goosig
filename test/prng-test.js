/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */

'use strict';

const assert = require('bsert');
const PRNG = require('../lib/js/prng');

describe('PRNG', function() {
  it('should generate deterministically random numbers', () => {
    const key = Buffer.alloc(32, 0xaa);
    const rng = new PRNG(key);
    const x = rng.randomBits(256);

    assert(x.cmpn(0) > 0);
    assert(x.bitLength() <= 256);

    const y = rng.randomInt(x);

    assert(y.cmpn(0) > 0);
    assert(y.bitLength() <= 256);
    assert(y.cmp(x) < 0);

    assert.strictEqual(rng.randomBits(30).toString(), '660784431');
    assert.strictEqual(rng.randomBits(31).toString(), '2044965173');
    assert.strictEqual(rng.randomInt(rng.randomBits(31)).toString(),
                       '196040056');
  });
});
