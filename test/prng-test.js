/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const PRNG = require('../lib/js/prng');

describe('PRNG', function() {
  it('should generate deterministically random numbers', () => {
    const key = Buffer.alloc(32, 0xaa);
    const rng = PRNG.fromKey(key);
    const x = rng.randomBits(256);

    assert(x.cmpn(0) > 0);
    assert(x.bitLength() <= 256);

    const y = rng.randomInt(x);

    assert(y.cmpn(0) > 0);
    assert(y.bitLength() <= 256);
    assert(y.cmp(x) < 0);

    assert.strictEqual(rng.randomBits(30).toString(), '889224476');
    assert.strictEqual(rng.randomBits(31).toString(), '1264675751');
    assert.strictEqual(rng.randomInt(rng.randomBits(31)).toString(),
                       '768829332');

    assert.strictEqual(rng.randomNum(65537).toString(), '21931');

    const p = rng.randomBits(1024);
    const q = rng.randomBits(1024);
    const s_prime = rng.generate(32);
    const msg = rng.generate(32);
    const rng2 = PRNG.fromSign(p, q, s_prime, msg);

    assert.strictEqual(rng2.randomBits(31).toString(), '1529442110');
  });
});
