/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint max-len: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('./util/assert');
const RSAKey = require('../lib/rsa');
const testUtil = require('./util');
const util = require('../lib/util');

describe('RSA', function() {
  this.timeout(10000);

  it('should encrypt and decrypt', () => {
    const [p1, q1] = util.rand.sample(testUtil.primes_1024, 2);
    const [p2, q2] = util.rand.sample(testUtil.primes_2048, 2);

    const r1 = new RSAKey(p1, q1);
    const m1 = util.rand.getrandbits(512);
    const c1 = r1.encrypt(m1);
    const d1 = r1.decrypt(c1);

    const r2 = new RSAKey(p2, q2);
    const m2 = util.rand.getrandbits(512);
    const c2 = r2.encrypt(m2);
    const d2 = r2.decrypt(c2);

    assert.strictEqual(m1.toString(), d1.toString());
    assert.strictEqual(m2.toString(), d2.toString());
  });
});
