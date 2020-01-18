/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const rng = require('bcrypto/lib/random');
const util = require('./util');
const native = require('loady')('goosig', __dirname).Goo;
const Goo = require('../');

describe('RSA', function() {
  it('should encrypt and decrypt', () => {
    for (const bits of [2048, 4096]) {
      for (let i = 0; i < 10; i++) {
        const key = util.genKey(bits);
        const msg = rng.randomBytes(32);
        const ent0 = rng.randomBytes(32);
        const ent1 = rng.randomBytes(32);
        const ent2 = rng.randomBytes(32);
        const ct0 = Goo.encrypt(msg, key);
        const ct1 = native.encrypt(msg, key.n, key.e, ent0);

        assert.bufferEqual(native.decrypt(ct0, key.p, key.q, key.e, ent1), msg);
        assert.bufferEqual(native.decrypt(ct1, key.p, key.q, key.e, ent2), msg);

        assert.bufferEqual(Goo.decrypt(ct0, key), msg);
        assert.bufferEqual(Goo.decrypt(ct1, key), msg);
      }
    }
  });
});
