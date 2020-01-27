/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const rng = require('bcrypto/lib/random');
const rsa = require('bcrypto/lib/rsa');
const util = require('./util');
const native = require('loady')('goosig', __dirname).Goo;
const Goo = require('../');

describe('RSA', function() {
  it('should encrypt and decrypt', () => {
    for (const bits of [2048, 4096]) {
      for (let i = 0; i < 10; i++) {
        const key = util.genKey(bits);
        const pub = rsa.publicKeyCreate(key);
        const {n, e, p, q} = rsa.privateKeyExport(key);
        const msg = rng.randomBytes(32);
        const ent0 = rng.randomBytes(32);
        const ent1 = rng.randomBytes(32);
        const ent2 = rng.randomBytes(32);
        const ct0 = Goo.encrypt(msg, pub);
        const ct1 = native.encrypt(msg, n, e, ent0);

        assert.bufferEqual(native.decrypt(ct0, p, q, e, ent1), msg);
        assert.bufferEqual(native.decrypt(ct1, p, q, e, ent2), msg);

        assert.bufferEqual(Goo.decrypt(ct0, key), msg);
        assert.bufferEqual(Goo.decrypt(ct1, key), msg);
      }
    }
  });
});
