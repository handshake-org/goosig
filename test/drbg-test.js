/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */

'use strict';

const assert = require('bsert');
const HmacDRBG = require('bcrypto/lib/hmac-drbg');
const SHA256 = require('bcrypto/lib/sha256');

describe('DRBG', function() {
  it('should generate deterministically random bits', () => {
    const entropy = Buffer.alloc(32, 0xaa);
    const nonce = Buffer.alloc(32, 0xaa);
    const drbg = new HmacDRBG(SHA256, entropy, nonce);

    const h1 = drbg.generate(32);
    const h2 = drbg.generate(16);
    const h3 = drbg.generate(16);

    assert.strictEqual(h1.toString('hex'),
      '40e95c4dba22fd05d15784075b05ca7c0b063a43dcec3307122575a7b5e32d3b');
    assert.strictEqual(h2.toString('hex'),
      '4d065662afc2927a3426c12dd1c35262');
    assert.strictEqual(h3.toString('hex'),
      '705119fd1536e2a7ec804db49f8262ce');
  });
});
