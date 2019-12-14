/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */

'use strict';

const assert = require('bsert');
const ChaCha20 = require('bcrypto/lib/chacha20');

describe('ChaCha20', function() {
  it('should encrypt bytes', () => {
    const key = Buffer.alloc(32, 0x01);
    const nonce = Buffer.alloc(24, 0x02);
    const out = Buffer.alloc(32, 0x00);
    const ctx = new ChaCha20();

    ctx.init(key, nonce);

    for (let i = 0; i < 1000; i++)
      ctx.encrypt(out);

    assert.bufferEqual(out,
      '018696ef4b939da6006069fb618c097ffe8003276cf409eac3de597a44cb06cd');
  });
});
