/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */

'use strict';

const assert = require('bsert');
const Goo = require('../');

describe('GooSig', function() {
  it('should have correct environment', () => {
    switch (process.env.NODE_BACKEND) {
      case 'js':
      case 'node':
        assert.strictEqual(Goo.native, 0);
        break;
      case 'native':
      default:
        assert.strictEqual(Goo.native, 2);
        break;
    }
  });
});
