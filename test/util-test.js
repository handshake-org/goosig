/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const util = require('../lib/js/util');

describe('Util', function() {
  this.timeout(10000);

  it('should compute sqrt', () => {
    assert.strictEqual(util.dsqrt(1024), 32);
    assert.strictEqual(util.dsqrt(1025), 32);
  });
});
