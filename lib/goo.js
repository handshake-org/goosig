/*!
 * goo.js - groups of unknown order for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Parts of this software are based on kwantam/libGooPy:
 *   Copyright (c) 2018, Dan Boneh, Riad S. Wahby (Apache License).
 *   https://github.com/kwantam/GooSig
 */

'use strict';

try {
  module.exports = require('./native/goo');
} catch (e) {
  if (typeof BigInt !== 'function')
    throw new Error('goosig: node version must support v8 bigints!');

  module.exports = require('./js/goo');
}
