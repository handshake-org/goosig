/*!
 * goo.js - groups of unknown order for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Parts of this software are based on kwantam/libGooPy:
 *   Copyright (c) 2018, Dan Boneh, Riad S. Wahby (Apache License).
 *   https://github.com/kwantam/GooSig
 */

'use strict';

if (process.env.NODE_BACKEND === 'js')
  module.exports = require('./js/goo');
else
  module.exports = require('./native/goo');
