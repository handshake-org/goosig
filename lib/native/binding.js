/*!
 * binding.js - groups of unknown order binding
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

'use strict';

const crypto = require('crypto');
const randomBytes = crypto.randomBytes.bind(crypto);

const binding = require('loady')('goosig', __dirname);

binding.entropy = function entropy() {
  return randomBytes(32);
};

Object.freeze(binding);

module.exports = binding;
