/*!
 * binding.js - groups of unknown order binding
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

'use strict';

if (process.env.NODE_BACKEND && process.env.NODE_BACKEND !== 'native')
  throw new Error('Non-native backend selected.');

const crypto = require('crypto');
const binding = require('loady')('goosig', __dirname);
const randomBytes = crypto.randomBytes.bind(crypto);

binding.entropy = function entropy() {
  return randomBytes(32);
};

Object.freeze(binding);

module.exports = binding;
