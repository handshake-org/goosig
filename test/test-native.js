'use strict';

if (process.env.NODE_BACKEND && process.env.NODE_BACKEND !== 'native')
  return;

const {Goo} = require('../lib/native/binding');

if (Goo.test)
  Goo.test();
