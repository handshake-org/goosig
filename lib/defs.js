'use strict';

/* eslint camelcase: "off" */

const primes = require('./primes');

const defs = {
  max_rsa_keysize: 4096,
  rand_exponent_size: 2048,
  winsize: 6,
  max_rsa_comb_size: 512,
  max_bqf_comb_size: 64,
  chalbits: 128,
  elldiff_max: 512n,
  primes: (() => {
    const out = [];

    for (const prime of primes.primes()) {
      if (prime >= 1000n)
        break;

      out.push(prime);
    }

    return out;
  })()
};

module.exports = defs;
