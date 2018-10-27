'use strict';

/* eslint camelcase: "off" */

const primes = require('./primes');

const low_primes = [];

const defs = {
  max_rsa_keysize: 4096,
  rand_exponent_size: 2048,
  winsize: 6,
  max_rsa_comb_size: 512,
  max_bqf_comb_size: 64,
  chalbits: 128,
  elldiff_max: 512n,
  get primes() {
    if (low_primes.length === 0) {
      for (const prime of primes.primes()) {
        if (prime >= 1000n)
          break;

        low_primes.push(prime);
      }
    }

    return low_primes;
  }
};

module.exports = defs;
