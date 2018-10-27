'use strict';

/* eslint camelcase: "off" */

const primes = require('./primes');

const defs = {
  winsize: 6,
  max_rsa_comb_size: 512,
  max_bqf_comb_size: 64,
  chalbits: 128,
  pdelta: 18,
  ft_prime_opts: null,
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

defs.ft_prime_opts = primes.gen_ft_prime_opts(defs.chalbits, defs.pdelta);

module.exports = defs;
