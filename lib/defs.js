'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const BLAKE2b256 = require('bcrypto/lib/blakeb256');
const primes = require('./primes');

const Defs = {
  winsize: 6,
  max_rsa_comb_size: 512,
  max_bqf_comb_size: 64,
  hashfn: BLAKE2b256,
  chalbits: 128,
  pdelta: 18,
  ft_prime_opts: null,
  primes: (() => {
    const out = [];

    // primes = list( takewhile(lambda x: x < 1000, lprimes.primes()) )
    for (const p of primes.primes()) {
      if (p >= 1000n)
        break;
      out.push(p);
      // if (out.length === 1000)
      //   break;
    }

    return out;
  })()
};

Defs.ft_prime_opts = primes.gen_ft_prime_opts(Defs.chalbits, Defs.pdelta);

module.exports = Defs;
