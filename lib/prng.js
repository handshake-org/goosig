'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const DRBG = require('bcrypto/lib/drbg');
const bm = require('./bigmath');
const Defs = require('./defs');
const primes = require('./primes');
const util = require('./util');

const PREFIX = Buffer.from('libGooPy:', 'binary');
const PERS = Buffer.from('libGooPy_prng', 'binary');

class HashPRNG {
  constructor(prng_key) {
    assert(Buffer.isBuffer(prng_key));
    assert(prng_key.length === 32);

    const entropy = prng_key.slice(0, 24);
    const nonce = prng_key.slice(24, 32);

    this.prng = new DRBG(Defs.hashfn, entropy, nonce, PERS);
  }

  getrandbits(nbits) {
    assert((nbits >>> 0) === nbits);

    const bytes = (nbits + 7) >>> 3;
    const b = this.prng.generate(bytes);

    b[0] &= (1 << (nbits & 7)) - 1;

    // if (nbits & 7)
    //   b[0] |= 1 << ((nbits & 7) - 1);

    return bm.decode(b);
  }

  _randrange(maxval) {
    const nbits = util.clog2(maxval);

    let ret = maxval;

    while (ret >= maxval)
      ret = this.getrandbits(nbits);

    return ret;
  }

  randrange(start, stop = null) {
    assert(stop == null || (typeof start === typeof stop));

    if (stop == null)
      return this._randrange(start);

    if (stop <= start)
      throw new Error('require stop > start in randrange(start, stop)');

    return start + this._randrange(stop - start);
  }
}

function fs_chal(...args) {
  const fs_hash = new Defs.hashfn();

  fs_hash.update(PREFIX);

  for (const arg of args)
    fs_hash.update(bm.encode(arg));

  const prng_key = fs_hash.final();
  const fs_hash_prng = new HashPRNG(prng_key);
  const chal = fs_hash_prng.getrandbits(Defs.chalbits);
  const ell = primes.fouque_tibouchi_primegen(Defs.ft_prime_opts, fs_hash_prng);

  return [chal, ell];
}

exports.HashPRNG = HashPRNG;
exports.fs_chal = fs_chal;
