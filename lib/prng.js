'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const DRBG = require('bcrypto/lib/drbg');
const BigMath = require('./bigmath');
const defs = require('./defs');
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

    this.prng = new DRBG(defs.Hash, entropy, nonce, PERS);
  }

  sample(pop, k) {
    assert(Array.isArray(pop));
    assert((k >>> 0) === k);
    assert(k <= pop.length);

    const out = [];
    const set = new Set();

    while (out.length < k) {
      const i = Number(this.getrandbits(8)) % pop.length;

      if (set.has(i))
        continue;

      out.push(pop[i]);
      set.add(i);
    }

    return out;
  }

  getrandbits(nbits) {
    assert((nbits >>> 0) === nbits);

    const bytes = (nbits + 7) >>> 3;
    const b = this.prng.generate(bytes);

    if (nbits & 7) {
      b[0] &= (1 << (nbits & 7)) - 1;
      // b[0] |= 1 << ((nbits & 7) - 1);
    }

    return BigMath.decode(b);
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

function *recurse(items) {
  assert(Array.isArray(items));

  for (const item of items) {
    if (Array.isArray(item)) {
      yield *recurse(item);
      continue;
    }
    yield item;
  }
}

function fs_chal(...items) {
  const fs_hash = new defs.Hash();

  fs_hash.init();
  fs_hash.update(PREFIX);

  for (const item of recurse(items))
    fs_hash.update(BigMath.encode(item));

  const prng_key = fs_hash.final();
  const fs_hash_prng = new HashPRNG(prng_key);
  const chal = fs_hash_prng.getrandbits(defs.chalbits);
  const ell = primes.fouque_tibouchi_primegen(defs.ft_prime_opts, fs_hash_prng);

  return [chal, ell];
}

exports.HashPRNG = HashPRNG;
exports.fs_chal = fs_chal;
