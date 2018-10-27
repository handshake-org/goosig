'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const SHA256 = require('bcrypto/lib/sha256');
const DRBG = require('bcrypto/lib/drbg');
const BigMath = require('./bigmath');
const defs = require('./defs');
const primes = require('./primes');
const util = require('./util');

const PREFIX = Buffer.from('libGooPy:', 'binary');
const PERS = Buffer.from('libGooPy_prng', 'binary');
const NONCE = Buffer.alloc(32, 0x00);

class HashPRNG {
  constructor(prng_key) {
    assert(Buffer.isBuffer(prng_key));
    assert(prng_key.length === 32);

    this.drbg = new DRBG(SHA256, prng_key, NONCE, PERS);
    this.r_save = 0n;
  }

  _next_rand() {
    return BigMath.decode(this.drbg.generate(32));
  }

  getrandbits(nbits) {
    assert((nbits >>> 0) === nbits);

    let r = this.r_save;
    let b = BigMath.bitLength(r);

    while (b < nbits) {
      r <<= 256n;
      r += this._next_rand();
      b += 256;
    }

    const left = BigInt(b - nbits);

    this.r_save = r & ((1n << left) - 1n);

    r >>= left;

    return r;
  }

  _randrange(maxval) {
    if (typeof maxval === 'number')
      maxval = BigInt(maxval);

    assert(typeof maxval === 'bigint');

    const nbits = util.clog2(maxval);

    let ret = maxval;

    while (ret >= maxval)
      ret = this.getrandbits(nbits);

    return ret;
  }

  randrange(start, stop = null) {
    assert(stop == null || (typeof start === typeof stop));
    assert(typeof start === 'number' || typeof start === 'bigint');

    if (stop == null)
      return this._randrange(start);

    if (stop <= start)
      throw new Error('require stop > start in randrange(start, stop)');

    return start + this._randrange(stop - start);
  }

  sample(pop, k) {
    assert(Array.isArray(pop));
    assert((k >>> 0) === k);
    assert(k <= pop.length);

    const out = [];
    const set = new Set();

    while (out.length < k) {
      const i = Number(this.getrandbits(32)) % pop.length;

      if (set.has(i))
        continue;

      out.push(pop[i]);
      set.add(i);
    }

    return out;
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
  const fs_hash = new SHA256();

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
