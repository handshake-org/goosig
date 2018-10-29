'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const SHA256 = require('bcrypto/lib/sha256');
const BigMath = require('./bigmath');
const defs = require('./defs');
const primes = require('./primes');
const RNG = require('./rng');

const PREFIX = Buffer.from('libGooPy:', 'binary');
const PERS = Buffer.from('libGooPy_prng', 'binary');
const NONCE = Buffer.alloc(32, 0x00);
const POOL = Buffer.alloc(2, 0x00);

class DRBG {
  constructor(hash, key, nonce, pers) {
    assert(hash && typeof hash.digest === 'function');
    assert(Buffer.isBuffer(key));
    assert(key.length === 32);
    assert(Buffer.isBuffer(nonce));
    assert(!pers || Buffer.isBuffer(pers));

    const state = Buffer.alloc(64, 0x00);

    PERS.copy(state, 0);
    key.copy(state, 32);

    for (let i = 0; i < 32; i++)
      state[i] ^= key[i];

    this.hash = hash;
    this.state = state;
  }

  generate(size) {
    assert((size >>> 0) === size);

    for (let i = 0; i < 32; i++) {
      this.state[i] += 1;
      if (this.state[i] !== 0)
        break;
    }

    const out = this.hash.digest(this.state);

    out.copy(this.state, 32);

    return out;
  }
}

class HashPRNG extends RNG {
  constructor(prng_key) {
    super(new DRBG(SHA256, prng_key, NONCE, PERS));
  }
}

function hash_all(...items) {
  const fs_hash = new SHA256();
  const size = POOL;

  fs_hash.init();
  fs_hash.update(PREFIX);

  for (const item of walk(items)) {
    // Commit to integer size.
    let len = BigMath.byteLength(item);
    assert(len <= 0x7fff);

    // Commit to sign.
    if (item < 0n)
      len |= 0x8000;

    size[0] = len;
    size[1] = len >>> 8;

    fs_hash.update(size);
    fs_hash.update(BigMath.encode(item));
  }

  return fs_hash.final();
}

function fs_chal(ver_only, ...items) {
  assert(typeof ver_only === 'boolean');

  const prng_key = hash_all(items);
  const fs_hash_prng = new HashPRNG(prng_key);
  const chal = fs_hash_prng.getrandbits(defs.chalbits);

  let ell = fs_hash_prng.getrandbits(defs.chalbits);

  if (!ver_only) {
    // for prover, call next_prime on ell_r to get ell
    ell = primes.next_prime(ell, defs.elldiff_max);
  }

  return [chal, ell];
}

function expand_sprime(s_prime) {
  const rng = new HashPRNG(BigMath.encode(s_prime, 32));
  return rng.getrandbits(defs.rand_exponent_size);
}

function *walk(items) {
  assert(Array.isArray(items));

  for (const item of items) {
    if (Array.isArray(item)) {
      yield *walk(item);
      continue;
    }
    yield item;
  }
}

exports.HashPRNG = HashPRNG;
exports.hash_all = hash_all;
exports.expand_sprime = expand_sprime;
exports.fs_chal = fs_chal;
