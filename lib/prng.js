'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const SHA256 = require('bcrypto/lib/sha256');
const DRBG = require('bcrypto/lib/drbg');
const BigMath = require('./bigmath');
const defs = require('./defs');
const primes = require('./primes');
const RNG = require('./rng');

const PREFIX = Buffer.from('libGooPy:', 'binary');
const PERS = Buffer.from('libGooPy_prng', 'binary');
const NONCE = Buffer.alloc(32, 0x00);

class HashPRNG extends RNG {
  constructor(prng_key) {
    super(new DRBG(SHA256, prng_key, NONCE, PERS));
  }
}

function hash_all(...items) {
  const fs_hash = new SHA256();

  fs_hash.init();
  fs_hash.update(PREFIX);

  for (const item of recurse(items))
    fs_hash.update(BigMath.encode(item, 512));

  return fs_hash.final();
}

function fs_chal(ver_only, ...items) {
  assert(typeof ver_only === 'boolean');

  const prng_key = hash_all(items);
  const fs_hash_prng = new HashPRNG(prng_key);
  const chal = fs_hash_prng.getrandbits(defs.chalbits);

  let ell;

  if (ver_only)
    ell = fs_hash_prng.getrandbits(defs.chalbits);

  if (!ver_only) {
    // for prover, call next_prime on ell_r to get ell
    ell = primes.next_prime(fs_hash_prng.getrandbits(defs.chalbits), defs.elldiff_max);
  }

  return [chal, ell];
}

function expand_sprime(s_prime) {
  const rng = new HashPRNG(BigMath.encode(s_prime));
  return rng.getrandbits(defs.rand_exponent_size);
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

exports.HashPRNG = HashPRNG;
exports.hash_all = hash_all;
exports.expand_sprime = expand_sprime;
exports.fs_chal = fs_chal;
