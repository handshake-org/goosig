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

function fs_chal(...items) {
  const fs_hash = new SHA256();

  fs_hash.init();
  fs_hash.update(PREFIX);

  for (const item of recurse(items))
    fs_hash.update(BigMath.encode(item, 512));

  const prng_key = fs_hash.final();
  const fs_hash_prng = new HashPRNG(prng_key);
  const chal = fs_hash_prng.getrandbits(defs.chalbits);
  const ell = primes.fouque_tibouchi_primegen(defs.ft_prime_opts, fs_hash_prng);

  return [chal, ell];
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
exports.fs_chal = fs_chal;
