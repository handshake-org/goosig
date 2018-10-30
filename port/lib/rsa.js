'use strict';

/* eslint camelcase: 'off' */
/* eslint max-len: 'off' */

const assert = require('bsert');
const SHA256 = require('bcrypto/lib/sha256');
const BigMath = require('./bigmath');
const primes = require('./primes');
const prng = require('./prng');
const util = require('./util');
const {umod, decode, bitLength, modPow} = BigMath;

const LABEL = Buffer.from('libGooPy_RSA_OAEP_LABEL', 'binary');

// RSA-OAEP enc/dec using SHA-256
// NOTE this is a non-standard implementation that you should probably not use except for benchmarking
class RSAKey {
  constructor(p, q) {
    assert(typeof p === 'bigint');
    assert(typeof q === 'bigint');
    assert(p !== q);
    assert(primes.is_prime(p));
    assert(primes.is_prime(q));

    this.p = p;
    this.q = q;
    this.n = p * q;

    const n_octets = (bitLength(this.n) + 7) >>> 3;

    if (n_octets < 128)
      throw new Error('RSAKey does not support <1024-bit moduli');

    this.hash_size = 32;
    this.max_mlen = n_octets - 2 * this.hash_size - 2;
    this.dblen = n_octets - 1 - this.hash_size;
    this.dbmask = (1n << (8n * BigInt(this.dblen))) - 1n;

    const shift = BigInt(8 * (this.dblen - this.hash_size));

    this.lhash = decode(SHA256.digest(LABEL)) << shift;

    // find a decryption exponent
    this.lam = (p - 1n) * (q - 1n) / util.gcd(p - 1n, q - 1n);

    for (const e of primes.primes_skip(1)) {
      if (e > 1000n)
        throw new Error('could find a suitable exponent!');

      const d = util.invert_modp(e, this.lam);

      if (d != null) {
        this.e = e;
        this.d = d;
        break;
      }
    }

    assert(umod(this.d * this.e, this.lam) === 1n);
  }

  mask_gen(seed, length) {
    assert((length >>> 0) === length);

    const key = SHA256.digest(BigMath.encode(seed));
    const rng = new prng.HashPRNG(key);
    return rng.getrandbits(length);
  }

  encrypt(m) {
    assert(typeof m === 'bigint');

    const mlen = (bitLength(m) + 7) >>> 3; // round up to some number of bytes

    if (mlen > this.max_mlen)
      throw new Error('message is too long');

    const data = this.lhash | (1n << (8n * BigInt(mlen))) | m;
    const seed = util.rand.getrandbits(8 * this.hash_size);

    const dbMask = this.mask_gen(seed, this.dblen);
    const maskedDb = dbMask ^ data;

    const sMask = this.mask_gen(maskedDb, this.hash_size);
    const maskedSeed = sMask ^ seed;

    const enc_msg = (maskedSeed << BigInt(8 * this.dblen)) | maskedDb;

    return modPow(enc_msg, this.e, this.n);
  }

  decrypt(c) {
    assert(typeof c === 'bigint');

    const enc_msg = modPow(c, this.d, this.n);

    const maskedDb = enc_msg & this.dbmask;
    const maskedSeed = enc_msg >> (8n * BigInt(this.dblen));

    if (bitLength(maskedSeed) > 8 * this.hash_size)
      throw new Error('invalid ciphertext');

    const sMask = this.mask_gen(maskedDb, this.hash_size);
    const seed = maskedSeed ^ sMask;

    const dbMask = this.mask_gen(seed, this.dblen);

    let data = dbMask ^ maskedDb;

    data ^= this.lhash;

    if (data >> (8n * BigInt(this.dblen - this.hash_size)) !== 0n)
      throw new Error('invalid ciphertext');

    const dlen = BigInt((7 + bitLength(data)) >>> 3);

    data ^= 1n << (8n * (dlen - 1n));

    if (data >> (8n * (dlen - 1n)) !== 0n)
      throw new Error('invalid padding');

    if (bitLength(data) > 8 * this.max_mlen)
      throw new Error('invalid message');

    return data;
  }
}

module.exports = RSAKey;
