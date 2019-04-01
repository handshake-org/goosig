/*!
 * primes.js - prime number generation for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Parts of this software are based on kwantam/libGooPy:
 *   Copyright (c) 2018, Dan Boneh, Riad S. Wahby (Apache License).
 *   https://github.com/kwantam/GooSig
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Parts of this software are based on indutny/miller-rabin:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/miller-rabin
 *
 * Resources:
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/primes.py
 *   https://github.com/golang/go/blob/master/src/math/big/prime.go
 *   https://github.com/golang/go/blob/master/src/math/big/int.go
 *   https://github.com/golang/go/blob/master/src/math/big/nat.go
 *   https://github.com/golang/go/blob/master/src/crypto/rand/util.go
 *   https://github.com/indutny/miller-rabin/blob/master/lib/mr.js
 *   https://svn.python.org/projects/python/trunk/Lib/heapq.py
 */

/* eslint valid-typeof: "off" */

'use strict';

const assert = require('bsert');
const random = require('bcrypto/lib/random');
const BN = require('bcrypto/lib/bn.js');
const PRNG = require('./prng');

/*
 * Constants
 */

const testPrimes = [];

/*
 * Primes
 */

const primes = {
  initial: [2, 3, 5, 7],

  increments: [
    2, 4, 2, 4, 6, 2, 6, 4, 2, 4, 6,
    6, 2, 6, 4, 2, 6, 4, 6, 8, 4, 2,
    4, 2, 4, 8, 6, 4, 6, 2, 4, 6, 2,
    6, 6, 4, 2, 4, 6, 2, 6, 4, 2, 4,
    2, 10, 2, 10
  ],

  smallPrimes: [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
    59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
    191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
    257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
    401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
    467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
    563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619,
    631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
    709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
    797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
    877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
    967, 971, 977, 983, 991, 997
  ],

  *wheel() {
    let i = 0;
    let n = 11;

    for (;;) {
      if (i === this.increments.length)
        i = 0;

      yield n;

      n += this.increments[i];
      i += 1;
    }
  },

  *primes() {
    // First, the initial primes of the wheel.
    for (const p of this.initial)
      yield p;

    const items = [];

    // Then, a prime heap-based iterator.
    for (const n of this.wheel()) {
      let prime = true;

      while (items.length) {
        const [nx, inc] = items[0];

        if (nx > n)
          break;

        if (nx === n)
          prime = false;

        heapReplace(items, [nx + inc, inc]);
      }

      if (prime) {
        heapPush(items, [n * n, n]);
        yield n;
      }
    }
  },

  get testPrimes() {
    if (testPrimes.length === 0) {
      for (const prime of this.primes()) {
        testPrimes.push(prime);

        if (testPrimes.length === 1000)
          break;
      }
    }

    return testPrimes;
  },

  primesSkip(skip) {
    assert((skip >>> 0) === skip);

    const p = this.primes();

    for (let i = 0; i < skip; i++)
      assert(!p.next().done);

    return p;
  },

  isPrimeDiv(n) {
    assert(BN.isBN(n));

    if (n.cmpn(1) <= 0)
      return false;

    for (const p of this.testPrimes) {
      if (n.cmpn(p) === 0)
        return true;

      if (n.modrn(p) === 0)
        return false;
    }

    return true;
  },

  isPrimeMR(n, key, reps, force2) {
    if (key == null)
      key = random.randomBytes(32);

    assert(BN.isBN(n));

    const prng = new PRNG(key);
    const rng = bits => prng.randomBits(bits);

    return n.isPrimeMR(rng, reps, force2);
  },

  isPrimeLucas(n) {
    assert(BN.isBN(n));
    return n.isPrimeLucas(50);
  },

  // Baillie-PSW primality test.
  isPrime(n, key) {
    assert(BN.isBN(n));
    assert(key == null || Buffer.isBuffer(key));

    if (n.cmpn(1) <= 0)
      return false;

    // Early exit.
    for (const p of this.testPrimes) {
      if (n.cmpn(p) === 0)
        return true;
    }

    if (!this.isPrimeDiv(n))
      return false;

    if (!this.isPrimeMR(n, key, 16 + 1, true))
      return false;

    if (!this.isPrimeLucas(n))
      return false;

    return true;
  },

  nextPrime(p, key, max = null) {
    assert(BN.isBN(p));
    assert(Buffer.isBuffer(key));
    assert(max == null || (max >>> 0) === max);

    let inc = 0;

    p = p.clone();

    if (p.isEven()) {
      inc = 1;
      p.iuorn(1);
    }

    while (!this.isPrime(p, key)) {
      if (max != null && inc > max)
        break;
      p.iaddn(2);
      inc += 2;
    }

    if (max != null && inc > max)
      return null;

    return p;
  }
};

/*
 * Helpers
 */

function siftDown(heap, startpos, pos) {
  const newitem = heap[pos];

  while (pos > startpos) {
    const parentpos = (pos - 1) >>> 1;
    const parent = heap[parentpos];

    if (newitem[0] < parent[0]) {
      heap[pos] = parent;
      pos = parentpos;
      continue;
    }

    break;
  }

  heap[pos] = newitem;
}

function siftUp(heap, pos) {
  const endpos = heap.length;
  const startpos = pos;
  const newitem = heap[pos];

  let childpos = 2 * pos + 1;

  while (childpos < endpos) {
    const rightpos = childpos + 1;
    if (rightpos < endpos && !(heap[childpos][0] < heap[rightpos][0]))
      childpos = rightpos;
    heap[pos] = heap[childpos];
    pos = childpos;
    childpos = 2 * pos + 1;
  }

  heap[pos] = newitem;
  siftDown(heap, startpos, pos);
}

function heapReplace(heap, item) {
  const returnitem = heap[0];
  heap[0] = item;
  siftUp(heap, 0);
  return returnitem;
}

function heapPush(heap, item) {
  heap.push(item);
  siftDown(heap, 0, heap.length - 1);
}

/*
 * Expose
 */

module.exports = primes;
