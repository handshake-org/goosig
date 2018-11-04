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

'use strict';

const assert = require('bsert');
const random = require('bcrypto/lib/random');
const BigMath = require('./bigmath');
const PRNG = require('./prng');
const util = require('./util');

/*
 * Constants
 */

const testPrimes = [];

/*
 * Primes
 */

const primes = {
  initial: [2n, 3n, 5n, 7n],

  increments: [
    2n, 4n, 2n, 4n, 6n, 2n, 6n, 4n, 2n, 4n, 6n,
    6n, 2n, 6n, 4n, 2n, 6n, 4n, 6n, 8n, 4n, 2n,
    4n, 2n, 4n, 8n, 6n, 4n, 6n, 2n, 4n, 6n, 2n,
    6n, 6n, 4n, 2n, 4n, 6n, 2n, 6n, 4n, 2n, 4n,
    2n, 10n, 2n, 10n
  ],

  smallPrimes: [
    2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n,
    59n, 61n, 67n, 71n, 73n, 79n, 83n, 89n, 97n, 101n, 103n, 107n, 109n, 113n,
    127n, 131n, 137n, 139n, 149n, 151n, 157n, 163n, 167n, 173n, 179n, 181n,
    191n, 193n, 197n, 199n, 211n, 223n, 227n, 229n, 233n, 239n, 241n, 251n,
    257n, 263n, 269n, 271n, 277n, 281n, 283n, 293n, 307n, 311n, 313n, 317n,
    331n, 337n, 347n, 349n, 353n, 359n, 367n, 373n, 379n, 383n, 389n, 397n,
    401n, 409n, 419n, 421n, 431n, 433n, 439n, 443n, 449n, 457n, 461n, 463n,
    467n, 479n, 487n, 491n, 499n, 503n, 509n, 521n, 523n, 541n, 547n, 557n,
    563n, 569n, 571n, 577n, 587n, 593n, 599n, 601n, 607n, 613n, 617n, 619n,
    631n, 641n, 643n, 647n, 653n, 659n, 661n, 673n, 677n, 683n, 691n, 701n,
    709n, 719n, 727n, 733n, 739n, 743n, 751n, 757n, 761n, 769n, 773n, 787n,
    797n, 809n, 811n, 821n, 823n, 827n, 829n, 839n, 853n, 857n, 859n, 863n,
    877n, 881n, 883n, 887n, 907n, 911n, 919n, 929n, 937n, 941n, 947n, 953n,
    967n, 971n, 977n, 983n, 991n, 997n
  ],

  *wheel() {
    let i = 0;
    let n = 11n;

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

  isSquare(n) {
    assert(typeof n === 'bigint');

    const isqn = util.isqrt(n);

    if (isqn * isqn === n)
      return true;

    return false;
  },

  isPrimeDiv(n) {
    assert(typeof n === 'bigint');

    if (n <= 1n)
      return false;

    for (const p of this.testPrimes) {
      if (n === p)
        return true;

      if (BigMath.mod(n, p) === 0n)
        return false;
    }

    return true;
  },

  // https://github.com/golang/go/blob/aadaec5/src/math/big/prime.go#L81
  // https://github.com/indutny/miller-rabin/blob/master/lib/mr.js
  isPrimeMR(n, key, reps, force2) {
    if (key == null)
      key = random.randomBytes(32);

    assert(typeof n === 'bigint');
    assert(Buffer.isBuffer(key));
    assert((reps >>> 0) === reps);
    assert(typeof force2 === 'boolean');

    if (n < 7n) {
      if (n === 2n || n === 3n || n === 5n)
        return true;
      return false;
    }

    const nm1 = n - 1n;
    const k = BigMath.zeroBits(nm1);
    const q = nm1 >> BigInt(k);

    const nm3 = nm1 - 2n;

    // XOR with the prime we're testing?
    const prng = new PRNG(key);

next:
    for (let i = 0; i < reps; i++) {
      let x, y;

      if (i === reps - 1 && force2) {
        x = 2n;
      } else {
        x = prng.randomInt(nm3);
        x += 2n;
      }

      y = BigMath.modPow(x, q, n);

      if (y === 1n || y === nm1)
        continue;

      for (let j = 1; j < k; j++) {
        y = BigMath.modPow(y, 2n, n);

        if (y === nm1)
          continue next;

        if (y === 1n)
          return false;
      }

      return false;
    }

    return true;
  },

  // https://github.com/golang/go/blob/aadaec5/src/math/big/prime.go#L150
  isPrimeLucas(n) {
    assert(typeof n === 'bigint');

    // Ignore 0 and 1.
    if (n <= 1n)
      return false;

    // Two is the only even prime.
    if ((n & 1n) === 0n)
      return n === 2n;

    // Baillie-OEIS "method C" for choosing D, P, Q.
    // See: https://oeis.org/A217719/a217719.txt.
    let p = 3n;
    let d = 1n;

    for (;;) {
      if (p > 10000n) {
        // Thought to be impossible.
        throw new Error(`Cannot find (D/n) = -1 for ${n.toString(10)}.`);
      }

      d = p * p - 4n;

      const j = util.jacobi(d, n);

      if (j === -1)
        break;

      if (j === 0)
        return n === p + 2n;

      if (p === 40n) {
        if (this.isSquare(n))
          return false;
      }

      p += 1n;
    }

    // Check for Grantham definition of
    // "extra strong Lucas pseudoprime".
    let s = n + 1n;
    const r = BigMath.zeroBits(s);
    const nm2 = n - 2n;

    s >>= BigInt(r);

    const bp = p;

    let vk = 2n;
    let vk1 = p;

    for (let i = BigInt(BigMath.bitLength(s)); i >= 0n; i--) {
      let t1;

      if (s & (1n << i)) {
        t1 = vk * vk1;
        t1 += n;
        t1 -= bp;
        vk = BigMath.mod(t1, n);
        t1 = vk1 * vk1;
        t1 += nm2;
        vk1 = BigMath.mod(t1, n);
      } else {
        t1 = vk * vk1;
        t1 += n;
        t1 -= bp;
        vk1 = BigMath.mod(t1, n);
        t1 = vk * vk;
        t1 += nm2;
        vk = BigMath.mod(t1, n);
      }
    }

    if (vk === 2n || vk === nm2) {
      let t1 = vk * bp;
      let t2 = vk1 << 1n;

      if (t1 < t2)
        [t1, t2] = [t2, t1];

      t1 -= t2;

      const t3 = BigMath.mod(t1, n);

      if (t3 === 0n)
        return true;
    }

    for (let t = 0; t < r - 1; t++) {
      if (vk === 0n)
        return true;

      if (vk === 2n)
        return false;

      let t1 = vk * vk;
      t1 -= 2n;
      vk = BigMath.mod(t1, n);
    }

    return false;
  },

  // Baillie-PSW primality test.
  isPrime(n, key) {
    assert(typeof n === 'bigint');
    assert(key == null || Buffer.isBuffer(key));

    if (n <= 1n)
      return false;

    // Early exit.
    for (const p of this.testPrimes) {
      if (n === p)
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
    assert(typeof p === 'bigint');
    assert(Buffer.isBuffer(key));
    assert(max == null || (typeof max === 'bigint'));

    let inc = 0n;

    if ((p & 1n) === 0n) {
      inc = 1n;
      p |= 1n;
    }

    while (!this.isPrime(p, key)) {
      if (max != null && inc > max)
        break;
      p += 2n;
      inc += 2n;
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
