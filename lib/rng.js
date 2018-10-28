'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const BigMath = require('./bigmath');

class RNG {
  constructor(prng) {
    assert(prng && typeof prng.generate === 'function');
    this.prng = prng;
    this.r_save = 0n;
  }

  _next_rand() {
    return BigMath.decode(this.prng.generate(32));
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
    assert(typeof maxval === 'bigint');

    const nbits = BigMath.bitLength(maxval - 1n); // util.clog2

    let ret = maxval;

    while (ret >= maxval)
      ret = this.getrandbits(nbits);

    return ret;
  }

  randrange(start, stop = null) {
    assert(typeof start === 'bigint');
    assert(stop == null || (typeof stop === 'bigint'));

    if (stop == null)
      return this._randrange(start);

    if (stop <= start)
      throw new Error('require stop > start in randrange(start, stop)');

    return start + this._randrange(stop - start);
  }

  randint(a, b) {
    assert(typeof a === 'bigint');
    assert(typeof b === 'bigint');

    if (b <= a)
      throw new Error('require b > a in randint(a, b)');

    return a + this._randrange(b - a);
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

module.exports = RNG;
