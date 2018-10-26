'use strict';

/* eslint camelcase: "off" */

const assert = require('bsert');
const random = require('bcrypto/lib/random');
const BigMath = require('./bigmath');
const util = require('./util');
const {
  umod,
  bitLength,
  bitLengthInt,
  byteLength,
  modPow,
  decode
} = BigMath;

// https://svn.python.org/projects/python/trunk/Lib/heapq.py

function _siftdown(heap, startpos, pos) {
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

function _siftup(heap, pos) {
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
  _siftdown(heap, startpos, pos);
}

function heapreplace(heap, item) {
  const returnitem = heap[0];
  heap[0] = item;
  _siftup(heap, 0);
  return returnitem;
}

function heappush(heap, item) {
  heap.push(item);
  _siftdown(heap, 0, heap.length - 1);
}

const primes = {
  PrimeDefs: {
    wheel_incs: [
      2n, 4n, 2n, 4n, 6n, 2n, 6n, 4n, 2n, 4n, 6n,
      6n, 2n, 6n, 4n, 2n, 6n, 4n, 6n, 8n, 4n, 2n,
      4n, 2n, 4n, 8n, 6n, 4n, 6n, 2n, 4n, 6n, 2n,
      6n, 6n, 4n, 2n, 4n, 6n, 2n, 6n, 4n, 2n, 4n,
      2n, 10n, 2n, 10n
    ],
    wheel_ps: [2n, 3n, 5n, 7n],
    test_primes: []
  },

  *_wheel() {
    const incs = util.cycle(this.PrimeDefs.wheel_incs);

    let nval = 11n;

    for (const inc of incs) {
      const ret = nval;
      nval += inc;
      yield ret;
    }
  },

  *primes() {
    // first, the initial primes of the wheel
    for (const p of this.PrimeDefs.wheel_ps)
      yield p;

    const f = [];

    // then, a prime heap-based iterator
    for (const n of this._wheel()) {
      let prime = true;

      while (f.length) {
        const [nx, inc] = f[0];

        if (nx > n)
          break;

        if (nx === n)
          prime = false;

        heapreplace(f, [nx + inc, inc]);
      }

      if (prime) {
        heappush(f, [n * n, n]);
        yield n;
      }
    }
  },

  primes_skip(nskip) {
    assert((nskip >>> 0) === nskip);

    const p = this.primes();

    for (let i = 0; i < nskip; i++)
      util.next(p);

    return p;
  },

  is_square(n) {
    assert(typeof n === 'bigint');

    const isqn = util.isqrt(n);

    if (isqn * isqn === n)
      return true;

    return false;
  },

  is_prime_lucas(n, nreps) {
    assert(typeof n === 'bigint');
    assert((nreps >>> 0) === nreps);

    const half = (n + 1n) / 2n;

    if (umod(2n * half, n) !== 1n)
      return false;

    const [d, s] = util.factor_twos(n + 1n);
    const iter = util.num_to_bits(d);
    const msbit = util.next(iter);

    assert(msbit);

    const dbits = util.list(iter);

    let i = 0n;
    let ilim = 20n;
    let D = 0n;
    let Q;

    const lucas_double = (u, v, Qk) => {
      u = umod(u * v, n);
      v = umod(v ** 2n - 2n * Qk, n);
      if (v < 0n)
        v += n;
      assert(v >= 0n);
      Qk = umod(Qk * Qk, n);
      return [u, v, Qk];
    };

    const lucas_add1 = (u, v, Qk, D) => {
      [u, v] = [umod((u + v) * half, n), umod((D * u + v) * half, n)];
      Qk = umod(Qk * Q, n);
      return [u, v, Qk];
    };

    for (let j = 0; j < nreps; j++) {
      for (;;) {
        if (i === ilim) {
          if (this.is_square(n))
            return false;
        }

        i += 1n;

        D = ((-1n) ** (i + 1n)) * (3n + 2n * i);

        if (D < 0n)
          D += n;

        assert(D >= 0n);

        if (util.jacobi(D, n) === -1)
          break;
      }

      ilim = -1n;

      Q = (1n - D) / 4n;

      if (Q < 0n)
        Q += n;

      assert(Q >= 0n);

      let [u, v, Qk] = [1n, 1n, Q];

      for (const db of dbits) {
        [u, v, Qk] = lucas_double(u, v, Qk);
        if (db)
          [u, v, Qk] = lucas_add1(u, v, Qk, D);
      }

      // now we have Ud and Vd
      if (umod(u, n) === 0n)
        continue;

      // check V_{d * 2^r}, 0 <= r < s
      let cont = false;

      for (let i = 0n; i < s; i++) {
        if (umod(v, n) === 0n) {
          cont = true;
          break;
        }

        [u, v, Qk] = lucas_double(u, v, Qk);
      }

      if (cont)
        continue;

      return false;
    }

    return true;
  },

  is_prime_rm(n, nreps) {
    assert(typeof n === 'bigint');
    assert((nreps >>> 0) === nreps);

    if (n < 7n) {
      if (n === 3n || n === 5n)
        return true;
      return false;
    }

    const [d, r] = util.factor_twos(n - 1n);

    for (let i = 0; i < nreps; i++) {
      const m = n - 2n;
      const len = byteLength(m);

      let a = 0n;

      while (a < 2n || a >= m)
        a = decode(random.randomBytes(len));

      let x = modPow(a, d, n);

      if (x === 1n || x === n - 1n)
        continue;

      let cont = false;

      for (let j = 0n; j < r - 1n; j++) {
        x = modPow(x, 2n, n);
        if (x === n - 1n) {
          cont = true;
          break;
        }
      }

      if (cont)
        continue;

      return false;
    }

    return true;
  },

  is_prime_div(n) {
    assert(typeof n === 'bigint');

    for (const p of this.PrimeDefs.test_primes) {
      if (umod(n, p) === 0n)
        return false;
    }

    return true;
  },

  // Baillie-PSW primality test (default #reps is overkill)
  is_prime(n, nreps = 2) {
    assert(typeof n === 'bigint');
    assert((nreps >>> 0) === nreps);

    if (!this.is_prime_div(n))
      return false;

    if (!this.is_prime_rm(n, 16 * nreps))
      return false;

    // if (!this.is_prime_lucas(n, nreps))
    //   return false;

    return true;
  },

  primeinc(nbits, rng) {
    assert((nbits >>> 0) === nbits);
    assert(rng && typeof rng.getrandbits === 'function');

    let p = 1n;

    while (bitLength(p) !== nbits || !this.is_prime(p)) {
      p = rng.getrandbits(nbits) | 1n;
      while (bitLength(p) === nbits && !this.is_prime(p))
        p += 2n;
    }

    return p;
  },

  primeprod_and_carmichael(nbits) {
    assert((nbits >>> 0) === nbits);

    const p = this.primes_skip(1);

    let prod = 1n;
    let carm = 1n;

    for (const np of p) {
      const [prod_, carm_] = [prod, carm];

      prod *= np;
      carm = (carm * (np - 1n)) / util.gcd(carm, np - 1n);

      if (bitLength(prod) > nbits)
        return [prod_, carm_];
    }

    return [0n, 0n];
  },

  find_mindelta(m, maxmult) {
    assert(typeof m === 'bigint');
    assert(typeof maxmult === 'bigint');

    let mindelta = 1n;
    let iii = 1n;

    for (let i = 1n; i < maxmult; i++) {
      const mm = m * i;
      // const delta = (((1 << mm.bit_length()) - mm + 0.0)
      //               / (1 << mm.bit_length()));
      const bl = bitLengthInt(mm);
      const delta = ((1n << bl) - mm) / (1n << bl);

      if (delta < mindelta) {
        iii = i;
        mindelta = delta;
      }
    }

    return iii;
  },

  gen_ft_prime_opts(nbits, nfix) {
    assert((nbits >>> 0) === nbits);
    assert((nfix >>> 0) === nfix);

    const [m, lamm] = this.primeprod_and_carmichael(nbits - nfix);
    const m_multiplier = this.find_mindelta(m, 1024n);
    const amax = (1n << BigInt(nbits)) / m;
    const a_multiplier = this.find_mindelta(amax, 1024n);

    return [m, m_multiplier, lamm, amax, a_multiplier];
  },

  // From Fouque and Tibouchi,
  // "Close to uniform prime number generation with fewer random bits."
  // https://eprint.iacr.org/2011/418

  fouque_tibouchi_primegen(opts, rng) {
    assert(Array.isArray(opts));
    assert(rng && typeof rng.randrange === 'function');

    const [m, m_multiplier, lamm, amax, a_multiplier] = opts;
    const mlimit = m * m_multiplier;
    const alimit = amax * a_multiplier;

    for (;;) {
      let u = 1n;
      let b = 0n;

      while (u !== 0n) {
        const r = umod(rng.randrange(mlimit) * u / m_multiplier, m);

        b = umod(b + r, m);
        u = 1n - modPow(b, lamm, m);
        u = u < 0n ? u + m : u;
      }

      let p = 2n;
      let i = 0n;
      let cont = false;

      while (!this.is_prime(p)) {
        if (i > amax / 10n) {
          // did we choose a "bad" b?
          cont = true;
          break;
        }
        i += 1n;
        const a = rng.randrange(alimit) / a_multiplier;
        p = (a * m + b) | 1n;
      }

      if (!cont)
        return p;
    }
  }
};

for (const p of primes.primes()) {
  primes.PrimeDefs.test_primes.push(p);
  if (primes.PrimeDefs.test_primes.length === 1000)
    break;
}

module.exports = primes;
