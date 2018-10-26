'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const assert = require('bsert');
const bm = require('./bigmath');
const util = require('./util');

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

    const f = [[0n, 0n]];

    // then, a prime heap-based iterator
    for (const n of this._wheel()) {
      let prime = true;

      // while f
      for (;;) {
        let [nx, inc] = f[0];

        if (nx > n)
          break;

        if (nx === n)
          prime = false;

        // XXX
        heapq.heapreplace(f, [nx + inc, inc]);

        if (prime) {
          // XXX
          heapq.heappush(f, [n * n, n]);
          yield n;
        }
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

    if ((2n * half) % n !== 1n)
      return false;

    let [d, s] = util.factor_twos(n + 1n);
    let dbits = util.num_to_bits(d);
    let msbit = util.next(dbits);

    assert(msbit);

    dbits = util.list(dbits);

    const lucas_double = (u, v, Qk) => {
      u = (u * v) % n;
      v = (v ** 2n - 2n * Qk) % n;
      Qk = (Qk * Qk) % n;
      return [u, v, Qk];
    };

    const lucas_add1 = (u, v, Qk, D) => {
      [u, v] = [((u + v) * half) % n, ((D * u + v) * half) % n];
      Qk = (Qk * Q) % n;
      return [u, v, Qk];
    };

    let i = 0n;
    let ilim = 20n;
    let D = 0n;

    for (let j = 0; j < nreps; j++) {
      for (;;) {
        if (i === ilim) {
          if (this.is_square(n))
            return false;
        }

        i += 1n;

        D = (-1n ** (i + 1n)) * (3n + 2n * i);

        if (util.jacobi(D, n) === -1n)
          break;
      }

      ilim = -1n;
      Q = (1n - D) / 4n;

      let [u, v, Qk] = [1n, 1n, Q];

      for (const db in dbits) {
        [u, v, Qk] = lucas_double(u, v, Qk);
        if (db)
          [u, v, Qk] = lucas_add1(u, v, Qk, D);
      }

      // now we have Ud and Vd
      if (u % n === 0n)
        continue;

      // check V_{d * 2^r}, 0 <= r < s
      let cont = false;

      for (let i = 0n; i < s; i++) {
        if (v % n === 0n) {
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

    let [d, r] = util.factor_twos(n - 1n);

    for (let i = 0; i < nreps; i++) {
      const m = n - 2n;
      const len = bm.byteLength(m);

      let a = 0n;

      while (a < 2n && a >= m)
        a = bm.decode(random.randomBytes(len));

      let x = bm.modPow(a, d, n);

      if (x === 1n || x === n - 1n)
        continue;

      let cont = false;

      for (let j = 0n; j < r - 1n; j++) {
        x = bm.modPow(x, 2n, n);
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
      if (n % p === 0n)
        return false;
    }

    return true;
  },

  // Baillie-PSW primality test (default #reps is overkill)
  is_prime(n, nreps = 2) {
    assert(typeof n === 'bigint');
    assert((nreps >>> 0) === nreps);

    if (!is_prime_div(n))
      return false;

    if (!is_prime_rm(n, 16 * nreps))
      return false;

    if (!is_prime_lucas(n, nreps))
      return false;

    return true;
  },

  primeinc(nbits, rng) {
    assert((nbits >>> 0) === nbits);
    assert(rng && typeof rng.getrandbits === 'function');

    let p = 1n;

    while (bm.bitLength(p) !== nbits || !this.is_prime(p)) {
      p = rng.getrandbits(nbits) | 1n;
      while (bm.bitLength(p) === nbits && !this.is_prime(p))
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
      let [prod_, carm_] = [prod, carm];

      prod *= np;
      carm = (carm * (np - 1)) / util.gcd(carm, np - 1n);

      if (bm.bitLength(prod) > nbits)
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
      let mm = m * i;
      // let delta = ((1 << mm.bit_length()) - mm + 0.0) / (1 << mm.bit_length());
      let bl = bm.bitLengthInt(mm);
      let delta = ((1n << bl) - mm) / (1n << bl);
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
    let [m, lamm] = this.primeprod_and_carmichael(nbits - nfix);
    let m_multiplier = this.find_mindelta(m, 1024n);
    let amax = (1n << BigInt(nbits)) / m;
    let a_multiplier = this.find_mindelta(amax, 1024n);
    return [m, m_multiplier, lamm, amax, a_multiplier];
  },

  // from Fouque and Tibouchi, "Close to uniform prime number generation with fewer random bits."
  //      https://eprint.iacr.org/2011/418

  fouque_tibouchi_primegen(opts, rng) {
    assert(Array.isArray(opts));
    assert(rng && typeof rng.randrange ==== 'function');

    let [m, m_multiplier, lamm, amax, a_multiplier] = opts;
    let mlimit = m * m_multiplier;
    let alimit = amax * a_multiplier;

    for (;;) {
      let u = 1n;
      let b = 0n;

      while (u !== 0n) {
        let r = (rng.randrange(mlimit) * u / m_multiplier) % m;
        b = (b + r) % m;
        u = 1n - bm.modPow(b, lamm, m);
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
        a = rng.randrange(alimit) / a_multiplier;
        p = (a * m + b) | 1n;
      }

      if (!cont)
        break;
    }

    return p;
  }
};

for (let i = 0; i < 1000; i++) {
  for (const p of primes.primes())
    primes.PrimeDefs.test_primes.push(p);
}

module.exports = primes;
