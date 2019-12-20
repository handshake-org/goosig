/*!
 * bench/index.js - GoUO benchmarks for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Parts of this software are based on kwantam/libGooPy:
 *   Copyright (c) 2018, Dan Boneh, Riad S. Wahby (Apache License).
 *   https://github.com/kwantam/GooSig
 *
 * Resources:
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/__main__.py
 */

/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const {performance} = require('perf_hooks');
const Goo = require('../');
const util = require('../test/util');

/*
 * Main
 */

function main(argv) {
  const ops = (argv[2] >>> 0) || 4;
  const prover42 = new Goo(Goo.AOL2, 2, 3, 2048);
  const prover44 = new Goo(Goo.AOL2, 2, 3, 4096);
  const verifier40 = new Goo(Goo.AOL2, 2, 3);
  const prover22 = new Goo(Goo.RSA2048, 2, 3, 2048);
  const prover24 = new Goo(Goo.RSA2048, 2, 3, 4096);
  const verifier20 = new Goo(Goo.RSA2048, 2, 3);

  const tests = [
    ['4096-bit RSA GoUO, 2048-bit Signer PK', prover42, verifier40, 2048],
    ['4096-bit RSA GoUO, 4096-bit Signer PK', prover44, verifier40, 4096],
    ['2048-bit RSA GoUO, 2048-bit Signer PK', prover22, verifier20, 2048],
    ['2048-bit RSA GoUO, 4096-bit Signer PK', prover24, verifier20, 4096]
  ];

  const times = new Array(tests.length);

  for (let i = 0; i < tests.length; i++)
    times[i] = [[], [], []];

  for (const [i, [name, goo, ver, bits]] of tests.entries()) {
    const msg = Buffer.from(name, 'binary');

    // Random signer modulus.
    const key = util.genKey(bits);

    for (let j = 0; j < ops; j++) {
      let start, stop;

      // Generate the challenge token.
      start = performance.now();

      const s_prime = goo.generate();
      const C1 = goo.challenge(s_prime, key);

      stop = performance.now();

      times[i][0].push(stop - start);

      // Generate the signature.
      start = performance.now();

      const sig = goo.sign(msg, s_prime, key);

      stop = performance.now();

      times[i][1].push(stop - start);

      // Verify the signature.
      start = performance.now();

      assert.strictEqual(ver.verify(msg, sig, C1), true);

      stop = performance.now();

      times[i][2].push(stop - start);
    }
  }

  for (const [i, items] of times.entries()) {
    console.log('\x1b[38;5;33mTimings for %s\x1b[m:', tests[i][0]);

    for (const [type, times] of [['Generation', items[0]],
                                 ['Signing', items[1]],
                                 ['Verifying', items[2]]]) {
      let min = Infinity;
      let max = -Infinity;
      let mean = 0;
      let sigma = 0;

      for (const time of times) {
        if (time < min)
          min = time;

        if (time > max)
          max = time;
      }

      for (const time of times)
        mean += time;

      mean /= times.length;

      for (const time of times)
        sigma += (time - mean) ** 2;

      sigma = Math.sqrt(sigma / Math.max(1, times.length - 1));

      const line =
        '\x1b[92m \u25f7 %s\x1b[m: %s ms, \u03c3=%s ms, max=%s ms, min=%s ms';

      const args = [
        type,
        mean.toFixed(2),
        sigma.toFixed(2),
        max.toFixed(2),
        min.toFixed(2)
      ];

      console.log(line, ...args);
    }

    console.log('');
  }
}

/*
 * Execute
 */

main(process.argv);
