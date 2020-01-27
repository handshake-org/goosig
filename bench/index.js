/*!
 * bench/index.js - GoUO benchmarks for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Parts of this software are based on kwantam/libGooPy:
 *   Copyright (c) 2018, Dan Boneh, Riad S. Wahby (Apache License).
 *   https://github.com/kwantam/GooSig
 *
 * Resources:
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/__main__.py
 *   https://github.com/kwantam/GooSig/blob/master/libGooPy/test_util.py
 */

/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const {performance} = require('perf_hooks');
const rsa = require('bcrypto/lib/rsa');
const Goo = require('../');
const util = require('../test/util');

/*
 * Main
 */

function main(argv) {
  const ops = (argv[2] >>> 0) || 4;

  const vectors = [
    ['4096-bit RSA GoUO, 2048-bit Signer PK', Goo.AOL2, 2, 3, 2048],
    ['4096-bit RSA GoUO, 4096-bit Signer PK', Goo.AOL2, 2, 3, 4096],
    ['2048-bit RSA GoUO, 2048-bit Signer PK', Goo.RSA2048, 2, 3, 2048],
    ['2048-bit RSA GoUO, 4096-bit Signer PK', Goo.RSA2048, 2, 3, 4096]
  ];

  const results = [];

  for (const [name, n, g, h, bits] of vectors) {
    const goo = new Goo(n, g, h, bits);
    const ver = new Goo(n, g, h);
    const msg = Buffer.from(name, 'binary');
    const key = util.genKey(bits);
    const pub = rsa.publicKeyCreate(key);
    const items = [[], [], []];

    for (let j = 0; j < ops; j++) {
      // Generate the challenge token.
      const start0 = performance.now();
      const s_prime = goo.generate();
      const C1 = goo.challenge(s_prime, pub);
      const stop0 = performance.now();

      // Generate the signature.
      const start1 = performance.now();
      const sig = goo.sign(msg, s_prime, key);
      const stop1 = performance.now();

      // Verify the signature.
      const start2 = performance.now();
      const result = ver.verify(msg, sig, C1);
      const stop2 = performance.now();

      assert.strictEqual(result, true);

      // Record times.
      items[0].push(stop0 - start0);
      items[1].push(stop1 - start1);
      items[2].push(stop2 - start2);
    }

    results.push(items);
  }

  for (const [i, items] of results.entries()) {
    console.log('\x1b[38;5;33mTimings for %s\x1b[m:', vectors[i][0]);

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
