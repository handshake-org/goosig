/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const {performance} = require('perf_hooks');
const util = require('../test/util');
const Goo = require('../');

/*
 * Main
 */

function main(argv) {
  const ops = (argv[2] >>> 0) || 1000;
  const goo = new Goo(Goo.RSA2048, 2, 3, 2048);
  const ver = new Goo(Goo.RSA2048, 2, 3);
  const msg = Buffer.from('2048-bit RSA GoUO, 2048-bit Signer PK');
  const key = util.genKey(2048);
  const s_prime = goo.generate();
  const C1 = goo.challenge(s_prime, key);
  const sig = goo.sign(msg, s_prime, key);
  const start = performance.now();

  for (let i = 0; i < ops; i++)
    assert.strictEqual(ver.verify(msg, sig, C1), true);

  const stop = performance.now();
  const ms = stop - start;

  console.log('ms: %d', ms);
  console.log('ops: %d', ops);
  console.log('ms/op: %d', ms / ops);
}

/*
 * Execute
 */

main(process.argv);
