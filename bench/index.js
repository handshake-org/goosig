'use strict';

/* eslint camelcase: "off" */
/* eslint max-len: "off" */

const BigMath = require('../lib/bigmath');
const GooChallenger = require('../lib/challenge');
const consts = require('../lib/consts');
const ops = require('../lib/ops');
const GooSigner = require('../lib/sign');
const testUtil = require('../test/util');
const util = require('../lib/util');
const GooVerifier = require('../lib/verify');
const RSAKey = require('../lib/rsa');
const {bitLength} = BigMath;

function main(nreps) {
  // reuse Gops throughout. Notice that you can reuse gops for different
  // Signer modulus as long as the *size* of the Signer's modulus is no
  // larger than the one the gops object was built for.

  // 4096-bit GoUO
  // 4096-bit RSA GoUO, 2048-bit Signer key
  const gops_4_2_p = new ops.RSAGroupOps(consts.Gaol, 2048);
  // 4096-bit RSA GoUO, 4096-bit Signer key
  const gops_4_4_p = new ops.RSAGroupOps(consts.Gaol, 4096);
  // 4096-bit RSA GoUO (verification)
  const gops_4_v = new ops.RSAGroupOps(consts.Gaol, null);

  // 2048-bit GoUO
  // 2048-bit RSA GoUO, 2048-bit Signer key
  const gops_2_2_p = new ops.RSAGroupOps(consts.Grsa2048, 2048);
  // 2048-bit RSA GoUO, 4096-bit Signer key
  const gops_2_4_p = new ops.RSAGroupOps(consts.Grsa2048, 4096);
  // 2048-bit RSA GoUO (verification)
  const gops_2_v = new ops.RSAGroupOps(consts.Grsa2048, null);

  // 2048-bit BQF discriminant
  // 2048-bit BQF GoUO, 2048-bit Signer key
  // const gops_c2_2_p = new ops.ClassGroupOps(consts.Ggoo2048, 2048);
  // 2048-bit BQF GoUO, 4096-bit Signer key
  // const gops_c2_4_p = new ops.ClassGroupOps(consts.Ggoo2048, 4096);
  // 2048-bit BQF GoUO (verification)
  // const gops_c2_v = new ops.ClassGroupOps(consts.Ggoo2048, null);

  // 1024-bit BQF discriminant
  // 1024-bit BQF GoUO, 2048-bit Signer key
  // const gops_c1_2_p = new ops.ClassGroupOps(consts.Ggoo1024, 2048);
  // 1024-bit BQF GoUO, 2048-bit Signer key
  // const gops_c1_4_p = new ops.ClassGroupOps(consts.Ggoo1024, 4096);
  // 1024-bit BQF GoUO, 4096-bit Signer key
  // const gops_c1_v = new ops.ClassGroupOps(consts.Ggoo1024, null);

  // measure times
  const pv_expts = [
    ['4096-bit RSA GoUO, 2048-bit Signer PK', gops_4_2_p, gops_4_v],
    ['4096-bit RSA GoUO, 4096-bit Signer PK', gops_4_4_p, gops_4_v],
    ['2048-bit RSA GoUO, 2048-bit Signer PK', gops_2_2_p, gops_2_v],
    ['2048-bit RSA GoUO, 4096-bit Signer PK', gops_2_4_p, gops_2_v]
    // ['2048-bit BQF GoUO, 2048-bit Signer PK', gops_c2_2_p, gops_c2_v],
    // ['2048-bit BQF GoUO, 4096-bit Signer PK', gops_c2_4_p, gops_c2_v],
    // ['1024-bit BQF GoUO, 2048-bit Signer PK', gops_c1_2_p, gops_c1_v],
    // ['1024-bit BQF GoUO, 4096-bit Signer PK', gops_c1_4_p, gops_c1_v]
  ];

  const pv_times = [];

  for (let i = 0; i < 2 * pv_expts.length; i++)
    pv_times.push([[], [], []]);

  const pv_plsts = [testUtil.primes_1024, testUtil.primes_2048];

  const test_sign_verify = () => {
    const res = new Array(pv_times.length);

    for (const [idx, [msg, gops_p, gops_v]] of pv_expts.entries()) {
      // random Signer modulus
      const [p, q] = util.rand.sample(pv_plsts[idx % 2], 2);
      const rsakey = new RSAKey(p, q);
      const gen = new GooChallenger(gops_p);
      const prv = new GooSigner(rsakey, gops_p);
      const ver = new GooVerifier(gops_v);

      let start_time, stop_time;

      // generate the challenge token
      start_time = Date.now();
      const [C0, C1] = gen.create_challenge(rsakey);
      stop_time = Date.now();
      pv_times[idx][0].push(stop_time - start_time);

      // generate the signature
      start_time = Date.now();
      const [C2, t, sigma] = prv.sign(C0, C1, msg);
      stop_time = Date.now();
      pv_times[idx][1].push(stop_time - start_time);

      // verify the signature
      start_time = Date.now();
      res[idx] = ver.verify([C1, C2, t], msg, sigma);
      stop_time = Date.now();
      pv_times[idx][2].push(stop_time - start_time);
    }

    return res;
  };

  testUtil.run_all_tests(nreps, 'end-to-end', [
    [
      test_sign_verify,
      // 'sign_and_verify,4x2,4x4,2x2,2x4,c2x2,c2x4,c1x2,c1x4'
      'sign_and_verify,4x2,4x4,2x2,2x4'
    ]
  ]);

  for (let [idx, [n]] of pv_expts.entries())
    testUtil.show_timing_triple(n, pv_times[idx]);
}

{
  let nr = 1;

  for (let i = 2; i < process.argv.length; i++) {
    if (/^\d+$/.test(process.argv[i]))
      nr = process.argv[i] >>> 0;
  }

  main(nr);
}
