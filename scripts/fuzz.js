/* eslint camelcase: "off" */

'use strict';

const assert = require('../test/util/assert');
const rsa = require('bcrypto/lib/rsa');
const random = require('bcrypto/lib/random');
const Goo = require('../lib/goo');
const Signature = require('../lib/js/signature');

const SIG_LENGTH = new Signature().encode(2048).length; // 1426
assert(SIG_LENGTH === 1426);

const DQ_START = 1058;
const DQ_PAD = 16;
// const DQ_SIZE = 240;
// const DQ_END = 1314;

const goo = new Goo(Goo.RSA2048, 2, 3, 2048);
const ver = new Goo(Goo.RSA2048, 2, 3, null);
const key = rsa.privateKeyGenerate(2048);
const pub = rsa.publicKeyCreate(key);

function rand(num) {
  return (Math.random() * num) >>> 0;
}

function concat(data, side) {
  let x = Buffer.from([rand(0x100)]);
  let y = data;

  if (side)
    [x, y] = [y, x];

  return Buffer.concat([x, y]);
}

console.log('Fuzzing with random bytes.');

for (let i = 0; i < 10000000; i++) {
  let msg, sig, C1;

  if (i % 100000 === 0)
    console.log('  Iterations: %d', i);

  switch (rand(4)) {
    case 0:
      msg = random.randomBytes(32);
      sig = random.randomBytes(SIG_LENGTH);
      C1 = random.randomBytes(goo.bits / 8);
      break;
    case 1:
      msg = random.randomBytes(32);
      sig = random.randomBytes(SIG_LENGTH + 1);
      C1 = random.randomBytes(goo.bits / 8 + 1);
      break;
    case 2:
      msg = random.randomBytes(32);
      sig = random.randomBytes(SIG_LENGTH - 1);
      C1 = random.randomBytes(goo.bits / 8 - 1);
      break;
    case 3:
      msg = random.randomBytes(32);
      sig = random.randomBytes(SIG_LENGTH);
      C1 = random.randomBytes(goo.bits / 8);
      switch (rand(3)) {
        case 0:
          msg = Buffer.alloc(0);
          break;
        case 1:
          sig = Buffer.alloc(0);
          break;
        case 2:
          C1 = Buffer.alloc(0);
          break;
        case 3:
          msg = Buffer.alloc(0);
          sig = Buffer.alloc(0);
          C1 = Buffer.alloc(0);
          break;
      }
      break;
  }

  if (sig.length > 0)
    sig.fill(0x00, DQ_START, DQ_START + DQ_PAD);

  assert(!ver.verify(msg, sig, C1));
}

console.log('Fuzzing with mangled signatures.');

for (let i = 0; i < Infinity; i++) {
  if ((i * 100) % 1000 === 0)
    console.log('  Iterations: %d', i * 100);

  // Generate the challenge token.
  const s_prime = goo.generate();
  const C1 = goo.challenge(s_prime, pub);

  // Encrypt to the recipient.
  const ct = goo.encrypt(s_prime, pub);

  // Recipient decrypts.
  const pt = goo.decrypt(ct, key);

  assert.bufferEqual(pt, s_prime);

  // Generate the proof.
  assert(goo.validate(s_prime, C1, key));
  const msg = random.randomBytes(32);
  const sig = goo.sign(msg, s_prime, key);

  // Verify the proof.
  assert(ver.verify(msg, sig, C1));

  for (let i = 0; i < 100; i++) {
    const msg2 = Buffer.from(msg);
    let sig2 = Buffer.from(sig);
    const C12 = Buffer.from(C1);

    switch (rand(20)) {
      case 0:
        sig2 = sig2.slice(0, -1);
        break;
      case 1:
        sig2 = sig2.slice(1);
        break;
      case 2:
        sig2 = concat(sig2, 0);
        break;
      case 3:
        sig2 = concat(sig2, 1);
        break;
      default:
        sig2[rand(sig2.length)] ^= 1;
        break;
    }

    assert(!ver.verify(msg2, sig2, C12));
  }
}
