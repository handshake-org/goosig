/* eslint camelcase: "off" */

'use strict';

const assert = require('./util/assert');
const rsa = require('bcrypto/lib/rsa');
const random = require('bcrypto/lib/random');
const Goo = require('../lib/goo');
const Signature = require('../lib/js/signature');

const SIG_LENGTH = new Signature().encode(2048).length;
const ZERO = Buffer.alloc(1, 0x00);

const goo = new Goo(Goo.RSA2048, 2, 3, 2048);
const ver = new Goo(Goo.RSA2048, 2, 3, null);
const key = rsa.privateKeyGenerate(2048);
const pub = rsa.publicKeyCreate(key);

function concat(...items) {
  return Buffer.concat(items);
}

function rand(num) {
  return (Math.random() * num) >>> 0;
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

  assert(!ver.verify(msg, sig, C1));
}

console.log('Fuzzing with mangled signatures.');

for (let i = 0; i < Infinity; i++) {
  if ((i * 100) % 1000 === 0)
    console.log('  Iterations: %d', i * 100);

  // Generate the challenge token.
  const [s_prime, C1] = goo.challenge(pub);

  // Encrypt to the recipient.
  const ct = goo.encrypt(s_prime, C1, pub);

  // Recipient decrypts.
  const [x, y] = goo.decrypt(ct, key);

  assert.bufferEqual(x, s_prime);
  assert.bufferEqual(y, C1);

  // Generate the proof.
  const msg = random.randomBytes(32);
  const sig = goo.sign(msg, s_prime, C1, key);

  // Verify the proof.
  assert(ver.verify(msg, sig, C1));

  for (let i = 0; i < 100; i++) {
    let msg2 = Buffer.from(msg);
    let sig2 = Buffer.from(sig);
    let C12 = Buffer.from(C1);

    switch (rand(20)) {
      case 0:
        sig2 = sig2.slice(0, -1);
        break;
      case 1:
        sig2 = sig2.slice(1);
        break;
      case 2:
        sig2 = Buffer.concat([
          sig2,
          Buffer.from([rand(0x100)])
        ]);
        break;
      case 3:
        sig2 = Buffer.concat([
          Buffer.from([rand(0x100)]),
          sig2
        ]);
        break;
      default:
        sig2[rand(sig2.length)] ^= 1;
        break;
    }

    assert(!ver.verify(msg2, sig2, C12));
  }
}
