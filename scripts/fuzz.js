/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const rsa = require('bcrypto/lib/rsa');
const rng = require('bcrypto/lib/random');
const Goo = require('../');
const Signature = require('../lib/js/signature');

const SIG_LENGTH = new Signature().encode(2048).length; // 1964
assert.strictEqual(SIG_LENGTH, 1964);

const EQ_START = 1571;
const EQ_PAD = 16;
// const EQ_SIZE = 240;
// const EQ_END = 1827;

const goo = new Goo(Goo.RSA2048, 2, 3, 2048);
const ver = new Goo(Goo.RSA2048, 2, 3, null);
const key = rsa.privateKeyGenerate(2048);
const pub = rsa.publicKeyCreate(key);

function rand(num) {
  return rng.randomRange(0, num);
}

function concat(data, side) {
  let x = Buffer.from([rand(0x100)]);
  let y = data;

  if (side)
    [x, y] = [y, x];

  return Buffer.concat([x, y]);
}

console.log('Fuzzing with random bytes.');

for (let i = 0; i < 1000000; i++) {
  let msg, sig, C1;

  if (i % 100000 === 0)
    console.log('  Iterations: %d', i);

  switch (rand(4)) {
    case 0:
      msg = rng.randomBytes(32);
      sig = rng.randomBytes(SIG_LENGTH);
      C1 = rng.randomBytes(goo.size);
      break;
    case 1:
      msg = rng.randomBytes(32);
      sig = rng.randomBytes(SIG_LENGTH + 1);
      C1 = rng.randomBytes(goo.size + 1);
      break;
    case 2:
      msg = rng.randomBytes(32);
      sig = rng.randomBytes(SIG_LENGTH - 1);
      C1 = rng.randomBytes(goo.size - 1);
      break;
    case 3:
      msg = rng.randomBytes(32);
      sig = rng.randomBytes(SIG_LENGTH);
      C1 = rng.randomBytes(goo.size);
      switch (rand(4)) {
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
    sig.fill(0x00, EQ_START, EQ_START + EQ_PAD);

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

  assert(goo.validate(s_prime, C1, key));

  // Generate the proof.
  const msg = rng.randomBytes(32);
  const sig = goo.sign(msg, s_prime, key);

  // Verify the proof.
  assert(ver.verify(msg, sig, C1));

  for (let i = 0; i < 100; i++) {
    const msg0 = Buffer.from(msg);
    const C10 = Buffer.from(C1);

    let sig0 = Buffer.from(sig);

    switch (rand(20)) {
      case 0:
        sig0 = sig0.slice(0, -1);
        break;
      case 1:
        sig0 = sig0.slice(1);
        break;
      case 2:
        sig0 = concat(sig0, 0);
        break;
      case 3:
        sig0 = concat(sig0, 1);
        break;
      case 4:
        sig0[sig0.length - 1] ^= 1;
        break;
      default:
        switch (rand(3)) {
          case 0:
            msg0[rand(msg0.length)] ^= 1 << rand(8);
            break;
          case 1:
            C10[rand(C10.length)] ^= 1 << rand(8);
            break;
          case 2:
            sig0[rand(sig0.length)] ^= 1 << rand(8);
            break;
        }
        break;
    }

    assert(!ver.verify(msg0, sig0, C10));
  }
}
