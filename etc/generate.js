#!/usr/bin/env node

'use strict';

const assert = require('bsert');
const fs = require('fs');
const Path = require('path');
const BLAKE2b = require('bcrypto/lib/blake2b256');
const BN = require('bcrypto/lib/bn.js');
const rsa = require('bcrypto/lib/rsa');
const SHA256 = require('bcrypto/lib/sha256');
const SHA3 = require('bcrypto/lib/sha3-256');
const x509 = require('bcrypto/lib/encoding/x509');

function parseAOL(file) {
  assert(typeof file === 'string');

  const path = Path.resolve(__dirname, file);
  const str = fs.readFileSync(path, 'utf8');
  const cert = x509.Certificate.fromPEM(str);
  const spki = cert.tbsCertificate.subjectPublicKeyInfo;
  const key = rsa.publicKeyImportSPKI(spki.raw);

  return key.n;
}

function parseRSA(file) {
  assert(typeof file === 'string');

  const path = Path.resolve(__dirname, file);
  const str = fs.readFileSync(path, 'utf8');
  const base10 = str.trim().split(/\n+/).pop();
  const num = new BN(base10, 10);

  return num.toArrayLike(Buffer);
}

function encode(name, data, desc) {
  assert(typeof name === 'string');
  assert(Buffer.isBuffer(data));
  assert(!desc || typeof desc === 'string');

  const blake2b = BLAKE2b.digest(data);
  const sha256 = SHA256.digest(data);
  const sha3 = SHA3.digest(data);
  const hex = data.toString('hex');

  // Digit Sum (used for RSA-2048 -- see challengenumbers.txt)
  const num = new BN(data);
  const base10 = num.toString(10);

  let sum = 0;
  for (let i = 0; i < base10.length; i++)
    sum += Number(base10[i]);

  // Checksum (used for RSA-617 -- see rsa-fact.txt)
  const checksum = num.modn(991889);

  let out = '';

  if (desc)
    out += `// ${desc}\n`;
  out += `// BLAKE2b-256: ${blake2b.toString('hex')}\n`;
  out += `// SHA-256: ${sha256.toString('hex')}\n`;
  out += `// SHA-3: ${sha3.toString('hex')}\n`;
  out += `// Digit Sum: ${sum}\n`;
  out += `// Checksum: ${checksum}\n`;
  out += `exports.${name} = Buffer.from(''`;

  for (let i = 0; i < hex.length; i += 60) {
    const chunk = hex.slice(i, i + 60);

    out += '\n';
    out += `  + '${chunk}'`;
  }

  out += `, 'hex');\n`;

  return out;
}

function generate(items) {
  assert(Array.isArray(items));

  let str = '';

  for (const [name, type, file, desc] of items) {
    let data = null;

    if (type === 'AOL')
      data = parseAOL(file);
    else
      data = parseRSA(file);

    str += encode(name, data, desc) + '\n';
  }

  return str;
}

function main() {
  const out = generate([
    ['AOL1', 'AOL', 'aol1.pem', 'America Online Root CA 1 (2048)'],
    ['AOL2', 'AOL', 'aol2.pem', 'America Online Root CA 2 (4096)'],
    ['RSA2048', 'RSA', 'RSA-2048.txt', 'RSA-2048 Factoring Challenge (2048)'],
    ['RSA617', 'RSA', 'RSA-617.txt', 'RSA-617 Factoring Challenge (2048)']
  ]);
  console.log(out);
}

main();
