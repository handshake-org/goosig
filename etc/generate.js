#!/usr/bin/env node

'use strict';

const fs = require('fs');
const Path = require('path');
const BN = require('bcrypto/lib/bn.js');
const rsa = require('bcrypto/lib/rsa');
const SHA256 = require('bcrypto/lib/sha256');
const x509 = require('bcrypto/lib/encoding/x509');

function parseAOL(file) {
  const path = Path.resolve(__dirname, file);
  const str = fs.readFileSync(path, 'utf8');
  const cert = x509.Certificate.fromPEM(str);
  const spki = cert.tbsCertificate.subjectPublicKeyInfo;
  const key = rsa.publicKeyImportSPKI(spki.raw);

  return key.n;
}

function parseRSA(file) {
  const path = Path.resolve(__dirname, file);
  const str = fs.readFileSync(path, 'utf8');
  const number = str.trim().split(/\n+/).pop();
  const n = new BN(number, 10);
  return n.toArrayLike(Buffer);
}

function encode(name, data) {
  const hash = SHA256.digest(data);
  const h = data.toString('hex');

  // Digit Sum (used for RSA-2048 -- see challengenumbers.txt)
  const number = new BN(data);
  const base10 = number.toString(10);

  let sum = 0;
  for (let i = 0; i < base10.length; i++)
    sum += Number(base10[i]);

  // Checksum (used for RSA-617 -- see rsa-fact.txt)
  const checksum = number.modn(991889);

  let out = '';

  out += `// SHA-256: ${hash.toString('hex')}\n`;
  out += `// Digit Sum: ${sum}\n`;
  out += `// Checksum: ${checksum}\n`;
  out += `exports.${name} = Buffer.from(''`;

  for (let i = 0; i < h.length; i += 60) {
    const chunk = h.slice(i, i + 60);

    out += '\n';
    out += `  + '${chunk}'`;
  }

  out += `, 'hex');\n`;

  return out;
}

function generate(items) {
  let str = '';

  for (const [name, type, file] of items) {
    let data = null;

    if (type === 'AOL')
      data = parseAOL(file);
    else
      data = parseRSA(file);

    str += encode(name, data) + '\n';
  }

  return str;
}

function main() {
  const out = generate([
    ['AOL1', 'AOL', 'aol1.pem'],
    ['AOL2', 'AOL', 'aol2.pem'],
    ['RSA617', 'RSA', 'RSA-617.txt'],
    ['RSA2048', 'RSA', 'RSA-2048.txt']
  ]);
  console.log(out);
}

main();
