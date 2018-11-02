'use strict';

const fs = require('fs');
const Path = require('path');
const SHA256 = require('bcrypto/lib/sha256');
const Goo = require('../lib/js/goo');

const moduli = [
  // ['aol1', Goo.AOL1],
  // ['aol2', Goo.AOL2],
  ['rsa2048', Goo.RSA2048]
  // ['rsa619', Goo.RSA617]
];

const sizes = [
  null,
  // 1024,
  // 2048,
  4096
];

const MAX_SIZE = 510;
const MAX_LEN = 2;

function mkdir(path, mode = 0o755) {
  path = Path.resolve(__dirname, '..', ...path);

  try {
    fs.mkdirSync(path, mode);
  } catch (e) {
    if (e.code === 'EEXIST')
      return;
    throw e;
  }
}

function write(path, txt) {
  path = Path.resolve(__dirname, '..', ...path);
  fs.writeFileSync(path, txt);
}

function combToC(lines, name, comb) {
  lines.push(`      .${name} = {`);
  lines.push(`        .points_per_add = ${comb.pointsPerAdd},`);
  lines.push(`        .adds_per_shift = ${comb.addsPerShift},`);
  lines.push(`        .shifts = ${comb.shifts},`);
  lines.push(`        .bits_per_window = ${comb.bitsPerWindow},`);
  lines.push(`        .bits = ${comb.bits},`);
  lines.push(`        .points_per_subcomb = ${comb.pointsPerSubcomb},`);
  lines.push(`        .size = ${comb.size},`);
  lines.push(`        .items = {`);

  for (const item of comb.items)
    lines.push(`          "${item}",`);

  lines.push(`        },`);
  lines.push(`      },`);
}

function combItemToC(lines, item) {
  lines.push(`    {`);
  combToC(lines, 'g', item.g);
  combToC(lines, 'h', item.h);
  lines.push(`    },`);
}

const HEADER = `
typedef struct goo_precomb_s {
  long points_per_add;
  long adds_per_shift;
  long shifts;
  long bits_per_window;
  long bits;
  long points_per_subcomb;
  long size;
  const char *items[${MAX_SIZE}];
} goo_precomb_t;

typedef struct goo_precomb_item_s {
  goo_precomb_t g;
  goo_precomb_t h;
} goo_precomb_item_t;

typedef struct goo_precombs_s {
  const char hash[64];
  long size;
  goo_precomb_item_t items[${MAX_LEN}];
} goo_precombs_t;
`;

function combsToC(name, bits, modulus, json) {
  const hash = SHA256.digest(modulus).toString('hex');
  const suffix = bits == null ? '' : `_${bits}`;
  const def = name.toUpperCase() + suffix;
  const len = json.length;
  const lines = [];

  lines.push(HEADER);
  lines.push(`static const goo_precombs_t GOO_COMB_${def} = {`);
  lines.push(`  .hash = "${hash}",`);
  lines.push(`  .size = ${len},`);
  lines.push(`  .items = {`);

  for (const item of json)
    combItemToC(lines, item);

  let i = MAX_LEN - json.length;

  while (i > 0) {
    lines.push('  NULL,');
    i -= 1;
  }

  lines.push(`  },`);
  lines.push(`};`);

  return lines.join('\n');
}

function main() {
  mkdir(['combs']);

  for (const [name, modulus] of moduli) {
    for (const bits of sizes) {
      const goo = new Goo(modulus, 2, 3, bits);
      const json = goo.toJSON().combs;
      const suffix = bits == null ? '' : `-${bits.toString(10)}`;
      const file = `${name}${suffix}`;
      const str = JSON.stringify(json, null, 2);
      const c = combsToC(name, bits, modulus, json);

      write(['combs', `${file}.json`], str + '\n');
      write(['combs', `${file}.h`], c + '\n');
    }
  }
}

main();
