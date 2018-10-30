'use strict';

const assert = require('bsert');

function encode(num, pad = 0, le = false) {
  if (typeof pad === 'boolean')
    [pad, le] = [le, pad];

  assert(typeof num === 'bigint');
  assert((pad >>> 0) === pad);
  assert(typeof le === 'boolean');

  if (num < 0n)
    num = -num;

  let str = num.toString(16);

  if (str.length & 1)
    str = '0' + str;

  if (pad !== 0) {
    let len = str.length >>> 1;

    if (len > pad)
      throw new RangeError('Number too large.');

    while (len < pad) {
      str = '00' + str;
      len += 1;
    }
  }

  const out = Buffer.from(str, 'hex');

  if (le) {
    let i = out.length - 1;
    let j = 0;

    while (i > j) {
      const t = out[i];
      out[i] = out[j];
      out[j] = t;
      i -= 1;
      j += 1;
    }
  }

  return out;
}

function decode(buf, le = false) {
  assert(Buffer.isBuffer(buf));
  assert(typeof le === 'boolean');

  let n = 0n;

  if (!le) {
    for (let i = 0; i < buf.length; i++) {
      n <<= 8n;
      n |= BigInt(buf[i]);
    }
  } else {
    for (let i = buf.length - 1; i >= 0; i--) {
      n <<= 8n;
      n |= BigInt(buf[i]);
    }
  }

  return n;
}

function encodeHex(num, pad = 0, le = false) {
  if (typeof pad === 'boolean')
    [pad, le] = [le, pad];

  assert(typeof num === 'bigint');
  assert((pad >>> 0) === pad);
  assert(typeof le === 'boolean');

  let neg = false;

  if (num < 0n) {
    num = -num;
    neg = true;
  }

  let str = num.toString(16);

  if (str.length & 1)
    str = '0' + str;

  if (pad !== 0) {
    let len = str.length >>> 1;

    if (len > pad)
      throw new RangeError('Number too large.');

    while (len < pad) {
      str = '00' + str;
      len += 1;
    }
  }

  if (neg)
    str = '-' + str;

  return str;
}

function decodeHex(str, le) {
  assert(typeof str === 'string');

  let neg = false;

  if (str.length > 0 && str[0] === '-') {
    str = str.substring(1);
    neg = true;
  }

  if (str.length & 1)
    str = '0' + str;

  const buf = Buffer.from(str, 'hex');

  if (buf.length !== (str.length >>> 1))
    throw new Error('Invalid hex string.');

  let num = decode(buf, le);

  if (neg)
    num = -num;

  return num;
}

function size(num, pad = 0) {
  assert(typeof num === 'bigint');
  assert((pad >>> 0) === pad);

  if (num < 0n)
    num = -num;

  const len = (num.toString(16).length + 1) >>> 1;

  if (pad !== 0) {
    if (len > pad)
      throw new RangeError('Number too large.');
  }

  return len;
}

function write(data, num, off, pad = 0, le = false) {
  if (typeof pad === 'boolean')
    [pad, le] = [le, pad];

  assert(Buffer.isBuffer(data));
  assert(typeof num === 'bigint');
  assert((off >>> 0) === off);
  assert((pad >>> 0) === pad);
  assert(typeof le === 'boolean');

  if (num < 0n)
    num = -num;

  let str = num.toString(16);

  if (str.length & 1)
    str = '0' + str;

  if (pad !== 0) {
    let len = str.length >>> 1;

    if (len > pad)
      throw new RangeError('Number too large.');

    while (len < pad) {
      str = '00' + str;
      len += 1;
    }
  }

  const w = data.write(str, off, 'hex');

  if (w !== (str.length >>> 1))
    throw new RangeError('Out of bounds write.');

  if (le) {
    let i = (off + w) - 1;
    let j = off;

    while (i > j) {
      const t = data[i];
      data[i] = data[j];
      data[j] = t;
      i -= 1;
      j += 1;
    }
  }

  return off + w;
}

function read(data, off, size, le = false) {
  assert(Buffer.isBuffer(data));
  assert((off >>> 0) === off);
  assert((size >>> 0) === size);
  assert(typeof le === 'boolean');

  let n = 0n;

  const len = off + size;

  if (len > data.length)
    throw new RangeError('Out of bounds read.');

  if (!le) {
    for (let i = off; i < len; i++) {
      n <<= 8n;
      n |= BigInt(data[i]);
    }
  } else {
    for (let i = len - 1; i >= off; i--) {
      n <<= 8n;
      n |= BigInt(data[i]);
    }
  }

  return n;
}

function writeBW(bw, num, pad, le) {
  assert(bw && typeof bw.writeU8 === 'function');
  bw.offset = write(bw.data, num, bw.offset, pad, le);
  return bw;
}

function readBR(br, size, le) {
  assert(br && typeof br.readU8 === 'function');
  const num = read(br.data, br.offset, size, le);
  br.offset += size;
  return num;
}

function byteLength(x) {
  assert(typeof x === 'bigint');

  if (x === 0n)
    return 0;

  if (x < 0n)
    x = -x;

  let i = 0;

  while (x > 0n) {
    i += 1;
    x >>= 8n;
  }

  return i;
}

function bitLength(x) {
  assert(typeof x === 'bigint');

  if (x === 0n)
    return 0;

  if (x < 0n)
    x = -x;

  let i = 0;

  while (x > 0n) {
    i += 1;
    x >>= 1n;
  }

  return i;
}

function zeroBits(x) {
  assert(typeof x === 'bigint');

  if (x === 0n)
    return 0;

  if (x < 0n)
    x = -x;

  let i = 0;

  while ((x & 1n) === 0n) {
    i += 1;
    x >>= 1n;
  }

  return i;
}

function modPow(x, y, m) {
  assert(typeof x === 'bigint');
  assert(typeof y === 'bigint');
  assert(typeof m === 'bigint');
  assert(y >= 0n);
  assert(m >= 0n);

  if (m === 0n)
    throw new Error('Cannot divide by zero.');

  if (m === 1n)
    return 0n;

  x = umod(x, m);

  let r = 1n;

  while (y > 0n) {
    if ((y & 1n) === 1n)
      r = (r * x) % m;

    y >>= 1n;
    x = (x * x) % m;
  }

  return r;
}

function gcd(a, b) {
  assert(typeof a === 'bigint');
  assert(typeof b === 'bigint');
  assert(a >= 0);
  assert(b >= 0);

  let d = 0n;

  while ((a & 1n) === 0n && ((b & 1n) === 0n)) {
    a >>= 1n;
    b >>= 1n;
    d += 1n;
  }

  while (a !== b) {
    if ((a & 1n) === 0n)
      a >>= 1n;
    else if ((b & 1n) === 0n)
      b >>= 1n;
    else if (a > b)
      a = (a - b) >> 1n;
  }

  return a * (2n * d);
}

function bgcd(u, v) {
  assert(typeof u === 'bigint');
  assert(typeof v === 'bigint');
  assert(u >= 0n);
  assert(v >= 0n);

  if (u === 0n)
    return v;

  if (v === 0n)
    return u;

  let shift = 0n;

  while (((u | v) & 1n) === 0n) {
    u >>= 1n;
    v >>= 1n;
    shift += 1n;
  }

  while ((u & 1n) === 0n)
    u >>= 1n;

  do {
    while ((v & 1n) === 0n)
      v >>= 1n;

    if (u > v)
      [u, v] = [v, u];

    v -= u;
  } while (v !== 0n);

  return u << shift;
}

function egcd(a, b) {
  assert(typeof a === 'bigint');
  assert(typeof b === 'bigint');

  let s = 0n;
  let os = 1n;
  let t = 1n;
  let ot = 0n;
  let r = b;
  let or = a;

  while (r !== 0n) {
    const q = or / r;

    [or, r] = [r, or - q * r];
    [os, s] = [s, os - q * s];
    [ot, t] = [t, ot - q * t];
  }

  return or;
}

function inverse(a, n) {
  assert(typeof a === 'bigint');
  assert(typeof n === 'bigint');
  assert(n >= 0n);

  a = umod(a, n);

  let t = 0n;
  let nt = 1n;
  let r = n;
  let nr = a;

  while (nr !== 0n) {
    const q = r / nr;

    [t, nt] = [nt, t - q * nt];
    [r, nr] = [nr, r - q * nr];
  }

  if (r > 1n)
    throw new Error('Not invertible.');

  if (t < 0n)
    t += n;

  return t;
}

function inverseP(a, b) {
  assert(typeof a === 'bigint');
  assert(typeof b === 'bigint');
  assert(b >= 0n);

  a = umod(a, b);

  let t = 0n;
  let nt = 1n;
  let r = b;
  let nr = a;

  while (nr !== 0n) {
    const q = r / nr;

    [r, nr] = [nr, r - q * nr];
    [t, nt] = [nt, t - q * nt];
  }

  if (r === 0)
    throw new Error('Not invertible.');

  return t / r;
}

function abs(x) {
  assert(typeof x === 'bigint');
  return x < 0n ? -x : x;
}

function jacobi(x, y) {
  assert(typeof x === 'bigint');
  assert(typeof y === 'bigint');
  assert(y >= 0n);

  if (y === 0n || (y & 1n) === 0n)
    throw new Error('jacobi: `y` must be odd.');

  x = umod(x, y);

  let a = x;
  let b = y;
  let j = 1;

  if (b < 0n) {
    if (a < 0n)
      j = -1;
    b = -b;
  }

  for (;;) {
    if (b === 1n)
      return j;

    if (a === 0n)
      return 0;

    a %= b;

    if (a === 0n)
      return 0;

    const s = zeroBits(a);

    if (s & 1) {
      const bmod8 = b & 7n;

      if (bmod8 === 3n || bmod8 === 5n)
        j = -j;
    }

    const c = a >> BigInt(s);

    if ((b & 3n) === 3n && (c & 3n) === 3n)
      j = -j;

    a = b;
    b = c;
  }
}

function sqrt(x) {
  assert(typeof x === 'bigint');

  if (x < 0n)
    x = -x;

  if (x <= 1n)
    return x;

  const len = BigInt(bitLength(x));

  let z1 = 1n;

  z1 <<= (len >> 1n) + 1n;

  for (;;) {
    let z2 = x / z1;

    z2 += z1;
    z2 >>= 1n;

    if (z2 >= z1)
      return z1;

    z1 = z2;
  }
}

function modAdd(x, y, p) {
  assert(typeof x === 'bigint');
  assert(typeof y === 'bigint');
  assert(typeof p === 'bigint');
  assert(p >= 0n);

  x = umod(x, p);
  y = umod(y, p);

  return (x + x) % p;
}

function modSub(x, y, p) {
  assert(typeof x === 'bigint');
  assert(typeof y === 'bigint');
  assert(typeof p === 'bigint');
  assert(p >= 0n);

  x = umod(x, p);
  y = umod(y, p);

  x -= y;

  if (x < 0n)
    x += p;

  return x;
}

function modMul(x, y, p) {
  assert(typeof x === 'bigint');
  assert(typeof y === 'bigint');
  assert(typeof p === 'bigint');
  assert(p >= 0n);

  x = umod(x, p);

  return (x * y) % p;
}

function modDiv(x, y, p) {
  assert(typeof x === 'bigint');
  assert(typeof y === 'bigint');
  assert(typeof p === 'bigint');
  assert(p >= 0n);

  x = umod(x, p);
  y = umod(y, p);

  return x / y;
}

function modSqr(x, p) {
  assert(typeof x === 'bigint');
  assert(typeof p === 'bigint');
  assert(p >= 0n);

  x = umod(x, p);

  return (x * x) % p;
}

function modSqrt(x, p) {
  assert(typeof x === 'bigint');
  assert(typeof p === 'bigint');
  assert(p >= 0n);

  x = umod(x, p);

  switch (jacobi(x, p)) {
    case -1:
      throw new Error('X is not a square mod P.');
    case 0:
      return 0n;
    case 1:
      break;
  }

  if ((x & 3n) === 3n) {
    let e = p + 1n;
    e >>= 2n;
    return modPow(x, e, p);
  }

  // if ((x & 7n) === 5n) {
  //   let e = p >> 3n;
  //   let tx = x << 1n;
  //   let alpha = modPow(tx, e, p);
  //   let beta = alpha * alpha;
  //   beta %= p;
  //   beta *= tx;
  //   beta %= p;
  //   beta -= 1n;
  //   beta *= x;
  //   beta %= p;
  //   beta *= alpha;
  //   return beta % p;
  // }

  let s = p - 1n;

  const e = BigInt(zeroBits(s));

  s >>= e;

  let n = 2n;

  while (jacobi(n, p) !== -1)
    n += 1n;

  let y = 0n;
  let b = 0n;
  let g = 0n;

  y = s + 1n;
  y >>= 1n;
  y = modPow(x, y, p);
  b = modPow(x, s, p);
  g = modPow(n, s, p);

  let r = e;
  let t = 0n;

  for (;;) {
    let m = 0n;

    t = b;

    while (t !== 1n) {
      t = (t * t) % p;
      m += 1n;
    }

    if (m === 0n)
      return y;

    t = 0n;
    t |= 1n << (r - m - 1n);
    t = modPow(g, t, p);
    g = (t * t) % p;
    y = (y * t) % p;
    b = (b * g) % p;
    r = m;
  }
}

function max(a, b) {
  assert(typeof a === 'bigint');
  assert(typeof b === 'bigint');
  return a > b ? a : b;
}

function min(a, b) {
  assert(typeof a === 'bigint');
  assert(typeof b === 'bigint');
  return a < b ? a : b;
}

function umod(x, y) {
  assert(typeof x === 'bigint');
  assert(typeof y === 'bigint');

  x %= y;

  if (y < 0n) {
    if (x > 0n)
      x += y;
  } else {
    if (x < 0n)
      x += y;
  }

  return x;
}

function div(x, y) {
  assert(typeof x === 'bigint');
  assert(typeof y === 'bigint');

  if ((x < 0n) !== (y < 0n)) {
    if (x % y !== 0n)
      return (x / y) - 1n;
  }

  return x / y;
}

function divmod(x, y) {
  assert(typeof x === 'bigint');
  assert(typeof y === 'bigint');
  return [div(x, y), umod(x, y)];
}

exports.encode = encode;
exports.decode = decode;
exports.encodeHex = encodeHex;
exports.decodeHex = decodeHex;
exports.size = size;
exports.write = write;
exports.read = read;
exports.writeBW = writeBW;
exports.readBR = readBR;
exports.byteLength = byteLength;
exports.bitLength = bitLength;
exports.zeroBits = zeroBits;
exports.modPow = modPow;
exports.gcd = gcd;
exports.bgcd = bgcd;
exports.egcd = egcd;
exports.inverse = inverse;
exports.inverseP = inverseP;
exports.abs = abs;
exports.jacobi = jacobi;
exports.sqrt = sqrt;
exports.modAdd = modAdd;
exports.modSub = modSub;
exports.modMul = modMul;
exports.modDiv = modDiv;
exports.modSqr = modSqr;
exports.modSqrt = modSqrt;
exports.min = min;
exports.max = max;
exports.umod = umod;
exports.div = div;
exports.divmod = divmod;
