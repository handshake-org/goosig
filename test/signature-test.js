/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: 'off' */

'use strict';

const assert = require('bsert');
const Signature = require('../lib/js/signature');

describe('Signature', function() {
  it('should deserialize and reserialize', () => {
    const sig1 = new Signature();

    sig1.C2 = 0x01n;
    sig1.C3 = 0x01n;
    sig1.t = 0x02n;
    sig1.chal = 0x03n;
    sig1.ell = 0x04n;
    sig1.Aq = 0x05n;
    sig1.Bq = 0x06n;
    sig1.Cq = 0x07n;
    sig1.Dq = 0x08n;
    sig1.Eq = 0x08n;
    sig1.z_w = 0x09n;
    sig1.z_w2 = 0x0an;
    sig1.z_s1 = 0x0bn;
    sig1.z_a = 0x0cn;
    sig1.z_an = 0x0dn;
    sig1.z_s1w = 0x0en;
    sig1.z_sa = 0x0fn;
    sig1.z_s2 = 0x0fn;

    const sig2 = Signature.decode(sig1.encode(2048), 2048);

    assert.strictEqual(sig2.C2, 0x01n);
    assert.strictEqual(sig2.C3, 0x01n);
    assert.strictEqual(sig2.t, 0x02n);
    assert.strictEqual(sig2.chal, 0x03n);
    assert.strictEqual(sig2.ell, 0x04n);
    assert.strictEqual(sig2.Aq, 0x05n);
    assert.strictEqual(sig2.Bq, 0x06n);
    assert.strictEqual(sig2.Cq, 0x07n);
    assert.strictEqual(sig2.Dq, 0x08n);
    assert.strictEqual(sig2.Eq, 0x08n);
    assert.strictEqual(sig2.z_w, 0x09n);
    assert.strictEqual(sig2.z_w2, 0x0an);
    assert.strictEqual(sig2.z_s1, 0x0bn);
    assert.strictEqual(sig2.z_a, 0x0cn);
    assert.strictEqual(sig2.z_an, 0x0dn);
    assert.strictEqual(sig2.z_s1w, 0x0en);
    assert.strictEqual(sig2.z_sa, 0x0fn);
    assert.strictEqual(sig2.z_s2, 0x0fn);
  });

  it('should deserialize and reserialize (with options)', () => {
    const sig1 = new Signature({
      C2: 0x01n,
      C3: 0x01n,
      t: 0x02n,
      chal: 0x03n,
      ell: 0x04n,
      Aq: 0x05n,
      Bq: 0x06n,
      Cq: 0x07n,
      Dq: 0x08n,
      Eq: 0x08n,
      z_prime: [
        0x09n,
        0x0an,
        0x0bn,
        0x0cn,
        0x0dn,
        0x0en,
        0x0fn,
        0x0fn
      ]
    });

    const sig2 = Signature.decode(sig1.encode(2048), 2048);

    assert.strictEqual(sig2.C2, 0x01n);
    assert.strictEqual(sig2.C3, 0x01n);
    assert.strictEqual(sig2.t, 0x02n);
    assert.strictEqual(sig2.chal, 0x03n);
    assert.strictEqual(sig2.ell, 0x04n);
    assert.strictEqual(sig2.Aq, 0x05n);
    assert.strictEqual(sig2.Bq, 0x06n);
    assert.strictEqual(sig2.Cq, 0x07n);
    assert.strictEqual(sig2.Dq, 0x08n);
    assert.strictEqual(sig2.Eq, 0x08n);
    assert.strictEqual(sig2.z_w, 0x09n);
    assert.strictEqual(sig2.z_w2, 0x0an);
    assert.strictEqual(sig2.z_s1, 0x0bn);
    assert.strictEqual(sig2.z_a, 0x0cn);
    assert.strictEqual(sig2.z_an, 0x0dn);
    assert.strictEqual(sig2.z_s1w, 0x0en);
    assert.strictEqual(sig2.z_sa, 0x0fn);
    assert.strictEqual(sig2.z_s2, 0x0fn);
  });

  it('should deserialize and reserialize JSON', () => {
    const sig1 = new Signature({
      C2: 0x01n,
      C3: 0x01n,
      t: 0x02n,
      chal: 0x03n,
      ell: 0x04n,
      Aq: 0x05n,
      Bq: 0x06n,
      Cq: 0x07n,
      Dq: 0x08n,
      Eq: 0x08n,
      z_prime: [
        0x09n,
        0x0an,
        0x0bn,
        0x0cn,
        0x0dn,
        0x0en,
        0x0fn,
        0x0fn
      ]
    });

    const sig2 = Signature.fromJSON(sig1.toJSON());

    assert.strictEqual(sig2.C2, 0x01n);
    assert.strictEqual(sig2.C3, 0x01n);
    assert.strictEqual(sig2.t, 0x02n);
    assert.strictEqual(sig2.chal, 0x03n);
    assert.strictEqual(sig2.ell, 0x04n);
    assert.strictEqual(sig2.Aq, 0x05n);
    assert.strictEqual(sig2.Bq, 0x06n);
    assert.strictEqual(sig2.Cq, 0x07n);
    assert.strictEqual(sig2.Dq, 0x08n);
    assert.strictEqual(sig2.Eq, 0x08n);
    assert.strictEqual(sig2.z_w, 0x09n);
    assert.strictEqual(sig2.z_w2, 0x0an);
    assert.strictEqual(sig2.z_s1, 0x0bn);
    assert.strictEqual(sig2.z_a, 0x0cn);
    assert.strictEqual(sig2.z_an, 0x0dn);
    assert.strictEqual(sig2.z_s1w, 0x0en);
    assert.strictEqual(sig2.z_sa, 0x0fn);
    assert.strictEqual(sig2.z_s2, 0x0fn);
  });
});
