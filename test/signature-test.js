/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */
/* eslint camelcase: 'off' */

'use strict';

const assert = require('bsert');
const BN = require('bcrypto/lib/bn.js');
const Signature = require('../lib/js/signature');

describe('Signature', function() {
  it('should deserialize and reserialize', () => {
    const sig1 = new Signature();

    sig1.C2 = new BN(0x01);
    sig1.C3 = new BN(0x01);
    sig1.t = new BN(0x02);
    sig1.chal = new BN(0x03);
    sig1.ell = new BN(0x04);
    sig1.Aq = new BN(0x05);
    sig1.Bq = new BN(0x06);
    sig1.Cq = new BN(0x07);
    sig1.Dq = new BN(0x08);
    sig1.Eq = new BN(0x08);
    sig1.z_w = new BN(0x09);
    sig1.z_w2 = new BN(0x0a);
    sig1.z_s1 = new BN(0x0b);
    sig1.z_a = new BN(0x0c);
    sig1.z_an = new BN(0x0d);
    sig1.z_s1w = new BN(0x0e);
    sig1.z_sa = new BN(0x0f);
    sig1.z_s2 = new BN(0x0f);

    const sig2 = Signature.decode(sig1.encode(2048), 2048);

    assert.strictEqual(sig2.C2.toString(), new BN(0x01).toString());
    assert.strictEqual(sig2.C3.toString(), new BN(0x01).toString());
    assert.strictEqual(sig2.t.toString(), new BN(0x02).toString());
    assert.strictEqual(sig2.chal.toString(), new BN(0x03).toString());
    assert.strictEqual(sig2.ell.toString(), new BN(0x04).toString());
    assert.strictEqual(sig2.Aq.toString(), new BN(0x05).toString());
    assert.strictEqual(sig2.Bq.toString(), new BN(0x06).toString());
    assert.strictEqual(sig2.Cq.toString(), new BN(0x07).toString());
    assert.strictEqual(sig2.Dq.toString(), new BN(0x08).toString());
    assert.strictEqual(sig2.Eq.toString(), new BN(0x08).toString());
    assert.strictEqual(sig2.z_w.toString(), new BN(0x09).toString());
    assert.strictEqual(sig2.z_w2.toString(), new BN(0x0a).toString());
    assert.strictEqual(sig2.z_s1.toString(), new BN(0x0b).toString());
    assert.strictEqual(sig2.z_a.toString(), new BN(0x0c).toString());
    assert.strictEqual(sig2.z_an.toString(), new BN(0x0d).toString());
    assert.strictEqual(sig2.z_s1w.toString(), new BN(0x0e).toString());
    assert.strictEqual(sig2.z_sa.toString(), new BN(0x0f).toString());
    assert.strictEqual(sig2.z_s2.toString(), new BN(0x0f).toString());
  });

  it('should deserialize and reserialize (with options)', () => {
    const sig1 = new Signature({
      C2: new BN(0x01),
      C3: new BN(0x01),
      t: new BN(0x02),
      chal: new BN(0x03),
      ell: new BN(0x04),
      Aq: new BN(0x05),
      Bq: new BN(0x06),
      Cq: new BN(0x07),
      Dq: new BN(0x08),
      Eq: new BN(0x08),
      z_w: new BN(0x09),
      z_w2: new BN(0x0a),
      z_s1: new BN(0x0b),
      z_a: new BN(0x0c),
      z_an: new BN(0x0d),
      z_s1w: new BN(0x0e),
      z_sa: new BN(0x0f),
      z_s2: new BN(0x0f)
    });

    const sig2 = Signature.decode(sig1.encode(2048), 2048);

    assert.strictEqual(sig2.C2.toString(), new BN(0x01).toString());
    assert.strictEqual(sig2.C3.toString(), new BN(0x01).toString());
    assert.strictEqual(sig2.t.toString(), new BN(0x02).toString());
    assert.strictEqual(sig2.chal.toString(), new BN(0x03).toString());
    assert.strictEqual(sig2.ell.toString(), new BN(0x04).toString());
    assert.strictEqual(sig2.Aq.toString(), new BN(0x05).toString());
    assert.strictEqual(sig2.Bq.toString(), new BN(0x06).toString());
    assert.strictEqual(sig2.Cq.toString(), new BN(0x07).toString());
    assert.strictEqual(sig2.Dq.toString(), new BN(0x08).toString());
    assert.strictEqual(sig2.Eq.toString(), new BN(0x08).toString());
    assert.strictEqual(sig2.z_w.toString(), new BN(0x09).toString());
    assert.strictEqual(sig2.z_w2.toString(), new BN(0x0a).toString());
    assert.strictEqual(sig2.z_s1.toString(), new BN(0x0b).toString());
    assert.strictEqual(sig2.z_a.toString(), new BN(0x0c).toString());
    assert.strictEqual(sig2.z_an.toString(), new BN(0x0d).toString());
    assert.strictEqual(sig2.z_s1w.toString(), new BN(0x0e).toString());
    assert.strictEqual(sig2.z_sa.toString(), new BN(0x0f).toString());
    assert.strictEqual(sig2.z_s2.toString(), new BN(0x0f).toString());
  });

  it('should deserialize and reserialize JSON', () => {
    const sig1 = new Signature({
      C2: new BN(0x01),
      C3: new BN(0x01),
      t: new BN(0x02),
      chal: new BN(0x03),
      ell: new BN(0x04),
      Aq: new BN(0x05),
      Bq: new BN(0x06),
      Cq: new BN(0x07),
      Dq: new BN(0x08),
      Eq: new BN(0x08),
      z_w: new BN(0x09),
      z_w2: new BN(0x0a),
      z_s1: new BN(0x0b),
      z_a: new BN(0x0c),
      z_an: new BN(0x0d),
      z_s1w: new BN(0x0e),
      z_sa: new BN(0x0f),
      z_s2: new BN(0x0f)
    });

    const sig2 = Signature.fromJSON(sig1.toJSON());

    assert.strictEqual(sig2.C2.toString(), new BN(0x01).toString());
    assert.strictEqual(sig2.C3.toString(), new BN(0x01).toString());
    assert.strictEqual(sig2.t.toString(), new BN(0x02).toString());
    assert.strictEqual(sig2.chal.toString(), new BN(0x03).toString());
    assert.strictEqual(sig2.ell.toString(), new BN(0x04).toString());
    assert.strictEqual(sig2.Aq.toString(), new BN(0x05).toString());
    assert.strictEqual(sig2.Bq.toString(), new BN(0x06).toString());
    assert.strictEqual(sig2.Cq.toString(), new BN(0x07).toString());
    assert.strictEqual(sig2.Dq.toString(), new BN(0x08).toString());
    assert.strictEqual(sig2.Eq.toString(), new BN(0x08).toString());
    assert.strictEqual(sig2.z_w.toString(), new BN(0x09).toString());
    assert.strictEqual(sig2.z_w2.toString(), new BN(0x0a).toString());
    assert.strictEqual(sig2.z_s1.toString(), new BN(0x0b).toString());
    assert.strictEqual(sig2.z_a.toString(), new BN(0x0c).toString());
    assert.strictEqual(sig2.z_an.toString(), new BN(0x0d).toString());
    assert.strictEqual(sig2.z_s1w.toString(), new BN(0x0e).toString());
    assert.strictEqual(sig2.z_sa.toString(), new BN(0x0f).toString());
    assert.strictEqual(sig2.z_s2.toString(), new BN(0x0f).toString());
  });

  it('should deserialize and reserialize (with negative Eq)', () => {
    const sig1 = new Signature({
      C2: new BN(0x01),
      C3: new BN(0x01),
      t: new BN(0x02),
      chal: new BN(0x03),
      ell: new BN(0x04),
      Aq: new BN(0x05),
      Bq: new BN(0x06),
      Cq: new BN(0x07),
      Dq: new BN(0x08),
      Eq: new BN(-0x08),
      z_w: new BN(0x09),
      z_w2: new BN(0x0a),
      z_s1: new BN(0x0b),
      z_a: new BN(0x0c),
      z_an: new BN(0x0d),
      z_s1w: new BN(0x0e),
      z_sa: new BN(0x0f),
      z_s2: new BN(0x0f)
    });

    const sig2 = Signature.decode(sig1.encode(2048), 2048);

    assert.strictEqual(sig2.C2.toString(), new BN(0x01).toString());
    assert.strictEqual(sig2.C3.toString(), new BN(0x01).toString());
    assert.strictEqual(sig2.t.toString(), new BN(0x02).toString());
    assert.strictEqual(sig2.chal.toString(), new BN(0x03).toString());
    assert.strictEqual(sig2.ell.toString(), new BN(0x04).toString());
    assert.strictEqual(sig2.Aq.toString(), new BN(0x05).toString());
    assert.strictEqual(sig2.Bq.toString(), new BN(0x06).toString());
    assert.strictEqual(sig2.Cq.toString(), new BN(0x07).toString());
    assert.strictEqual(sig2.Dq.toString(), new BN(0x08).toString());
    assert.strictEqual(sig2.Eq.toString(), new BN(-0x08).toString());
    assert.strictEqual(sig2.z_w.toString(), new BN(0x09).toString());
    assert.strictEqual(sig2.z_w2.toString(), new BN(0x0a).toString());
    assert.strictEqual(sig2.z_s1.toString(), new BN(0x0b).toString());
    assert.strictEqual(sig2.z_a.toString(), new BN(0x0c).toString());
    assert.strictEqual(sig2.z_an.toString(), new BN(0x0d).toString());
    assert.strictEqual(sig2.z_s1w.toString(), new BN(0x0e).toString());
    assert.strictEqual(sig2.z_sa.toString(), new BN(0x0f).toString());
    assert.strictEqual(sig2.z_s2.toString(), new BN(0x0f).toString());
  });
});
