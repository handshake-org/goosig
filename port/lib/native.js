/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const BigMath = require('./bigmath');
const wire = require('./wire');
const goosig = require('bindings')('goosig');

class GooVerifier extends goosig.GooVerifier {
  constructor(desc) {
    assert(desc);
    super(
      BigMath.encode(desc.modulus),
      Number(desc.g),
      Number(desc.h)
    );
  }

  encode(pubkey, msg, sigma) {
    if (typeof msg === 'string')
      msg = Buffer.from(msg, 'binary');

    if (Buffer.isBuffer(msg))
      msg = BigMath.decode(msg);

    assert(Array.isArray(pubkey));
    assert(typeof msg === 'bigint');
    assert(Array.isArray(sigma));
    assert(sigma.length === 7);
    assert(Array.isArray(sigma[6]));

    const [chal, ell, Aq, Bq, Cq, Dq, z_prime] = sigma;
    const p = new wire.PublicKey(...pubkey);
    const z = new wire.ZPrime(...z_prime);
    const s = new wire.Sigma(chal, ell, Aq, Bq, Cq, Dq, z);
    const proof = new wire.Proof(p, s);

    return [BigMath.encode(msg), proof.encode()];
  }

  verify(pubkey, msg, sigma) {
    const [hash, proof] = this.encode(pubkey, msg, sigma);
    return super.verify(hash, proof);
  }

  verifyRaw(msg, proof) {
    return super.verify(msg, proof);
  }
}

module.exports = GooVerifier;
