/*!
 * constants.js - goosig constants & moduli for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Parts of this software are based on kwantam/libGooPy:
 *   Copyright (c) 2018, Dan Boneh, Riad S. Wahby (Apache License).
 *   https://github.com/kwantam/GooSig
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/RSA_Factoring_Challenge
 *   https://en.wikipedia.org/wiki/RSA_numbers
 *   https://en.wikipedia.org/wiki/RSA_numbers#RSA-617
 *   https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048
 *   https://ssl-tools.net/subjects/3c8008731e5ff9a0e7a6b0fb906fc6e439cbe862
 *   https://ssl-tools.net/subjects/28ecf0993d30f9e4e607bef4f5c487f64a2a71a6
 *   https://web.archive.org/web/20130507091636/http://www.rsa.com/rsalabs/node.asp?id=2092
 *   https://web.archive.org/web/20130507115513/http://www.rsa.com/rsalabs/node.asp?id=2093
 *   https://web.archive.org/web/20130507115513/http://www.rsa.com/rsalabs/challenges/factoring/challengenumbers.txt
 *   https://web.archive.org/web/20130502202924/http://www.rsa.com/rsalabs/node.asp?id=2094
 *   http://www.ontko.com/pub/rayo/primes/rsa_fact.html
 */

'use strict';

/*
 * Constants
 */

// America Online Root CA 1 (2048)
// BLAKE2b-256: de2fcb98f153761deabe5ba0187418f19f3129f2204d34ae6ae93f6578fce139
// SHA-256: 7bd082427ff18b35c8e2cdb2b848d9c139877a273663d1eeea1d2a3d72b01140
// SHA-3: 978c1dc3a011927c7ce28a2747344f8f643e4d6a8cb263ca1a7ae786794f4d0a
// Digit Sum: 2776
// Checksum: 940443
exports.AOL1 = Buffer.from(''
  + 'a82fe8a469060347c3e92a98ff19a2709ac650b27ea5df684d1b7c0fb697'
  + '687d2da68b97e96486c9a3efa086bf60659c4b5488c248c54a39bf14e359'
  + '55e519b474c8b405395c16a5e29505e012ae598ba23368581ca6d415b7d8'
  + '9fd7dc71ab7e9abf9b8e330f22fd1f2ee70736ef6239c5ddcbba251423de'
  + '0cc63d3cce8208e6663eda513b163aa3057fa0dc87d59cfc72a9a07d78e4'
  + 'b731551e65bbd461b02160ed103272c592251ef8904a187847df7e30373e'
  + '501bdb1cd36b9a865307b0efac0678f88499fe218d4c80b60c82f6667079'
  + '1ad34fa3cff1cf46b04b0f3edd8862b88ca909283b7ac797e11ee5f49fc0'
  + 'c0ae24a0c8a1d90fd67b268269323da7', 'hex');

// America Online Root CA 2 (4096)
// BLAKE2b-256: ff88e50b2bcd0486d537347617b626f802be32ad75872abbc8e4b68af208dc4b
// SHA-256: 1c25b6b4a8e3b684dc828c0922b2359399c36b93f3ebaa6b71a1e412555545ba
// SHA-3: 825230318e29939794b73cdf200a650c6fc144db7d60ec0c35e380d68e627798
// Digit Sum: 5522
// Checksum: 915896
exports.AOL2 = Buffer.from(''
  + 'cc41451de93d4d10f68cb141c9e05ecb0db7bf4773d3f0554dddc60cfab1'
  + '66056acd78b4dc02db4e81f3d7a77c71bc7563a05de3070c48ec25c40320'
  + 'f4ff0e3b12ff9b8de1c6d51bb46d22e3b1db7f2164af86bc57222ad64781'
  + '5744825653bd8614010bfc7f74a45aaef1ba11b59b585a80b4377809337c'
  + '3247035cc4a58348f457566e813627184fec9b28c2d4b4d77c0c3e0c2bdf'
  + 'ca04d7c68eea584ea8a4a5181c6c4598a341d12dd2c76d8d19f1ad79b781'
  + '3fbd0682272d105805b57805b92fdb0c6b90907e145938bb942413e5d19d'
  + '14dfd3824d46f0803952320fe384b27a43f25ede5f3f1ddde3b21ba0a12a'
  + '23036e2e0115875ca67575c79761bede86dcd448dbbd2abf4a55dae87d50'
  + 'fbb48017b894bf013deadaba7ce0586717b958e0888646676c9d10475832'
  + 'd0357c792a90a25a10112335ad2fcce44a5ba7c827f283de5ebb5e77e7e8'
  + 'a56e63c20d5d61d08cd26c5a210eca28a3ce2ae995c748cf966f1d9225c8'
  + 'c6c6c1c10c05ac26c4d275d2e12a67c03d5ba59aebcf7b1aa89d1445e50f'
  + 'a09a65de2f28bdce6f9466834829d8ea658caf93d9649f555726bf6fcb37'
  + '3199a360bb1cad89343262b8432106720ca15c6d46c5fa29cf30de89dc71'
  + '5bddb6373edf50f5b8072526e5bcb5fe3c02b3b7f8be43c18711949e236c'
  + '178ab88a270c5447f0a9b3c0808ca027eb1d19e3078e7770ca2bf47d76e0'
  + '7867', 'hex');

// RSA-2048 Factoring Challenge (2048)
// BLAKE2b-256: 6bd6195870dc2627bcce76c24d248d0b4f9fa69c8e0b5f4fe1a55307546e3fd7
// SHA-256: 6ae9d033c1d76c4f535b5ad5c0073933a0b375b4120a75fbb66be814eab1a9ce
// SHA-3: 27cd119bc094ae4caa250860ceeb294056f25fd613c4c3642765148821a2b754
// Digit Sum: 2738
// Checksum: 543967
exports.RSA2048 = Buffer.from(''
  + 'c7970ceedcc3b0754490201a7aa613cd73911081c790f5f1a8726f463550'
  + 'bb5b7ff0db8e1ea1189ec72f93d1650011bd721aeeacc2acde32a04107f0'
  + '648c2813a31f5b0b7765ff8b44b4b6ffc93384b646eb09c7cf5e8592d40e'
  + 'a33c80039f35b4f14a04b51f7bfd781be4d1673164ba8eb991c2c4d730bb'
  + 'be35f592bdef524af7e8daefd26c66fc02c479af89d64d373f442709439d'
  + 'e66ceb955f3ea37d5159f6135809f85334b5cb1813addc80cd05609f10ac'
  + '6a95ad65872c909525bdad32bc729592642920f24c61dc5b3c3b7923e56b'
  + '16a4d9d373d8721f24a3fc0f1b3131f55615172866bccc30f95054c824e7'
  + '33a5eb6817f7bc16399d48c6361cc7e5', 'hex');

// RSA-617 Factoring Challenge (2048)
// BLAKE2b-256: 87bccdf2b1261c9c237671787ceb02dcaa305b1c64064db1b23b36ca3deec065
// SHA-256: 8a090bf2cdbf9fac321b2ffb48b75d4d196118fc27d7430dca10c1d06085d448
// SHA-3: 108e6ee888ad418df6f074b782a80e32f05e67fa54a17c879a160cd3761177e5
// Digit Sum: 2680
// Checksum: 909408
exports.RSA617 = Buffer.from(''
  + 'b3d5395c45b56d1cfcf411ff0f6da6b9ae45b1b06bcfab61880a911b22cf'
  + 'b28c3e011e6a07c7ec345f67486687b9581c475b9da08cecad9bef004315'
  + 'ed3b0120c88e31c134aa6848a70e879c38af31539bc065d91432729413de'
  + 'eb475e033049cd283648bff48676bb2d336e5abfe0a5a6b46e8934d711a6'
  + '85c4c42b1b9ac422eea8b64a81afc4e29a726f53ca5613cb44c8c6660e36'
  + 'b8852ec1e090dd6296457b15b164d1f2f7a51c003736cc5d8902059a7bcb'
  + 'eaf1c5a0f0eae6319ad7a1445b1df1fc79d1fa263302869800ce7bf8b8ae'
  + '340c0153a514def658f6195f3661644669df0b9514e6e1344dfa5b221045'
  + '1ab5e9838738bd15ed4a7aa79e96b765', 'hex');

exports.DEFAULT_N = exports.RSA2048;
exports.DEFAULT_G = 2;
exports.DEFAULT_H = 3;
exports.MIN_RSA_BITS = 1024;
exports.MAX_RSA_BITS = 4096;
exports.EXP_BITS = 2048;
exports.WINDOW_SIZE = 6;
exports.MAX_COMB_SIZE = 512;
exports.CHAL_BITS = 128;
exports.ELL_BITS = 136;
exports.ELLDIFF_MAX = 512;

exports.MIN_RSA_BYTES = (exports.MIN_RSA_BITS + 7) >>> 3;
exports.MAX_RSA_BYTES = (exports.MAX_RSA_BITS + 7) >>> 3;
exports.EXP_BYTES = (exports.EXP_BITS + 7) >>> 3;
exports.CHAL_BYTES = (exports.CHAL_BITS + 7) >>> 3;
exports.ELL_BYTES = (exports.ELL_BITS + 7) >>> 3;

// SHA256("Goo Signature")
exports.HASH_PREFIX = Buffer.from(''
  + 'c830d5fddcb223cd86007abf91c44027'
  + '6b008066bcb64591ef8061c89c1c5882', 'hex');

// SHA256("Goo Generate")
exports.PRNG_GENERATE = Buffer.from(''
  + '32f07d966020b46ba5901746665f3183'
  + '129678d053a30b33d92f1bcf544e1660', 'hex');

// SHA256("Goo Expand")
exports.PRNG_EXPAND = Buffer.from(''
  + '21a27ed5efc095450b7b4ddb6130491f'
  + '2417ec258eb2f4b7b2a6a936f7cfecfb', 'hex');

// SHA256("Goo Derive")
exports.PRNG_DERIVE = Buffer.from(''
  + '9989618e450e09fbed0bc951a3b309a9'
  + 'b5d2bae3db7696b76a894281e56534af', 'hex');

// SHA256("Goo Primality")
exports.PRNG_PRIMALITY = Buffer.from(''
  + 'f33184c56d6cc4f60e3962a3ada4ef03'
  + '97a6d60f14c1c3a6d8a1e67eb4334855', 'hex');

// SHA256("Goo Sign")
exports.PRNG_SIGN = Buffer.from(''
  + '22e64a953d87742d7ce6dd663d4ceaf3'
  + '55cea1746ab812206668a1b2f1e32db3', 'hex');
