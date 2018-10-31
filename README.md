# goosig

More or less a line-for-line port of [libGooPy][libgoopy]. Experimental.

## Usage

``` js
const Goo = require('goosig');
const rsa = require('bcrypto/lib/rsa');

// Generate RSA private key.
const key = rsa.privateKeyGenerate(2048);

// Publish RSA public key.
const pub = rsa.publicKeyCreate(key);

// GooSig context (using the RSA-2048 challenge modulus).
const goo = new Goo(Goo.RSA2048, 2, 3, 2048);

// Generate s_prime and C1 based on user's pubkey.
// Handshake contributors do this part.
// `s_prime` is the seed for the `s` scalar.
const [s_prime, C1] = goo.challenge(pub);

// Sign the hash of the serialized airdrop proof.
// This proof includes an address.
// Handshake users do this part after retrieving
// s_prime and C1 from the encrypted public files.
const msg = Buffer.alloc(32, 0xff); // A sighash in reality.
const sig = goo.sign(msg, s_prime, C1, key);

// Verify the proof.
// The Handshake blockchain does this part.
// C1 effectively becomes the "identifier" for the key.
const result = goo.verify(msg, sig, C1);

result === true;
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

Parts of this software are based on libGooPy.

### libGooPy

- Copyright (c) 2018, Dane Boneh, Riad S. Wahby (Apache License).

### goosig.js

- Copyright (c) 2018, Christopher Jeffrey (MIT License).

See LICENSE for more info.

[libgoopy]: https://github.com/kwantam/GooSig
