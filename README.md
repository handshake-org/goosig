# GooSig

More or less a line-for-line port of [libGooPy][libgoopy]. Experimental.

GooSig was created specifically for the [Handshake Project][handshake] and
addresses a very specific problem: an [airdrop] to Github users' RSA keys
allows Github users to be _identified on-chain_. In order to anonymize who is
receiving coins from the airdrop, cryptographic trickery is required: GooSig
allows the creation of signatures originating from RSA private keys _without
revealing the RSA public key_.

GooSig implements a [cryptographic protocol][protocol] devised by Dan Boneh and
Riad Wahby which makes use of Groups of unknOwn Order. It was originally ported
from the python [reference implementation][libgoopy] to javascript, but has
since been [implemented in C][c] as well.

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

## Benchmarks

C verification time is currently around 1ms with highend consumer-grade
hardware. We hope to get sub-1ms verification times by mainnet launch.

### Javascript

```
Timings for 4096-bit RSA GoUO, 2048-bit Signer PK:
 ◷ Generation: 64.00 ms, σ=5.71 ms, max=84.65 ms, min=60.80 ms
 ◷ Signing: 1097.95 ms, σ=48.20 ms, max=1196.90 ms, min=1025.47 ms
 ◷ Verifying: 61.25 ms, σ=6.40 ms, max=83.81 ms, min=58.02 ms

Timings for 4096-bit RSA GoUO, 4096-bit Signer PK:
 ◷ Generation: 65.08 ms, σ=2.29 ms, max=71.01 ms, min=63.59 ms
 ◷ Signing: 1768.06 ms, σ=284.67 ms, max=2469.98 ms, min=1526.67 ms
 ◷ Verifying: 59.30 ms, σ=0.66 ms, max=60.51 ms, min=58.26 ms

Timings for 2048-bit RSA GoUO, 2048-bit Signer PK:
 ◷ Generation: 10.77 ms, σ=0.40 ms, max=12.10 ms, min=10.45 ms
 ◷ Signing: 303.64 ms, σ=27.47 ms, max=372.32 ms, min=267.90 ms
 ◷ Verifying: 20.31 ms, σ=0.86 ms, max=22.36 ms, min=19.60 ms

Timings for 2048-bit RSA GoUO, 4096-bit Signer PK:
 ◷ Generation: 31.74 ms, σ=0.66 ms, max=33.81 ms, min=30.98 ms
 ◷ Signing: 779.28 ms, σ=163.26 ms, max=1261.87 ms, min=589.59 ms
 ◷ Verifying: 20.46 ms, σ=1.85 ms, max=27.17 ms, min=19.62 ms
```

### C (libgmp)

```
Timings for 4096-bit RSA GoUO, 2048-bit Signer PK:
 ◷ Generation: 6.21 ms, σ=0.26 ms, max=7.11 ms, min=6.03 ms
 ◷ Signing: 95.29 ms, σ=7.54 ms, max=123.13 ms, min=91.12 ms
 ◷ Verifying: 4.15 ms, σ=0.17 ms, max=4.79 ms, min=4.06 ms

Timings for 4096-bit RSA GoUO, 4096-bit Signer PK:
 ◷ Generation: 6.37 ms, σ=0.12 ms, max=6.71 ms, min=6.24 ms
 ◷ Signing: 153.96 ms, σ=15.93 ms, max=194.38 ms, min=136.60 ms
 ◷ Verifying: 4.32 ms, σ=0.84 ms, max=7.47 ms, min=4.04 ms

Timings for 2048-bit RSA GoUO, 2048-bit Signer PK:
 ◷ Generation: 1.19 ms, σ=0.23 ms, max=2.03 ms, min=1.12 ms
 ◷ Signing: 26.22 ms, σ=3.92 ms, max=40.60 ms, min=23.92 ms
 ◷ Verifying: 1.34 ms, σ=0.02 ms, max=1.37 ms, min=1.31 ms

Timings for 2048-bit RSA GoUO, 4096-bit Signer PK:
 ◷ Generation: 3.93 ms, σ=0.11 ms, max=4.18 ms, min=3.81 ms
 ◷ Signing: 69.51 ms, σ=13.73 ms, max=97.56 ms, min=48.25 ms
 ◷ Verifying: 1.38 ms, σ=0.18 ms, max=2.04 ms, min=1.32 ms
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

Parts of this software are based on libGooPy.

### libGooPy

- Copyright (c) 2018, Dan Boneh, Riad S. Wahby (Apache License).

### goosig.js

- Copyright (c) 2018, Christopher Jeffrey (MIT License).

See LICENSE for more info.

[handshake]: https://handshake.org
[airdrop]: https://github.com/handshake-org/hs-airdrop
[protocol]: https://github.com/kwantam/GooSig/blob/master/protocol.txt
[libgoopy]: https://github.com/kwantam/GooSig
[c]: https://github.com/handshake-org/goosig/tree/master/src/goo
