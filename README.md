# goosig

More or less a line-for-line port of [libGooPy][libgoopy]. Experimental.

## Usage

``` js
const goosig = require('goosig');
const group = new goo.ops.RSAGroupOps(goo.consts.Grsa2048, 2048);

const key = new RSAKey(p, q); // get p and q from somewhere
const challenger = new goo.GooChallenger(group);
const signer = new goo.GooSigner(key, group);
const verifier = new goo.GooVerifier(group);

// Generate C0 and C1 based on user's pubkey.
// Handshake contributors do this part.
// C0 is the encrypted seed for the `s` scalar.
const [C0, C1] = challenger.create_challenge(key);

// Sign the hash of the serialized airdrop proof.
// This proof includes an address.
// Handshake users do this part after retrieving
// C0 and C1 from the encrypted public files.
const msg = Buffer.alloc(32, 0xff); // A sighash in reality.
const [C2, t, sigma] = prv.sign(C0, C1, msg);

// Verify the proof.
// The Handshake blockchain does this part.
const result = ver.verify([C1, C2, t], msg, sigma);
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
