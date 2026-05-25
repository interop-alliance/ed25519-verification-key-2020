# Ed25519VerificationKey2020 Key Pair Library for Linked Data _(@interop/ed25519-verification-key-2020)_

[![Node.js CI](https://github.com/interop-alliance/ed25519-verification-key-2020/workflows/CI/badge.svg)](https://github.com/interop-alliance/ed25519-verification-key-2020/actions?query=workflow%3A%22CI%22)
[![NPM Version](https://img.shields.io/npm/v/@interop/ed25519-verification-key-2020.svg)](https://npm.im/@interop/ed25519-verification-key-2020)

> Typescript/Javascript library for generating and working with Ed25519VerificationKey2020 key pairs, for Node.js, browser and React Native.

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Serialization](#serialization)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

(Forked from [`digitalbazaar/ed25519-verification-key-2020` v4.1.0](https://github.com/digitalbazaar/ed25519-verification-key-2020)
to provide TypeScript compatibility.)

For use with:

* [`@digitalcredentials/ed25519-signature-2020`](https://github.com/digitalcredentials/ed25519-signature-2020) `^2.0.0`
  crypto suite (with [`linked-data-integrity`](https://github.com/digitalcredentials/linked-data-integrity))
* [`@digitalcredentials/vc`](https://github.com/digitalcredentials/vc) `^2.0.0`

See also (related specs):

* [Ed25519VerificationKey2020](https://w3c-ccg.github.io/lds-ed25519-2020/#ed25519verificationkey2020) spec.

## Security

As with most security- and cryptography-related tools, the overall security of
your system will largely depend on your design decisions.

## Install

 - Node.js 20+ is required.

To install locally (for development):

```
git clone https://github.com/interop-alliance/ed25519-verification-key-2020.git
cd ed25519-verification-key-2020
pnpm install
```

## Usage

### Generating a new public/private key pair

To generate a new public/private key pair:

* `{string} [controller]` Optional controller URI or DID to initialize the
  generated key. (This will also init the key id.)
* `{string} [seed]` Optional deterministic seed value from which to generate the
  key.

```js
import {Ed25519VerificationKey2020} from '@interop/ed25519-verification-key-2020';

const edKeyPair = await Ed25519VerificationKey2020.generate();
```

### Importing a key pair from storage

To create an instance of a public/private key pair from data imported from
storage, use `.from()`:

```js
const serializedKeyPair = { ... };

const keyPair = await Ed25519VerificationKey2020.from(serializedKeyPair);
````

### Exporting the public key only

To export just the public key of a pair, use `export()` (which returns a
`Multikey`, the default serialization -- see [Serialization](#serialization)):

```js
await keyPair.export({publicKey: true});
// ->
{
  '@context': 'https://w3id.org/security/multikey/v1',
  type: 'Multikey',
  id: 'did:example:1234#z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3',
  controller: 'did:example:1234',
  publicKeyMultibase: 'z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3'
}
```

If you specifically need an `Ed25519VerificationKey2020`-shaped object (with
`publicKeyMultibase` but no Multikey context), use `toVerificationKey2020()`:

```js
keyPair.toVerificationKey2020({publicKey: true});
// ->
{
  type: 'Ed25519VerificationKey2020',
  id: 'did:example:1234#z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3',
  controller: 'did:example:1234',
  publicKeyMultibase: 'z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3'
}
```

### Exporting the full public-private key pair

To export the full key pair, including the secret key (warning: this should be a
carefully considered operation, best left to dedicated Key Management Systems).
With `export()`, the secret key material is requested via the `secretKey` option
and emitted as `secretKeyMultibase` (Multikey naming):

```js
await keyPair.export({publicKey: true, secretKey: true});
// ->
{
  '@context': 'https://w3id.org/security/multikey/v1',
  type: 'Multikey',
  id: 'did:example:1234#z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3',
  controller: 'did:example:1234',
  publicKeyMultibase: 'z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3',
  secretKeyMultibase: 'z4E7Q4neNHwv3pXUNzUjzc6TTYspqn9Aw6vakpRKpbVrCzwKWD4hQDHnxuhfrTaMjnR8BTp9NeUvJiwJoSUM6xHAZ'
}
```

For the legacy `Ed25519VerificationKey2020` shape (with `privateKeyMultibase`),
use `toVerificationKey2020({publicKey: true, privateKey: true})`. See
[Serialization](#serialization) for the important difference between the
32-byte and 64-byte secret key encodings.

### Generating and verifying key fingerprint

To generate a fingerprint:

```js
keyPair.fingerprint();
// ->
'z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3'
```

To verify a fingerprint:

```js
const fingerprint = 'z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3';
keyPair.verifyFingerprint({fingerprint});
// ->
{verified: true}
```

### Creating a signer function

In order to perform a cryptographic signature, you need to create a `sign`
function, and then invoke it.

```js
const keyPair = Ed25519VerificationKey2020.generate();

const {sign} = keyPair.signer();

// data is a Uint8Array of bytes
const data = (new TextEncoder()).encode('test data goes here');
// Signing also outputs a Uint8Array, which you can serialize to text etc.
const signatureValueBytes = await sign({data});
```

### Creating a verifier function

In order to verify a cryptographic signature, you need to create a `verify`
function, and then invoke it (passing it the data to verify, and the signature).

```js
const keyPair = Ed25519VerificationKey2020.generate();

const {verify} = keyPair.verifier();

const verified = await verify({data, signature});
// true
```

## Serialization

This library is a **superset** that can read and write several related key
formats. `Multikey` is the default serialization; the legacy 2020/2018 and JWK
formats are also supported for backward compatibility and interop.

### Importing (`from()`)

`Ed25519VerificationKey2020.from()` dispatches on the `type` field of the object
you pass it:

| `type`                                 | Produces a key pair from ...   |
|----------------------------------------|--------------------------------|
| `Multikey`                             | a Multikey verification method |
| `Ed25519VerificationKey2018`           | a legacy 2018 key pair         |
| `JsonWebKey2020`                       | a JsonWebKey2020 object        |
| `Ed25519VerificationKey2020` (default) | a 2020 key pair                |

```js
// All of these return an Ed25519VerificationKey2020 instance:
const fromMultikey = await Ed25519VerificationKey2020.from({type: 'Multikey', ...});
const from2018 = await Ed25519VerificationKey2020.from({type: 'Ed25519VerificationKey2018', ...});
const from2020 = await Ed25519VerificationKey2020.from(serialized2020KeyPair);
```

### Exporting

There is a Multikey-default `export()` plus a `to<Format>()` family:

| Method                            | Output format                                       |
|-----------------------------------|-----------------------------------------------------|
| `export()`                        | **Multikey** (`type: 'Multikey'`, multikey context) |
| `toVerificationKey2020()`         | `Ed25519VerificationKey2020`                         |
| `toEd255519VerificationKey2018()` | `Ed25519VerificationKey2018`                         |
| `toJwk()`                         | JWK (RFC 8037)                                       |
| `toJsonWebKey2020()`              | `JsonWebKey2020`                                     |

> **Note:** `export()` returns a **Multikey** (using Multikey field naming, e.g.
> `secretKeyMultibase`). If you need a 2020-format verification method (with
> `privateKeyMultibase`), use `toVerificationKey2020()` instead.

### Secret key length: 32-byte vs 64-byte

> Exporting secret key material should be a carefully considered operation, best
> left to dedicated Key Management Systems.

Ed25519 has a 32-byte canonical seed, but historically the secret key has often
been stored as a **64-byte** value: the 32-byte seed concatenated with the
32-byte public key (`seed || publicKey`). Both encodings share the *same*
multicodec header (`0x8026`), so **length is the only thing that distinguishes
them** -- a consumer cannot tell them apart from the header alone, and different
libraries default differently. This is the main interop hazard to be aware of.

How this library handles each format:

- **`Ed25519VerificationKey2020` (`privateKeyMultibase`)** is always the
  **64-byte** `seed || publicKey` form. The signing path asserts exactly 64
  bytes.
- **Multikey (`secretKeyMultibase`)** is **64-byte by default** (the legacy
  `seed || publicKey` form, matching `@digitalbazaar/ed25519-multikey`). Pass
  `export({secretKey: true, canonicalize: true})` to emit the **canonical
  32-byte** seed instead.

```js
// Default: 64-byte legacy secret (seed||pub), maximum interop with existing data:
await keyPair.export({secretKey: true});
// -> { ..., secretKeyMultibase: 'z<64-byte payload>' }

// Canonical 32-byte seed (smaller, spec-canonical):
await keyPair.export({secretKey: true, canonicalize: true});
// -> { ..., secretKeyMultibase: 'z<32-byte payload>' }
```

**On import, both lengths are accepted and the conversion is lossless.** A
32-byte Multikey secret is re-concatenated with the public key to rebuild the
64-byte buffer the signer needs; a 64-byte secret passes through unchanged. Any
other length is rejected.

Practical guidance:

- For round-tripping with `@digitalbazaar/ed25519-multikey` or existing stored
  keys, keep the default (64-byte) export.
- Prefer `canonicalize: true` (32-byte) when you want the spec-canonical form
  and control both ends of serialization.
- Whichever you choose, never log or persist secret key material outside a
  trusted store.

## Contribute

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

* MIT License - DCC - TypeScript compatibility.
* New BSD License (3-clause) © 2020-2021 Digital Bazaar - Initial implementation.
