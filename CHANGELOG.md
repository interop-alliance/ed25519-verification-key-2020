# @interop/ed25519-verification-key ChangeLog

## 6.1.0 -

### Changed
- **BREAKING**: Renamed the main exported class from `Ed25519VerificationKey2020` to
  `Ed25519VerificationKey`. The wire-format `type` string `'Ed25519VerificationKey2020'`,
  the `suite` static property, and all format-specific method names
  (`fromEd25519VerificationKey2018`, `fromJsonWebKey2020`, `toVerificationKey2020`, etc.)
  are unchanged. Renamed npm package from `@interop/ed25519-verification-key-2020` to
  `@interop/ed25519-verification-key`.
- **BREAKING**: Replaced usage of `base-x` for `base64url` encoding with
  `@scure/base` library (same author as the `@noble` library we use). Base-x's
  implementation is not compatible with the `base64url` standard, and was
  leading to incompatibilities reading and writing JWKs.

### Added
- Add Multikey support from `@digitalbazaar/ed25519-multikey` library:
  - Add logic to `from()` that dispatches on `Multikey` type.
  - **BREAKING**: Changed `export()` to serialize to `Multikey` type, and moved
    the previous behavior to `toVerificationKey2020()`. Note also that the
    `privateKey` export function parameter is now `secretKey`, to match the
    `Multikey` type.
  - Added unit tests from `@digitalbazaar/ed25519-multikey`.
  - Fixed JWK-related tests.

## 6.0.0-6.0.1 - 2026-05-24
### Changed

- Fork from `@digitalcredentials/ed25519-verification-key-2020@5.0.0` to `@interop/`.
- Update @noble/ed25519 ^1.7.5 to ^3.1.0 in dependencies
- src/ed25519-browser.ts: Switch to signAsync/verifyAsync/getPublicKeyAsync, configured hashes.sha512Async via crypto.subtle
- src/ed25519-reactnative.ts: Replace @stablelib/ed25519 with @noble/ed25519 + @noble/hashes (sha512 sync+async, sha256 for sha256digest)
- Remove `@stablelib/ed25519` from devDependencies
- Remove `@digitalbazaar/ed25519-verification-key-2018` from devDependencies and tests (broken on Node.js v24 via esm shim; 2018 compat tests dropped)
- Remove stablelib cross-library tests

## 5.0.0 -
### Changed
- Update to `@digitalcredentials/keypair@3.0.0` and
  `@digitalcredentials/ssi@5.2.0` libraries.

## 5.0.0-beta.1 & 2
### Changed
- Update to latest versions of `keypair` and `ssi` libraries.
  `signer.id` is now required.
- **BREAKING**: Drop CommonJS export option. (Now ESM only.)

## 4.0.0 - 2022-12-22
### Changed
- Update to upstream `v4.1.0` (use `assertKeyBytes()` etc).
- **BREAKING**: Convert to Typescript, use [`@digitalcredentials/keypair`](https://github.com/digitalcredentials/keypair)
  lib instead of `crypto-ld`.
- Fix `toJwk()` and `fromJsonWebKey2020()` logic (see [issue #5](https://github.com/digitalcredentials/ed25519-verification-key-2020/issues/5))

### Added
- Public key byte checks have error codes compatible with the `did:key` spec.

### Fixed
- No longer throw a `TypeError` when passing in a Uint8Array of the wrong length.

## 3.3.0 - 2022-05-27
### Added
- Add `toEd255519VerificationKey2018()` instance method, round trip serialization
  and import to 2018.

### Changed
- Replace underlying ed25519 implementation with `@noble/ed25519`. This
  should be a non-breaking change.

## 3.2.2 - 2021-10-15
### Added
- Add some type check validation to toJwk() method.

## 3.2.0 - 2021-09-28
### Added
- Add support for `JsonWebKey2020` and JWK import/export, and JWK thumbprint.

## 3.1.1 - 2021-09-17

### Changed
- **BREAKING**: Synced with [`@digitalbazaar/ed25519-verification-key-2020 v3.1.0`
  (see its CHANGELOG)](https://github.com/digitalbazaar/ed25519-verification-key-2020/blob/main/CHANGELOG.md#310---2021-06-24)
- Removed `esm` runtime transpiler usage, make compatible with TypeScript.

## 1.0.0 - 2021-02-27

Initial version.
