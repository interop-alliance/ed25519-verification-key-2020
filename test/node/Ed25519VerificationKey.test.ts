/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import { describe, it, expect } from 'vitest'
import * as jose from 'jose'
import { base58btc, base64url } from '../../src/baseX.js'
import { mockKey, seed, suites } from './mock-data.js'
import * as multibase from 'multibase'
import * as multicodec from 'multicodec'
import { Ed25519VerificationKey } from '../../src/index.js'

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('')
}

// multibase base58-btc header
const MULTIBASE_BASE58BTC_HEADER = 'z'

describe('Ed25519VerificationKey', () => {
  describe('class', () => {
    it('should have suite and SUITE_CONTEXT properties', async () => {
      expect(Ed25519VerificationKey).toHaveProperty(
        'suite',
        'Ed25519VerificationKey2020'
      )
      expect(Ed25519VerificationKey).toHaveProperty(
        'SUITE_CONTEXT',
        'https://w3id.org/security/suites/ed25519-2020/v1'
      )
    })

    it('should have a multibaseHeader property', async () => {
      expect(Ed25519VerificationKey).toHaveProperty('multibaseHeader', 'z6Mk')
    })
  })

  describe('constructor', () => {
    it('should auto-set key.id based on controller', async () => {
      const { publicKeyMultibase } = mockKey
      const controller = 'did:example:1234'

      const keyPair = new Ed25519VerificationKey({
        controller,
        publicKeyMultibase
      })
      expect(keyPair.id).toBe(
        'did:example:1234#z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      )
    })

    it('should error if publicKeyMultibase property is missing', async () => {
      let error: unknown
      try {
        new Ed25519VerificationKey({})
      } catch (err: unknown) {
        error = err
      }
      expect(error).toBeInstanceOf(TypeError)
      expect((error as TypeError).message).toBe(
        'The "publicKeyMultibase" property is required.'
      )
    })
  })

  describe('generate', () => {
    it('should generate a key pair', async () => {
      let ldKeyPair: Ed25519VerificationKey | undefined
      let error: unknown
      try {
        ldKeyPair = await Ed25519VerificationKey.generate()
      } catch (err: unknown) {
        error = err
      }

      expect(error).toBeUndefined()
      expect(ldKeyPair?.publicKeyMultibase).toBeDefined()
      expect(ldKeyPair?.privateKeyMultibase).toBeDefined()

      const privateKeyBytes = base58btc.decode(
        ldKeyPair!.privateKeyMultibase!.slice(1)
      )
      const publicKeyBytes = base58btc.decode(
        ldKeyPair!.publicKeyMultibase.slice(1)
      )
      expect(privateKeyBytes.length).toBe(66)
      expect(publicKeyBytes.length).toBe(34)
    })

    it('should generate the same key from the same seed', async () => {
      const seed = new Uint8Array(32)
      seed.fill(0x01)
      const keyPair1 = await Ed25519VerificationKey.generate({ seed })
      const keyPair2 = await Ed25519VerificationKey.generate({ seed })
      expect(keyPair1.publicKeyMultibase).toBe(keyPair2.publicKeyMultibase)
      expect(keyPair1.privateKeyMultibase).toBe(keyPair2.privateKeyMultibase)
    })
  })

  describe('export (Multikey)', () => {
    it('should export as Multikey by default', async () => {
      const seedBytes = new TextEncoder().encode(seed).slice(0, 32)
      const keyPair = await Ed25519VerificationKey.generate({
        seed: seedBytes,
        controller: 'did:example:1234'
      })
      const exported = keyPair.export({ publicKey: true, secretKey: true })

      expect(exported.type).toBe('Multikey')
      expect(exported['@context']).toBe('https://w3id.org/security/multikey/v1')
      expect(exported.controller).toBe('did:example:1234')
      expect(exported.publicKeyMultibase).toBe(
        'z6Mkpw72M9suPCBv48X2Xj4YKZJH9W7wzEK1aS6JioKSo89C'
      )
      // default (non-canonical) secretKeyMultibase is 66 bytes (2 header + 64
      // seed||pub), matching @digitalbazaar/ed25519-multikey
      const secretMulticodec = base58btc.decode(exported.secretKeyMultibase!.slice(1))
      expect(secretMulticodec.length).toBe(66)
    })

    it('should export a canonical 32-byte secret when canonicalize is true', async () => {
      const seedBytes = new TextEncoder().encode(seed).slice(0, 32)
      const keyPair = await Ed25519VerificationKey.generate({
        seed: seedBytes,
        controller: 'did:example:1234'
      })
      const exported = keyPair.export({
        publicKey: true,
        secretKey: true,
        canonicalize: true
      })

      // canonical secretKeyMultibase is 34 bytes (2 header + 32 seed)
      const secretMulticodec = base58btc.decode(exported.secretKeyMultibase!.slice(1))
      expect(secretMulticodec.length).toBe(34)
      expect(exported.secretKeyMultibase).toBe(
        'z3u2V1vM4u3wUmcB8M77WQWmMvscQpPAtdpj7iEJRGpzoMtg'
      )
    })

    it('default export() args include publicKey and context', async () => {
      const keyPair = await Ed25519VerificationKey.generate({
        id: 'did:ex:123#test-id'
      })
      const exported = keyPair.export()

      expect(Object.keys(exported).sort()).toEqual(
        ['@context', 'id', 'type', 'publicKeyMultibase'].sort()
      )
      expect(exported.id).toBe('did:ex:123#test-id')
      expect(exported.type).toBe('Multikey')
    })

  })

  describe('toVerificationKey2020', () => {
    it('should export id, type and key material', async () => {
      // Encoding returns a 64 byte Uint8Array, seed needs to be 32 bytes
      const seedBytes = new TextEncoder().encode(seed).slice(0, 32)
      const keyPair = await Ed25519VerificationKey.generate({
        seed: seedBytes,
        controller: 'did:example:1234'
      })
      const pastDate = new Date(2020, 11, 17)
        .toISOString()
        .replace(/\.[0-9]{3}/, '')
      keyPair.revoked = pastDate
      const exported = keyPair.toVerificationKey2020({
        publicKey: true,
        privateKey: true
      })

      expect(Object.keys(exported).sort()).toEqual(
        ['id', 'type', 'controller', 'publicKeyMultibase', 'privateKeyMultibase', 'revoked'].sort()
      )

      expect(exported.controller).toBe('did:example:1234')
      expect(exported.type).toBe('Ed25519VerificationKey2020')
      expect(exported.id).toBe(
        'did:example:1234#' + 'z6Mkpw72M9suPCBv48X2Xj4YKZJH9W7wzEK1aS6JioKSo89C'
      )
      expect(exported.publicKeyMultibase).toBe(
        'z6Mkpw72M9suPCBv48X2Xj4YKZJH9W7wzEK1aS6JioKSo89C'
      )
      expect(exported.privateKeyMultibase).toBe(
        'zrv1mHUXWkWUpThaapTt8tkxSotE1iSRRuPNarhs3vTn2z61hQESuKXG7zGQsePB7JHd' +
          'jaCzPZmBkkqULLvoLHoD82a'
      )
      expect(exported.revoked).toBe(pastDate)
    })

    it('should only export public key if specified', async () => {
      const keyPair = await Ed25519VerificationKey.generate({
        id: 'did:ex:123#test-id'
      })
      const exported = keyPair.toVerificationKey2020({ publicKey: true })

      expect(Object.keys(exported).sort()).toEqual(
        ['id', 'type', 'publicKeyMultibase'].sort()
      )
      expect(exported.id).toBe('did:ex:123#test-id')
      expect(exported.type).toBe('Ed25519VerificationKey2020')
    })
  })

  describe('static fromFingerprint', () => {
    it('should round-trip load keys', async () => {
      const keyPair = await Ed25519VerificationKey.generate()
      const fingerprint = keyPair.fingerprint()

      const newKey = Ed25519VerificationKey.fromFingerprint({ fingerprint })
      expect(newKey.publicKeyMultibase).toBe(keyPair.publicKeyMultibase)
    })
  })

  describe('static from', () => {
    it('should round-trip load exported keys (2020 format)', async () => {
      // Encoding returns a 64 byte uint8array, seed needs to be 32 bytes
      const seedBytes = new TextEncoder().encode(seed).slice(0, 32)
      const keyPair = await Ed25519VerificationKey.generate({
        seed: seedBytes,
        controller: 'did:example:1234'
      })
      const exported = keyPair.toVerificationKey2020({
        publicKey: true,
        privateKey: true
      })
      const imported = await Ed25519VerificationKey.from(exported)

      expect(
        imported.toVerificationKey2020({ publicKey: true, privateKey: true })
      ).toEqual(exported)
    })

    it('should round-trip via Multikey export from() to sign/verify', async () => {
      const keyPair = await Ed25519VerificationKey.generate({
        controller: 'did:example:multikey'
      })
      // Export as Multikey (default 64-byte secret)
      const multikeyDoc = keyPair.export({ publicKey: true, secretKey: true })
      expect(multikeyDoc.type).toBe('Multikey')

      // Re-import via from()
      const imported = await Ed25519VerificationKey.from(multikeyDoc)
      expect(imported.publicKeyMultibase).toBe(keyPair.publicKeyMultibase)

      // Confirm sign/verify works after the 32 to 64 byte re-concat
      const data = new TextEncoder().encode('multikey round-trip test')
      const signer = imported.signer()
      const signature = await signer.sign({ data })
      const result = await keyPair.verifier().verify({ data, signature })
      expect(result).toBe(true)
    })

    it('from() ingests a Multikey document with 64-byte legacy secret', async () => {
      const keyPair = await Ed25519VerificationKey.generate({
        controller: 'did:example:legacy'
      })
      // Build a legacy Multikey document by reusing the internal 64-byte
      // privateKeyMultibase directly as secretKeyMultibase.
      const legacyMultikey = {
        type: 'Multikey' as const,
        controller: 'did:example:legacy',
        publicKeyMultibase: keyPair.publicKeyMultibase,
        secretKeyMultibase: keyPair.privateKeyMultibase!
      }
      const secretMulticodec = base58btc.decode(legacyMultikey.secretKeyMultibase.slice(1))
      expect(secretMulticodec.length).toBe(66) // 2 header + 64

      const imported = await Ed25519VerificationKey.from(legacyMultikey)
      const data = new TextEncoder().encode('legacy multikey test')
      const signature = await imported.signer().sign({ data })
      const result = await keyPair.verifier().verify({ data, signature })
      expect(result).toBe(true)
    })

    it('from() with Multikey ingests public-key-only documents', async () => {
      const keyPair = await Ed25519VerificationKey.generate({
        controller: 'did:example:pubonly'
      })
      const publicOnlyMultikey = keyPair.export({ publicKey: true })
      expect(publicOnlyMultikey.secretKeyMultibase).toBeUndefined()

      const imported = await Ed25519VerificationKey.from(publicOnlyMultikey)
      expect(imported.publicKeyMultibase).toBe(keyPair.publicKeyMultibase)
      expect(imported.privateKeyMultibase).toBeUndefined()
    })
  })

  describe('sign and verify', () => {
    // The same Ed25519 signature must be produced on every platform and by
    // every interoperable implementation (this value is byte-identical to the
    // one produced by @digitalbazaar/ed25519-multikey for the same key).
    const targetSignatureBase58 =
      '25fgrioJMRbKuq4sGz2Ngh6K7GuonRTUAzRk7asgvnVA2W' +
      'YSHtLBPX1BXiTtMqTwen7MKgQfbMpm6N6vgDc7VDF9'

    it('produces a known-answer signature and verifies it', async () => {
      const keyPair = await Ed25519VerificationKey.from({
        controller: 'did:example:1234',
        ...mockKey
      })
      const signer = keyPair.signer()
      const verifier = keyPair.verifier()
      expect(signer.id).toBe(
        'did:example:1234#z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      )
      expect(verifier.id).toBe(
        'did:example:1234#z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      )
      const data = new TextEncoder().encode('test 1234')
      const signature = await signer.sign({ data })
      expect(base58btc.encode(signature)).toBe(targetSignatureBase58)
      const result = await verifier.verify({ data, signature })
      expect(result).toBe(true)
    })

    it('fails to verify if the signed data is changed', async () => {
      const keyPair = await Ed25519VerificationKey.from({
        controller: 'did:example:1234',
        ...mockKey
      })
      const signer = keyPair.signer()
      const data = new TextEncoder().encode('test 1234')
      const signature = await signer.sign({ data })
      const changedData = new TextEncoder().encode('test 4321')
      const result = await keyPair
        .verifier()
        .verify({ data: changedData, signature })
      expect(result).toBe(false)
    })

    // Verify signatures produced by this library in other environments
    // (node, browser) to lock cross-platform interop.
    for (const suite of suites) {
      it(suite.title, async () => {
        const keyPair = await Ed25519VerificationKey.from({
          controller: 'did:example:1234',
          ...suite.key
        })
        const data = new TextEncoder().encode(suite.data)
        const signature = base58btc.decode(suite.signature)
        const result = await keyPair.verifier().verify({ data, signature })
        expect(result).toBe(true)
      })
    }
  })

  describe('fingerprint', () => {
    it('should create an Ed25519 key fingerprint', async () => {
      const keyPair = await Ed25519VerificationKey.generate()
      const fingerprint = keyPair.fingerprint()
      expect(typeof fingerprint).toBe('string')
      expect(fingerprint.startsWith('z')).toBe(true)
    })

    it('should be properly multicodec encoded', async () => {
      const keyPair = await Ed25519VerificationKey.generate()
      const fingerprint = keyPair.fingerprint()
      const mcPubkeyBytes = multibase.decode(fingerprint)
      const mcType = multicodec.getCodec(mcPubkeyBytes)
      expect(mcType).toBe('ed25519-pub')
      const pubkeyBytes = multicodec.addPrefix(
        'ed25519-pub',
        multicodec.rmPrefix(mcPubkeyBytes)
      )
      const encodedPubkey =
        MULTIBASE_BASE58BTC_HEADER + base58btc.encode(pubkeyBytes)

      expect(encodedPubkey).toBe(keyPair.publicKeyMultibase)
      expect(typeof keyPair.fingerprint()).toBe('string')
    })
  })

  describe('verify fingerprint', () => {
    it('should verify a valid fingerprint', async () => {
      const keyPair = await Ed25519VerificationKey.generate()
      const fingerprint = keyPair.fingerprint()
      const result = keyPair.verifyFingerprint({ fingerprint })
      expect(result).toBeDefined()
      expect(typeof result).toBe('object')
      expect(result.verified).toBeDefined()
      expect(result.verified).toBe(true)
    })

    it('should reject an improperly encoded fingerprint', async () => {
      const keyPair = await Ed25519VerificationKey.generate()
      const fingerprint = keyPair.fingerprint()
      const result = keyPair.verifyFingerprint({
        fingerprint: fingerprint.slice(1)
      })
      expect(result).toBeDefined()

      expect(result.verified).toBeDefined()
      expect(result.verified).toBe(false)
      expect(result.error).toBeDefined()
      expect(result.error?.message).toBe(
        '"fingerprint" must be a multibase encoded string.'
      )
    })

    it('should reject an invalid fingerprint', async () => {
      const keyPair = await Ed25519VerificationKey.generate()
      const fingerprint = keyPair.fingerprint()
      // reverse the valid fingerprint
      const t = fingerprint.slice(1).split('').reverse().join('')
      const badFingerprint = fingerprint[0] + t
      const result = keyPair.verifyFingerprint({ fingerprint: badFingerprint })
      expect(result).toBeDefined()
      expect(result.verified).toBeDefined()
      expect(result.verified).toBe(false)
      expect(result.error).toBeDefined()

      expect(result.error?.message).toBe(
        'Invalid fingerprint encoding (expecting 0xed01 byte prefix).'
      )
    })

    it('should reject an improperly encoded fingerprint', async () => {
      const keyPair = await Ed25519VerificationKey.generate()
      const result = keyPair.verifyFingerprint({ fingerprint: 'zTESTSTRNG' })
      expect(result).toBeDefined()
      expect(result.verified).toBeDefined()
      expect(result.verified).toBe(false)
      expect(result.error).toBeDefined()

      expect(result.error?.message).toBe(
        'Invalid fingerprint encoding (expecting 0xed01 byte prefix).'
      )
    })

    it('generates the same fingerprint from the same seed', async () => {
      const seed = new Uint8Array(32)
      seed.fill(0x01)
      const keyPair1 = await Ed25519VerificationKey.generate({ seed })
      const keyPair2 = await Ed25519VerificationKey.generate({ seed })
      const fingerprint = keyPair1.fingerprint()
      const fingerprint2 = keyPair2.fingerprint()
      const result = keyPair2.verifyFingerprint({ fingerprint })
      expect(result).toBeDefined()
      expect(typeof result).toBe('object')
      expect(result.verified).toBeDefined()
      expect(result.verified).toBe(true)
      expect(fingerprint).toBe(fingerprint2)
    })
  })

  describe('JsonWebKey2020', () => {
    // Shared fixture from @digitalbazaar/ed25519-multikey's JWK tests.
    const publicKeyJwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'
    }

    it('round-trips publicKeyJwk through from() and toJwk()', async () => {
      const key = await Ed25519VerificationKey.from({
        type: 'JsonWebKey2020',
        controller: 'did:example:123',
        publicKeyJwk
      })
      expect(key.toJwk({ publicKey: true })).toEqual(publicKeyJwk)
    })

    it('preserves id and controller when importing publicKeyJwk', async () => {
      const key = await Ed25519VerificationKey.from({
        type: 'JsonWebKey2020',
        id: 'urn:id:1#0',
        controller: 'urn:id:1',
        publicKeyJwk
      })
      expect(key.id).toBe('urn:id:1#0')
      expect(key.controller).toBe('urn:id:1')
      expect(key.toJwk({ publicKey: true })).toEqual(publicKeyJwk)
    })

    // Known-answer test pinning RFC 4648 base64url compliance. A
    // non-compliant codec (e.g. a big-number radix conversion) decodes this
    // vector to different -- even differently-lengthed -- bytes, so JWKs would
    // not interoperate with standard JOSE/JWK consumers.
    it('decodes the RFC 8037 A.2 public key vector to the exact bytes', () => {
      // x and its raw public key from RFC 8037 Appendix A.2; this is also the
      // canonical did:key Ed25519 example.
      const rfcX = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'
      const rfcPublicKeyHex =
        'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'

      const decoded = base64url.decode(rfcX)
      expect(decoded.length).toBe(32)
      expect(bytesToHex(decoded)).toBe(rfcPublicKeyHex)
      // re-encoding the bytes reproduces the exact RFC string
      expect(base64url.encode(decoded)).toBe(rfcX)
    })

    it('imports the RFC 8037 vector to the canonical did:key multibase', async () => {
      const rfcX = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'
      const expectedMultibase =
        'z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw'
      const key = await Ed25519VerificationKey.from({
        type: 'JsonWebKey2020',
        controller: 'did:example:123',
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: rfcX }
      })
      expect(key.publicKeyMultibase).toBe(expectedMultibase)
      expect(key.toJwk({ publicKey: true }).x).toBe(rfcX)
    })

    it('exports a JWK whose key bytes agree with jose (cross-library)', async () => {
      // Generate a key, export its JWK, and confirm jose decodes the same
      // public key bytes -- this is the interop a self-consistent but
      // non-standard codec silently breaks.
      const key = await Ed25519VerificationKey.generate()
      const exportedJwk = key.toJwk({ publicKey: true, privateKey: true })

      const josePublicJwk = await jose.exportJWK(
        await jose.importJWK({ ...exportedJwk }, 'EdDSA')
      )
      expect(josePublicJwk.x).toBe(exportedJwk.x)
      expect(josePublicJwk.d).toBe(exportedJwk.d)

      // the JWK `x` must be the true public key bytes (multibase minus header)
      const decodedX = base64url.decode(exportedJwk.x as string)
      const multibaseBytes = base58btc.decode(
        (key.publicKeyMultibase as string).slice(1)
      )
      expect(bytesToHex(decodedX)).toBe(bytesToHex(multibaseBytes.slice(2)))
    })

    it('round-trips through JsonWebKey2020 serialization', async () => {
      const key = await Ed25519VerificationKey.from({
        type: 'JsonWebKey2020',
        controller: 'did:example:123',
        publicKeyJwk
      })
      const exported = await key.toJsonWebKey2020()
      const reimported = await Ed25519VerificationKey.from(exported)

      expect(await reimported.toJsonWebKey2020()).toEqual(exported)
      // id is the JWK thumbprint encoded as a hash fragment of the controller
      expect(exported.id).toBe(
        `${exported.controller}#${await key.jwkThumbprint()}`
      )
    })
  })
})
