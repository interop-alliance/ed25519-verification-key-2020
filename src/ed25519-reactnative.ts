/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import * as ed25519 from '@noble/ed25519'
import { sha256, sha512 } from '@noble/hashes/sha2.js'

// React Native MUST provide "crypto.getRandomValues"
const crypto = globalThis.crypto
if (typeof crypto?.getRandomValues === 'undefined') {
  throw new Error('Environment does not provide "crypto.getRandomValues".')
}

// configure sha512 for noble/ed25519 v3 using @noble/hashes (pure JS, no WebCrypto needed)
ed25519.hashes.sha512 = sha512
ed25519.hashes.sha512Async = async (m: Uint8Array) => sha512(m)

interface EdKeyPair {
  publicKey: Uint8Array
  secretKey: Uint8Array
}

export default {
  async generateKeyPair(): Promise<EdKeyPair> {
    const seed = new Uint8Array(32)
    crypto.getRandomValues(seed)
    const keyPair = await generateKeyPairFromSeed(seed)
    seed.fill(0)
    return keyPair
  },

  generateKeyPairFromSeed,

  async sign(
    secretKey: Uint8Array,
    data: Uint8Array
  ): Promise<Uint8Array> {
    return ed25519.signAsync(data, secretKey.slice(0, 32))
  },

  async verify(
    publicKey: Uint8Array,
    data: Uint8Array,
    signature: Uint8Array
  ): Promise<boolean> {
    return ed25519.verifyAsync(signature, data, publicKey)
  },

  async sha256digest(data: Uint8Array): Promise<Uint8Array> {
    return sha256(data)
  }
}

async function generateKeyPairFromSeed(seed: Uint8Array): Promise<EdKeyPair> {
  const publicKey = await ed25519.getPublicKeyAsync(seed)
  const secretKey = new Uint8Array(64)
  secretKey.set(seed)
  secretKey.set(publicKey, seed.length)
  return { publicKey, secretKey }
}
