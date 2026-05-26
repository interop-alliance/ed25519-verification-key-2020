/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import { describe, it, expect } from 'vitest'
import { Ed25519VerificationKey } from '../../src/index.js'
import { mockKey, suites } from './mock-data.js'
import { stringToUint8Array } from './text-encoder.js'
import { base58btc } from '../../src/baseX.js'

const keyPair = new Ed25519VerificationKey({
  controller: 'did:example:1234',
  ...mockKey
})

const signer = keyPair.signer()
const verifier = keyPair.verifier()

// the same signature should be generated on every test platform
// (eg. browser, node)
const targetSignatureBase58 =
  '25fgrioJMRbKuq4sGz2Ngh6K7GuonRTUAzRk7asgvnVA2W' +
  'YSHtLBPX1BXiTtMqTwen7MKgQfbMpm6N6vgDc7VDF9'

describe('sign and verify', () => {
  it('works properly', async () => {
    expect(signer).toHaveProperty(
      'id',
      'did:example:1234#z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
    )
    expect(verifier).toHaveProperty(
      'id',
      'did:example:1234#z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
    )
    const data = stringToUint8Array('test 1234')
    const signature = await signer.sign({ data })
    expect(base58btc.encode(signature)).toBe(targetSignatureBase58)
    const result = await verifier.verify({ data, signature })
    expect(result).toBe(true)
  })

  it('fails if signing data is changed', async () => {
    const data = stringToUint8Array('test 1234')
    const signature = await signer.sign({ data })
    const changedData = stringToUint8Array('test 4321')
    const result = await verifier.verify({ data: changedData, signature })
    expect(result).toBe(false)
  })

  // these tests simulate what happens when a key & signature
  // created in either the browser or the node is verified
  // in a different environment
  for (const suite of suites) {
    it(suite.title, async () => {
      const _keyPair = new Ed25519VerificationKey({
        controller: 'did:example:1234',
        ...suite.key
      })

      const data = stringToUint8Array(suite.data)
      const signature = base58btc.decode(suite.signature)
      const result = await _keyPair.verifier().verify({ data, signature })
      expect(result).toBe(true)
    })
  }
})
