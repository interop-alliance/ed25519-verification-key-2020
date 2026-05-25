import { test, expect } from '@playwright/test'

test('Ed25519VerificationKey2020 generates keys in browser', async ({
  page
}) => {
  await page.goto('/test/index.html')
  const result = await page.evaluate(async () => {
    const { Ed25519VerificationKey2020 } = await import('/src/index.ts')
    const keyPair = await Ed25519VerificationKey2020.generate()
    return {
      publicKey: keyPair.publicKeyMultibase,
      hasPrivateKey: !!keyPair.privateKeyMultibase,
      suite: Ed25519VerificationKey2020.suite
    }
  })
  expect(result.publicKey).toMatch(/^z/)
  expect(result.hasPrivateKey).toBe(true)
  expect(result.suite).toBe('Ed25519VerificationKey2020')
})

test('Ed25519VerificationKey2020 signs and verifies in browser', async ({
  page
}) => {
  await page.goto('/test/index.html')
  const result = await page.evaluate(async () => {
    const { Ed25519VerificationKey2020 } = await import('/src/index.ts')
    const keyPair = await Ed25519VerificationKey2020.generate({
      controller: 'did:example:test'
    })
    const signer = keyPair.signer()
    const verifier = keyPair.verifier()
    const data = new TextEncoder().encode('test message')
    const signature = await signer.sign({ data })
    const verified = await verifier.verify({ data, signature })
    return { verified }
  })
  expect(result.verified).toBe(true)
})
