import { defineConfig } from 'vitest/config'

export default defineConfig(({ mode }) => ({
  resolve: {
    // In browser/dev mode, redirect the Node.js crypto backend to the browser
    // backend. Vitest node tests use mode 'test' and keep the Node.js backend.
    alias:
      mode !== 'test'
        ? [{ find: './ed25519.js', replacement: './ed25519-browser.ts' }]
        : []
  },
  test: {
    include: ['test/node/**/*.test.ts', 'src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts']
    }
  }
}))
