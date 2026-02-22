import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { getRandomHex } from '../lib/utils/getRandomHex.js'

describe('getRandomHex()', () => {
  it('should return a hex string of default length (64 chars for 32 bytes)', async () => {
    const hex = await getRandomHex()
    assert.equal(typeof hex, 'string')
    assert.equal(hex.length, 64)
    assert.ok(/^[0-9a-f]+$/.test(hex))
  })

  it('should return a hex string of specified length', async () => {
    const hex = await getRandomHex(16)
    assert.equal(hex.length, 32)
    assert.ok(/^[0-9a-f]+$/.test(hex))
  })

  it('should return unique values on subsequent calls', async () => {
    const hex1 = await getRandomHex()
    const hex2 = await getRandomHex()
    assert.notEqual(hex1, hex2)
  })

  it('should handle a size of 1', async () => {
    const hex = await getRandomHex(1)
    assert.equal(hex.length, 2)
    assert.ok(/^[0-9a-f]+$/.test(hex))
  })

  it('should handle a large size', async () => {
    const hex = await getRandomHex(256)
    assert.equal(hex.length, 512)
    assert.ok(/^[0-9a-f]+$/.test(hex))
  })
})
