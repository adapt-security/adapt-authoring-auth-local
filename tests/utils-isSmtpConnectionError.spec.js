import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { isSmtpConnectionError } from '../lib/utils/isSmtpConnectionError.js'

describe('isSmtpConnectionError()', () => {
  const cases = [
    ['wrapped code (mailer err.data.error.code)', { data: { error: { code: 'ECONNREFUSED' } } }, true],
    ['direct code', { code: 'ETIMEDOUT' }, true],
    ['code embedded in message', { message: 'connect ECONNREFUSED 127.0.0.1:1025' }, true],
    ['wrapped code embedded in message', { data: { error: { message: 'getaddrinfo ENOTFOUND smtp.example.com' } } }, true],
    ['ESOCKET', { code: 'ESOCKET' }, true],
    ['rejected message, not a connection error', { code: 'EENVELOPE', message: 'Invalid recipient' }, false],
    ['generic error', new Error('something else'), false],
    ['null', null, false],
    ['undefined', undefined, false]
  ]
  for (const [name, input, expected] of cases) {
    it(`returns ${expected} for ${name}`, () => {
      assert.equal(isSmtpConnectionError(input), expected)
    })
  }
})
