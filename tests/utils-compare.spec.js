import { describe, it, before, mock } from 'node:test'
import assert from 'node:assert/strict'
import bcrypt from 'bcryptjs'
import { promisify } from 'util'

const mockErrors = {
  INVALID_LOGIN_DETAILS: { setData: (d) => ({ ...mockErrors.INVALID_LOGIN_DETAILS, data: d, name: 'INVALID_LOGIN_DETAILS' }), name: 'INVALID_LOGIN_DETAILS' },
  INVALID_PARAMS: { setData: (d) => ({ ...mockErrors.INVALID_PARAMS, data: d, name: 'INVALID_PARAMS' }), name: 'INVALID_PARAMS' },
  INCORRECT_PASSWORD: { name: 'INCORRECT_PASSWORD' }
}

mock.module('adapt-authoring-core', {
  namedExports: { App: { instance: { errors: mockErrors } } }
})

const { compare } = await import('../lib/utils/compare.js')

describe('compare()', () => {
  let hash

  before(async () => {
    const salt = await promisify(bcrypt.genSalt)(10)
    hash = await promisify(bcrypt.hash)('correctpassword', salt)
  })

  it('should resolve without error when password matches hash', async () => {
    await assert.doesNotReject(() => compare('correctpassword', hash))
  })

  it('should throw when password does not match hash', async () => {
    await assert.rejects(
      () => compare('wrongpassword', hash),
      (err) => err.name === 'INVALID_LOGIN_DETAILS'
    )
  })

  it('should throw when plainPassword is empty', async () => {
    await assert.rejects(
      () => compare('', hash),
      (err) => err.name === 'INVALID_LOGIN_DETAILS'
    )
  })

  it('should throw when hash is empty', async () => {
    await assert.rejects(
      () => compare('password', ''),
      (err) => err.name === 'INVALID_LOGIN_DETAILS'
    )
  })

  it('should throw when both arguments are missing', async () => {
    await assert.rejects(
      () => compare(undefined, undefined),
      (err) => err.name === 'INVALID_LOGIN_DETAILS'
    )
  })

  it('should set INCORRECT_PASSWORD as nested error on mismatch', async () => {
    await assert.rejects(
      () => compare('wrongpassword', hash),
      (err) => {
        assert.equal(err.data.error.name, 'INCORRECT_PASSWORD')
        return true
      }
    )
  })

  it('should set INVALID_PARAMS as nested error when params missing', async () => {
    await assert.rejects(
      () => compare('', ''),
      (err) => {
        assert.equal(err.data.error.name, 'INVALID_PARAMS')
        assert.deepEqual(err.data.error.data.params, ['plainPassword', 'hash'])
        return true
      }
    )
  })
})
