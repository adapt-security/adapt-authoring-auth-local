import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'

const mockErrors = {
  INVALID_PARAMS: { setData: (d) => ({ ...mockErrors.INVALID_PARAMS, data: d, name: 'INVALID_PARAMS' }), name: 'INVALID_PARAMS' },
  INVALID_PASSWORD: { setData: (d) => ({ ...mockErrors.INVALID_PASSWORD, data: d, name: 'INVALID_PASSWORD' }), name: 'INVALID_PASSWORD' },
  INVALID_PASSWORD_LENGTH: { setData: (d) => ({ ...mockErrors.INVALID_PASSWORD_LENGTH, data: d, name: 'INVALID_PASSWORD_LENGTH' }), name: 'INVALID_PASSWORD_LENGTH' },
  INVALID_PASSWORD_NUMBER: { setData: (d) => ({ ...mockErrors.INVALID_PASSWORD_NUMBER, data: d, name: 'INVALID_PASSWORD_NUMBER' }), name: 'INVALID_PASSWORD_NUMBER' },
  INVALID_PASSWORD_UPPERCASE: { setData: (d) => ({ ...mockErrors.INVALID_PASSWORD_UPPERCASE, data: d, name: 'INVALID_PASSWORD_UPPERCASE' }), name: 'INVALID_PASSWORD_UPPERCASE' },
  INVALID_PASSWORD_LOWERCASE: { setData: (d) => ({ ...mockErrors.INVALID_PASSWORD_LOWERCASE, data: d, name: 'INVALID_PASSWORD_LOWERCASE' }), name: 'INVALID_PASSWORD_LOWERCASE' },
  INVALID_PASSWORD_SPECIAL: { setData: (d) => ({ ...mockErrors.INVALID_PASSWORD_SPECIAL, data: d, name: 'INVALID_PASSWORD_SPECIAL' }), name: 'INVALID_PASSWORD_SPECIAL' },
  BLACKLISTED_PASSWORD_VALUE: { setData: (d) => ({ ...mockErrors.BLACKLISTED_PASSWORD_VALUE, data: d, name: 'BLACKLISTED_PASSWORD_VALUE' }), name: 'BLACKLISTED_PASSWORD_VALUE' }
}

let authlocalConfig = {
  minPasswordLength: 8,
  passwordMustHaveNumber: false,
  passwordMustHaveUppercase: false,
  passwordMustHaveLowercase: false,
  passwordMustHaveSpecial: false,
  blacklistedPasswordValues: []
}

const mockAuthlocal = {
  getConfig: (key) => authlocalConfig[key]
}

mock.module('adapt-authoring-core', {
  namedExports: {
    App: {
      instance: {
        errors: mockErrors,
        waitForModule: async () => mockAuthlocal
      }
    }
  }
})

const { validate } = await import('../lib/utils/validate.js')

describe('validate()', () => {
  beforeEach(() => {
    authlocalConfig = {
      minPasswordLength: 8,
      passwordMustHaveNumber: false,
      passwordMustHaveUppercase: false,
      passwordMustHaveLowercase: false,
      passwordMustHaveSpecial: false,
      blacklistedPasswordValues: []
    }
  })

  it('should resolve for a valid password meeting minimum length', async () => {
    await assert.doesNotReject(() => validate('abcdefgh'))
  })

  it('should throw when password is not a string', async () => {
    await assert.rejects(
      () => validate(12345678),
      (err) => err.name === 'INVALID_PARAMS'
    )
  })

  it('should throw when password is null', async () => {
    await assert.rejects(
      () => validate(null),
      (err) => err.name === 'INVALID_PARAMS'
    )
  })

  it('should throw when password is too short', async () => {
    await assert.rejects(
      () => validate('short'),
      (err) => err.name === 'INVALID_PASSWORD'
    )
  })

  it('should include minimum length in error data', async () => {
    await assert.rejects(
      () => validate('short'),
      (err) => {
        assert.equal(err.name, 'INVALID_PASSWORD')
        const lengthErr = err.data.errors.find(e => e.name === 'INVALID_PASSWORD_LENGTH')
        assert.ok(lengthErr)
        assert.equal(lengthErr.data.length, 8)
        return true
      }
    )
  })

  it('should throw when number is required but missing', async () => {
    authlocalConfig.passwordMustHaveNumber = true
    await assert.rejects(
      () => validate('abcdefgh'),
      (err) => err.name === 'INVALID_PASSWORD'
    )
  })

  it('should accept password with number when required', async () => {
    authlocalConfig.passwordMustHaveNumber = true
    await assert.doesNotReject(() => validate('abcdefg1'))
  })

  it('should throw when uppercase is required but missing', async () => {
    authlocalConfig.passwordMustHaveUppercase = true
    await assert.rejects(
      () => validate('abcdefgh'),
      (err) => err.name === 'INVALID_PASSWORD'
    )
  })

  it('should accept password with uppercase when required', async () => {
    authlocalConfig.passwordMustHaveUppercase = true
    await assert.doesNotReject(() => validate('Abcdefgh'))
  })

  it('should throw when special character is required but missing', async () => {
    authlocalConfig.passwordMustHaveSpecial = true
    await assert.rejects(
      () => validate('abcdefgh'),
      (err) => err.name === 'INVALID_PASSWORD'
    )
  })

  it('should collect multiple validation errors', async () => {
    authlocalConfig.passwordMustHaveNumber = true
    authlocalConfig.passwordMustHaveUppercase = true
    authlocalConfig.passwordMustHaveSpecial = true
    await assert.rejects(
      () => validate('abcdefgh'),
      (err) => {
        assert.equal(err.name, 'INVALID_PASSWORD')
        assert.ok(err.data.errors.length >= 3)
        return true
      }
    )
  })

  it('should throw when password contains a blacklisted value', async () => {
    authlocalConfig.blacklistedPasswordValues = ['password']
    await assert.rejects(
      () => validate('password123'),
      (err) => err.name === 'INVALID_PASSWORD'
    )
  })

  it('should accept password not containing blacklisted values', async () => {
    authlocalConfig.blacklistedPasswordValues = ['password']
    await assert.doesNotReject(() => validate('securevalue'))
  })
})
