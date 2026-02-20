import { describe, it, before, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import bcrypt from 'bcryptjs'
import { promisify } from 'util'

// --- Stub App.instance before importing PasswordUtils ---

const mockErrors = {
  INVALID_LOGIN_DETAILS: { setData: (d) => ({ ...mockErrors.INVALID_LOGIN_DETAILS, data: d, name: 'INVALID_LOGIN_DETAILS' }), name: 'INVALID_LOGIN_DETAILS' },
  INVALID_PARAMS: { setData: (d) => ({ ...mockErrors.INVALID_PARAMS, data: d, name: 'INVALID_PARAMS' }), name: 'INVALID_PARAMS' },
  INVALID_PASSWORD: { setData: (d) => ({ ...mockErrors.INVALID_PASSWORD, data: d, name: 'INVALID_PASSWORD' }), name: 'INVALID_PASSWORD' },
  INVALID_PASSWORD_LENGTH: { setData: (d) => ({ ...mockErrors.INVALID_PASSWORD_LENGTH, data: d, name: 'INVALID_PASSWORD_LENGTH' }), name: 'INVALID_PASSWORD_LENGTH' },
  INVALID_PASSWORD_NUMBER: { setData: (d) => ({ ...mockErrors.INVALID_PASSWORD_NUMBER, data: d, name: 'INVALID_PASSWORD_NUMBER' }), name: 'INVALID_PASSWORD_NUMBER' },
  INVALID_PASSWORD_UPPERCASE: { setData: (d) => ({ ...mockErrors.INVALID_PASSWORD_UPPERCASE, data: d, name: 'INVALID_PASSWORD_UPPERCASE' }), name: 'INVALID_PASSWORD_UPPERCASE' },
  INVALID_PASSWORD_LOWERCASE: { setData: (d) => ({ ...mockErrors.INVALID_PASSWORD_LOWERCASE, data: d, name: 'INVALID_PASSWORD_LOWERCASE' }), name: 'INVALID_PASSWORD_LOWERCASE' },
  INVALID_PASSWORD_SPECIAL: { setData: (d) => ({ ...mockErrors.INVALID_PASSWORD_SPECIAL, data: d, name: 'INVALID_PASSWORD_SPECIAL' }), name: 'INVALID_PASSWORD_SPECIAL' },
  BLACKLISTED_PASSWORD_VALUE: { setData: (d) => ({ ...mockErrors.BLACKLISTED_PASSWORD_VALUE, data: d, name: 'BLACKLISTED_PASSWORD_VALUE' }), name: 'BLACKLISTED_PASSWORD_VALUE' },
  INCORRECT_PASSWORD: { name: 'INCORRECT_PASSWORD' },
  NOT_FOUND: { setData: (d) => ({ ...mockErrors.NOT_FOUND, data: d, name: 'NOT_FOUND' }), name: 'NOT_FOUND' },
  AUTH_TOKEN_INVALID: { name: 'AUTH_TOKEN_INVALID' },
  AUTH_TOKEN_EXPIRED: { name: 'AUTH_TOKEN_EXPIRED' },
  ACCOUNT_NOT_LOCALAUTHD: { name: 'ACCOUNT_NOT_LOCALAUTHD' }
}

let authlocalConfig = {
  saltRounds: 10,
  minPasswordLength: 8,
  passwordMustHaveNumber: false,
  passwordMustHaveUppercase: false,
  passwordMustHaveLowercase: false,
  passwordMustHaveSpecial: false,
  blacklistedPasswordValues: [],
  resetTokenLifespan: 86400000
}

const mockPasswordResetsStore = []
const mockUsersStore = []

const mockAuthlocal = {
  getConfig: (key) => authlocalConfig[key],
  log: () => {}
}

const mockJsonschema = {
  getSchema: async () => ({
    validate: async () => true
  })
}

const mockMongodbCollection = {
  deleteMany: async () => {}
}

const mockMongodb = {
  find: async (collection, query) => {
    if (collection === 'passwordresets') {
      return mockPasswordResetsStore.filter(r => r.token === query.token)
    }
    return []
  },
  insert: async (collection, data) => {
    mockPasswordResetsStore.push(data)
    return data
  },
  delete: async (collection, query) => {
    const idx = mockPasswordResetsStore.findIndex(r => r.token === query.token)
    if (idx !== -1) mockPasswordResetsStore.splice(idx, 1)
  },
  getCollection: () => mockMongodbCollection
}

const mockUsers = {
  find: async (query) => {
    return mockUsersStore.filter(u => u.email === query.email)
  }
}

const moduleMap = {
  'auth-local': mockAuthlocal,
  jsonschema: mockJsonschema,
  mongodb: mockMongodb,
  users: mockUsers
}

const mockApp = {
  errors: mockErrors,
  waitForModule: async (...names) => {
    if (names.length === 1) return moduleMap[names[0]]
    return names.map(n => moduleMap[n])
  }
}

// Register the mock for adapt-authoring-core before importing PasswordUtils
mock.module('adapt-authoring-core', {
  namedExports: { App: { instance: mockApp } }
})

const { default: PasswordUtils } = await import('../lib/PasswordUtils.js')

describe('PasswordUtils', () => {
  describe('#getConfig()', () => {
    it('should return a single config value when one key is passed', async () => {
      const result = await PasswordUtils.getConfig('saltRounds')
      assert.equal(result, 10)
    })

    it('should return an object of config values when multiple keys are passed', async () => {
      const result = await PasswordUtils.getConfig('saltRounds', 'minPasswordLength')
      assert.deepEqual(result, { saltRounds: 10, minPasswordLength: 8 })
    })

    it('should return undefined for an unknown config key', async () => {
      const result = await PasswordUtils.getConfig('nonExistentKey')
      assert.equal(result, undefined)
    })

    it('should return an object with undefined values for unknown keys in multi-key mode', async () => {
      const result = await PasswordUtils.getConfig('saltRounds', 'unknownKey')
      assert.deepEqual(result, { saltRounds: 10, unknownKey: undefined })
    })
  })

  describe('#compare()', () => {
    let hash

    before(async () => {
      const salt = await promisify(bcrypt.genSalt)(10)
      hash = await promisify(bcrypt.hash)('correctpassword', salt)
    })

    it('should resolve without error when password matches hash', async () => {
      await assert.doesNotReject(() => PasswordUtils.compare('correctpassword', hash))
    })

    it('should throw when password does not match hash', async () => {
      await assert.rejects(
        () => PasswordUtils.compare('wrongpassword', hash),
        (err) => err.name === 'INVALID_LOGIN_DETAILS'
      )
    })

    it('should throw when plainPassword is empty', async () => {
      await assert.rejects(
        () => PasswordUtils.compare('', hash),
        (err) => err.name === 'INVALID_LOGIN_DETAILS'
      )
    })

    it('should throw when hash is empty', async () => {
      await assert.rejects(
        () => PasswordUtils.compare('password', ''),
        (err) => err.name === 'INVALID_LOGIN_DETAILS'
      )
    })

    it('should throw when both arguments are missing', async () => {
      await assert.rejects(
        () => PasswordUtils.compare(undefined, undefined),
        (err) => err.name === 'INVALID_LOGIN_DETAILS'
      )
    })

    it('should throw when plainPassword is null', async () => {
      await assert.rejects(
        () => PasswordUtils.compare(null, hash),
        (err) => err.name === 'INVALID_LOGIN_DETAILS'
      )
    })

    it('should throw when hash is null', async () => {
      await assert.rejects(
        () => PasswordUtils.compare('password', null),
        (err) => err.name === 'INVALID_LOGIN_DETAILS'
      )
    })

    it('should set INCORRECT_PASSWORD as nested error data on mismatch', async () => {
      await assert.rejects(
        () => PasswordUtils.compare('wrongpassword', hash),
        (err) => {
          assert.equal(err.data.error.name, 'INCORRECT_PASSWORD')
          return true
        }
      )
    })

    it('should set INVALID_PARAMS as nested error data when params missing', async () => {
      await assert.rejects(
        () => PasswordUtils.compare('', ''),
        (err) => {
          assert.equal(err.data.error.name, 'INVALID_PARAMS')
          assert.deepEqual(err.data.error.data.params, ['plainPassword', 'hash'])
          return true
        }
      )
    })
  })

  describe('#validate()', () => {
    beforeEach(() => {
      authlocalConfig = {
        ...authlocalConfig,
        minPasswordLength: 8,
        passwordMustHaveNumber: false,
        passwordMustHaveUppercase: false,
        passwordMustHaveLowercase: false,
        passwordMustHaveSpecial: false,
        blacklistedPasswordValues: []
      }
    })

    it('should resolve for a valid password meeting minimum length', async () => {
      await assert.doesNotReject(() => PasswordUtils.validate('abcdefgh'))
    })

    it('should throw when password is not a string', async () => {
      await assert.rejects(
        () => PasswordUtils.validate(12345678),
        (err) => err.name === 'INVALID_PARAMS'
      )
    })

    it('should throw when password is null', async () => {
      await assert.rejects(
        () => PasswordUtils.validate(null),
        (err) => err.name === 'INVALID_PARAMS'
      )
    })

    it('should throw when password is undefined', async () => {
      await assert.rejects(
        () => PasswordUtils.validate(undefined),
        (err) => err.name === 'INVALID_PARAMS'
      )
    })

    it('should throw when password is a boolean', async () => {
      await assert.rejects(
        () => PasswordUtils.validate(true),
        (err) => err.name === 'INVALID_PARAMS'
      )
    })

    it('should throw when password is too short', async () => {
      await assert.rejects(
        () => PasswordUtils.validate('short'),
        (err) => err.name === 'INVALID_PASSWORD'
      )
    })

    it('should include minimum length in INVALID_PASSWORD_LENGTH error data', async () => {
      await assert.rejects(
        () => PasswordUtils.validate('short'),
        (err) => {
          assert.equal(err.name, 'INVALID_PASSWORD')
          const lengthErr = err.data.errors.find(e => e.name === 'INVALID_PASSWORD_LENGTH')
          assert.ok(lengthErr)
          assert.equal(lengthErr.data.length, 8)
          return true
        }
      )
    })

    it('should accept a password of exactly minimum length', async () => {
      await assert.doesNotReject(() => PasswordUtils.validate('12345678'))
    })

    it('should throw when number is required but missing', async () => {
      authlocalConfig.passwordMustHaveNumber = true
      await assert.rejects(
        () => PasswordUtils.validate('abcdefgh'),
        (err) => {
          assert.equal(err.name, 'INVALID_PASSWORD')
          return true
        }
      )
    })

    it('should accept a password with a number when required', async () => {
      authlocalConfig.passwordMustHaveNumber = true
      await assert.doesNotReject(() => PasswordUtils.validate('abcdefg1'))
    })

    it('should throw when uppercase is required but missing', async () => {
      authlocalConfig.passwordMustHaveUppercase = true
      await assert.rejects(
        () => PasswordUtils.validate('abcdefgh'),
        (err) => err.name === 'INVALID_PASSWORD'
      )
    })

    it('should accept a password with uppercase when required', async () => {
      authlocalConfig.passwordMustHaveUppercase = true
      await assert.doesNotReject(() => PasswordUtils.validate('Abcdefgh'))
    })

    it('should throw when lowercase is required but missing', async () => {
      authlocalConfig.passwordMustHaveLowercase = true
      await assert.rejects(
        () => PasswordUtils.validate('ABCDEFGH'),
        (err) => err.name === 'INVALID_PASSWORD'
      )
    })

    it('should accept a password with lowercase when required', async () => {
      authlocalConfig.passwordMustHaveLowercase = true
      await assert.doesNotReject(() => PasswordUtils.validate('abcdefgh'))
    })

    it('should throw when special character is required but missing', async () => {
      authlocalConfig.passwordMustHaveSpecial = true
      await assert.rejects(
        () => PasswordUtils.validate('abcdefgh'),
        (err) => err.name === 'INVALID_PASSWORD'
      )
    })

    it('should accept each recognized special character', async () => {
      authlocalConfig.passwordMustHaveSpecial = true
      const specials = ['#', '?', '!', '@', '$', '%', '^', '&', '*', '-']
      for (const ch of specials) {
        await assert.doesNotReject(() => PasswordUtils.validate('abcdefg' + ch))
      }
    })

    it('should collect multiple validation errors', async () => {
      authlocalConfig.passwordMustHaveNumber = true
      authlocalConfig.passwordMustHaveUppercase = true
      authlocalConfig.passwordMustHaveSpecial = true
      await assert.rejects(
        () => PasswordUtils.validate('abcdefgh'),
        (err) => {
          assert.equal(err.name, 'INVALID_PASSWORD')
          assert.ok(err.data.errors.length >= 3)
          return true
        }
      )
    })

    it('should pass all complexity rules simultaneously', async () => {
      authlocalConfig.passwordMustHaveNumber = true
      authlocalConfig.passwordMustHaveUppercase = true
      authlocalConfig.passwordMustHaveLowercase = true
      authlocalConfig.passwordMustHaveSpecial = true
      await assert.doesNotReject(() => PasswordUtils.validate('Abcdef1!'))
    })

    it('should accept an empty string when minPasswordLength is zero', async () => {
      authlocalConfig.minPasswordLength = 0
      await assert.doesNotReject(() => PasswordUtils.validate(''))
    })

    // NOTE: The blacklist check in the source has a bug -- it uses .some() where
    // it should use .every(). This means a password containing a blacklisted
    // value can still pass if there are other blacklisted values it doesn't
    // contain. The test below documents the expected (correct) behaviour.
    // See PasswordUtils.js line 67.
    it('should throw when password contains a blacklisted value', async () => {
      authlocalConfig.blacklistedPasswordValues = ['password']
      // With only one blacklisted entry, .some() and .every() behave identically
      await assert.rejects(
        () => PasswordUtils.validate('password123'),
        (err) => err.name === 'INVALID_PASSWORD'
      )
    })

    it('should accept a password not containing blacklisted values', async () => {
      authlocalConfig.blacklistedPasswordValues = ['password']
      await assert.doesNotReject(() => PasswordUtils.validate('securevalue'))
    })

    it('should handle an empty blacklist array', async () => {
      authlocalConfig.blacklistedPasswordValues = []
      await assert.doesNotReject(() => PasswordUtils.validate('anything1'))
    })

    it('should throw when password contains any blacklisted value (multiple entries)', async () => {
      authlocalConfig.blacklistedPasswordValues = ['password', 'qwerty']
      await assert.rejects(
        () => PasswordUtils.validate('password123'),
        (err) => err.name === 'INVALID_PASSWORD'
      )
    })
  })

  describe('#generate()', () => {
    it('should return a bcrypt hash for a valid password', async () => {
      const hash = await PasswordUtils.generate('validpassword')
      assert.equal(typeof hash, 'string')
      assert.ok(hash.startsWith('$2a$') || hash.startsWith('$2b$'))
    })

    it('should throw when plainPassword is empty', async () => {
      await assert.rejects(
        () => PasswordUtils.generate(''),
        (err) => err.name === 'INVALID_PARAMS'
      )
    })

    it('should throw when plainPassword is undefined', async () => {
      await assert.rejects(
        () => PasswordUtils.generate(undefined),
        (err) => err.name === 'INVALID_PARAMS'
      )
    })

    it('should throw when plainPassword is null', async () => {
      await assert.rejects(
        () => PasswordUtils.generate(null),
        (err) => err.name === 'INVALID_PARAMS'
      )
    })

    it('should generate different hashes for the same password (salted)', async () => {
      const hash1 = await PasswordUtils.generate('samepassword')
      const hash2 = await PasswordUtils.generate('samepassword')
      assert.notEqual(hash1, hash2)
    })

    it('should generate a hash verifiable with bcrypt compare', async () => {
      const password = 'verifyMe123'
      const hash = await PasswordUtils.generate(password)
      const isValid = await promisify(bcrypt.compare)(password, hash)
      assert.equal(isValid, true)
    })
  })

  describe('#getRandomHex()', () => {
    it('should return a hex string of default length (64 chars for 32 bytes)', async () => {
      const hex = await PasswordUtils.getRandomHex()
      assert.equal(typeof hex, 'string')
      assert.equal(hex.length, 64)
      assert.ok(/^[0-9a-f]+$/.test(hex))
    })

    it('should return a hex string of specified length', async () => {
      const hex = await PasswordUtils.getRandomHex(16)
      assert.equal(hex.length, 32)
    })

    it('should return unique values on subsequent calls', async () => {
      const hex1 = await PasswordUtils.getRandomHex()
      const hex2 = await PasswordUtils.getRandomHex()
      assert.notEqual(hex1, hex2)
    })

    it('should handle a size of 1', async () => {
      const hex = await PasswordUtils.getRandomHex(1)
      assert.equal(hex.length, 2)
      assert.ok(/^[0-9a-f]+$/.test(hex))
    })
  })

  describe('#createReset()', () => {
    beforeEach(() => {
      mockPasswordResetsStore.length = 0
      mockUsersStore.length = 0
    })

    it('should create a reset token for a valid local auth user', async () => {
      mockUsersStore.push({ email: 'test@example.com', authType: 'local' })
      const token = await PasswordUtils.createReset('test@example.com', 86400000)
      assert.equal(typeof token, 'string')
      assert.ok(token.length > 0)
    })

    it('should store the reset data in the collection', async () => {
      mockUsersStore.push({ email: 'test@example.com', authType: 'local' })
      await PasswordUtils.createReset('test@example.com', 86400000)
      assert.equal(mockPasswordResetsStore.length, 1)
      assert.equal(mockPasswordResetsStore[0].email, 'test@example.com')
      assert.ok(mockPasswordResetsStore[0].expiresAt)
      assert.ok(mockPasswordResetsStore[0].token)
    })

    it('should set expiresAt to a future date based on lifespan', async () => {
      mockUsersStore.push({ email: 'test@example.com', authType: 'local' })
      const beforeTime = Date.now()
      await PasswordUtils.createReset('test@example.com', 86400000)
      const expiresAt = new Date(mockPasswordResetsStore[0].expiresAt).getTime()
      assert.ok(expiresAt >= beforeTime + 86400000)
      assert.ok(expiresAt <= Date.now() + 86400000)
    })

    it('should throw when user is not found', async () => {
      await assert.rejects(
        () => PasswordUtils.createReset('noone@example.com', 86400000),
        (err) => err.name === 'NOT_FOUND'
      )
    })

    it('should include user email as id in NOT_FOUND error data', async () => {
      await assert.rejects(
        () => PasswordUtils.createReset('noone@example.com', 86400000),
        (err) => {
          assert.equal(err.data.id, 'noone@example.com')
          assert.equal(err.data.type, 'user')
          return true
        }
      )
    })

    it('should throw when user is not authenticated with local auth', async () => {
      mockUsersStore.push({ email: 'sso@example.com', authType: 'sso' })
      await assert.rejects(
        () => PasswordUtils.createReset('sso@example.com', 86400000),
        (err) => err.name === 'ACCOUNT_NOT_LOCALAUTHD'
      )
    })

    it('should use default resetTokenLifespan when lifespan is not provided', async () => {
      mockUsersStore.push({ email: 'test@example.com', authType: 'local' })
      const token = await PasswordUtils.createReset('test@example.com')
      assert.equal(typeof token, 'string')
    })
  })

  describe('#deleteReset()', () => {
    beforeEach(() => {
      mockPasswordResetsStore.length = 0
    })

    it('should remove the reset token from the store', async () => {
      mockPasswordResetsStore.push({ token: 'abc123', email: 'test@example.com' })
      await PasswordUtils.deleteReset('abc123')
      assert.equal(mockPasswordResetsStore.length, 0)
    })

    it('should not error when deleting a non-existent token', async () => {
      await assert.doesNotReject(() => PasswordUtils.deleteReset('nonexistent'))
    })
  })

  describe('#validateReset()', () => {
    beforeEach(() => {
      mockPasswordResetsStore.length = 0
      mockUsersStore.length = 0
    })

    it('should throw when token is empty', async () => {
      await assert.rejects(
        () => PasswordUtils.validateReset(''),
        (err) => err.name === 'INVALID_PARAMS'
      )
    })

    it('should throw when token is undefined', async () => {
      await assert.rejects(
        () => PasswordUtils.validateReset(undefined),
        (err) => err.name === 'INVALID_PARAMS'
      )
    })

    it('should throw when token is null', async () => {
      await assert.rejects(
        () => PasswordUtils.validateReset(null),
        (err) => err.name === 'INVALID_PARAMS'
      )
    })

    it('should throw when token is not found', async () => {
      await assert.rejects(
        () => PasswordUtils.validateReset('nonexistent'),
        (err) => err.name === 'AUTH_TOKEN_INVALID'
      )
    })

    it('should throw when token is expired', async () => {
      mockPasswordResetsStore.push({
        token: 'expired-token',
        email: 'test@example.com',
        expiresAt: new Date(Date.now() - 1000).toISOString()
      })
      await assert.rejects(
        () => PasswordUtils.validateReset('expired-token'),
        (err) => err.name === 'AUTH_TOKEN_EXPIRED'
      )
    })

    it('should throw when user associated with token is not found', async () => {
      mockPasswordResetsStore.push({
        token: 'valid-token',
        email: 'deleted@example.com',
        expiresAt: new Date(Date.now() + 86400000).toISOString()
      })
      await assert.rejects(
        () => PasswordUtils.validateReset('valid-token'),
        (err) => err.name === 'NOT_FOUND'
      )
    })

    it('should include correct email in NOT_FOUND error when user is missing', async () => {
      mockPasswordResetsStore.push({
        token: 'orphan-token',
        email: 'orphan@example.com',
        expiresAt: new Date(Date.now() + 86400000).toISOString()
      })
      await assert.rejects(
        () => PasswordUtils.validateReset('orphan-token'),
        (err) => {
          assert.equal(err.data.id, 'orphan@example.com')
          return true
        }
      )
    })

    it('should return token data for a valid, non-expired token', async () => {
      const tokenData = {
        token: 'valid-token',
        email: 'test@example.com',
        expiresAt: new Date(Date.now() + 86400000).toISOString()
      }
      mockPasswordResetsStore.push(tokenData)
      mockUsersStore.push({ email: 'test@example.com' })
      const result = await PasswordUtils.validateReset('valid-token')
      assert.equal(result.token, 'valid-token')
      assert.equal(result.email, 'test@example.com')
    })

    it('should accept a token that has not yet expired', async () => {
      mockPasswordResetsStore.push({
        token: 'edge-token',
        email: 'test@example.com',
        expiresAt: new Date(Date.now() + 1000).toISOString()
      })
      mockUsersStore.push({ email: 'test@example.com' })
      const result = await PasswordUtils.validateReset('edge-token')
      assert.equal(result.token, 'edge-token')
    })
  })
})
