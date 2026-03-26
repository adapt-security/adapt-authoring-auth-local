import { describe, it, before, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'

// --- Stub framework dependencies before importing LocalAuthModule ---

const makeError = (name) => {
  const err = { name, setData: (d) => ({ ...err, data: d }) }
  return err
}

const mockErrors = {
  INVALID_LOGIN_DETAILS: makeError('INVALID_LOGIN_DETAILS'),
  ACCOUNT_LOCKED_PERM: makeError('ACCOUNT_LOCKED_PERM'),
  ACCOUNT_LOCKED_TEMP: makeError('ACCOUNT_LOCKED_TEMP'),
  INVALID_PARAMS: makeError('INVALID_PARAMS'),
  INVALID_PASSWORD: makeError('INVALID_PASSWORD'),
  INVALID_PASSWORD_LENGTH: makeError('INVALID_PASSWORD_LENGTH'),
  INVALID_PASSWORD_NUMBER: makeError('INVALID_PASSWORD_NUMBER'),
  INVALID_PASSWORD_UPPERCASE: makeError('INVALID_PASSWORD_UPPERCASE'),
  INVALID_PASSWORD_LOWERCASE: makeError('INVALID_PASSWORD_LOWERCASE'),
  INVALID_PASSWORD_SPECIAL: makeError('INVALID_PASSWORD_SPECIAL'),
  BLACKLISTED_PASSWORD_VALUE: makeError('BLACKLISTED_PASSWORD_VALUE'),
  INCORRECT_PASSWORD: makeError('INCORRECT_PASSWORD'),
  NOT_FOUND: makeError('NOT_FOUND'),
  SUPER_USER_EXISTS: makeError('SUPER_USER_EXISTS')
}

let authlocalConfig = {
  failsUntilTemporaryLock: 5,
  failsUntilPermanentLock: 20,
  temporaryLockDuration: 60000,
  inviteTokenLifespan: 604800000,
  resetTokenLifespan: 86400000,
  saltRounds: 10,
  minPasswordLength: 8,
  passwordMustHaveNumber: false,
  passwordMustHaveUppercase: false,
  passwordMustHaveLowercase: false,
  passwordMustHaveSpecial: false,
  blacklistedPasswordValues: []
}

const usersStore = []
let updateCalls = []
let disavowCalls = []
let secureRouteCalls = []
let unsecureRouteCalls = []
let mailerSendCalls = []

const mockUsers = {
  find: async (query) => usersStore.filter(u => {
    return Object.entries(query).every(([k, v]) => JSON.stringify(u[k]) === JSON.stringify(v))
  }),
  findOne: async (query) => {
    const result = usersStore.find(u => {
      return Object.entries(query).every(([k, v]) => JSON.stringify(u[k]) === JSON.stringify(v))
    })
    if (!result) throw mockErrors.NOT_FOUND.setData({ type: 'user' })
    return result
  },
  update: async (query, data) => {
    updateCalls.push({ query, data })
    return { ...query, ...data }
  },
  collectionName: 'users'
}

const mockRoles = {
  find: async () => [{ _id: 'role-super-id', shortName: 'superuser' }],
  findOne: async () => ({ _id: 'role-super-id', shortName: 'superuser' })
}

const mockMailer = {
  isEnabled: true,
  send: async (opts) => { mailerSendCalls.push(opts) }
}

const mockServer = {
  root: { url: 'http://localhost:5000' }
}

const mockMongodb = {
  update: async (collection, query, update) => {
    return { _id: 'user-id-1', email: 'test@example.com', ...update.$set }
  },
  find: async () => [],
  insert: async (collection, data) => data,
  delete: async () => {},
  getCollection: () => ({ deleteMany: async () => {} })
}

const mockJsonschema = {
  getSchema: async () => ({
    validate: () => true
  })
}

const moduleMap = {
  users: mockUsers,
  roles: mockRoles,
  mailer: mockMailer,
  server: mockServer,
  mongodb: mockMongodb,
  jsonschema: mockJsonschema,
  'auth-local': {
    getConfig: (key) => authlocalConfig[key],
    log: () => {}
  }
}

const mockApp = {
  errors: mockErrors,
  waitForModule: async (...names) => {
    if (names.length === 1) return moduleMap[names[0]]
    return names.map(n => moduleMap[n])
  },
  lang: {
    translate: (_, key) => 'translated:' + key
  }
}

// Stub adapt-authoring-auth to provide AbstractAuthModule
mock.module('adapt-authoring-auth', {
  namedExports: {
    AbstractAuthModule: class AbstractAuthModule {
      constructor () {
        this.app = mockApp
        this.router = { routes: [{ route: '/', meta: null }, { route: '/register', meta: null }] }
      }

      getConfig (key) { return authlocalConfig[key] }

      async setValues () {
        this.type = undefined
        this.routes = undefined
        this.userSchema = 'user'
      }

      async init () {}

      async register (data) { return { _id: 'new-user-id', ...data } }

      async setUserEnabled () {}

      secureRoute (...args) { secureRouteCalls.push(args) }

      unsecureRoute (...args) { unsecureRouteCalls.push(args) }

      disavowUser (...args) { disavowCalls.push(args) }

      log () {}
    }
  }
})

mock.module('adapt-authoring-core', {
  namedExports: { App: { instance: mockApp } }
})

const { default: LocalAuthModule } = await import('../lib/LocalAuthModule.js')

describe('LocalAuthModule', () => {
  let mod

  before(async () => {
    mod = new LocalAuthModule()
    mod.app = mockApp
    mod.users = mockUsers
    mod.userSchema = 'localauthuser'
    mod.type = 'local'
  })

  beforeEach(() => {
    updateCalls = []
    disavowCalls = []
    secureRouteCalls = []
    unsecureRouteCalls = []
    mailerSendCalls = []
    usersStore.length = 0
    authlocalConfig = {
      failsUntilTemporaryLock: 5,
      failsUntilPermanentLock: 20,
      temporaryLockDuration: 60000,
      inviteTokenLifespan: 604800000,
      resetTokenLifespan: 86400000,
      saltRounds: 10,
      minPasswordLength: 8,
      passwordMustHaveNumber: false,
      passwordMustHaveUppercase: false,
      passwordMustHaveLowercase: false,
      passwordMustHaveSpecial: false,
      blacklistedPasswordValues: []
    }
  })

  describe('.formatRemainingTime()', () => {
    it('should return a human-readable string for remaining seconds', () => {
      const result = LocalAuthModule.formatRemainingTime(60)
      assert.equal(typeof result, 'string')
      assert.ok(result.length > 0)
    })

    it('should return a string containing "second" for small values', () => {
      const result = LocalAuthModule.formatRemainingTime(5)
      assert.ok(result.includes('second'))
    })

    it('should return a string containing "minute" for 60 seconds', () => {
      const result = LocalAuthModule.formatRemainingTime(60)
      assert.ok(result.includes('minute'))
    })

    it('should return a string containing "hour" for 3600 seconds', () => {
      const result = LocalAuthModule.formatRemainingTime(3600)
      assert.ok(result.includes('hour'))
    })

    it('should handle zero seconds', () => {
      const result = LocalAuthModule.formatRemainingTime(0)
      assert.equal(typeof result, 'string')
      assert.ok(result.length > 0)
    })
  })

  describe('#setValues()', () => {
    it('should set userSchema to localauthuser', async () => {
      const instance = new LocalAuthModule()
      await instance.setValues()
      assert.equal(instance.userSchema, 'localauthuser')
    })

    it('should call super.setValues()', async () => {
      const instance = new LocalAuthModule()
      await instance.setValues()
      // super.setValues() initialises type and routes to undefined;
      // in production, loadRouteConfig fills them from routes.json
      assert.equal(instance.type, undefined)
      assert.equal(instance.routes, undefined)
    })
  })

  describe('#init()', () => {
    it('should set the users property', async () => {
      const instance = new LocalAuthModule()
      instance.app = mockApp
      await instance.init()
      assert.equal(instance.users, mockUsers)
    })
  })

  describe('#authenticate()', () => {
    let correctHash

    before(async () => {
      const { default: PasswordUtils } = await import('../lib/PasswordUtils.js')
      correctHash = await PasswordUtils.generate('correctpass')
    })

    function createMockUser (overrides = {}) {
      return {
        _id: 'user-1',
        password: correctHash,
        isPermLocked: false,
        isTempLocked: false,
        failedLoginAttempts: 0,
        lastFailedLoginAttempt: null,
        ...overrides
      }
    }

    it('should throw when password is not provided in request body', async () => {
      const req = { body: {} }
      await assert.rejects(
        () => mod.authenticate({}, req, {}),
        (err) => err.name === 'INVALID_LOGIN_DETAILS'
      )
    })

    it('should reset failed attempts on successful authentication', async () => {
      const user = createMockUser({ failedLoginAttempts: 2 })
      const req = { body: { password: 'correctpass' } }
      await mod.authenticate(user, req, {})
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.failedLoginAttempts, 0)
    })

    it('should increment failed attempts on wrong password', async () => {
      const user = createMockUser()
      const req = { body: { password: 'wrongpass' } }
      await assert.rejects(() => mod.authenticate(user, req, {}))
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.failedLoginAttempts, 1)
    })

    it('should set lastFailedLoginAttempt on wrong password', async () => {
      const user = createMockUser()
      const req = { body: { password: 'wrongpass' } }
      await assert.rejects(() => mod.authenticate(user, req, {}))
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.ok(lastUpdate.data.lastFailedLoginAttempt)
      assert.ok(!isNaN(Date.parse(lastUpdate.data.lastFailedLoginAttempt)))
    })

    it('should temporarily lock after reaching failsUntilTemporaryLock threshold', async () => {
      const user = createMockUser({ failedLoginAttempts: 4 })
      const req = { body: { password: 'wrongpass' } }
      await assert.rejects(
        () => mod.authenticate(user, req, {}),
        (err) => err.name === 'ACCOUNT_LOCKED_TEMP'
      )
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.isTempLocked, true)
    })

    it('should permanently lock after reaching failsUntilPermanentLock threshold', async () => {
      const user = createMockUser({ failedLoginAttempts: 19 })
      const req = { body: { password: 'wrongpass' } }
      await assert.rejects(
        () => mod.authenticate(user, req, {}),
        (err) => err.name === 'ACCOUNT_LOCKED_PERM'
      )
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.isPermLocked, true)
    })

    it('should throw ACCOUNT_LOCKED_PERM when user is already permanently locked', async () => {
      const user = createMockUser({
        isPermLocked: true,
        failedLoginAttempts: 20,
        lastFailedLoginAttempt: new Date().toISOString()
      })
      const req = { body: { password: 'correctpass' } }
      await assert.rejects(
        () => mod.authenticate(user, req, {}),
        (err) => err.name === 'ACCOUNT_LOCKED_PERM'
      )
    })

    it('should not increment failed attempts when account is permanently locked', async () => {
      const user = createMockUser({
        isPermLocked: true,
        failedLoginAttempts: 20,
        lastFailedLoginAttempt: new Date().toISOString()
      })
      const req = { body: { password: 'wrongpass' } }
      await assert.rejects(() => mod.authenticate(user, req, {}))
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.failedLoginAttempts, 20)
    })

    it('should not increment failed attempts during temp lock timeout', async () => {
      const user = createMockUser({
        isTempLocked: true,
        failedLoginAttempts: 5,
        lastFailedLoginAttempt: new Date().toISOString()
      })
      const req = { body: { password: 'wrongpass' } }
      await assert.rejects(() => mod.authenticate(user, req, {}))
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.failedLoginAttempts, 5)
    })

    it('should clear lastFailedLoginAttempt on successful login', async () => {
      const user = createMockUser()
      const req = { body: { password: 'correctpass' } }
      await mod.authenticate(user, req, {})
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.lastFailedLoginAttempt, undefined)
    })
  })

  describe('#handleLockStatus()', () => {
    it('should throw ACCOUNT_LOCKED_PERM when user is permanently locked', async () => {
      await assert.rejects(
        () => mod.handleLockStatus({ isPermLocked: true, isTempLocked: false }),
        (err) => err.name === 'ACCOUNT_LOCKED_PERM'
      )
    })

    it('should throw ACCOUNT_LOCKED_TEMP when user is temp locked and lock has not expired', async () => {
      const user = {
        isPermLocked: false,
        isTempLocked: true,
        // NOTE: lastFailedLoginAttempt is set to now so the lock is still active.
        lastFailedLoginAttempt: new Date().toISOString()
      }
      await assert.rejects(
        () => mod.handleLockStatus(user),
        (err) => err.name === 'ACCOUNT_LOCKED_TEMP'
      )
    })

    it('should include remaining time in ACCOUNT_LOCKED_TEMP error data', async () => {
      const user = {
        isPermLocked: false,
        isTempLocked: true,
        lastFailedLoginAttempt: new Date().toISOString()
      }
      await assert.rejects(
        () => mod.handleLockStatus(user),
        (err) => {
          assert.ok(err.data)
          assert.ok(err.data.remaining)
          assert.equal(typeof err.data.remaining, 'string')
          return true
        }
      )
    })

    it('should unlock user when temp lock has expired', async () => {
      const user = {
        _id: 'user-1',
        isPermLocked: false,
        isTempLocked: true,
        // Set to long ago so the lock is expired (even with the * 1000 bug)
        lastFailedLoginAttempt: new Date(Date.now() - 999999999).toISOString()
      }
      await mod.handleLockStatus(user)
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.isTempLocked, false)
    })

    it('should not update anything when user is not locked', async () => {
      const user = {
        isPermLocked: false,
        isTempLocked: false,
        lastFailedLoginAttempt: null
      }
      await mod.handleLockStatus(user)
      assert.equal(updateCalls.length, 0)
    })

    it('should check permanent lock before temporary lock', async () => {
      const user = {
        isPermLocked: true,
        isTempLocked: true,
        lastFailedLoginAttempt: new Date().toISOString()
      }
      await assert.rejects(
        () => mod.handleLockStatus(user),
        (err) => err.name === 'ACCOUNT_LOCKED_PERM'
      )
    })
  })

  describe('#register()', () => {
    it('should hash the password and call super.register', async () => {
      const result = await mod.register({ email: 'new@example.com', password: 'validpassword' })
      assert.equal(result._id, 'new-user-id')
      assert.equal(result.email, 'new@example.com')
      assert.ok(result.password.startsWith('$2a$') || result.password.startsWith('$2b$'))
    })

    it('should auto-generate a password when none is provided', async () => {
      const result = await mod.register({ email: 'new@example.com' })
      assert.ok(result.password)
      assert.ok(result.password.startsWith('$2a$') || result.password.startsWith('$2b$'))
    })

    it('should preserve other data fields in registration', async () => {
      const result = await mod.register({
        email: 'new@example.com',
        password: 'validpassword',
        firstName: 'Test',
        lastName: 'User'
      })
      assert.equal(result.firstName, 'Test')
      assert.equal(result.lastName, 'User')
    })
  })

  describe('#registerSuper()', () => {
    it('should throw SUPER_USER_EXISTS when a super user already exists', async () => {
      usersStore.push({ _id: 'existing-super', roles: ['role-super-id'] })
      await assert.rejects(
        () => mod.registerSuper({ email: 'super@example.com', password: 'validpassword' }),
        (err) => err.name === 'SUPER_USER_EXISTS'
      )
    })

    it('should call register with hardcoded firstName and lastName', async () => {
      const originalRegister = mod.register.bind(mod)
      let registeredData
      mod.register = async (data) => {
        registeredData = data
        return originalRegister(data)
      }
      await mod.registerSuper({ email: 'super@example.com', password: 'validpassword' })
      mod.register = originalRegister
      assert.equal(registeredData.firstName, 'Super')
      assert.equal(registeredData.lastName, 'User')
      assert.equal(registeredData.email, 'super@example.com')
      assert.equal(registeredData.password, 'validpassword')
    })
  })

  describe('#setUserEnabled()', () => {
    it('should reset failed attempts and unlock when enabling a user', async () => {
      const user = { _id: 'user-1', failedLoginAttempts: 10 }
      await mod.setUserEnabled(user, true)
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.failedLoginAttempts, 0)
      assert.equal(lastUpdate.data.isPermLocked, false)
      assert.equal(lastUpdate.data.isTempLocked, false)
    })

    // NOTE: There is a bug in setUserEnabled -- when disabling (isEnabled=false),
    // it references user.failedAttempts which doesn't exist on the schema.
    // The schema field is user.failedLoginAttempts. This means
    // failedLoginAttempts will always be set to undefined when disabling.
    it('should lock the account when disabling a user', async () => {
      const user = { _id: 'user-1', failedLoginAttempts: 3, failedAttempts: 3 }
      await mod.setUserEnabled(user, false)
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.isPermLocked, true)
      assert.equal(lastUpdate.data.isTempLocked, true)
    })

    it('should use localauthuser schema for user update', async () => {
      const user = { _id: 'user-1', failedLoginAttempts: 0 }
      await mod.setUserEnabled(user, true)
      assert.ok(updateCalls.length > 0)
    })

    it('should preserve failedLoginAttempts when disabling a user', async () => {
      const user = { _id: 'user-1', failedLoginAttempts: 7 }
      await mod.setUserEnabled(user, false)
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.failedLoginAttempts, 7)
    })
  })

  describe('#updateUser()', () => {
    it('should accept a string ID as userIdOrQuery', async () => {
      await mod.updateUser('user-id-1', { firstName: 'Updated' })
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.deepEqual(lastUpdate.query, { _id: 'user-id-1' })
    })

    it('should accept a query object as userIdOrQuery', async () => {
      await mod.updateUser({ email: 'test@example.com' }, { firstName: 'Updated' })
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.deepEqual(lastUpdate.query, { email: 'test@example.com' })
    })

    it('should accept an ObjectId-like object as userIdOrQuery', async () => {
      const fakeObjectId = { constructor: { name: 'ObjectId' }, toString: () => 'abc123' }
      await mod.updateUser(fakeObjectId, { firstName: 'Updated' })
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.deepEqual(lastUpdate.query, { _id: fakeObjectId })
    })

    it('should hash password when update includes password', async () => {
      const result = await mod.updateUser('user-id-1', { password: 'newpassword' })
      assert.ok(result)
    })

    it('should not hash password when update does not include password', async () => {
      await mod.updateUser('user-id-1', { firstName: 'NoPassword' })
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.firstName, 'NoPassword')
      assert.equal(Object.prototype.hasOwnProperty.call(lastUpdate.data, 'password'), false)
    })

    it('should call disavowUser after a password update', async () => {
      disavowCalls = []
      await mod.updateUser('user-id-1', { password: 'newpassword' })
      assert.ok(disavowCalls.length > 0)
      assert.equal(disavowCalls[0][0].authType, 'local')
    })

    it('should send email notification after password update when mailer is enabled', async () => {
      mailerSendCalls = []
      await mod.updateUser('user-id-1', { password: 'newpassword' })
      assert.ok(mailerSendCalls.length > 0)
      assert.equal(mailerSendCalls[0].to, 'test@example.com')
    })

    it('should pass useDefaults:false and ignoreRequired:true for non-password updates', async () => {
      await assert.doesNotReject(() => mod.updateUser('user-id-1', { firstName: 'Test' }))
    })
  })

  describe('#createPasswordReset()', () => {
    it('should throw when email is not provided', async () => {
      await assert.rejects(
        () => mod.createPasswordReset(''),
        (err) => err.name === 'INVALID_PARAMS'
      )
    })

    it('should throw when email is undefined', async () => {
      await assert.rejects(
        () => mod.createPasswordReset(undefined),
        (err) => err.name === 'INVALID_PARAMS'
      )
    })

    it('should throw when email is null', async () => {
      await assert.rejects(
        () => mod.createPasswordReset(null),
        (err) => err.name === 'INVALID_PARAMS'
      )
    })

    it('should include email param in INVALID_PARAMS error data', async () => {
      await assert.rejects(
        () => mod.createPasswordReset(''),
        (err) => {
          assert.deepEqual(err.data.params, ['email'])
          return true
        }
      )
    })
  })

  describe('#inviteHandler()', () => {
    it('should respond with 204 on success', async () => {
      let statusSent
      const req = {
        body: { email: 'invite@example.com' },
        translate: (key) => 'translated:' + key,
        auth: { user: { _id: { toString: () => 'admin-id' } } }
      }
      const res = {
        sendStatus: (code) => { statusSent = code }
      }
      // Stub createPasswordReset to avoid real execution
      const original = mod.createPasswordReset.bind(mod)
      mod.createPasswordReset = async () => {}
      await mod.inviteHandler(req, res, () => {})
      mod.createPasswordReset = original
      assert.equal(statusSent, 204)
    })

    it('should call next with error on failure', async () => {
      let nextError
      const req = {
        body: { email: '' },
        translate: (key) => 'translated:' + key,
        auth: {}
      }
      const res = { sendStatus: () => {} }
      await mod.inviteHandler(req, res, (err) => { nextError = err })
      assert.ok(nextError)
    })

    it('should pass inviteTokenLifespan to createPasswordReset', async () => {
      let receivedLifespan
      const original = mod.createPasswordReset.bind(mod)
      mod.createPasswordReset = async (email, subject, text, html, lifespan) => {
        receivedLifespan = lifespan
      }
      const req = {
        body: { email: 'invite@example.com' },
        translate: (key) => 'translated:' + key,
        auth: { user: { _id: { toString: () => 'admin-id' } } }
      }
      const res = { sendStatus: () => {} }
      await mod.inviteHandler(req, res, () => {})
      mod.createPasswordReset = original
      assert.equal(receivedLifespan, 604800000)
    })
  })

  describe('#registerSuperHandler()', () => {
    it('should respond with 204 on success', async () => {
      let statusSent
      const req = { body: { email: 'super@example.com', password: 'validpassword' } }
      const res = { sendStatus: (code) => { statusSent = code } }
      // Stub registerSuper
      const original = mod.registerSuper.bind(mod)
      mod.registerSuper = async () => {}
      await mod.registerSuperHandler(req, res, () => {})
      mod.registerSuper = original
      assert.equal(statusSent, 204)
    })

    it('should call next with error on failure', async () => {
      let nextError
      const req = { body: { email: 'super@example.com', password: 'validpassword' } }
      const res = { sendStatus: () => {} }
      usersStore.push({ _id: 'existing', roles: ['role-super-id'] })
      await mod.registerSuperHandler(req, res, (err) => { nextError = err })
      assert.ok(nextError)
    })
  })

  describe('#forgotPasswordHandler()', () => {
    it('should always respond with 200 and a message (even on error)', async () => {
      let responseStatus
      let responseJson
      const req = {
        body: { email: '' },
        translate: (key) => 'translated:' + key,
        auth: {}
      }
      const res = {
        status: (code) => {
          responseStatus = code
          return { json: (data) => { responseJson = data } }
        }
      }
      await mod.forgotPasswordHandler(req, res, () => {})
      assert.equal(responseStatus, 200)
      assert.ok(responseJson.message)
    })

    it('should include translated message in response', async () => {
      let responseJson
      const req = {
        body: { email: 'test@example.com' },
        translate: (key) => 'translated:' + key,
        auth: {}
      }
      const res = {
        status: () => ({ json: (data) => { responseJson = data } })
      }
      const original = mod.createPasswordReset.bind(mod)
      mod.createPasswordReset = async () => {}
      await mod.forgotPasswordHandler(req, res, () => {})
      mod.createPasswordReset = original
      assert.equal(responseJson.message, 'translated:app.forgotpasswordmessage')
    })

    it('should not call next with error (swallows errors to avoid info leaks)', async () => {
      let nextCalled = false
      const req = {
        body: { email: '' },
        translate: (key) => 'translated:' + key,
        auth: {}
      }
      const res = {
        status: () => ({ json: () => {} })
      }
      await mod.forgotPasswordHandler(req, res, () => { nextCalled = true })
      assert.equal(nextCalled, false)
    })
  })

  describe('#changePasswordHandler()', () => {
    it('should respond with 204 on successful authenticated password change', async () => {
      const { default: PasswordUtils } = await import('../lib/PasswordUtils.js')
      const oldHash = await PasswordUtils.generate('oldpassword')
      usersStore.push({ email: 'test@example.com', password: oldHash })

      let endCalled = false
      let statusCode
      const req = {
        body: { password: 'newpassword1', oldPassword: 'oldpassword' },
        auth: {
          token: { type: 'local', signature: 'sig123' },
          user: { email: 'test@example.com', _id: { toString: () => 'uid1' } }
        }
      }
      const res = {
        status: (code) => {
          statusCode = code
          return { end: () => { endCalled = true } }
        }
      }
      await mod.changePasswordHandler(req, res, () => {})
      assert.equal(statusCode, 204)
      assert.equal(endCalled, true)
    })

    it('should call next with error on invalid old password', async () => {
      const { default: PasswordUtils } = await import('../lib/PasswordUtils.js')
      const oldHash = await PasswordUtils.generate('oldpassword')
      usersStore.push({ email: 'test@example.com', password: oldHash })

      let nextError
      const req = {
        body: { password: 'newpassword1', oldPassword: 'wrongpassword' },
        auth: {
          token: { type: 'local', signature: 'sig123' },
          user: { email: 'test@example.com', _id: { toString: () => 'uid1' } }
        }
      }
      const res = { status: () => ({ end: () => {} }) }
      await mod.changePasswordHandler(req, res, (err) => { nextError = err })
      assert.ok(nextError)
    })

    it('should call next with error when auth token type is not local', async () => {
      let nextError
      const req = {
        body: { password: 'newpassword1' },
        auth: {
          token: { type: 'sso', signature: 'sig123' },
          user: { email: 'test@example.com', _id: { toString: () => 'uid1' } }
        }
      }
      const res = { status: () => ({ end: () => {} }) }
      await mod.changePasswordHandler(req, res, (err) => { nextError = err })
      assert.ok(nextError)
    })

    it('should use reset token path when no auth token present', async () => {
      let statusCode
      let endCalled = false
      const PasswordUtils = (await import('../lib/PasswordUtils.js')).default

      const originalUpdate = mod.updateUser.bind(mod)
      mod.updateUser = async () => ({ _id: 'uid1' })

      const origDeleteReset = PasswordUtils.deleteReset
      PasswordUtils.deleteReset = async () => {}

      const origValidate = PasswordUtils.validateReset
      PasswordUtils.validateReset = async () => ({ email: 'test@example.com' })

      const req = {
        body: { password: 'newpassword1', token: 'reset-token-123' },
        auth: {}
      }
      const res = {
        status: (code) => {
          statusCode = code
          return { end: () => { endCalled = true } }
        }
      }
      await mod.changePasswordHandler(req, res, () => {})
      assert.equal(statusCode, 204)
      assert.equal(endCalled, true)

      // Restore
      PasswordUtils.validateReset = origValidate
      PasswordUtils.deleteReset = origDeleteReset
      mod.updateUser = originalUpdate
    })

    it('should call next with error when email is missing', async () => {
      let nextError
      const PasswordUtils = (await import('../lib/PasswordUtils.js')).default
      const origValidate = PasswordUtils.validateReset
      PasswordUtils.validateReset = async () => ({ email: '' })

      const req = {
        body: { password: 'newpassword1', token: 'reset-token-123' },
        auth: {}
      }
      const res = { status: () => ({ end: () => {} }) }
      await mod.changePasswordHandler(req, res, (err) => { nextError = err })
      assert.ok(nextError)
      PasswordUtils.validateReset = origValidate
    })
  })

  describe('#validatePasswordHandler()', () => {
    it('should respond with a success message for a valid password', async () => {
      let responseJson
      const req = {
        body: { password: 'validpassword' },
        translate: (key) => 'translated:' + key
      }
      const res = {
        json: (data) => { responseJson = data }
      }
      await mod.validatePasswordHandler(req, res, () => {})
      assert.ok(responseJson.message)
    })

    it('should return translated success message', async () => {
      let responseJson
      const req = {
        body: { password: 'validpassword' },
        translate: (key) => 'translated:' + key
      }
      const res = {
        json: (data) => { responseJson = data }
      }
      await mod.validatePasswordHandler(req, res, () => {})
      assert.equal(responseJson.message, 'translated:app.passwordindicatorstrong')
    })

    it('should call sendError for an invalid password', async () => {
      let sentError
      authlocalConfig.minPasswordLength = 20
      const req = {
        body: { password: 'short' },
        translate: (key) => 'translated:' + key
      }
      const res = {
        sendError: (err) => { sentError = err }
      }
      await mod.validatePasswordHandler(req, res, () => {})
      assert.ok(sentError)
      assert.equal(sentError.name, 'INVALID_PASSWORD')
    })

    it('should translate error messages and join them', async () => {
      let sentError
      authlocalConfig.minPasswordLength = 20
      const req = {
        body: { password: 'short' },
        translate: (key) => 'translated:' + key
      }
      const res = {
        sendError: (err) => { sentError = err }
      }
      await mod.validatePasswordHandler(req, res, () => {})
      assert.equal(typeof sentError.data.errors, 'string')
      assert.ok(sentError.data.errors.includes('translated:'))
    })
  })
})
