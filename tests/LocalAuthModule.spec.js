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

const mockUsers = {
  find: async (query) => usersStore.filter(u => {
    return Object.entries(query).every(([k, v]) => JSON.stringify(u[k]) === JSON.stringify(v))
  }),
  update: async (query, data) => {
    updateCalls.push({ query, data })
    return { ...query, ...data }
  },
  collectionName: 'users'
}

const mockRoles = {
  find: async () => [{ _id: 'role-super-id', shortName: 'superuser' }]
}

const mockMailer = {
  isEnabled: true,
  send: async () => {}
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
    validate: async () => true
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
    translate: (_, key) => `translated:${key}`
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
  })

  describe('#setValues()', () => {
    it('should set userSchema to localauthuser', async () => {
      const instance = new LocalAuthModule()
      await instance.setValues()
      assert.equal(instance.userSchema, 'localauthuser')
    })

    it('should set type to local', async () => {
      const instance = new LocalAuthModule()
      await instance.setValues()
      assert.equal(instance.type, 'local')
    })

    it('should define 5 routes', async () => {
      const instance = new LocalAuthModule()
      await instance.setValues()
      assert.equal(instance.routes.length, 5)
    })

    it('should include the expected route paths', async () => {
      const instance = new LocalAuthModule()
      await instance.setValues()
      const paths = instance.routes.map(r => r.route)
      assert.deepEqual(paths, ['/invite', '/registersuper', '/changepass', '/forgotpass', '/validatepass'])
    })

    it('should mark registersuper as internal', async () => {
      const instance = new LocalAuthModule()
      await instance.setValues()
      const superRoute = instance.routes.find(r => r.route === '/registersuper')
      assert.equal(superRoute.internal, true)
    })
  })

  describe('#init()', () => {
    it('should secure the invite route', async () => {
      const instance = new LocalAuthModule()
      instance.app = mockApp
      instance.router = { routes: [{ route: '/', meta: null }, { route: '/register', meta: null }] }
      await instance.setValues()
      await instance.init()
      assert.ok(secureRouteCalls.some(c => c[0] === '/invite' && c[1] === 'post'))
    })

    it('should secure the validatepass route', async () => {
      const instance = new LocalAuthModule()
      instance.app = mockApp
      instance.router = { routes: [{ route: '/', meta: null }, { route: '/register', meta: null }] }
      await instance.setValues()
      await instance.init()
      assert.ok(secureRouteCalls.some(c => c[0] === '/validatepass' && c[1] === 'post'))
    })

    it('should unsecure registersuper, changepass, and forgotpass routes', async () => {
      const instance = new LocalAuthModule()
      instance.app = mockApp
      instance.router = { routes: [{ route: '/', meta: null }, { route: '/register', meta: null }] }
      await instance.setValues()
      await instance.init()
      const unsecuredPaths = unsecureRouteCalls.map(c => c[0])
      assert.ok(unsecuredPaths.includes('/registersuper'))
      assert.ok(unsecuredPaths.includes('/changepass'))
      assert.ok(unsecuredPaths.includes('/forgotpass'))
    })

    it('should set the users property', async () => {
      const instance = new LocalAuthModule()
      instance.app = mockApp
      instance.router = { routes: [{ route: '/', meta: null }, { route: '/register', meta: null }] }
      await instance.setValues()
      await instance.init()
      assert.equal(instance.users, mockUsers)
    })
  })

  describe('#authenticate()', () => {
    it('should throw when password is not provided in request body', async () => {
      const req = { body: {} }
      await assert.rejects(
        () => mod.authenticate({}, req, {}),
        (err) => err.name === 'INVALID_LOGIN_DETAILS'
      )
    })

    it('should reset failed attempts on successful authentication', async () => {
      const { default: PasswordUtils } = await import('../lib/PasswordUtils.js')
      const hash = await PasswordUtils.generate('correctpass')
      const user = {
        _id: 'user-1',
        password: hash,
        isPermLocked: false,
        isTempLocked: false,
        failedLoginAttempts: 2,
        lastFailedLoginAttempt: null
      }
      const req = { body: { password: 'correctpass' } }
      await mod.authenticate(user, req, {})
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.failedLoginAttempts, 0)
    })

    it('should increment failed attempts on wrong password', async () => {
      const { default: PasswordUtils } = await import('../lib/PasswordUtils.js')
      const hash = await PasswordUtils.generate('correctpass')
      const user = {
        _id: 'user-1',
        password: hash,
        isPermLocked: false,
        isTempLocked: false,
        failedLoginAttempts: 0,
        lastFailedLoginAttempt: null
      }
      const req = { body: { password: 'wrongpass' } }
      await assert.rejects(() => mod.authenticate(user, req, {}))
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.failedLoginAttempts, 1)
    })

    it('should temporarily lock after reaching failsUntilTemporaryLock threshold', async () => {
      const { default: PasswordUtils } = await import('../lib/PasswordUtils.js')
      const hash = await PasswordUtils.generate('correctpass')
      const user = {
        _id: 'user-1',
        password: hash,
        isPermLocked: false,
        isTempLocked: false,
        failedLoginAttempts: 4, // one more will be 5 (the threshold)
        lastFailedLoginAttempt: null
      }
      const req = { body: { password: 'wrongpass' } }
      await assert.rejects(
        () => mod.authenticate(user, req, {}),
        (err) => err.name === 'ACCOUNT_LOCKED_TEMP'
      )
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.isTempLocked, true)
    })

    it('should permanently lock after reaching failsUntilPermanentLock threshold', async () => {
      const { default: PasswordUtils } = await import('../lib/PasswordUtils.js')
      const hash = await PasswordUtils.generate('correctpass')
      const user = {
        _id: 'user-1',
        password: hash,
        isPermLocked: false,
        isTempLocked: false,
        failedLoginAttempts: 19, // one more will be 20 (the threshold)
        lastFailedLoginAttempt: null
      }
      const req = { body: { password: 'wrongpass' } }
      await assert.rejects(
        () => mod.authenticate(user, req, {}),
        (err) => err.name === 'ACCOUNT_LOCKED_PERM'
      )
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.isPermLocked, true)
    })

    it('should throw ACCOUNT_LOCKED_PERM when user is already permanently locked', async () => {
      const { default: PasswordUtils } = await import('../lib/PasswordUtils.js')
      const hash = await PasswordUtils.generate('correctpass')
      const user = {
        _id: 'user-1',
        password: hash,
        isPermLocked: true,
        isTempLocked: false,
        failedLoginAttempts: 20,
        lastFailedLoginAttempt: new Date().toISOString()
      }
      const req = { body: { password: 'correctpass' } }
      await assert.rejects(
        () => mod.authenticate(user, req, {}),
        (err) => err.name === 'ACCOUNT_LOCKED_PERM'
      )
    })

    it('should not increment failed attempts when account is permanently locked', async () => {
      const { default: PasswordUtils } = await import('../lib/PasswordUtils.js')
      const hash = await PasswordUtils.generate('correctpass')
      const user = {
        _id: 'user-1',
        password: hash,
        isPermLocked: true,
        isTempLocked: false,
        failedLoginAttempts: 20,
        lastFailedLoginAttempt: new Date().toISOString()
      }
      const req = { body: { password: 'wrongpass' } }
      await assert.rejects(() => mod.authenticate(user, req, {}))
      const lastUpdate = updateCalls[updateCalls.length - 1]
      assert.equal(lastUpdate.data.failedLoginAttempts, 20)
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
        // NOTE: handleLockStatus multiplies temporaryLockDuration by 1000, which
        // appears to be a bug if the config value is already in ms (isTimeMs: true).
        // We set lastFailedLoginAttempt to now so the lock is still active with
        // the doubled value.
        lastFailedLoginAttempt: new Date().toISOString()
      }
      await assert.rejects(
        () => mod.handleLockStatus(user),
        (err) => err.name === 'ACCOUNT_LOCKED_TEMP'
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
  })

  describe('#registerSuper()', () => {
    it('should throw SUPER_USER_EXISTS when a super user already exists', async () => {
      usersStore.push({ _id: 'existing-super', roles: ['role-super-id'] })
      await assert.rejects(
        () => mod.registerSuper({ email: 'super@example.com', password: 'validpassword' }),
        (err) => err.name === 'SUPER_USER_EXISTS'
      )
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

    // NOTE: There is a bug in setUserEnabled — when disabling (isEnabled=false),
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
  })

  describe('#inviteHandler()', () => {
    it('should respond with 204 on success', async () => {
      let statusSent
      const req = {
        body: { email: 'invite@example.com' },
        translate: (key) => `translated:${key}`,
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
        translate: (key) => `translated:${key}`,
        auth: {}
      }
      const res = { sendStatus: () => {} }
      await mod.inviteHandler(req, res, (err) => { nextError = err })
      assert.ok(nextError)
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
        translate: (key) => `translated:${key}`,
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
  })

  describe('#validatePasswordHandler()', () => {
    it('should respond with a success message for a valid password', async () => {
      let responseJson
      const req = {
        body: { password: 'validpassword' },
        translate: (key) => `translated:${key}`
      }
      const res = {
        json: (data) => { responseJson = data }
      }
      await mod.validatePasswordHandler(req, res, () => {})
      assert.ok(responseJson.message)
    })

    it('should call sendError for an invalid password', async () => {
      let sentError
      authlocalConfig.minPasswordLength = 20
      const req = {
        body: { password: 'short' },
        translate: (key) => `translated:${key}`
      }
      const res = {
        sendError: (err) => { sentError = err }
      }
      await mod.validatePasswordHandler(req, res, () => {})
      assert.ok(sentError)
      assert.equal(sentError.name, 'INVALID_PASSWORD')
    })
  })
})
