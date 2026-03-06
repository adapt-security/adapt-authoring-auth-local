import { App } from 'adapt-authoring-core'
import bcrypt from 'bcryptjs'
import { compare, getRandomHex, validate } from './utils.js'
import { promisify } from 'node:util'

/** @ignore */ const passwordResetsCollectionName = 'passwordresets'
/**
 * Various utilities related to password functionality
 * @memberof localauth
 */
class PasswordUtils {
  /**
   * Retrieves a localauth config item
   * @return {Promise}
   */
  static async getConfig (...keys) {
    const authlocal = await App.instance.waitForModule('auth-local')

    if (keys.length === 1) {
      return authlocal.getConfig(keys[0])
    }
    return keys.reduce((m, k) => {
      m[k] = authlocal.getConfig(k)
      return m
    }, {})
  }

  /**
   * Compares a plain password to a hash
   * @param {String} plainPassword
   * @param {String} hash
   * @return {Promise}
   * @deprecated Use compare() from 'adapt-authoring-auth-local' instead
   */
  static async compare (plainPassword, hash) { return compare(plainPassword, hash) }

  /**
   * Validates a password against the stored config settings
   * @param {String} password Password to validate
   * @returns {Promise} Resolves if the password passes the validation
   * @deprecated Use validate() from 'adapt-authoring-auth-local' instead
   */
  static async validate (password) { return validate(password) }

  /**
   * Generates a secure hash from a plain-text password
   * @param {String} plainPassword
   * @return {Promise} Resolves with the hash
   */
  static async generate (plainPassword) {
    if (!plainPassword) {
      throw App.instance.errors.INVALID_PARAMS.setData({ params: ['plainPassword'] })
    }
    const jsonschema = await App.instance.waitForModule('jsonschema')
    const schema = await jsonschema.getSchema('localpassword')
    await schema.validate({ password: plainPassword })

    const saltRounds = await PasswordUtils.getConfig('saltRounds')
    const salt = await promisify(bcrypt.genSalt)(saltRounds)

    return promisify(bcrypt.hash)(plainPassword, salt)
  }

  /**
   * Creates a password reset token
   * @param {String} email The user's email address
   * @param {Number} lifespan The intended token lifespan in milliseconds
   * @return {Promise} Resolves with the token value
   */
  static async createReset (email, lifespan) {
    const [mongodb, users] = await App.instance.waitForModule('mongodb', 'users')
    const user = await users.findOne({ email })
    if (user.authType !== 'local') {
      const authlocal = await App.instance.waitForModule('auth-local')
      authlocal.log('error', `Failed to reset ${user._id} password, not authenticated with local auth`)
      throw App.instance.errors.ACCOUNT_NOT_LOCALAUTHD
    }
    // invalidate any previous tokens for this user
    await mongodb.getCollection(passwordResetsCollectionName).deleteMany({ email })

    if (!lifespan) {
      lifespan = await this.getConfig('resetTokenLifespan')
    }
    const { token } = await mongodb.insert(passwordResetsCollectionName, {
      email,
      expiresAt: new Date(Date.now() + lifespan).toISOString(),
      token: await getRandomHex()
    })
    return token
  }

  /**
   * Deletes a stored password reset token
   * @param {String} token The token value
   * @return {Promise}
   */
  static async deleteReset (token) {
    const mongodb = await App.instance.waitForModule('mongodb')
    return mongodb.delete(passwordResetsCollectionName, { token })
  }

  /**
   * Creates a random hex string
   * @param {Number} size Size of string
   * @return {Promise} Resolves with the string value
   * @deprecated Use getRandomHex() from 'adapt-authoring-auth-local' instead
   */
  static async getRandomHex (size = 32) { return getRandomHex(size) }

  /**
   * Validates a password reset token
   * @param {String} token The password reset token
   * @return {Promise} Rejects on invalid token
   */
  static async validateReset (token) {
    if (!token) {
      throw App.instance.errors.INVALID_PARAMS.setData({ params: ['token'] })
    }
    const [mongodb, users] = await App.instance.waitForModule('mongodb', 'users')
    const [tokenData] = await mongodb.find(passwordResetsCollectionName, { token })
    if (!tokenData) {
      throw App.instance.errors.AUTH_TOKEN_INVALID
    }
    if (new Date(tokenData.expiresAt) < new Date()) {
      throw App.instance.errors.AUTH_TOKEN_EXPIRED
    }
    await users.findOne({ email: tokenData.email })
    return tokenData
  }
}

export default PasswordUtils
