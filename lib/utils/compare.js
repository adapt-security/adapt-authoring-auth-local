import { App } from 'adapt-authoring-core'
import bcrypt from 'bcryptjs'
import { promisify } from 'util'

/**
 * Compares a plain password to a hash
 * @param {String} plainPassword
 * @param {String} hash
 * @return {Promise}
 * @memberof localauth
 */
export async function compare (plainPassword, hash) {
  const error = App.instance.errors.INVALID_LOGIN_DETAILS
  if (!plainPassword || !hash) {
    throw error.setData({
      error: App.instance.errors.INVALID_PARAMS.setData({ params: ['plainPassword', 'hash'] })
    })
  }
  try {
    const isValid = await promisify(bcrypt.compare)(plainPassword, hash)
    if (!isValid) throw new Error()
  } catch (e) {
    throw error.setData({ error: App.instance.errors.INCORRECT_PASSWORD })
  }
}
