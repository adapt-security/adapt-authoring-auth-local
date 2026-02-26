import crypto from 'node:crypto'
import { promisify } from 'node:util'

/**
 * Creates a random hex string
 * @param {Number} size Size of string
 * @return {Promise<String>} Resolves with the string value
 * @memberof localauth
 */
export async function getRandomHex (size = 32) {
  const buffer = await promisify(crypto.randomBytes)(size)
  return buffer.toString('hex')
}
