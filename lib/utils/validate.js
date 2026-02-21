import { App } from 'adapt-authoring-core'

/**
 * Validates a password against the stored config settings
 * @param {String} password Password to validate
 * @returns {Promise} Resolves if the password passes the validation
 * @memberof localauth
 */
export async function validate (password) {
  const authlocal = await App.instance.waitForModule('auth-local')
  if (typeof password !== 'string') {
    throw App.instance.errors.INVALID_PARAMS.setData({ params: ['password'] })
  }
  const blacklisted = authlocal.getConfig('blacklistedPasswordValues')
  const match = (key, re) => !authlocal.getConfig(key) || password.search(re) > -1
  const validationChecks = {
    INVALID_PASSWORD_LENGTH: [password.length >= authlocal.getConfig('minPasswordLength'), { length: authlocal.getConfig('minPasswordLength') }],
    INVALID_PASSWORD_NUMBER: [match('passwordMustHaveNumber', /[0-9]/)],
    INVALID_PASSWORD_UPPERCASE: [match('passwordMustHaveUppercase', /[A-Z]/)],
    INVALID_PASSWORD_LOWERCASE: [match('passwordMustHaveLowercase', /[a-z]/)],
    INVALID_PASSWORD_SPECIAL: [match('passwordMustHaveSpecial', /[#?!@$%^&*-]/)],
    BLACKLISTED_PASSWORD_VALUE: [blacklisted.length === 0 || blacklisted.every(p => !(password.includes(p)))]
  }
  const errors = Object.entries(validationChecks).reduce((m, [code, [isValid, data]]) => {
    if (!isValid) m.push(App.instance.errors[code].setData(data))
    return m
  }, [])
  if (errors.length) throw App.instance.errors.INVALID_PASSWORD.setData({ errors })
}
