/**
 * Whether a mailer failure stems from being unable to reach the SMTP server
 * (vs. a rejected/invalid message). MailerModule wraps the underlying transport
 * error in err.data.error, so inspect that as well as the error itself.
 * @param {Error} err Error thrown by the mailer
 * @returns {Boolean}
 * @memberof localauth
 */
const CONNECTION_CODES = ['ECONNREFUSED', 'ECONNRESET', 'ECONNECTION', 'ETIMEDOUT', 'ESOCKET', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'EDNS']

export function isSmtpConnectionError (err) {
  const cause = err?.data?.error ?? err
  if (!cause) return false
  if (CONNECTION_CODES.includes(cause.code)) return true
  return typeof cause.message === 'string' && CONNECTION_CODES.some(code => cause.message.includes(code))
}
