import { getRowsFromCsv } from '../../../utils/getRowsFromCsv.js'
import { parseOtpUri } from '../../shared/parseOtpUri.js'

/** @typedef {import('../../interfaces/OTPRecord.js').OTPRecord} OTPRecord */

// Bitwarden Authenticator exports URIs with an empty label segment, e.g.
// otpauth://totp/?secret=… — parseOtpUri requires a non-empty label, so we
// inject the item name when the URI carries none.
const withLabel = (uri, name) => {
  try {
    const url = new URL(uri)
    if (!decodeURIComponent(url.pathname.slice(1)) && name) {
      return `otpauth://${url.host}/${encodeURIComponent(name)}${url.search}`
    }
  } catch {
    // fall through and let parseOtpUri produce the error
  }
  return uri
}

/**
 * Extracts OTPRecord[] from a parsed Bitwarden Authenticator JSON export.
 * Reads item.login.totp from each item.
 * @param {object} json
 * @returns {OTPRecord[]}
 */
export function parseBitwardenAuthenticatorJson(json) {
  if (json.encrypted) {
    throw new Error(
      'Encrypted Bitwarden Authenticator exports are not supported — export without encryption and try again'
    )
  }

  const records = []
  for (const item of json.items ?? []) {
    const totp = item?.login?.totp
    if (!totp?.startsWith('otpauth://')) continue
    try {
      records.push(parseOtpUri(withLabel(totp, item.name)))
    } catch {
      // skip malformed URIs silently
    }
  }
  return records
}

/**
 * Extracts OTPRecord[] from a Bitwarden Authenticator CSV export.
 * Reads the login_totp column which contains full otpauth:// URIs.
 * @param {string} csvText
 * @returns {OTPRecord[]}
 */
export function parseBitwardenAuthenticatorCsv(csvText) {
  const records = []
  const [headers, ...rows] = getRowsFromCsv(csvText)
  const totpIdx = headers.indexOf('login_totp')
  const nameIdx = headers.indexOf('name')
  if (totpIdx === -1) return records

  for (const row of rows) {
    const totp = row[totpIdx]
    if (!totp?.startsWith('otpauth://')) continue
    const name = nameIdx !== -1 ? row[nameIdx] : ''
    try {
      records.push(parseOtpUri(withLabel(totp, name)))
    } catch {
      // skip malformed URIs silently
    }
  }
  return records
}

/**
 * Main entry point for Bitwarden Authenticator OTP import.
 * @param {string} data
 * @param {'json'|'csv'} fileType
 * @returns {OTPRecord[]}
 */
export function normalizeBitwardenAuthenticator(data, fileType) {
  if (fileType === 'json') {
    return parseBitwardenAuthenticatorJson(JSON.parse(data))
  }
  if (fileType === 'csv') {
    return parseBitwardenAuthenticatorCsv(data)
  }
  throw new Error('Unsupported file type, please use JSON or CSV')
}
