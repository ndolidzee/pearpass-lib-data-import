import {
  parseBitwardenAuthenticatorJson,
  parseBitwardenAuthenticatorCsv,
  normalizeBitwardenAuthenticator
} from './normalize'

// URI with empty label — the format Bitwarden Authenticator actually exports
const TOTP_EMPTY_LABEL =
  'otpauth://totp/?secret=JBSWY3DPEHPK3PXP&issuer=Test&algorithm=SHA1&digits=6&period=30'

// URI with an explicit label already present
const TOTP_WITH_LABEL =
  'otpauth://totp/user%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=30'

const CSV_HEADER =
  'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp'

describe('parseBitwardenAuthenticatorJson', () => {
  it('extracts OTPRecord and uses item name as label when URI label is empty', () => {
    const json = {
      encrypted: false,
      items: [{ name: 'Test', type: 1, login: { totp: TOTP_EMPTY_LABEL } }]
    }
    const records = parseBitwardenAuthenticatorJson(json)
    expect(records).toHaveLength(1)
    expect(records[0]).toMatchObject({
      type: 'TOTP',
      label: 'Test',
      issuer: 'Test',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30
    })
  })

  it('preserves existing label in URI over item name', () => {
    const json = {
      encrypted: false,
      items: [{ name: 'Item Name', type: 1, login: { totp: TOTP_WITH_LABEL } }]
    }
    const records = parseBitwardenAuthenticatorJson(json)
    expect(records[0].label).toBe('user@example.com')
    expect(records[0].issuer).toBe('GitHub')
  })

  it('skips items without a totp field', () => {
    const json = {
      encrypted: false,
      items: [
        { name: 'NoOTP', type: 1, login: { totp: null } },
        { name: 'AlsoNone', type: 1 }
      ]
    }
    expect(parseBitwardenAuthenticatorJson(json)).toHaveLength(0)
  })

  it('skips items with non-otpauth totp values', () => {
    const json = {
      encrypted: false,
      items: [{ name: 'Bad', type: 1, login: { totp: 'JBSWY3DPEHPK3PXP' } }]
    }
    expect(parseBitwardenAuthenticatorJson(json)).toHaveLength(0)
  })

  it('handles multiple items', () => {
    const json = {
      encrypted: false,
      items: [
        { name: 'A', type: 1, login: { totp: TOTP_EMPTY_LABEL } },
        { name: 'B', type: 1, login: { totp: TOTP_EMPTY_LABEL } }
      ]
    }
    expect(parseBitwardenAuthenticatorJson(json)).toHaveLength(2)
  })

  it('throws for encrypted exports', () => {
    expect(() =>
      parseBitwardenAuthenticatorJson({ encrypted: true, items: [] })
    ).toThrow('Encrypted')
  })
})

describe('parseBitwardenAuthenticatorCsv', () => {
  it('extracts OTPRecord from login_totp column and injects name as label', () => {
    const csv = [CSV_HEADER, `,,login,Test,,,0,,,,${TOTP_EMPTY_LABEL}`].join(
      '\n'
    )
    const records = parseBitwardenAuthenticatorCsv(csv)
    expect(records).toHaveLength(1)
    expect(records[0]).toMatchObject({
      type: 'TOTP',
      label: 'Test',
      issuer: 'Test',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30
    })
  })

  it('returns empty array when login_totp column is absent', () => {
    const csv = ['folder,name', ',Site'].join('\n')
    expect(parseBitwardenAuthenticatorCsv(csv)).toHaveLength(0)
  })

  it('skips rows with empty login_totp', () => {
    const csv = [CSV_HEADER, ',,login,Empty,,,0,,,,'].join('\n')
    expect(parseBitwardenAuthenticatorCsv(csv)).toHaveLength(0)
  })

  it('handles multiple data rows', () => {
    const csv = [
      CSV_HEADER,
      `,,login,A,,,0,,,,${TOTP_EMPTY_LABEL}`,
      `,,login,B,,,0,,,,${TOTP_EMPTY_LABEL}`
    ].join('\n')
    expect(parseBitwardenAuthenticatorCsv(csv)).toHaveLength(2)
  })
})

describe('normalizeBitwardenAuthenticator', () => {
  it('dispatches to JSON parser', () => {
    const json = JSON.stringify({
      encrypted: false,
      items: [{ name: 'Test', type: 1, login: { totp: TOTP_EMPTY_LABEL } }]
    })
    expect(normalizeBitwardenAuthenticator(json, 'json')).toHaveLength(1)
  })

  it('dispatches to CSV parser', () => {
    const csv = [CSV_HEADER, `,,login,Test,,,0,,,,${TOTP_EMPTY_LABEL}`].join(
      '\n'
    )
    expect(normalizeBitwardenAuthenticator(csv, 'csv')).toHaveLength(1)
  })

  it('throws on unsupported file type', () => {
    expect(() => normalizeBitwardenAuthenticator('', 'xml')).toThrow(
      'Unsupported file type'
    )
  })
})
