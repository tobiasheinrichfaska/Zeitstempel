/** Object identifiers and algorithm tables, as data. */

export const OID = {
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingCertificate: '1.2.840.113549.1.9.16.2.12',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
  ekuTimeStamping: '1.3.6.1.5.5.7.3.8',
  anyExtendedKeyUsage: '2.5.29.37.0',
  extBasicConstraints: '2.5.29.19',
  extKeyUsage: '2.5.29.15',
  extEku: '2.5.29.37',
  ecPublicKey: '1.2.840.10045.2.1',
  rsaEncryption: '1.2.840.113549.1.1.1',
} as const;

/**
 * Certificate extensions the reader knows and that are harmless when marked critical: it either
 * evaluates them (basic constraints, key usage, extended key usage) or they carry no restriction on
 * how the certificate may be used (identifiers, names, policies, access and CRL locations).
 * A critical extension that is not listed makes the certificate unusable (RFC 5280 § 4.2).
 */
export const KNOWN_EXTENSIONS: ReadonlySet<string> = new Set([
  '2.5.29.14', // subjectKeyIdentifier
  '2.5.29.15', // keyUsage
  '2.5.29.17', // subjectAltName
  '2.5.29.19', // basicConstraints
  '2.5.29.31', // cRLDistributionPoints
  '2.5.29.32', // certificatePolicies
  '2.5.29.35', // authorityKeyIdentifier
  '2.5.29.37', // extKeyUsage
  '1.3.6.1.5.5.7.1.1', // authorityInfoAccess
]);

export type HashName = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

/** Hash algorithms by OID; `bytes` is the digest length. */
export const HASHES: Readonly<Record<string, { name: HashName; bytes: number }>> = {
  '1.3.14.3.2.26': { name: 'SHA-1', bytes: 20 },
  '2.16.840.1.101.3.4.2.1': { name: 'SHA-256', bytes: 32 },
  '2.16.840.1.101.3.4.2.2': { name: 'SHA-384', bytes: 48 },
  '2.16.840.1.101.3.4.2.3': { name: 'SHA-512', bytes: 64 },
};

export const SHA256_OID = '2.16.840.1.101.3.4.2.1';

/**
 * Signature algorithms. `hash` is set when the OID names it (sha256WithRSA …); for the bare
 * rsaEncryption / id-ecPublicKey styles the hash comes from the signer's digest algorithm.
 * RSA-PSS is not supported (refused with `unsupported-signature`).
 */
export const SIGNATURES: Readonly<
  Record<string, { kind: 'rsa' | 'ecdsa'; hash: HashName | null }>
> = {
  '1.2.840.113549.1.1.1': { kind: 'rsa', hash: null },
  '1.2.840.113549.1.1.5': { kind: 'rsa', hash: 'SHA-1' },
  '1.2.840.113549.1.1.11': { kind: 'rsa', hash: 'SHA-256' },
  '1.2.840.113549.1.1.12': { kind: 'rsa', hash: 'SHA-384' },
  '1.2.840.113549.1.1.13': { kind: 'rsa', hash: 'SHA-512' },
  '1.2.840.10045.2.1': { kind: 'ecdsa', hash: null },
  '1.2.840.10045.4.1': { kind: 'ecdsa', hash: 'SHA-1' },
  '1.2.840.10045.4.3.2': { kind: 'ecdsa', hash: 'SHA-256' },
  '1.2.840.10045.4.3.3': { kind: 'ecdsa', hash: 'SHA-384' },
  '1.2.840.10045.4.3.4': { kind: 'ecdsa', hash: 'SHA-512' },
};

/** Named curves WebCrypto can verify, with the coordinate size in bytes. */
export const CURVES: Readonly<Record<string, { name: 'P-256' | 'P-384' | 'P-521'; size: number }>> =
  {
    '1.2.840.10045.3.1.7': { name: 'P-256', size: 32 },
    '1.3.132.0.34': { name: 'P-384', size: 48 },
    '1.3.132.0.35': { name: 'P-521', size: 66 },
  };
