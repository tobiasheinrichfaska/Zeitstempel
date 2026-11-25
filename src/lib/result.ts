/** Errors are codes, never sentences: the app owns the words. */
export type Reason =
  // input
  | 'bad-hash'
  | 'bad-nonce'
  | 'bad-options'
  | 'bad-services'
  | 'bad-key'
  | 'bad-key-id'
  | 'bad-key-file'
  | 'bad-batch'
  // DER / structure
  | 'too-large'
  | 'malformed'
  | 'indefinite-length'
  | 'too-deep'
  | 'trailing-bytes'
  | 'bad-structure'
  // response status
  | 'rejected'
  | 'no-token'
  // token content
  | 'not-signed-data'
  | 'unsupported-version'
  | 'bad-content-type'
  | 'bad-tst-info'
  | 'unsupported-hash'
  | 'bad-time'
  | 'time-in-future'
  | 'time-too-old'
  | 'imprint-mismatch'
  | 'nonce-mismatch'
  | 'one-signer-required'
  | 'unsupported-signature'
  | 'signed-attributes-missing'
  | 'message-digest-mismatch'
  | 'signing-certificate-missing'
  | 'signing-certificate-mismatch'
  | 'signature-invalid'
  | 'tsa-mismatch'
  | 'policy-mismatch'
  // certificates
  | 'bad-pem'
  | 'bad-certificate'
  | 'weak-key'
  | 'signer-certificate-missing'
  | 'certificate-not-valid-at-time'
  | 'bad-eku'
  | 'not-a-ca'
  | 'untrusted-chain'
  | 'chain-too-long'
  // relay client
  | 'relay-unreachable'
  | 'relay-timeout'
  | 'relay-refused'
  | 'relay-bad-response'
  | 'relay-rate-limited'
  | 'no-trusted-service';

export interface Failure {
  ok: false;
  reason: Reason;
  /** Extra facts that help a person (e.g. the status code of a refused request). */
  detail?: string;
}

export type Result<T> = { ok: true; value: T } | Failure;

export const ok = <T>(value: T): Result<T> => ({ ok: true, value });
export const fail = (reason: Reason, detail?: string): Failure =>
  detail === undefined ? { ok: false, reason } : { ok: false, reason, detail };

/**
 * Thrown inside the readers and caught in the core functions (`buildTimestampRequest`,
 * `readTimestampResponse`, `verifyTimestampToken`, `readServices`, `signRelayRequest`): those never throw,
 * whatever they are given. Not caught, by design: the building blocks `readToken`, `parseCertificate` and
 * `parsePemCertificates` throw `ReaderError`, and the byte writers `toBase64`, `toBase64Url` and `toHex`
 * throw `TypeError` for anything but a `Uint8Array`.
 */
export class ReaderError extends Error {
  readonly reason: Reason;
  constructor(reason: Reason) {
    super(reason);
    this.reason = reason;
  }
}

/** Runs a reader that may throw `ReaderError` and turns it into a result. */
export function guard<T>(run: () => T): Result<T> {
  try {
    return ok(run());
  } catch (e) {
    return fail(e instanceof ReaderError ? e.reason : 'malformed');
  }
}
