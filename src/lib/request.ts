import { TAG, encodeOid, encodeUnsigned, tlv } from './der.ts';
import { SHA256_OID } from './oids.ts';
import { fail, ok, type Result } from './result.ts';

const NONCE_BYTES = { min: 1, max: 16 } as const;

/**
 * Builds an RFC 3161 `TimeStampReq` for a SHA-256 hash: version 1, the message imprint, the given
 * nonce and `certReq = TRUE` (the answer carries the signing certificate chain). The nonce comes
 * from the caller (random bytes), so this function is pure.
 */
export function buildTimestampRequest(sha256: Uint8Array, nonce: Uint8Array): Result<Uint8Array> {
  if (!(sha256 instanceof Uint8Array) || sha256.length !== 32) return fail('bad-hash');
  if (
    !(nonce instanceof Uint8Array) ||
    nonce.length < NONCE_BYTES.min ||
    nonce.length > NONCE_BYTES.max
  ) {
    return fail('bad-nonce');
  }
  const algorithm = tlv(TAG.sequence, encodeOid(SHA256_OID), tlv(TAG.null));
  const imprint = tlv(TAG.sequence, algorithm, tlv(TAG.octetString, sha256));
  return ok(
    tlv(
      TAG.sequence,
      encodeUnsigned(Uint8Array.of(1)),
      imprint,
      encodeUnsigned(nonce),
      tlv(TAG.boolean, Uint8Array.of(0xff)),
    ),
  );
}
