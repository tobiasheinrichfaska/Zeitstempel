import { copyBytes } from './bytes.ts';
import { TAG, encodeOid, encodeUnsigned, tlv } from './der.ts';
import { SHA256_OID } from './oids.ts';
import { fail, ok, type Result } from './result.ts';

const NONCE_BYTES = { min: 1, max: 16 } as const;

/**
 * Builds an RFC 3161 `TimeStampReq` for a SHA-256 hash: version 1, the message imprint, the given
 * nonce and `certReq = TRUE` (the answer carries the signing certificate chain). The nonce comes
 * from the caller (random bytes), so this function is pure. It never throws, whatever it is given.
 */
export function buildTimestampRequest(sha256: Uint8Array, nonce: Uint8Array): Result<Uint8Array> {
  // each input is copied once (a hostile proxy gives a code, never a throw)
  const hash = copyBytes(sha256, 32, 32);
  if (!hash) return fail('bad-hash');
  const n = copyBytes(nonce, NONCE_BYTES.min, NONCE_BYTES.max);
  if (!n) return fail('bad-nonce');
  const algorithm = tlv(TAG.sequence, encodeOid(SHA256_OID), tlv(TAG.null));
  const imprint = tlv(TAG.sequence, algorithm, tlv(TAG.octetString, hash));
  return ok(
    tlv(
      TAG.sequence,
      encodeUnsigned(Uint8Array.of(1)),
      imprint,
      encodeUnsigned(n),
      tlv(TAG.boolean, Uint8Array.of(0xff)),
    ),
  );
}
