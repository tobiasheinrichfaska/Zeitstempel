import { createPublicKey, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fail, fromBase64Url, ok, toHex, type Result } from '../src/index.ts';

/**
 * A key the relay accepts: its id and the public ECDSA P-256 key as the uncompressed point
 * (65 bytes: `04 || X || Y`). The file holds no secret; what counts is who may write it (whoever can,
 * can enter a key of their own).
 */
export interface RelayKey {
  id: string;
  publicKey: Uint8Array;
}

const KEY_ID = /^[a-z][a-z0-9-]{0,31}$/;
export const MAX_KEYS = 64;
// DER prefix of a SubjectPublicKeyInfo for id-ecPublicKey / prime256v1 followed by the 65-byte point
const SPKI_P256 = Uint8Array.from(
  Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
);

/** The public key object for a point, or null when the point is not a valid point of the curve P-256. */
export function publicKeyObject(point: Uint8Array): KeyObject | null {
  if (!(point instanceof Uint8Array) || point.length !== 65 || point[0] !== 0x04) return null;
  try {
    const der = new Uint8Array(SPKI_P256.length + 65);
    der.set(SPKI_P256);
    der.set(point, SPKI_P256.length);
    return createPublicKey({ key: Buffer.from(der), format: 'der', type: 'spki' });
  } catch {
    return null; // OpenSSL checks that the point lies on the curve
  }
}

/**
 * Strict reader of the key file: `{"version": 2, "keys": [{"id", "publicKey"}]}` with 1 to 64 keys,
 * ids of the form `[a-z][a-z0-9-]{0,31}`, public keys as unpadded base64url of an uncompressed point
 * (65 bytes) that lies on the curve P-256, no duplicate id, no duplicate key, no other fields. The
 * failure carries a rule name and, for an entry, its index in `keys`, never content.
 */
export function readKeyFile(data: unknown): Result<RelayKey[]> {
  // `index`: the position of the entry in `keys` (never its content)
  const bad = (rule: string, index?: number) =>
    fail('bad-key-file', index === undefined ? rule : `${rule} in keys[${index}]`);
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return bad('not-an-object');
  const top = data as Record<string, unknown>;
  if (Object.keys(top).sort().join() !== 'keys,version') return bad('fields');
  if (top.version !== 2) return bad('version');
  if (!Array.isArray(top.keys) || top.keys.length < 1 || top.keys.length > MAX_KEYS) {
    return bad('key-count');
  }
  const keys: RelayKey[] = [];
  const ids = new Set<string>();
  const points = new Set<string>();
  for (const [index, entry] of (top.keys as unknown[]).entries()) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry))
      return bad('entry', index);
    const e = entry as Record<string, unknown>;
    if (Object.keys(e).sort().join() !== 'id,publicKey') return bad('entry-fields', index);
    if (typeof e.id !== 'string' || !KEY_ID.test(e.id)) return bad('id', index);
    if (typeof e.publicKey !== 'string') return bad('public-key', index);
    const point = fromBase64Url(e.publicKey);
    if (!point || point.length !== 65) return bad('public-key', index);
    if (publicKeyObject(point) === null) return bad('public-key-point', index);
    const hex = toHex(point);
    if (ids.has(e.id)) return bad('duplicate-id', index);
    if (points.has(hex)) return bad('duplicate-key', index);
    ids.add(e.id);
    points.add(hex);
    keys.push({ id: e.id, publicKey: point });
  }
  return ok(keys);
}

/**
 * Reads and checks the key file. Throws with a message a person can read: the path and a rule name,
 * never a piece of the file.
 */
export function loadKeys(
  path: string,
  read: (path: string) => string = (p) => readFileSync(p, 'utf8'),
): RelayKey[] {
  let data: unknown;
  try {
    data = JSON.parse(read(path));
  } catch {
    throw new Error(`${path}: Schlüsseldatei nicht lesbar oder kein JSON`);
  }
  const keys = readKeyFile(data);
  if (!keys.ok)
    throw new Error(`${path}: ungültige Schlüsseldatei (${keys.reason}: ${keys.detail})`);
  return keys.value;
}
