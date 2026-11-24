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
  /**
   * Key type 2 (`"solo": true` in the file): may ask for a direct stamp of its own (`mode: "solo"`) in
   * collecting operation. Absent or false: type 1 (normal).
   */
  solo?: boolean;
}

/** What a key file holds: the keys and the optional restart time (Unix seconds, `restartAfter`). */
export interface KeyFile {
  keys: RelayKey[];
  restartAfter?: number;
}

/** `restartAfter`: smallest and largest accepted Unix time in seconds (2001-09-09 to 5138-11-16). */
export const RESTART_AFTER_MIN = 1_000_000_000;
export const RESTART_AFTER_MAX = 99_999_999_999;

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
 * Strict reader of the key file: `{"version": 2, "keys": [{"id", "publicKey", "solo"?}], "restartAfter"?}` with 1
 * to 64 keys, ids of the form `[a-z][a-z0-9-]{0,31}`, public keys as unpadded base64url of an uncompressed
 * point (65 bytes) that lies on the curve P-256, no duplicate id, no duplicate key, no other fields. `solo` is
 * a boolean (nothing else), `restartAfter` an integer of Unix seconds. The failure carries a rule name and,
 * for an entry, its index in `keys`, never content.
 */
export function readKeyFileFull(data: unknown): Result<KeyFile> {
  // `index`: the position of the entry in `keys` (never its content)
  const bad = (rule: string, index?: number) =>
    fail('bad-key-file', index === undefined ? rule : `${rule} in keys[${index}]`);
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return bad('not-an-object');
  const top = data as Record<string, unknown>;
  const names = Object.keys(top).sort().join();
  if (names !== 'keys,version' && names !== 'keys,restartAfter,version') return bad('fields');
  if (top.version !== 2) return bad('version');
  let restartAfter: number | undefined;
  if ('restartAfter' in top) {
    const r = top.restartAfter;
    if (
      typeof r !== 'number' ||
      !Number.isInteger(r) ||
      r < RESTART_AFTER_MIN ||
      r > RESTART_AFTER_MAX
    ) {
      return bad('restart-after');
    }
    restartAfter = r;
  }
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
    const fields = Object.keys(e).sort().join();
    if (fields !== 'id,publicKey' && fields !== 'id,publicKey,solo')
      return bad('entry-fields', index);
    if (typeof e.id !== 'string' || !KEY_ID.test(e.id)) return bad('id', index);
    if (typeof e.publicKey !== 'string') return bad('public-key', index);
    if ('solo' in e && typeof e.solo !== 'boolean') return bad('solo', index);
    const point = fromBase64Url(e.publicKey);
    if (!point || point.length !== 65) return bad('public-key', index);
    if (publicKeyObject(point) === null) return bad('public-key-point', index);
    const hex = toHex(point);
    if (ids.has(e.id)) return bad('duplicate-id', index);
    if (points.has(hex)) return bad('duplicate-key', index);
    ids.add(e.id);
    points.add(hex);
    keys.push({ id: e.id, publicKey: point, ...(e.solo === true ? { solo: true } : {}) });
  }
  return ok({ keys, ...(restartAfter === undefined ? {} : { restartAfter }) });
}

/** The keys of a key file (see `readKeyFileFull`; `restartAfter` is checked but not returned). */
export function readKeyFile(data: unknown): Result<RelayKey[]> {
  const full = readKeyFileFull(data);
  return full.ok ? ok(full.value.keys) : full;
}

/**
 * Reads and checks the key file (keys and `restartAfter`). Throws with a message a person can read: the
 * path and a rule name, never a piece of the file.
 */
export function loadKeyFile(
  path: string,
  read: (path: string) => string = (p) => readFileSync(p, 'utf8'),
): KeyFile {
  let data: unknown;
  try {
    data = JSON.parse(read(path));
  } catch {
    throw new Error(`${path}: Schlüsseldatei nicht lesbar oder kein JSON`);
  }
  const file = readKeyFileFull(data);
  if (!file.ok)
    throw new Error(`${path}: ungültige Schlüsseldatei (${file.reason}: ${file.detail})`);
  return file.value;
}

/** Reads and checks the key file; the keys only (see `loadKeyFile`). */
export function loadKeys(
  path: string,
  read: (path: string) => string = (p) => readFileSync(p, 'utf8'),
): RelayKey[] {
  return loadKeyFile(path, read).keys;
}
