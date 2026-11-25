import { createPublicKey, type KeyObject } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync, statSync } from 'node:fs';
import { RELAY_LIMITS } from './limits.ts';
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
  /**
   * `"revoked": true` (file version 3): the key stays in the file but is refused like an unknown one (401, the same work,
   * counted globally as `keyRevoked`). Absent or false: the key counts.
   */
  revoked?: boolean;
  /** `notAfter` (file version 3, Unix seconds): from this moment on the key is refused like a revoked one (counted as `keyExpired`). */
  notAfter?: number;
  /** `services` (file version 3): the only service ids this key may stamp with (else `403 service-not-allowed`). Absent: all. */
  services?: string[];
  /** `perMinute` (file version 3): the key's own limit per minute instead of `perMinutePerKey` (1 to `perMinutePerKey`). */
  perMinute?: number;
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
/** The pattern of a service id (as in `services.json`). */
const SERVICE_ID = /^[a-z][a-z0-9-]{0,31}$/;
/** `services` of an entry: at most this many ids. */
export const MAX_KEY_SERVICES = 16;
const ENTRY_V2 = ['id', 'publicKey', 'solo'];
const ENTRY_V3 = ['notAfter', 'perMinute', 'revoked', 'services'];
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
 * Strict reader of the key file: `{"version": 2 or 3, "keys": [{"id", "publicKey", "solo"?, ...}], "restartAfter"?}`
 * with 0 to 64 keys (an expressly empty list is valid: nobody may stamp), ids of the form `[a-z][a-z0-9-]{0,31}`,
 * public keys as unpadded base64url of an uncompressed point (65 bytes) that lies on the curve P-256, no duplicate id,
 * no duplicate key, no other fields. `solo` is a boolean (nothing else), `restartAfter` an integer of Unix seconds.
 * Version 3 only, per entry: `revoked` (boolean), `notAfter` (integer, Unix seconds), `services` (1 to 16 distinct
 * service ids; with `knownServices` each must be one of them) and `perMinute` (integer, 1 to `perMinutePerKey`); in a
 * version 2 file these fields are a read error. The failure carries a rule name and, for an entry, its index in
 * `keys`, never content.
 */
export function readKeyFileFull(
  data: unknown,
  knownServices?: ReadonlySet<string>,
): Result<KeyFile> {
  // `index`: the position of the entry in `keys` (never its content)
  const bad = (rule: string, index?: number) =>
    fail('bad-key-file', index === undefined ? rule : `${rule} in keys[${index}]`);
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return bad('not-an-object');
  const top = data as Record<string, unknown>;
  const names = Object.keys(top).sort().join();
  if (names !== 'keys,version' && names !== 'keys,restartAfter,version') return bad('fields');
  if (top.version !== 2 && top.version !== 3) return bad('version');
  const v3 = top.version === 3;
  let restartAfter: number | undefined;
  if (Object.hasOwn(top, 'restartAfter')) {
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
  if (!Array.isArray(top.keys) || top.keys.length > MAX_KEYS) {
    return bad('key-count');
  }
  const keys: RelayKey[] = [];
  const ids = new Set<string>();
  const points = new Set<string>();
  for (const [index, entry] of (top.keys as unknown[]).entries()) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry))
      return bad('entry', index);
    const e = entry as Record<string, unknown>;
    const present = Object.keys(e);
    if (!present.includes('id') || !present.includes('publicKey'))
      return bad('entry-fields', index);
    const extra = present.filter((f) => f !== 'id' && f !== 'publicKey');
    if (extra.some((f) => !ENTRY_V2.includes(f) && !ENTRY_V3.includes(f)))
      return bad('entry-fields', index);
    if (!v3 && extra.some((f) => ENTRY_V3.includes(f))) return bad('v3-field-in-v2-file', index);
    if (typeof e.id !== 'string' || !KEY_ID.test(e.id)) return bad('id', index);
    if (typeof e.publicKey !== 'string') return bad('public-key', index);
    if (Object.hasOwn(e, 'solo') && typeof e.solo !== 'boolean') return bad('solo', index);
    if (Object.hasOwn(e, 'revoked') && typeof e.revoked !== 'boolean') return bad('revoked', index);
    if (Object.hasOwn(e, 'notAfter')) {
      const n = e.notAfter;
      if (
        typeof n !== 'number' ||
        !Number.isInteger(n) ||
        n < RESTART_AFTER_MIN ||
        n > RESTART_AFTER_MAX
      ) {
        return bad('not-after', index);
      }
    }
    if (Object.hasOwn(e, 'perMinute')) {
      const n = e.perMinute;
      if (
        typeof n !== 'number' ||
        !Number.isInteger(n) ||
        n < 1 ||
        n > RELAY_LIMITS.perMinutePerKey
      ) {
        return bad('per-minute', index);
      }
    }
    let services: string[] | undefined;
    if (Object.hasOwn(e, 'services')) {
      const list = e.services;
      if (!Array.isArray(list) || list.length < 1 || list.length > MAX_KEY_SERVICES)
        return bad('services', index);
      const seen = new Set<string>();
      for (const id of list as unknown[]) {
        if (typeof id !== 'string' || !SERVICE_ID.test(id) || seen.has(id))
          return bad('services', index);
        if (knownServices !== undefined && !knownServices.has(id))
          return bad('services-unknown', index);
        seen.add(id);
      }
      services = [...seen];
    }
    const point = fromBase64Url(e.publicKey);
    if (!point || point.length !== 65) return bad('public-key', index);
    if (publicKeyObject(point) === null) return bad('public-key-point', index);
    const hex = toHex(point);
    if (ids.has(e.id)) return bad('duplicate-id', index);
    if (points.has(hex)) return bad('duplicate-key', index);
    ids.add(e.id);
    points.add(hex);
    keys.push({
      id: e.id,
      publicKey: point,
      ...(e.solo === true ? { solo: true } : {}),
      ...(e.revoked === true ? { revoked: true } : {}),
      ...(typeof e.notAfter === 'number' ? { notAfter: e.notAfter } : {}),
      ...(services === undefined ? {} : { services }),
      ...(typeof e.perMinute === 'number' ? { perMinute: e.perMinute } : {}),
    });
  }
  return ok({ keys, ...(restartAfter === undefined ? {} : { restartAfter }) });
}

/** The keys of a key file (see `readKeyFileFull`; `restartAfter` is checked but not returned). */
export function readKeyFile(
  data: unknown,
  knownServices?: ReadonlySet<string>,
): Result<RelayKey[]> {
  const full = readKeyFileFull(data, knownServices);
  return full.ok ? ok(full.value.keys) : full;
}

/** The key file is not a plain file or is larger than `keyFileMaxBytes` (never read further). */
export class KeyFileKindError extends Error {}

/**
 * The bytes of the key file, for a plain file of at most `keyFileMaxBytes` only. The file is opened without waiting
 * (`O_NONBLOCK`: a FIFO must not block the relay until a writer comes) and examined through the open handle
 * (`fstat`, so nothing can change between the check and the read): a FIFO, a device, a directory or a file that
 * is too large (also one that grows while it is read) throws `KeyFileKindError`, with nothing read beyond the limit.
 * A symbolic link is followed (a link to a plain file is a normal way to deploy it); what it points to must pass
 * the same check.
 */
export function readKeyFileBytes(path: string): Buffer {
  const max = RELAY_LIMITS.keyFileMaxBytes;
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOCTTY);
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.size > max) throw new KeyFileKindError('kind');
    const buffer = Buffer.alloc(max + 1);
    let length = 0;
    for (;;) {
      const got = readSync(fd, buffer, length, max + 1 - length, null);
      if (got === 0) break;
      length += got;
      if (length > max) throw new KeyFileKindError('size');
    }
    return buffer.subarray(0, length);
  } finally {
    closeSync(fd);
  }
}

const readKeyFileText = (path: string): string => readKeyFileBytes(path).toString('utf8');

/**
 * A warning text when the key file can be written by its group or by others (POSIX; mode & 0o022): whoever
 * can write it can enter a key of their own. Null otherwise, also under Windows (no such modes) and when
 * the file cannot be examined. The text names the path and the mode, nothing from the file. Reading is
 * no problem: the file holds public keys only.
 */
export function keyFilePermissionWarning(
  path: string,
  stat: (path: string) => { mode: number } = statSync,
  platform: string = process.platform,
): string | null {
  if (platform === 'win32') return null;
  let mode: number;
  try {
    mode = stat(path).mode;
  } catch {
    return null;
  }
  if ((mode & 0o022) === 0) return null;
  return `${path}: Die Schlüsseldatei ist für Gruppe oder Andere schreibbar (Modus ${(mode & 0o777).toString(8)}); wer sie schreiben kann, kann einen eigenen Schlüssel eintragen. Schreibrechte entziehen (chmod go-w)`;
}

/**
 * Reads and checks the key file (keys and `restartAfter`). Throws with a message a person can read: the
 * path and a rule name, never a piece of the file.
 */
export function loadKeyFile(
  path: string,
  read: (path: string) => string = readKeyFileText,
  knownServices?: ReadonlySet<string>,
): KeyFile {
  // never a cause on the error: the message of a JSON error can quote a piece of the file
  let data: unknown;
  let problem: 'kind' | 'unreadable' | null = null;
  try {
    data = JSON.parse(read(path));
  } catch (e) {
    problem = e instanceof KeyFileKindError ? 'kind' : 'unreadable';
  }
  if (problem === 'kind') {
    throw new Error(
      `${path}: Schlüsseldatei ist keine reguläre Datei oder größer als ${RELAY_LIMITS.keyFileMaxBytes} Byte`,
    );
  }
  if (problem !== null) throw new Error(`${path}: Schlüsseldatei nicht lesbar oder kein JSON`);
  const file = readKeyFileFull(data, knownServices);
  if (!file.ok)
    throw new Error(`${path}: ungültige Schlüsseldatei (${file.reason}: ${file.detail})`);
  return file.value;
}

/** Reads and checks the key file; the keys only (see `loadKeyFile`). */
export function loadKeys(
  path: string,
  read: (path: string) => string = readKeyFileText,
  knownServices?: ReadonlySet<string>,
): RelayKey[] {
  return loadKeyFile(path, read, knownServices).keys;
}
