import { readFileSync } from 'node:fs';
import { fail, fromBase64Url, ok, type Result } from '../src/index.ts';

/**
 * A key the relay accepts: its id and V = SHA-256(K). V is the HMAC key of the request signature, so
 * whoever has V (this file) can sign requests: the file holds secrets of the same worth as K. K itself
 * stays in the app and is never transmitted; the relay never needs it.
 */
export interface RelayKey {
  id: string;
  verifier: Uint8Array;
}

const KEY_ID = /^[a-z][a-z0-9-]{0,31}$/;
export const MAX_KEYS = 64;

/**
 * Strict reader of the key file: `{"version": 1, "keys": [{"id", "verifier"}]}` with 1 to 64 keys,
 * ids of the form `[a-z][a-z0-9-]{0,31}`, verifiers of exactly 32 bytes (base64url, unpadded), no
 * duplicate id, no duplicate verifier, no other fields. The failure carries a rule name, never content.
 * Keep the file out of the repo and readable by the relay only (mode 0600).
 */
export function readKeyFile(data: unknown): Result<RelayKey[]> {
  const bad = (rule: string) => fail('bad-key-file', rule);
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return bad('not-an-object');
  const top = data as Record<string, unknown>;
  if (Object.keys(top).sort().join() !== 'keys,version') return bad('fields');
  if (top.version !== 1) return bad('version');
  if (!Array.isArray(top.keys) || top.keys.length < 1 || top.keys.length > MAX_KEYS) {
    return bad('key-count');
  }
  const keys: RelayKey[] = [];
  const ids = new Set<string>();
  const verifiers = new Set<string>();
  for (const entry of top.keys as unknown[]) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return bad('entry');
    const e = entry as Record<string, unknown>;
    if (Object.keys(e).sort().join() !== 'id,verifier') return bad('entry-fields');
    if (typeof e.id !== 'string' || !KEY_ID.test(e.id)) return bad('id');
    if (typeof e.verifier !== 'string') return bad('verifier');
    const verifier = fromBase64Url(e.verifier);
    if (!verifier || verifier.length !== 32) return bad('verifier');
    if (ids.has(e.id)) return bad('duplicate-id');
    if (verifiers.has(e.verifier)) return bad('duplicate-verifier');
    ids.add(e.id);
    verifiers.add(e.verifier);
    keys.push({ id: e.id, verifier });
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
