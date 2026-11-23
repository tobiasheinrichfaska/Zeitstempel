import { toBase64Url, toHex } from './bytes.ts';
import { fail, ok, type Result } from './result.ts';

/**
 * Authentication towards a relay (docs/relay.md). The app holds a permission key K (at least 16
 * bytes). The relay knows only V = SHA-256(K) and a key id. Each request carries an HMAC made with V;
 * K and V are never sent. Only standard APIs (WebCrypto), so this runs in a browser.
 */

const MIN_KEY_BYTES = 16;
const KEY_ID = /^[a-z][a-z0-9-]{0,31}$/;
const METHOD = /^[A-Z]{1,16}$/;
const PATH = /^\/[\x21-\x7e]*$/; // visible ASCII only
const PREFIX = 'zeitstempel-auth-v1';

export interface SignRelayRequestInput {
  /** The permission key K: stays in the app; it is only used here, to derive V. */
  key: Uint8Array;
  /** Key id as the relay's key file names it: `[a-z][a-z0-9-]{0,31}`. */
  keyId: string;
  /** HTTP method in capitals, e.g. `POST`. */
  method: string;
  /** Request path without query, starting with `/`, e.g. `/v1/stamp/freetsa`. */
  path: string;
  /** The raw bytes of the request body, exactly as sent. */
  body: Uint8Array;
  /** The current time in milliseconds since the epoch (a parameter: the clock is the caller's). */
  nowMs: number;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', data as BufferSource));
}

/** V = SHA-256(K): what the relay stores. A key under 16 bytes is refused. */
export async function deriveVerifier(key: Uint8Array): Promise<Result<Uint8Array>> {
  if (!(key instanceof Uint8Array) || key.length < MIN_KEY_BYTES) return fail('bad-key');
  try {
    return ok(await sha256(key));
  } catch {
    return fail('unsupported-signature'); // no WebCrypto (e.g. a page served over plain http)
  }
}

/**
 * The value of the `X-Zeitstempel-Auth` header: `v1.<keyId>.<ts>.<mac>` with `ts` in Unix seconds and
 * `mac = base64url(HMAC-SHA256(V, "zeitstempel-auth-v1\n" + method + "\n" + path + "\n" + ts + "\n" +
 * hex(SHA-256(body))))`. Never throws; never returns or keeps the key.
 */
export async function signRelayRequest(input: SignRelayRequestInput): Promise<Result<string>> {
  if (typeof input !== 'object' || input === null) return fail('bad-options');
  const { key, keyId, method, path, body, nowMs } = input;
  const verifier = await deriveVerifier(key);
  if (!verifier.ok) return verifier;
  if (typeof keyId !== 'string' || !KEY_ID.test(keyId)) return fail('bad-key-id');
  if (typeof method !== 'string' || !METHOD.test(method)) return fail('bad-options');
  if (typeof path !== 'string' || !PATH.test(path) || /[?#]/.test(path)) return fail('bad-options');
  if (!(body instanceof Uint8Array)) return fail('bad-options');
  if (typeof nowMs !== 'number' || !Number.isFinite(nowMs) || nowMs < 0) return fail('bad-options');
  const ts = Math.floor(nowMs / 1000);
  try {
    const message = `${PREFIX}\n${method}\n${path}\n${ts}\n${toHex(await sha256(body))}`;
    const hmacKey = await globalThis.crypto.subtle.importKey(
      'raw',
      verifier.value as BufferSource,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const mac = new Uint8Array(
      await globalThis.crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode(message)),
    );
    return ok(`v1.${keyId}.${ts}.${toBase64Url(mac)}`);
  } catch {
    return fail('unsupported-signature');
  }
}
