import { toBase64Url, toHex } from './bytes.ts';
import { fail, ok, type Result } from './result.ts';

/**
 * Authentication towards a relay (docs/relay.md). The app holds a private ECDSA P-256 key; the relay's
 * key file holds only the matching public key, so the file is no secret (its integrity counts). The
 * private key never leaves the app: each request carries only a signature. Only standard APIs
 * (WebCrypto), so this runs in a browser. Making a key pair is a tool (`scripts/make-key.ts`), not
 * part of the library.
 */

const KEY_ID = /^[a-z][a-z0-9-]{0,31}$/;
const METHOD = /^[A-Z]{1,16}$/;
const PATH = /^\/[\x21-\x7e]*$/; // visible ASCII only
const PREFIX = 'zeitstempel-auth-v2';

export interface SignRelayRequestInput {
  /** The private key: ECDSA P-256, PKCS#8 (DER) bytes. It stays in the app and is never returned. */
  privateKey: Uint8Array;
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

/**
 * The value of the `X-Zeitstempel-Auth` header: `v2.<keyId>.<ts>.<sig>` with `ts` in Unix seconds and
 * `sig = base64url(ECDSA-P256-SHA256 (r || s, 64 bytes) over "zeitstempel-auth-v2\n" + method + "\n" +
 * path + "\n" + ts + "\n" + hex(SHA-256(body)))`. Never throws; the key is imported as non-extractable
 * and is never returned or kept. ECDSA is randomised: two calls give two different signatures.
 */
export async function signRelayRequest(input: SignRelayRequestInput): Promise<Result<string>> {
  if (typeof input !== 'object' || input === null) return fail('bad-options');
  const { privateKey, keyId, method, path, body, nowMs } = input;
  if (!(privateKey instanceof Uint8Array)) return fail('bad-key');
  if (typeof keyId !== 'string' || !KEY_ID.test(keyId)) return fail('bad-key-id');
  if (typeof method !== 'string' || !METHOD.test(method)) return fail('bad-options');
  if (typeof path !== 'string' || !PATH.test(path) || /[?#]/.test(path)) return fail('bad-options');
  if (!(body instanceof Uint8Array)) return fail('bad-options');
  if (typeof nowMs !== 'number' || !Number.isFinite(nowMs) || nowMs < 0) return fail('bad-options');
  const subtle = globalThis.crypto?.subtle;
  if (typeof subtle?.importKey !== 'function') return fail('unsupported-signature'); // e.g. plain http
  let key: CryptoKey;
  try {
    key = await subtle.importKey(
      'pkcs8',
      privateKey as BufferSource,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    );
  } catch {
    return fail('bad-key'); // not PKCS#8, or not an ECDSA P-256 key
  }
  const ts = Math.floor(nowMs / 1000);
  try {
    const digest = new Uint8Array(await subtle.digest('SHA-256', body as BufferSource));
    const message = `${PREFIX}\n${method}\n${path}\n${ts}\n${toHex(digest)}`;
    const signature = new Uint8Array(
      await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(message)),
    );
    return ok(`v2.${keyId}.${ts}.${toBase64Url(signature)}`);
  } catch {
    return fail('unsupported-signature');
  }
}
