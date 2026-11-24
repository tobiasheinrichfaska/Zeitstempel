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
/** A P-256 PKCS#8 key is about 138 bytes; more than this is no key (`bad-key`). */
const MAX_PRIVATE_KEY_BYTES = 256;
/** The relay takes at most 512 bytes of body; a larger one is not signed (`bad-options`). */
const MAX_BODY_BYTES = 512;
/** `nowMs` below this is taken for seconds (or garbage): 1e11 ms is 1973, 1e11 s is the year 5138. */
const MIN_NOW_MS = 1e11;

export interface SignRelayRequestInput {
  /**
   * The private key: ECDSA P-256, either PKCS#8 (DER) bytes or a `CryptoKey` (type `private`, algorithm ECDSA on
   * P-256; it may be non-extractable, so the app never has to hold the key bytes). It stays in
   * the app and is never returned. A `CryptoKey` of another realm is refused (`bad-key`).
   */
  privateKey: Uint8Array | CryptoKey;
  /** Key id as the relay's key file names it: `[a-z][a-z0-9-]{0,31}`. */
  keyId: string;
  /** HTTP method in capitals, e.g. `POST`. */
  method: string;
  /** Request path without query, starting with `/`, e.g. `/v1/stamp/freetsa`. */
  path: string;
  /** The raw bytes of the request body, exactly as sent. */
  body: Uint8Array;
  /**
   * The current time in **milliseconds** since the epoch (`Date.now()`), not seconds; a parameter: the clock
   * is the caller's. Finite and at least 1e11 (that is March 1973 in milliseconds, but year 5138 in
   * seconds), so a value in seconds is refused (`bad-options`) instead of signing a time in 1970.
   */
  nowMs: number;
}

/**
 * The value of the `X-Zeitstempel-Auth` header: `v2.<keyId>.<ts>.<sig>` with `ts` in Unix seconds and
 * `sig = base64url(ECDSA-P256-SHA256 (r || s, 64 bytes) over "zeitstempel-auth-v2\n" + method + "\n" +
 * path + "\n" + ts + "\n" + hex(SHA-256(body)))`. Never throws, also not for hostile Proxies as input, `privateKey` or
 * `body` (code `bad-options`/`bad-key`); each is read once, never iterated, and `privateKey` (at most 256 bytes) and
 * `body` (at most 512) are copied first. A `Uint8Array` of another realm is refused: pass `new Uint8Array(x)`.
 * Bytes are imported as a non-extractable key and are never returned or kept; a `CryptoKey` is used as it is
 * (checked with the built-in getters: a Proxy or a look-alike is no `CryptoKey`, `bad-key`). ECDSA is randomised: two calls give two different signatures.
 */
export async function signRelayRequest(input: SignRelayRequestInput): Promise<Result<string>> {
  try {
    return await sign(input);
  } catch {
    return fail('bad-options'); // whatever a hostile input still managed to throw
  }
}

// The built-in `length` getter of every typed array, taken once: it throws for anything that is not a
// real typed array (a Proxy included) and cannot be overridden by the value itself.
const typedArrayLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype) as object,
  'length',
)?.get as ((this: unknown) => number) | undefined;

/**
 * A private copy of a `Uint8Array` of `min` to `max` bytes, or null. The value is touched a fixed number of
 * times and never iterated: instanceof, the built-in length getter, one `set`. Anything that throws on the
 * way (a hostile Proxy) gives null, and later reads see the copy only. A `Uint8Array` of another realm
 * is refused (pass `new Uint8Array(x)`).
 */
function copyOf(value: unknown, min: number, max: number): Uint8Array | null {
  try {
    if (!(value instanceof Uint8Array) || typedArrayLength === undefined) return null;
    const length = typedArrayLength.call(value);
    if (!Number.isInteger(length) || length < min || length > max) return null;
    const copy = new Uint8Array(length);
    copy.set(value);
    return copy;
  } catch {
    return null;
  }
}

type CryptoKeyGetter = (this: unknown) => unknown;
const cryptoKeyGetter = (name: string): CryptoKeyGetter | undefined =>
  typeof CryptoKey === 'function'
    ? (Object.getOwnPropertyDescriptor(CryptoKey.prototype, name)?.get as
        CryptoKeyGetter | undefined)
    : undefined;
const keyType = cryptoKeyGetter('type');
const keyAlgorithm = cryptoKeyGetter('algorithm');

/**
 * `value` when it is a real `CryptoKey` for signing with ECDSA on P-256, else null: type `private` (a private ECDSA
 * key can only be used to `sign`, so no separate check of the usages is needed, and a key pair cannot be made
 * without it). Read
 * with the built-in getters of `CryptoKey.prototype` (they throw for anything that is not a real key, a Proxy
 * included) and each exactly once; anything that throws gives null.
 */
function usableCryptoKey(value: unknown): CryptoKey | null {
  try {
    if (typeof CryptoKey !== 'function' || !(value instanceof CryptoKey)) return null;
    if (!keyType || !keyAlgorithm) return null;
    if (keyType.call(value) !== 'private') return null;
    const algorithm = keyAlgorithm.call(value) as { name?: unknown; namedCurve?: unknown } | null;
    if (algorithm?.name !== 'ECDSA' || algorithm.namedCurve !== 'P-256') return null;
    return value;
  } catch {
    return null;
  }
}

async function sign(input: SignRelayRequestInput): Promise<Result<string>> {
  if (typeof input !== 'object' || input === null) return fail('bad-options');
  let fields: SignRelayRequestInput;
  try {
    // Every property exactly once: a getter that answers differently the second time changes nothing.
    const { privateKey, keyId, method, path, body, nowMs } = input;
    fields = { privateKey, keyId, method, path, body, nowMs };
  } catch {
    return fail('bad-options'); // a throwing getter or Proxy trap on the input
  }
  const { keyId, method, path, nowMs } = fields;
  // a real CryptoKey is used as it is; anything else must be PKCS#8 bytes (copied before any use)
  const given = fields.privateKey;
  const readyKey = usableCryptoKey(given);
  const privateKey = readyKey === null ? copyOf(given, 1, MAX_PRIVATE_KEY_BYTES) : null;
  if (readyKey === null && privateKey === null) return fail('bad-key');
  if (typeof keyId !== 'string' || !KEY_ID.test(keyId)) return fail('bad-key-id');
  if (typeof method !== 'string' || !METHOD.test(method)) return fail('bad-options');
  if (typeof path !== 'string' || !PATH.test(path) || /[?#]/.test(path)) return fail('bad-options');
  const body = copyOf(fields.body, 0, MAX_BODY_BYTES);
  if (body === null) return fail('bad-options');
  if (typeof nowMs !== 'number' || !Number.isFinite(nowMs) || nowMs < MIN_NOW_MS) {
    return fail('bad-options'); // also a time in seconds
  }
  const subtle = globalThis.crypto?.subtle;
  if (typeof subtle?.importKey !== 'function') return fail('unsupported-signature'); // e.g. plain http
  let key: CryptoKey;
  if (readyKey !== null) {
    key = readyKey;
  } else {
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
