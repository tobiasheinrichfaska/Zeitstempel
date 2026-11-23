/**
 * Small byte helpers that work in browsers and Node (no Node-only types).
 *
 * Wrong types never pass silently: the strict readers (`fromBase64`, `fromBase64Url`) give `null` for
 * anything but a string and `equalBytes` gives `false` for anything but two `Uint8Array` (also for a hostile
 * proxy whose traps throw); the writers (`toBase64`, `toBase64Url`, `toHex`) throw a `TypeError` for
 * anything but a `Uint8Array` (a string or an array would otherwise be encoded as if it were bytes). A
 * `Uint8Array` of another realm (iframe, worker, `vm`) is none here: pass `new Uint8Array(x)`.
 */

// The built-in `length` getter of every typed array: it reads the internal slot, so an own `length`, a
// subclass override or a hostile prototype cannot change the answer (a proxy or a non-typed-array throws).
const typedArrayLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype) as object,
  'length',
)!.get!;

/** The length of a genuine `Uint8Array` (built-in getter, internal slot); `null` for anything else; never throws. */
export function byteLength(value: unknown): number | null {
  try {
    if (!(value instanceof Uint8Array)) return null;
    return typedArrayLength.call(value) as number;
  } catch {
    return null; // a proxy whose traps throw, a value without the internal slot
  }
}

const needBytes = (bytes: unknown): Uint8Array => {
  // a genuine Uint8Array only (a proxy, also a transparent one, and a trap that throws are a TypeError)
  if (byteLength(bytes) === null) throw new TypeError('a Uint8Array is required');
  return bytes as Uint8Array;
};

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function toBase64(input: Uint8Array): string {
  const bytes = needBytes(input);
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]!;
    out += i + 1 < bytes.length ? B64[(n >> 6) & 63]! : '=';
    out += i + 2 < bytes.length ? B64[n & 63]! : '=';
  }
  return out;
}

/** Strict standard base64 (padded, no whitespace); null when invalid. */
export function fromBase64(text: string): Uint8Array | null {
  if (typeof text !== 'string') return null;
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return null;
  const pad = text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0;
  const out = new Uint8Array((text.length / 4) * 3 - pad);
  let o = 0;
  for (let i = 0; i < text.length; i += 4) {
    let n = 0;
    for (let j = 0; j < 4; j += 1) {
      const c = text[i + j]!;
      n = (n << 6) | (c === '=' ? 0 : B64.indexOf(c));
    }
    if (o < out.length) out[o++] = (n >> 16) & 255;
    if (o < out.length) out[o++] = (n >> 8) & 255;
    if (o < out.length) out[o++] = n & 255;
  }
  return out;
}

export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Strict unpadded base64url; null when invalid. */
export function fromBase64Url(text: string): Uint8Array | null {
  if (typeof text !== 'string') return null;
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
  const std = text.replace(/-/g, '+').replace(/_/g, '/');
  const bytes = fromBase64(std + '='.repeat((4 - (std.length % 4)) % 4));
  // reject a non-canonical last character (spare bits must be zero): re-encode and compare
  return bytes && toBase64Url(bytes) === text ? bytes : null;
}

export function toHex(input: Uint8Array): string {
  return Array.from(needBytes(input), (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Never throws: anything but two equal, genuine `Uint8Array` gives `false` (a proxy, whether its traps throw or
 * not, is none). Each length is read once with the built-in getter (an own `length` or a subclass cannot change
 * it) and the loop runs over that one number.
 */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  const length = byteLength(a);
  if (length === null || length !== byteLength(b)) return false;
  // Both are genuine typed arrays now (a proxy gave `null` above), so indexing cannot throw.
  let diff = 0;
  for (let i = 0; i < length; i += 1) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * A copy of `value` when it is a `Uint8Array` of `min` to `max` bytes, else `null`; never throws (a proxy whose
 * `getPrototypeOf` or `get` traps throw gives `null`). The length is read first with the built-in getter and
 * checked BEFORE anything is allocated or copied, and the copy is made with `TypedArray.prototype.set`, never
 * through the iterator (an overridden, endless `Symbol.iterator` is never called). The caller works with the
 * copy only (its own `ArrayBuffer`, also when the input lives in a `SharedArrayBuffer`), so a value that
 * answers differently the second time, or is changed meanwhile, cannot change anything.
 */
export function copyBytes(value: unknown, min: number, max: number): Uint8Array | null {
  const length = byteLength(value);
  if (length === null || length < min || length > max) return null;
  return copyKnown(value as Uint8Array, length);
}

/** A copy of a value whose `byteLength` has been read already (once: a proxy is asked only once, not twice). */
export function copyKnown(value: Uint8Array, length: number): Uint8Array | null {
  try {
    const copy = new Uint8Array(length);
    copy.set(value);
    return copy;
  } catch {
    return null;
  }
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Strips leading zero bytes of an unsigned big-endian integer (keeps one byte for zero). */
export function trimZeros(bytes: Uint8Array): Uint8Array {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i += 1;
  return bytes.subarray(i);
}
