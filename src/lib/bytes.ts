/**
 * Small byte helpers that work in browsers and Node (no Node-only types).
 *
 * Wrong types never pass silently: the strict readers (`fromBase64`, `fromBase64Url`) give `null` for
 * anything but a string and `equalBytes` gives `false` for anything but two `Uint8Array`; the writers
 * (`toBase64`, `toBase64Url`, `toHex`) throw a `TypeError` for anything but a `Uint8Array` (a string or an
 * array would otherwise be encoded as if it were bytes).
 */

const needBytes = (bytes: unknown): Uint8Array => {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('a Uint8Array is required');
  return bytes;
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

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i]! ^ b[i]!;
  return diff === 0;
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
