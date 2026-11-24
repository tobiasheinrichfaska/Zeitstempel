import { copyKnown, typedLength } from './bytes.ts';
import { ReaderError } from './result.ts';

/**
 * A strict, bounded DER reader (and the few writers the request needs). Definite lengths only, the
 * shortest length form only, single-byte tags only, nesting and size bounded. BER shortcuts
 * (indefinite length, long forms that could be short) are refused: a signed structure has one
 * encoding, so there is nothing to be lenient about.
 */

export const DER_LIMITS = {
  /** Largest structure read at all (a token with a long chain is about 10 KB). */
  maxBytes: 262_144,
  maxDepth: 24,
  /** Children of one constructed node. */
  maxChildren: 256,
} as const;

export const TAG = {
  boolean: 0x01,
  integer: 0x02,
  bitString: 0x03,
  octetString: 0x04,
  null: 0x05,
  oid: 0x06,
  utf8String: 0x0c,
  utcTime: 0x17,
  generalizedTime: 0x18,
  sequence: 0x30,
  set: 0x31,
} as const;

/** Class bits of a tag byte: 0x00 universal, 0x40 application, 0x80 context-specific, 0xc0 private. */
export interface Node {
  /** The whole tag byte, e.g. 0x30 or 0xa0. */
  tag: number;
  /** The whole element: header and content. */
  raw: Uint8Array;
  /** The content bytes. */
  value: Uint8Array;
}

/** `[n]` constructed, context-specific. */
export const ctx = (n: number): number => 0xa0 | n;
/** `[n]` primitive, context-specific. */
export const ctxPrimitive = (n: number): number => 0x80 | n;

/** Reads one element at `pos`; returns it and the position after it. */
function readOne(buf: Uint8Array, pos: number, end: number): { node: Node; next: number } {
  if (pos + 2 > end) throw new ReaderError('malformed');
  const tag = buf[pos]!;
  if ((tag & 0x1f) === 0x1f) throw new ReaderError('malformed'); // multi-byte tag numbers
  const first = buf[pos + 1]!;
  let len: number;
  let header: number;
  if (first < 0x80) {
    len = first;
    header = 2;
  } else if (first === 0x80) {
    throw new ReaderError('indefinite-length');
  } else {
    const n = first & 0x7f;
    if (n > 3 || pos + 2 + n > end) throw new ReaderError('malformed');
    len = 0;
    for (let i = 0; i < n; i += 1) len = len * 256 + buf[pos + 2 + i]!;
    // shortest form: no leading zero length byte, and not a length a short form could carry
    if (buf[pos + 2] === 0 || len < 0x80) throw new ReaderError('malformed');
    header = 2 + n;
  }
  if (pos + header + len > end) throw new ReaderError('malformed');
  return {
    node: {
      tag,
      raw: buf.subarray(pos, pos + header + len),
      value: buf.subarray(pos + header, pos + header + len),
    },
    next: pos + header + len,
  };
}

/**
 * A private copy of the bytes a reader is given (its own `ArrayBuffer`, also when the input lives in a
 * `SharedArrayBuffer`), so that nothing a reader returns points into the caller's buffer. The length is read from
 * the internal slot and checked against `maxBytes` BEFORE anything is copied; the copy is made with `set`, never
 * through the iterator. A typed array of another realm is fine; anything else (a proxy, an array, a string) is
 * `malformed`.
 */
export function ownBytes(bytes: unknown): Uint8Array {
  const length = typedLength(bytes);
  if (length === null) throw new ReaderError('malformed');
  if (length > DER_LIMITS.maxBytes) throw new ReaderError('too-large');
  const copy = copyKnown(bytes as Uint8Array, length);
  if (!copy) throw new ReaderError('malformed');
  return copy;
}

/** Reads exactly one element that spans all of `bytes` (nothing may follow it). */
export function parseDer(bytes: Uint8Array): Node {
  if (bytes.length > DER_LIMITS.maxBytes) throw new ReaderError('too-large');
  const { node, next } = readOne(bytes, 0, bytes.length);
  if (next !== bytes.length) throw new ReaderError('trailing-bytes');
  checkDepth(node, 1);
  return node;
}

/** Walks the whole tree once so the depth and child bounds hold everywhere. */
function checkDepth(node: Node, depth: number): void {
  if (depth > DER_LIMITS.maxDepth) throw new ReaderError('too-deep');
  if ((node.tag & 0x20) === 0) return;
  for (const child of children(node)) checkDepth(child, depth + 1);
}

/** The children of a constructed node; throws when the content is not a clean run of elements. */
export function children(node: Node): Node[] {
  if ((node.tag & 0x20) === 0) throw new ReaderError('bad-structure');
  const out: Node[] = [];
  let pos = 0;
  while (pos < node.value.length) {
    if (out.length >= DER_LIMITS.maxChildren) throw new ReaderError('too-large');
    const { node: child, next } = readOne(node.value, pos, node.value.length);
    out.push(child);
    pos = next;
  }
  return out;
}

/** Reads the content of a primitive-wrapped element as one inner element (EXPLICIT tagging). */
export function inner(node: Node): Node {
  const kids = children(node);
  if (kids.length !== 1) throw new ReaderError('bad-structure');
  return kids[0]!;
}

export function expect(node: Node | undefined, tag: number): Node {
  if (!node || node.tag !== tag) throw new ReaderError('bad-structure');
  return node;
}

export function oid(node: Node): string {
  expect(node, TAG.oid);
  const v = node.value;
  if (v.length === 0 || (v[v.length - 1]! & 0x80) !== 0) throw new ReaderError('malformed');
  const parts: number[] = [];
  let acc = 0;
  let started = false;
  for (const b of v) {
    if (!started && b === 0x80) throw new ReaderError('malformed'); // non-minimal
    started = true;
    acc = acc * 128 + (b & 0x7f);
    if (acc > Number.MAX_SAFE_INTEGER / 128) throw new ReaderError('malformed');
    if ((b & 0x80) === 0) {
      parts.push(acc);
      acc = 0;
      started = false;
    }
  }
  const first = parts[0]!;
  const head = first < 40 ? [0, first] : first < 80 ? [1, first - 40] : [2, first - 80];
  return [...head, ...parts.slice(1)].join('.');
}

/** An INTEGER's content bytes, checked for the minimal encoding. */
export function integerBytes(node: Node): Uint8Array {
  expect(node, TAG.integer);
  const v = node.value;
  if (v.length === 0) throw new ReaderError('malformed');
  if (
    v.length > 1 &&
    ((v[0] === 0 && (v[1]! & 0x80) === 0) || (v[0] === 0xff && (v[1]! & 0x80) !== 0))
  ) {
    throw new ReaderError('malformed');
  }
  return v;
}

/** An INTEGER's content bytes (minimal encoding) that must not be negative (sign bit clear). */
export function unsignedBytes(node: Node): Uint8Array {
  const v = integerBytes(node);
  if ((v[0]! & 0x80) !== 0) throw new ReaderError('malformed');
  return v;
}

/** A small non-negative INTEGER as a number. */
export function integerNumber(node: Node): number {
  const v = integerBytes(node);
  if ((v[0]! & 0x80) !== 0 || v.length > 6) throw new ReaderError('malformed');
  return v.reduce((n, b) => n * 256 + b, 0);
}

export function boolean(node: Node): boolean {
  expect(node, TAG.boolean);
  if (node.value.length !== 1 || (node.value[0] !== 0 && node.value[0] !== 0xff)) {
    throw new ReaderError('malformed');
  }
  return node.value[0] === 0xff;
}

export function octets(node: Node): Uint8Array {
  return expect(node, TAG.octetString).value;
}

/** A BIT STRING's bytes; the number of unused bits must be zero (all our uses are whole bytes). */
export function bitStringBytes(node: Node): Uint8Array {
  expect(node, TAG.bitString);
  if (node.value.length < 1 || node.value[0] !== 0) throw new ReaderError('malformed');
  return node.value.subarray(1);
}

/** UTCTime or GeneralizedTime (whole seconds, with an optional fraction of up to 9 digits for the latter, cut off to ms, never rounded) as ms.
 * `fraction: false` is the certificate form (RFC 5280 § 4.1.2.5.2: GeneralizedTime without fractional seconds);
 * a time stamp's `genTime` (RFC 3161) keeps the fraction. */
export function time(node: Node, fraction = true): number {
  const text = new TextDecoder('ascii').decode(node.value);
  let m: RegExpExecArray | null;
  let year: number;
  let frac = '';
  if (node.tag === TAG.utcTime) {
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (!m) throw new ReaderError('bad-time');
    year = Number(m[1]) >= 50 ? 1900 + Number(m[1]) : 2000 + Number(m[1]);
  } else if (node.tag === TAG.generalizedTime) {
    m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,9}))?Z$/.exec(text);
    if (!m) throw new ReaderError('bad-time');
    year = Number(m[1]);
    frac = m[7] ?? '';
    if (!fraction && frac !== '') throw new ReaderError('bad-time');
  } else {
    throw new ReaderError('bad-time');
  }
  const [mo, d, h, mi, s] = [m[2], m[3], m[4], m[5], m[6]].map(Number) as [
    number,
    number,
    number,
    number,
    number,
  ];
  if (node.tag === TAG.generalizedTime && frac.endsWith('0')) throw new ReaderError('bad-time');
  const ms =
    Date.UTC(year, mo - 1, d, h, mi, s) + (frac ? Number(frac.slice(0, 3).padEnd(3, '0')) : 0);
  const back = new Date(ms);
  if (
    back.getUTCFullYear() !== year ||
    back.getUTCMonth() !== mo - 1 ||
    back.getUTCDate() !== d ||
    back.getUTCHours() !== h ||
    back.getUTCMinutes() !== mi ||
    back.getUTCSeconds() !== s
  ) {
    throw new ReaderError('bad-time');
  }
  return ms;
}

// ----- writers -----

export function encodeLength(len: number): Uint8Array {
  if (len < 0x80) return Uint8Array.of(len);
  const bytes: number[] = [];
  for (let n = len; n > 0; n = Math.floor(n / 256)) bytes.unshift(n % 256);
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

export function tlv(tag: number, ...parts: Uint8Array[]): Uint8Array {
  const size = parts.reduce((n, p) => n + p.length, 0);
  const head = encodeLength(size);
  const out = new Uint8Array(1 + head.length + size);
  out[0] = tag;
  out.set(head, 1);
  let at = 1 + head.length;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function encodeOid(dotted: string): Uint8Array {
  const arcs = dotted.split('.').map(Number);
  const subIds = [arcs[0]! * 40 + arcs[1]!, ...arcs.slice(2)];
  const body: number[] = [];
  for (const id of subIds) {
    const group: number[] = [id & 0x7f];
    for (let n = Math.floor(id / 128); n > 0; n = Math.floor(n / 128))
      group.unshift((n & 0x7f) | 0x80);
    body.push(...group);
  }
  return tlv(TAG.oid, Uint8Array.from(body));
}

/** A non-negative INTEGER from big-endian magnitude bytes (adds the sign byte when needed). */
export function encodeUnsigned(magnitude: Uint8Array): Uint8Array {
  let i = 0;
  while (i < magnitude.length - 1 && magnitude[i] === 0) i += 1;
  const m = magnitude.subarray(i);
  return tlv(TAG.integer, (m[0]! & 0x80) !== 0 ? Uint8Array.of(0, ...m) : m);
}
