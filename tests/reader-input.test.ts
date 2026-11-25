// Audit 2, B2 and M21: what the copying readers accept as input.
// B2   only a `Uint8Array` (of any realm, a `Buffer`, a view into a SharedArrayBuffer) is bytes; every other typed array
//      is `malformed`, as for `verifyTimestampToken` (before, `Uint16Array` was cut to bytes modulo 256 and read).
// M21  a too large input is refused BEFORE anything is copied (the length comes from the internal slot).
import { runInNewContext } from 'node:vm';
import { parseCertificate, readTimestampResponse, readToken } from '../src/index.ts';
import { ownBytes } from '../src/lib/der.ts';
import { fixture } from './helpers.ts';

const RESPONSE = new Uint8Array(fixture('freetsa.tsr'));
const widen = <T extends { from(a: ArrayLike<number>): unknown }>(ctor: T) => ctor.from(RESPONSE);

const WRONG_TYPES: Record<string, () => unknown> = {
  Uint16Array: () => widen(Uint16Array),
  Int8Array: () => widen(Int8Array),
  Uint8ClampedArray: () => widen(Uint8ClampedArray),
  Int16Array: () => widen(Int16Array),
  Uint32Array: () => widen(Uint32Array),
  Float32Array: () => widen(Float32Array),
  Float64Array: () => widen(Float64Array),
  BigInt64Array: () => new BigInt64Array(8),
  'Uint16Array of another realm': () =>
    runInNewContext('Uint16Array.from(a)', { a: Array.from(RESPONSE) }),
  'Float64Array on a SharedArrayBuffer': () => new Float64Array(new SharedArrayBuffer(64)),
};

describe('B2: only a Uint8Array is bytes', () => {
  for (const [name, make] of Object.entries(WRONG_TYPES)) {
    it(`${name} is malformed in all three readers`, () => {
      const value = make();
      expect(readTimestampResponse(value as never)).toEqual({ ok: false, reason: 'malformed' });
      expect(() => readToken(value as never)).toThrow(
        expect.objectContaining({ reason: 'malformed' }),
      );
      expect(() => parseCertificate(value as never)).toThrow(
        expect.objectContaining({ reason: 'malformed' }),
      );
    });
  }
  it('a DataView, an ArrayBuffer and a plain array are malformed too', () => {
    for (const v of [
      new DataView(RESPONSE.buffer.slice(0)),
      RESPONSE.buffer.slice(0),
      [...RESPONSE],
    ]) {
      expect(readTimestampResponse(v as never)).toEqual({ ok: false, reason: 'malformed' });
    }
  });
  it('a Uint8Array, a Buffer, a subarray, a SharedArrayBuffer view and one of another realm are read', () => {
    const shared = new Uint8Array(new SharedArrayBuffer(RESPONSE.length));
    shared.set(RESPONSE);
    const foreign = runInNewContext('Uint8Array.from(a)', {
      a: Array.from(RESPONSE),
    }) as Uint8Array;
    const padded = new Uint8Array(RESPONSE.length + 10);
    padded.set(RESPONSE, 5);
    for (const v of [
      RESPONSE,
      Buffer.from(RESPONSE),
      padded.subarray(5, 5 + RESPONSE.length),
      shared,
      foreign,
    ]) {
      expect(readTimestampResponse(v).ok).toBe(true);
    }
  });
  it('a Uint8Array that lies about its element type is still a Uint8Array (and one that lies about length is read in full)', () => {
    const x = new Uint8Array(RESPONSE);
    Object.defineProperty(x, Symbol.toStringTag, { value: 'Uint16Array' });
    Object.defineProperty(x, 'length', { value: 3 });
    expect(readTimestampResponse(x).ok).toBe(true);
  });
});

describe('M21: a too large input is refused before the copy', () => {
  const big = () => new Uint8Array(300_000);
  it('too-large from all readers, and nothing is copied', () => {
    const set = vi.spyOn(Uint8Array.prototype, 'set');
    try {
      expect(readTimestampResponse(big())).toEqual({ ok: false, reason: 'too-large' });
      expect(() => readToken(big())).toThrow(expect.objectContaining({ reason: 'too-large' }));
      expect(() => parseCertificate(big())).toThrow(
        expect.objectContaining({ reason: 'too-large' }),
      );
      expect(() => ownBytes(big())).toThrow(expect.objectContaining({ reason: 'too-large' }));
      expect(set).not.toHaveBeenCalled();
    } finally {
      set.mockRestore();
    }
  });
  it('control: the spy sees the copy of an input of allowed size', () => {
    const set = vi.spyOn(Uint8Array.prototype, 'set');
    try {
      expect(readTimestampResponse(RESPONSE).ok).toBe(true);
      expect(set).toHaveBeenCalled();
    } finally {
      set.mockRestore();
    }
  });
});
