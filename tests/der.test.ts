import {
  buildTimestampRequest,
  readTimestampResponse,
  verifyTimestampToken,
} from '../src/lib/index.ts';
import {
  DER_LIMITS,
  TAG,
  children,
  encodeLength,
  encodeOid,
  oid,
  parseDer,
  time,
  tlv,
} from '../src/lib/der.ts';
import { ReaderError } from '../src/lib/result.ts';
import { fixture, fixtureText, sha256 } from './helpers.ts';

const reasonOfParse = (bytes: Uint8Array): string => {
  try {
    const n = parseDer(bytes);
    if ((n.tag & 0x20) !== 0) children(n);
    return 'ok';
  } catch (e) {
    return e instanceof ReaderError ? e.reason : 'other-error';
  }
};

describe('DER reader', () => {
  it('reads definite lengths in the shortest form', () => {
    expect(reasonOfParse(Uint8Array.of(0x04, 0x02, 1, 2))).toBe('ok');
    expect(reasonOfParse(tlv(TAG.octetString, new Uint8Array(200)))).toBe('ok'); // 0x81 0xc8
  });
  it('refuses indefinite length, long forms that could be short, and leading zero length bytes', () => {
    expect(reasonOfParse(Uint8Array.of(0x30, 0x80, 0, 0))).toBe('indefinite-length');
    expect(reasonOfParse(Uint8Array.of(0x04, 0x81, 0x02, 1, 2))).toBe('malformed');
    expect(reasonOfParse(Uint8Array.of(0x04, 0x82, 0x00, 0x90, ...new Uint8Array(0x90)))).toBe(
      'malformed',
    );
  });
  it('refuses a length beyond the data, trailing bytes and high tag numbers', () => {
    expect(reasonOfParse(Uint8Array.of(0x04, 0x05, 1, 2))).toBe('malformed');
    expect(reasonOfParse(Uint8Array.of(0x04, 0x01, 1, 0))).toBe('trailing-bytes');
    expect(reasonOfParse(Uint8Array.of(0x1f, 0x81, 0x01, 0x00))).toBe('malformed');
    expect(reasonOfParse(new Uint8Array(0))).toBe('malformed');
  });
  it('bounds the size and the nesting depth', () => {
    expect(reasonOfParse(new Uint8Array(DER_LIMITS.maxBytes + 1))).toBe('too-large');
    let nested: Uint8Array = Uint8Array.of(0x05, 0x00);
    for (let i = 0; i < DER_LIMITS.maxDepth + 1; i += 1) nested = tlv(TAG.sequence, nested);
    expect(reasonOfParse(nested)).toBe('too-deep');
    let fine: Uint8Array = Uint8Array.of(0x05, 0x00);
    for (let i = 0; i < DER_LIMITS.maxDepth - 1; i += 1) fine = tlv(TAG.sequence, fine);
    expect(reasonOfParse(fine)).toBe('ok');
  });
  it('bounds the number of children', () => {
    const many = tlv(
      TAG.sequence,
      ...Array.from({ length: DER_LIMITS.maxChildren + 1 }, () => Uint8Array.of(5, 0)),
    );
    expect(reasonOfParse(many)).toBe('too-large');
  });
  it('writes and reads object identifiers, including large arcs', () => {
    for (const id of [
      '2.16.840.1.101.3.4.2.1',
      '1.2.840.113549.1.7.2',
      '2.5.29.37',
      '1.3.6.1.4.1.311.10.3.8',
      '2.999.3',
    ]) {
      expect(oid(parseDer(encodeOid(id)))).toBe(id);
    }
    expect(() => oid(parseDer(Uint8Array.of(0x06, 0x02, 0x2a, 0x80)))).toThrow(); // unfinished arc
    expect(() => oid(parseDer(Uint8Array.of(0x06, 0x03, 0x2a, 0x80, 0x01)))).toThrow(); // leading 0x80
  });
  it('writes lengths at the form boundaries', () => {
    expect([...encodeLength(127)]).toEqual([127]);
    expect([...encodeLength(128)]).toEqual([0x81, 128]);
    expect([...encodeLength(256)]).toEqual([0x82, 1, 0]);
  });
  it('reads up to 9 fraction digits and cuts them off to milliseconds (never rounds)', () => {
    const gt = (s: string) =>
      time({ tag: TAG.generalizedTime, raw: new Uint8Array(), value: new TextEncoder().encode(s) });
    const base = Date.UTC(2026, 10, 23, 13, 5, 56);
    expect(gt('20261123130556.1234Z')).toBe(base + 123);
    expect(gt('20261123130556.123456Z')).toBe(base + 123);
    expect(gt('20261123130556.123456789Z')).toBe(base + 123);
    expect(gt('20261123130556.9999Z')).toBe(base + 999); // cut off, not rounded up to the next second
    expect(gt('20261123130556.0009Z')).toBe(base); // below one millisecond
    expect(gt('20261123130556.01Z')).toBe(base + 10);
    for (const bad of [
      '20261123130556.1230Z', // trailing zero
      '20261123130556.100Z',
      '20261123130556.1234567890Z', // 10 digits
      '20261123130556,123Z', // comma
      '20261123130556.123456', // no Z
      '20261123130556.123+0100', // zone
      '20261123130560.123456Z', // :60
      '20261123130556.Z', // empty fraction
    ]) {
      expect(() => gt(bad), bad).toThrow();
    }
  });
  it('reads strict times only', () => {
    const gt = (s: string) =>
      time({ tag: TAG.generalizedTime, raw: new Uint8Array(), value: new TextEncoder().encode(s) });
    expect(gt('20261123130556Z')).toBe(Date.UTC(2026, 10, 23, 13, 5, 56));
    expect(gt('20261123130556.5Z')).toBe(Date.UTC(2026, 10, 23, 13, 5, 56) + 500);
    for (const bad of [
      '20261123130556',
      '20261323130556Z',
      '20260230130556Z',
      '20261123130556.50Z',
      '2026112313055Z',
      '20261123250556Z',
    ]) {
      expect(() => gt(bad), bad).toThrow();
    }
  });
});

describe('request', () => {
  const hash = sha256('probe');
  const nonce = Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8);
  it('is the DER an RFC 3161 server expects (golden bytes)', () => {
    const r = buildTimestampRequest(hash, nonce);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const hex = Buffer.from(r.value).toString('hex');
    expect(hex.startsWith('3043020101' + '3031' + '300d06096086480165030402010500' + '0420')).toBe(
      true,
    );
    expect(hex.endsWith('0208' + '0102030405060708' + '0101ff')).toBe(true);
    expect(r.value.length).toBe(69);
  });
  it('matches the recorded request byte for byte', () => {
    const r = buildTimestampRequest(hash, nonce);
    expect(r.ok && Buffer.from(r.value).equals(Buffer.from(fixture('freetsa.tsq')))).toBe(true);
  });
  it('keeps the nonce positive (adds a zero byte when the top bit is set)', () => {
    const r = buildTimestampRequest(hash, Uint8Array.of(0xff, 0x01));
    expect(r.ok).toBe(true);
    if (r.ok) expect(Buffer.from(r.value).toString('hex')).toContain('020300ff01');
  });
  it('refuses a hash or nonce of the wrong size', () => {
    expect(buildTimestampRequest(new Uint8Array(31), nonce)).toEqual({
      ok: false,
      reason: 'bad-hash',
    });
    expect(buildTimestampRequest(hash, new Uint8Array(0))).toEqual({
      ok: false,
      reason: 'bad-nonce',
    });
    expect(buildTimestampRequest(hash, new Uint8Array(17))).toEqual({
      ok: false,
      reason: 'bad-nonce',
    });
  });
});

describe('response', () => {
  it('reads the recorded answer', () => {
    const r = readTimestampResponse(fixture('freetsa.tsr'));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.status).toBe(0);
      expect(r.value.info).toMatchObject({
        hashName: 'SHA-256',
        serial: '0a71c442',
        policy: '1.2.3.4.1',
      });
      expect(Buffer.from(r.value.info.imprint).equals(Buffer.from(sha256('probe')))).toBe(true);
    }
  });
  it('reports a refusal with the status number', () => {
    // TimeStampResp { PKIStatusInfo { status 2 (rejection) } }
    const refused = tlv(TAG.sequence, tlv(TAG.sequence, tlv(TAG.integer, Uint8Array.of(2))));
    expect(readTimestampResponse(refused)).toEqual({ ok: false, reason: 'rejected', detail: '2' });
  });
  it('reports a granted answer without a token', () => {
    const granted = tlv(TAG.sequence, tlv(TAG.sequence, tlv(TAG.integer, Uint8Array.of(0))));
    expect(readTimestampResponse(granted)).toEqual({ ok: false, reason: 'no-token' });
  });
});

describe('fuzzing (seeded): the public functions never throw and never accept noise', () => {
  function rng(seed: number): () => number {
    let s = seed >>> 0;
    return () => {
      s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
      return s / 4294967296;
    };
  }
  const real = fixture('freetsa.tsr');
  it('random bytes and mutated real answers', async () => {
    const rand = rng(7);
    for (let i = 0; i < 1500; i += 1) {
      const bytes = new Uint8Array(Math.floor(rand() * 200));
      for (let j = 0; j < bytes.length; j += 1) bytes[j] = Math.floor(rand() * 256);
      expect(readTimestampResponse(bytes).ok).toBe(false);
    }
    for (let i = 0; i < 1500; i += 1) {
      const copy = Uint8Array.from(real);
      for (let k = 0; k < 1 + Math.floor(rand() * 4); k += 1)
        copy[Math.floor(rand() * copy.length)] = Math.floor(rand() * 256);
      const r = readTimestampResponse(copy);
      if (r.ok) {
        const v = await verifyTimestampToken(r.value.token, sha256('probe'), [
          fixtureText('cacert.pem'),
        ]);
        expect(typeof v.ok).toBe('boolean'); // may be ok only when the changes hit unused bytes
      }
    }
  });
});
