// Audit findings B1 to B3 (token and certificate readers):
// B1  an element too many in a SEQUENCE that has a fixed shape is refused, as OpenSSL does (EncapsulatedContentInfo,
//     the issuerAndSerialNumber of the SignerInfo, an Attribute, an AttributeTypeAndValue of a name);
// B2  what the public readers give back never points into the caller's buffer;
// B3  error codes: a bad `accuracy`/`ordering` is `bad-tst-info`, a hostile input object of the batch check is `bad-options`.
import { runInNewContext } from 'node:vm';
import {
  buildTimestampRequest,
  parseCertificate,
  readServices,
  readTimestampResponse,
  readToken,
  signRelayRequest,
  verifyTimestampToken,
} from '../src/index.ts';
import type { Reason } from '../src/lib/index.ts';
import { verifyBatchedTimestamp } from '../src/lib/batch.ts';
import { tlv } from '../src/lib/der.ts';
import { sameName } from '../src/lib/x509.ts';
import { fixture, sha256 } from './helpers.ts';
import { build, int, nameWith, octet, oidT, seq, set, type Opts } from './token-builder.ts';

async function reason(o: Opts = {}, options: object = {}): Promise<Reason | 'ok'> {
  const t = build(o);
  const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem], options);
  return r.ok ? 'ok' : r.reason;
}
const readReason = (token: Uint8Array): string => {
  try {
    readToken(token);
    return 'ok';
  } catch (e) {
    return (e as { reason?: string }).reason ?? String(e);
  }
};

describe('B1: an element too many is refused (as OpenSSL does)', () => {
  const forged = tlv(0xa0, octet(new TextEncoder().encode('FORGED')));
  it('EncapsulatedContentInfo: a second [0] or any other trailing element is bad-structure', async () => {
    expect(await reason({})).toBe('ok');
    expect(await reason({ encapExtra: [forged] })).toBe('bad-structure');
    expect(await reason({ encapExtra: [tlv(5, new Uint8Array())] })).toBe('bad-structure');
    expect(await reason({ encapExtra: [forged, forged] })).toBe('bad-structure');
    expect(readReason(build({ encapExtra: [forged] }).token)).toBe('bad-structure');
  });
  it('SignerInfo.sid (issuerAndSerialNumber): a third element is bad-structure', async () => {
    expect(await reason({ sidExtra: [int(1)] })).toBe('bad-structure');
    expect(await reason({ sidExtra: [tlv(5, new Uint8Array())] })).toBe('bad-structure');
    expect(readReason(build({ sidExtra: [int(1)] }).token)).toBe('bad-structure');
  });
  it('an Attribute of the signed attributes: a third element is bad-structure', async () => {
    expect(await reason({ attributeExtra: [tlv(5, new Uint8Array())] })).toBe('bad-structure');
    expect(await reason({ attributeExtra: [set()] })).toBe('bad-structure');
  });
  it('an AttributeTypeAndValue of a name: a third element makes the name unreadable (compared byte for byte)', () => {
    const atv = (text: string, ...extra: Uint8Array[]) =>
      seq(set(seq(oidT('2.5.4.3'), tlv(0x0c, new TextEncoder().encode(text)), ...extra)));
    // sanity: ASCII case is ignored by the simplified rule
    expect(sameName(atv('TSA'), atv('tsa'))).toBe(true);
    // with a third element the name is unreadable: only identical bytes count
    expect(sameName(atv('TSA', int(1)), atv('tsa', int(1)))).toBe(false);
    expect(sameName(atv('TSA', int(1)), atv('TSA', int(1)))).toBe(true);
    // a name with one element in the ATV is unreadable, too
    const one = seq(set(seq(oidT('2.5.4.3'))));
    expect(sameName(one, one)).toBe(true);
    expect(sameName(one, atv('tsa'))).toBe(false);
    expect(nameWith(0x0c, 'TSA').length).toBeGreaterThan(0);
  });
  it('the recorded answers of real services are still read', () => {
    for (const f of ['freetsa', 'sectigo', 'digicert', 'certum']) {
      expect(readTimestampResponse(fixture(`${f}.tsr`)).ok, f).toBe(true);
    }
  });
});

/** Every byte field turned into hex (and a Map into entries), so that two reads can be compared by value. */
function snap(value: unknown): unknown {
  if (value instanceof Uint8Array) return `hex:${Buffer.from(value).toString('hex')}`;
  if (value instanceof Map) return [...value].map(([k, v]) => [k, snap(v)]);
  if (Array.isArray(value)) return value.map(snap);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, snap(v)]));
  }
  return value;
}

describe('B2: the readers give back copies, never views into the caller buffer', () => {
  const RESPONSE = fixture('freetsa.tsr');
  const tokenOf = (): Uint8Array => {
    const r = readTimestampResponse(RESPONSE);
    if (!r.ok) throw new Error('fixture unreadable');
    return r.value.token;
  };

  it('readTimestampResponse: overwriting the input afterwards changes nothing', () => {
    const input = new Uint8Array(RESPONSE);
    const r = readTimestampResponse(input);
    expect(r.ok).toBe(true);
    const before = JSON.stringify(snap(r));
    expect(before).toContain('hex:'); // token, imprint, nonce and tsa are really in there
    // the token has a buffer of its own (not a view into a buffer that holds the whole answer)
    if (r.ok) expect(r.value.token.buffer.byteLength).toBe(r.value.token.byteLength);
    input.fill(0);
    expect(JSON.stringify(snap(r))).toBe(before);
    if (r.ok) {
      expect(r.value.info.nonce).not.toBeNull();
      expect(r.value.info.tsa).not.toBeNull();
      for (const bytes of [
        r.value.token,
        r.value.info.imprint,
        r.value.info.nonce!,
        r.value.info.tsa!,
      ]) {
        expect(bytes.buffer).not.toBe(input.buffer);
      }
    }
  });
  it('readTimestampResponse: changing the result does not reach the input, nor the other fields', () => {
    const input = new Uint8Array(RESPONSE);
    const r = readTimestampResponse(input);
    if (!r.ok) throw new Error('unreadable');
    r.value.token.fill(0);
    r.value.info.imprint.fill(0);
    expect(Buffer.from(input).equals(Buffer.from(RESPONSE))).toBe(true);
    const again = readTimestampResponse(input);
    expect(again.ok).toBe(true);
    if (again.ok) expect(Buffer.from(again.value.token).equals(Buffer.from(tokenOf()))).toBe(true);
  });
  it('readTimestampResponse: an input in a SharedArrayBuffer, and one of another realm, give private copies too', () => {
    const shared = new Uint8Array(new SharedArrayBuffer(RESPONSE.length));
    shared.set(RESPONSE);
    const r = readTimestampResponse(shared);
    expect(r.ok).toBe(true);
    const before = JSON.stringify(snap(r));
    shared.fill(0);
    expect(JSON.stringify(snap(r))).toBe(before);
    if (r.ok) expect(r.value.token.buffer instanceof SharedArrayBuffer).toBe(false);

    const foreign = runInNewContext('new Uint8Array(n)', { n: RESPONSE.length }) as Uint8Array;
    foreign.set(RESPONSE);
    expect(foreign instanceof Uint8Array).toBe(false);
    const f = readTimestampResponse(foreign);
    expect(f.ok).toBe(true);
    const fBefore = JSON.stringify(snap(f));
    foreign.fill(0);
    expect(JSON.stringify(snap(f))).toBe(fBefore);
    expect(fBefore).toBe(before);
  });
  it('readTimestampResponse: an own `length` property does not fool the copy', () => {
    const input = new Uint8Array(RESPONSE);
    Object.defineProperty(input, 'length', { value: 7 });
    expect(readTimestampResponse(input).ok).toBe(true);
  });
  it('readTimestampResponse: not bytes, and too large, are failures (no throw)', () => {
    for (const bad of [[1, 2, 3], 'abc', null, undefined, {}, new Proxy(new Uint8Array(4), {})]) {
      const r = readTimestampResponse(bad as never);
      expect(r.ok).toBe(false);
    }
    expect(readTimestampResponse(new Uint8Array(300_000))).toEqual({
      ok: false,
      reason: 'too-large',
    });
  });
  it('readToken: nothing of the result points into the input (certificates and signer included)', () => {
    const input = new Uint8Array(tokenOf());
    const parsed = readToken(input);
    expect(parsed.certificates.length).toBeGreaterThan(0);
    const before = JSON.stringify(snap(parsed));
    input.fill(0);
    expect(JSON.stringify(snap(parsed))).toBe(before);
    expect(parsed.raw).not.toBe(input);
    expect(parsed.raw.buffer).not.toBe(input.buffer);
  });
  it('readToken: a token in a SharedArrayBuffer is read into a private copy', () => {
    const t = tokenOf();
    const shared = new Uint8Array(new SharedArrayBuffer(t.length));
    shared.set(t);
    const parsed = readToken(shared);
    const before = JSON.stringify(snap(parsed));
    shared.fill(0);
    expect(JSON.stringify(snap(parsed))).toBe(before);
  });
  it('readToken: not bytes is malformed, a token over the limit too-large', () => {
    for (const bad of [[1, 2], 'x', null, new Proxy(new Uint8Array(4), {})]) {
      expect(readReason(bad as never)).toBe('malformed');
    }
    expect(readReason(new Uint8Array(300_000))).toBe('too-large');
  });
  it('parseCertificate: overwriting the input afterwards changes nothing', () => {
    const der = new Uint8Array(build().tsaCert);
    const cert = parseCertificate(der);
    const before = JSON.stringify(snap(cert));
    der.fill(0);
    expect(JSON.stringify(snap(cert))).toBe(before);
    expect(cert.raw.buffer).not.toBe(der.buffer);
  });
});

describe('B3: error codes', () => {
  const bool = (b: number) => tlv(1, Uint8Array.of(b));
  const accuracy = (...parts: Uint8Array[]) => seq(...parts);
  it('a bad accuracy is bad-tst-info (not malformed): negative or padded seconds, bad millis/micros', async () => {
    const fields = (f: Uint8Array) => ({ tstFields: [f] });
    const bad = [
      accuracy(tlv(2, Uint8Array.of(0xff))), // -1 seconds
      accuracy(tlv(2, Uint8Array.of(0x80))), // negative
      accuracy(tlv(2, Uint8Array.of(0, 5))), // not minimal
      accuracy(tlv(2, new Uint8Array())), // empty INTEGER
      accuracy(tlv(2, Uint8Array.of(1, 2, 3, 4, 5, 6, 7))), // too large for a number
      accuracy(tlv(2, Uint8Array.of(1)), tlv(0x80, Uint8Array.of(0xff))), // negative millis
      accuracy(tlv(2, Uint8Array.of(1)), tlv(0x80, new Uint8Array())), // empty millis
      accuracy(tlv(2, Uint8Array.of(1)), tlv(0x81, Uint8Array.of(0, 5))), // micros not minimal
    ];
    for (const [i, a] of bad.entries()) {
      expect(await reason(fields(a)), String(i)).toBe('bad-tst-info');
      expect(readReason(build(fields(a)).token), String(i)).toBe('bad-tst-info');
    }
    expect(await reason(fields(accuracy(tlv(2, Uint8Array.of(1)))))).toBe('ok');
  });
  it('an ordering that is no DER BOOLEAN is bad-tst-info', async () => {
    for (const v of [1, 0x7f, 0x80]) {
      expect(await reason({ tstFields: [bool(v)] }), String(v)).toBe('bad-tst-info');
    }
    expect(await reason({ tstFields: [tlv(1, new Uint8Array())] })).toBe('bad-tst-info');
    expect(await reason({ tstFields: [bool(0xff)] })).toBe('ok');
  });
  it('verifyBatchedTimestamp: an input object whose getPrototypeOf trap throws is bad-options, and never throws', async () => {
    const hostile = (target: object) =>
      new Proxy(target, {
        getPrototypeOf() {
          throw new Error('trap');
        },
      });
    const t = build();
    const good = {
      token: t.token,
      hash: t.imprint,
      batch: { v: 1, size: 1, index: 0, salt: '', path: [] },
    };
    expect(await verifyBatchedTimestamp(hostile({}) as never, [t.caPem])).toEqual({
      ok: false,
      reason: 'bad-options',
    });
    expect(await verifyBatchedTimestamp(hostile(good) as never, [t.caPem])).toEqual({
      ok: false,
      reason: 'bad-options',
    });
    // a getter that throws, and a proxy whose get/getOwnPropertyDescriptor traps throw, are bad-options as well
    const getter = {
      get token(): Uint8Array {
        throw new Error('getter');
      },
      hash: t.imprint,
      batch: good.batch,
    };
    expect(await verifyBatchedTimestamp(getter as never, [t.caPem])).toEqual({
      ok: false,
      reason: 'bad-options',
    });
    const trapped = new Proxy(good, {
      getOwnPropertyDescriptor() {
        throw new Error('trap');
      },
    });
    expect(await verifyBatchedTimestamp(trapped as never, [t.caPem])).toEqual({
      ok: false,
      reason: 'bad-options',
    });
    // a hostile `batch` stays bad-batch
    const r = await verifyBatchedTimestamp({ ...good, batch: hostile(good.batch) } as never, [
      t.caPem,
    ]);
    expect(r).toEqual({ ok: false, reason: 'bad-batch' });
  });
  it('the other public functions answer a hostile object with their own code, never a throw', async () => {
    const hostile = (target: object) =>
      new Proxy(target, {
        getPrototypeOf() {
          throw new Error('trap');
        },
        get() {
          throw new Error('trap');
        },
        ownKeys() {
          throw new Error('trap');
        },
        has() {
          throw new Error('trap');
        },
      });
    const t = build();
    expect(await verifyTimestampToken(t.token, t.imprint, [t.caPem], hostile({}))).toEqual({
      ok: false,
      reason: 'bad-options',
    });
    expect(await signRelayRequest(hostile({}) as never)).toEqual({
      ok: false,
      reason: 'bad-options',
    });
    expect(readServices(hostile({}))).toEqual({ ok: false, reason: 'bad-services' });
    expect(buildTimestampRequest(sha256('x'), hostile(new Uint8Array(4)) as never)).toEqual({
      ok: false,
      reason: 'bad-nonce',
    });
  });
});
