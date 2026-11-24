// F1: the `tsa` field of the TSTInfo against the signer certificate (RFC 3161 § 2.4.2).
// F2: the TSTInfo is read as the schema it is: fixed order of the fields, each at most once, value ranges.
// Every rule here has a twin in tests/openssl.test.ts where `openssl ts -verify` can judge it.
import { verifyTimestampToken, readToken } from '../src/lib/index.ts';
import type { Reason } from '../src/lib/index.ts';
import { tlv } from '../src/lib/der.ts';
import { readTimestampResponse } from '../src/index.ts';
import { fixture, sha256 } from './helpers.ts';
import { build, ext, nameWith, octet, oidT, seq, int, type Opts } from './token-builder.ts';

async function reason(o: Opts = {}, options: object = {}): Promise<Reason | 'ok'> {
  const t = build(o);
  const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem], options);
  return r.ok ? 'ok' : r.reason;
}

const utf8 = (s: string) => new TextEncoder().encode(s);
const bool = (b: boolean) => tlv(1, Uint8Array.of(b ? 0xff : 0));
const dir = (cn: string, tag = 0x0c) => tlv(0xa0, tlv(0xa4, nameWith(tag, cn))); // tsa [0] directoryName
const gn = (tag: number, bytes: Uint8Array) => tlv(0xa0, tlv(tag, bytes)); // tsa [0] with a primitive GeneralName
const san = (...names: Uint8Array[]) => [ext('2.5.29.17', false, seq(...names))];
const accuracy = (...parts: Uint8Array[]) => seq(...parts);
const secs = (n: number) => tlv(2, Uint8Array.of(n));
const millis = (n: number) =>
  tlv(0x80, n < 128 ? Uint8Array.of(n) : Uint8Array.of(n >> 8, n & 0xff));
const micros = (n: number) =>
  tlv(0x81, n < 128 ? Uint8Array.of(n) : Uint8Array.of(n >> 8, n & 0xff));
const nonce = (n: number) => tlv(2, Uint8Array.of(n));
const exts = (...e: Uint8Array[]) => tlv(0xa1, ...e);
const anExt = (critical?: boolean) =>
  critical === undefined
    ? seq(oidT('1.2.3.4.5'), octet(tlv(5, new Uint8Array())))
    : seq(oidT('1.2.3.4.5'), bool(critical), octet(tlv(5, new Uint8Array())));

describe('F1: the tsa field names the signer (RFC 3161 § 2.4.2)', () => {
  it('a directoryName that is not the subject of the signer is refused', async () => {
    expect(await reason({ tstExtra: [dir('SomebodyElse')] })).toBe('tsa-mismatch');
  });
  it('the directoryName of the signer subject is accepted, also in another string type and case (simplified RFC 5280 rule)', async () => {
    expect(await reason({ tstExtra: [dir('TSA')] })).toBe('ok');
    expect(await reason({ tstExtra: [dir('tsa', 0x13)] })).toBe('ok');
    expect(await reason({ tstExtra: [dir(' Tsa ', 0x16)] })).toBe('ok');
  });
  it('the issuer of the signer is not the signer', async () => {
    expect(await reason({ tstExtra: [dir('CA')] })).toBe('tsa-mismatch');
  });
  it('no tsa field: nothing to compare', async () => {
    expect(await reason({})).toBe('ok');
  });
  it('a directoryName also matches a directoryName in the subjectAltName', async () => {
    const other = tlv(0xa4, nameWith(0x0c, 'Other Name'));
    expect(await reason({ tstExtra: [dir('Other Name')], extraTsaExts: san(other) })).toBe('ok');
    expect(await reason({ tstExtra: [dir('Third Name')], extraTsaExts: san(other) })).toBe(
      'tsa-mismatch',
    );
  });
  it('dNSName: equal to a subjectAltName entry (ASCII case ignored), else refused, also without any subjectAltName', async () => {
    const dns = tlv(0x82, utf8('tsa.example.org'));
    expect(
      await reason({ tstExtra: [gn(0x82, utf8('tsa.example.org'))], extraTsaExts: san(dns) }),
    ).toBe('ok');
    expect(
      await reason({ tstExtra: [gn(0x82, utf8('TSA.Example.ORG'))], extraTsaExts: san(dns) }),
    ).toBe('ok');
    expect(
      await reason({ tstExtra: [gn(0x82, utf8('other.example.org'))], extraTsaExts: san(dns) }),
    ).toBe('tsa-mismatch');
    expect(await reason({ tstExtra: [gn(0x82, utf8('tsa.example.org'))] })).toBe('tsa-mismatch');
  });
  it('rfc822Name, URI, iPAddress and registeredID: the same kind with the same bytes (exact), else refused', async () => {
    const cases: [number, Uint8Array, Uint8Array][] = [
      [0x81, utf8('ts@example.org'), utf8('ts@example.com')],
      [0x86, utf8('https://tsa.example.org/'), utf8('https://tsa.example.org')],
      [0x87, Uint8Array.of(192, 0, 2, 1), Uint8Array.of(192, 0, 2, 2)],
      [0x88, Uint8Array.of(0x2a, 3, 4), Uint8Array.of(0x2a, 3, 5)],
    ];
    for (const [tag, same, differs] of cases) {
      expect(
        await reason({ tstExtra: [gn(tag, same)], extraTsaExts: san(tlv(tag, same)) }),
        String(tag),
      ).toBe('ok');
      expect(
        await reason({ tstExtra: [gn(tag, differs)], extraTsaExts: san(tlv(tag, same)) }),
        String(tag),
      ).toBe('tsa-mismatch');
    }
    // exact: case is NOT ignored outside dNSName
    expect(
      await reason({
        tstExtra: [gn(0x81, utf8('TS@example.org'))],
        extraTsaExts: san(tlv(0x81, utf8('ts@example.org'))),
      }),
    ).toBe('tsa-mismatch');
  });
  it('the kind must be the same: a dNSName never matches a URI with the same text', async () => {
    expect(
      await reason({
        tstExtra: [gn(0x82, utf8('tsa.example.org'))],
        extraTsaExts: san(tlv(0x86, utf8('tsa.example.org'))),
      }),
    ).toBe('tsa-mismatch');
  });
  it('otherName: equal bytes in the subjectAltName, else refused', async () => {
    const other = tlv(0xa0, oidT('1.2.3.4.9'), tlv(0xa0, tlv(0x0c, utf8('x'))));
    const different = tlv(0xa0, oidT('1.2.3.4.9'), tlv(0xa0, tlv(0x0c, utf8('y'))));
    expect(await reason({ tstExtra: [tlv(0xa0, other)], extraTsaExts: san(other) })).toBe('ok');
    expect(await reason({ tstExtra: [tlv(0xa0, different)], extraTsaExts: san(other) })).toBe(
      'tsa-mismatch',
    );
  });
  it('a subjectAltName that cannot be read is bad-certificate when it is needed (and not needed for a subject match)', async () => {
    const junk = [ext('2.5.29.17', false, tlv(5, new Uint8Array()))];
    expect(await reason({ tstExtra: [gn(0x82, utf8('a.example.org'))], extraTsaExts: junk })).toBe(
      'bad-certificate',
    );
    expect(await reason({ tstExtra: [dir('TSA')], extraTsaExts: junk })).toBe('ok');
  });
  it('a tsa that is not a GeneralName is bad-tst-info', async () => {
    for (const bad of [
      tlv(0xa0), // empty [0]
      tlv(0xa0, tlv(0x89, utf8('x'))), // tag 9 is no GeneralName
      tlv(0xa0, tlv(0x82, Uint8Array.of(0xc3, 0xa4))), // dNSName must be ASCII
      tlv(0xa0, tlv(0x87, Uint8Array.of(1, 2, 3))), // iPAddress of 3 octets
      tlv(0xa0, tlv(0xa4, tlv(5, new Uint8Array()))), // directoryName that is no Name
      tlv(0xa0, tlv(0x82, utf8('a')), tlv(0x82, utf8('b'))), // two names
    ]) {
      expect(await reason({ tstExtra: [bad] })).toBe('bad-tst-info');
    }
  });
  it('the comparison is made at the verified signer: the tsa of a token whose signer was swapped does not match', async () => {
    // the real signer is TSA; a tsa naming the other certificate of the token (the intermediate) is a mismatch
    expect(await reason({ intermediate: {}, tstExtra: [dir('INT')] })).toBe('tsa-mismatch');
  });
  it('readToken exposes the name that was read (DER of the GeneralName)', () => {
    const t = build({ tstExtra: [dir('TSA')] });
    const info = readToken(t.token).info;
    expect(info.tsa).not.toBeNull();
    expect(info.tsa![0]).toBe(0xa4);
    expect(readToken(build().token).info.tsa).toBeNull();
  });
  it('the recorded answers of the real services still verify (freetsa, sectigo and certum set tsa; digicert does not)', async () => {
    const seen: Record<string, boolean> = {};
    for (const f of ['freetsa', 'sectigo', 'digicert', 'certum']) {
      const r = readTimestampResponse(fixture(`${f}.tsr`));
      expect(r.ok, f).toBe(true);
      if (r.ok) seen[f] = r.value.info.tsa !== null;
    }
    expect(seen).toEqual({ freetsa: true, sectigo: true, digicert: false, certum: true });
  });
});

describe('F2: the TSTInfo is read as a schema', () => {
  const fieldsOk = async (tstFields: Uint8Array[], expected: Reason | 'ok', o: Opts = {}) =>
    expect(await reason({ ...o, tstFields })).toBe(expected);

  it('every field in the order of the schema is accepted', async () => {
    const all = [
      accuracy(secs(1), millis(500), micros(250)),
      bool(true),
      nonce(7),
      dir('TSA'),
      exts(anExt(), anExt(true)),
    ];
    const t = build({ tstFields: all });
    const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem], {
      expectedNonce: Uint8Array.of(7),
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value.accuracyMs).toBe(1500.25);
  });
  it('each optional field alone, and none', async () => {
    for (const one of [
      [accuracy(secs(1))],
      [bool(true)],
      [nonce(7)],
      [dir('TSA')],
      [exts(anExt())],
      [],
    ]) {
      await fieldsOk(one, 'ok');
    }
  });
  it('ordering twice, accuracy twice, nonce twice, tsa twice, extensions twice are refused', async () => {
    await fieldsOk([bool(true), bool(true)], 'bad-tst-info');
    await fieldsOk([accuracy(secs(1)), accuracy(secs(2))], 'bad-tst-info');
    await fieldsOk([nonce(1), nonce(2)], 'bad-tst-info');
    await fieldsOk([dir('TSA'), dir('TSA')], 'bad-tst-info');
    await fieldsOk([exts(anExt()), exts(anExt())], 'bad-tst-info');
  });
  it('a field out of order is refused (each pair that swaps two neighbours)', async () => {
    const A = accuracy(secs(1));
    const O = bool(true);
    const N = nonce(7);
    const T = dir('TSA');
    const E = exts(anExt());
    await fieldsOk([N, A], 'bad-tst-info'); // accuracy after nonce
    await fieldsOk([O, A], 'bad-tst-info');
    await fieldsOk([N, O], 'bad-tst-info');
    await fieldsOk([T, N], 'bad-tst-info');
    await fieldsOk([E, T], 'bad-tst-info');
    await fieldsOk([E, N], 'bad-tst-info');
    await fieldsOk([A, O, N, T, E], 'ok'); // the reference order itself
  });
  it('an element that is no field of the schema is refused (anywhere after genTime)', async () => {
    await fieldsOk([tlv(5, new Uint8Array())], 'bad-tst-info');
    await fieldsOk([nonce(7), tlv(5, new Uint8Array())], 'bad-tst-info');
    await fieldsOk([tlv(4, Uint8Array.of(1))], 'bad-tst-info');
    await fieldsOk([tlv(0xa2, Uint8Array.of(5, 0))], 'bad-tst-info'); // [2] is not defined
    await fieldsOk([tlv(0x80, Uint8Array.of(1))], 'bad-tst-info'); // a bare [0] without the SEQUENCE
  });
  it('ordering FALSE written out is refused: DER leaves a DEFAULT value out', async () => {
    await fieldsOk([bool(false)], 'bad-tst-info');
    await fieldsOk([bool(true)], 'ok');
  });
  it('accuracy parts: in order, each once, seconds first', async () => {
    await fieldsOk([accuracy(millis(5), secs(1))], 'bad-tst-info');
    await fieldsOk([accuracy(micros(5), millis(5))], 'bad-tst-info');
    await fieldsOk([accuracy(secs(1), secs(2))], 'bad-tst-info');
    await fieldsOk([accuracy(millis(5), millis(6))], 'bad-tst-info');
    await fieldsOk([accuracy(micros(5), micros(6))], 'bad-tst-info');
    await fieldsOk([accuracy(secs(1), micros(5), millis(5))], 'bad-tst-info');
    await fieldsOk([accuracy(tlv(5, new Uint8Array()))], 'bad-tst-info');
    await fieldsOk([accuracy(secs(1), tlv(0x82, Uint8Array.of(1)))], 'bad-tst-info'); // [2] is not defined
    await fieldsOk([accuracy(secs(1), millis(5), micros(5))], 'ok');
    await fieldsOk([accuracy(millis(5), micros(5))], 'ok'); // seconds are optional
    await fieldsOk([accuracy(micros(5))], 'ok');
  });
  it('accuracy ranges: millis and micros are 1 to 999', async () => {
    for (const bad of [0, 1000, 1500]) {
      await fieldsOk([accuracy(secs(1), millis(bad))], 'bad-tst-info');
      await fieldsOk([accuracy(secs(1), micros(bad))], 'bad-tst-info');
    }
    for (const good of [1, 999]) {
      await fieldsOk([accuracy(secs(1), millis(good))], 'ok');
      await fieldsOk([accuracy(secs(1), micros(good))], 'ok');
    }
  });
  it('an empty accuracy SEQUENCE is allowed by the schema (all parts are optional)', async () => {
    await fieldsOk([accuracy()], 'ok');
  });
  it('extensions: a non-empty list of Extension, critical only written when TRUE', async () => {
    await fieldsOk([exts()], 'bad-tst-info'); // SIZE (1..MAX)
    await fieldsOk([tlv(0xa1, tlv(5, new Uint8Array()))], 'bad-tst-info'); // garbage inside [1]
    await fieldsOk([exts(seq(oidT('1.2.3')))], 'bad-tst-info'); // no value
    await fieldsOk(
      [
        exts(
          seq(oidT('1.2.3'), bool(true), octet(Uint8Array.of(5, 0)), octet(Uint8Array.of(5, 0))),
        ),
      ],
      'bad-tst-info',
    );
    await fieldsOk([exts(anExt(false))], 'bad-tst-info'); // critical FALSE written out
    await fieldsOk([exts(anExt(true))], 'ok'); // a critical extension is not judged (docs/grenzen.md)
    await fieldsOk([exts(anExt())], 'ok');
  });
  it('the head: version 1, policy OID, a messageImprint of exactly two parts', async () => {
    const imp = (...p: Uint8Array[]) => seq(...p);
    const alg = seq(oidT('2.16.840.1.101.3.4.2.1'));
    const algNull = seq(oidT('2.16.840.1.101.3.4.2.1'), tlv(5, new Uint8Array()));
    const hash = octet(sha256('x'));
    expect(await reason({ tstImprintRaw: imp(alg, hash, hash) })).toBe('bad-tst-info');
    expect(await reason({ tstImprintRaw: imp(alg) })).toBe('bad-tst-info');
    expect(
      await reason({
        tstImprintRaw: imp(
          seq(oidT('2.16.840.1.101.3.4.2.1'), tlv(5, new Uint8Array()), tlv(5, new Uint8Array())),
          hash,
        ),
      }),
    ).toBe('bad-tst-info');
    expect(
      await reason({ tstImprintRaw: imp(seq(oidT('2.16.840.1.101.3.4.2.1'), int(1)), hash) }),
    ).toBe('bad-tst-info');
    expect(await reason({ tstImprintRaw: imp(algNull, hash) })).toBe('ok');
    expect(await reason({ tstImprintRaw: imp(alg, hash) })).toBe('ok');
  });
  it('a recorded answer of a real service fills the schema in order (freetsa: ordering, nonce, tsa)', () => {
    const r = readTimestampResponse(fixture('freetsa.tsr'));
    expect(r.ok).toBe(true);
  });
  it('readToken throws bad-tst-info (not malformed) for a field out of order', () => {
    const t = build({ tstFields: [nonce(1), accuracy(secs(1))] });
    expect(() => readToken(t.token)).toThrowError(
      expect.objectContaining({ reason: 'bad-tst-info' }),
    );
  });
});
