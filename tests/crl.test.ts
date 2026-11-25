// The CRL reader (`parseCrl`): the good form and every flaw it must refuse as `bad-crl`.
import { ReaderError, parseCrl } from '../src/index.ts';
import { tlv } from '../src/lib/der.ts';
import { build, ext, seq, set, oidT } from './token-builder.ts';
import { OID_CRL, buildCrl, crlEntry } from './crl-builder.ts';

const keys = build().keys;
const mk = (o: Partial<Parameters<typeof buildCrl>[0]> = {}) => buildCrl({ key: keys.ca, ...o });
const ENTRY = { serial: 7, date: '20251210000000Z' };
const bool = (b: boolean) => tlv(1, Uint8Array.of(b ? 0xff : 0));
const enumerated = (n: number) => tlv(0x0a, Uint8Array.of(n));

function refused(der: unknown): void {
  let caught: unknown;
  try {
    parseCrl(der as Uint8Array);
  } catch (e) {
    caught = e;
  }
  expect(caught).toBeInstanceOf(ReaderError);
  expect((caught as ReaderError).reason).toBe('bad-crl');
}

describe('parseCrl: the good forms', () => {
  it('reads a v1 list (no version field, no extensions) with entries', () => {
    const crl = parseCrl(mk({ entries: [ENTRY, { serial: 9, date: '20251211000000Z' }] }));
    expect(crl.revoked.map((e) => e.serial[0])).toEqual([7, 9]);
    expect(crl.thisUpdate).toBe(Date.UTC(2025, 11, 1));
    expect(crl.nextUpdate).toBe(Date.UTC(2026, 1, 1));
    expect(crl.revoked[0]!.revocationDate).toBe(Date.UTC(2025, 11, 10));
    expect(crl.revoked[0]!.reason).toBeNull();
  });
  it('reads reason and invalidity date; UTCTime works too', () => {
    const crl = parseCrl(
      mk({ entries: [{ ...ENTRY, reason: 1, invalidity: '20251205000000Z' }], utcTimes: true }),
    );
    expect(crl.revoked[0]).toMatchObject({ reason: 1, invalidityDate: Date.UTC(2025, 11, 5) });
  });
  it('accepts an empty list, a v2 list without entries and the harmless extensions', () => {
    expect(parseCrl(mk()).revoked).toEqual([]);
    expect(parseCrl(mk({ version: 1 })).revoked).toEqual([]);
    parseCrl(
      mk({
        exts: [
          ext(OID_CRL.number, false, tlv(2, Uint8Array.of(5))),
          ext('1.2.3.4.5', false, seq()), // unknown, not critical: ignored
          ext(OID_CRL.idp, true, seq(tlv(0x81, Uint8Array.of(0xff)))), // only user certificates
        ],
      }),
    );
  });
  it('ignores an unknown entry extension that is not critical and a hold instruction', () => {
    parseCrl(
      mk({
        entries: [
          {
            ...ENTRY,
            exts: [
              ext('1.2.3.4.5', false, seq()),
              ext('2.5.29.23', false, tlv(6, Uint8Array.of(0x2a))),
            ],
          },
        ],
      }),
    );
  });
  it('copies its input (a later change of the buffer changes nothing)', () => {
    const der = mk({ entries: [ENTRY] });
    const copy = new Uint8Array(der);
    const crl = parseCrl(copy);
    copy.fill(0);
    expect(crl.revoked[0]!.serial[0]).toBe(7);
  });
});

describe('parseCrl: every flaw is bad-crl', () => {
  const flaws: [string, () => unknown][] = [
    ['not a Uint8Array', () => 'abc'],
    ['another typed array', () => new Uint16Array(40)],
    ['empty', () => new Uint8Array()],
    ['too large', () => new Uint8Array(262145)],
    ['trailing byte', () => Uint8Array.of(...mk(), 0)],
    ['version 3', () => mk({ version: 2 })],
    ['version 1 (v1 is written without the field)', () => mk({ version: 0 })],
    [
      'extensions without version',
      () => mk({ entries: [{ ...ENTRY, reason: 1 }], version: 'none' }),
    ],
    ['no nextUpdate', () => mk({ nextUpdate: null })],
    ['nextUpdate with a fraction', () => mk({ nextUpdate: '20260201000000.5Z' })],
    ['inner and outer algorithm differ', () => mk({ outerAlg: seq(oidT('1.2.840.10045.4.3.3')) })],
    ['empty issuer', () => mk({ issuerRaw: seq() })],
    ['element after the extensions', () => mk({ tbsExtra: [tlv(4, Uint8Array.of(1))] })],
    [
      'negative serial',
      () => mk({ entries: [{ serial: Uint8Array.of(0x80), date: '20251210000000Z' }] }),
    ],
    ['entry with one field', () => mk({ revokedRaw: seq(seq(tlv(2, Uint8Array.of(7)))) })],
    ['entry with a bad date', () => mk({ entries: [{ ...ENTRY, date: '20251310000000Z' }] })],
    ['unknown critical CRL extension', () => mk({ exts: [ext('1.2.3.4.5', true, seq())] })],
    [
      'delta CRL indicator',
      () => mk({ exts: [ext(OID_CRL.delta, true, tlv(2, Uint8Array.of(3)))] }),
    ],
    [
      'delta CRL indicator, not critical',
      () => mk({ exts: [ext(OID_CRL.delta, false, tlv(2, Uint8Array.of(3)))] }),
    ],
    ['critical freshestCRL', () => mk({ exts: [ext('2.5.29.46', true, seq())] })],
    [
      'the same CRL extension twice',
      () =>
        mk({
          exts: [
            ext(OID_CRL.number, false, tlv(2, Uint8Array.of(1))),
            ext(OID_CRL.number, false, tlv(2, Uint8Array.of(2))),
          ],
        }),
    ],
    [
      'indirect CRL',
      () => mk({ exts: [ext(OID_CRL.idp, true, seq(tlv(0x84, Uint8Array.of(0xff))))] }),
    ],
    [
      'CRL of attribute certificates',
      () => mk({ exts: [ext(OID_CRL.idp, true, seq(tlv(0x85, Uint8Array.of(0xff))))] }),
    ],
    [
      'issuing distribution point out of order',
      () =>
        mk({
          exts: [
            ext(OID_CRL.idp, true, seq(tlv(0x82, Uint8Array.of(0)), tlv(0x81, Uint8Array.of(0)))),
          ],
        }),
    ],
    [
      'issuing distribution point with a doubled field',
      () =>
        mk({
          exts: [
            ext(OID_CRL.idp, true, seq(tlv(0x81, Uint8Array.of(0)), tlv(0x81, Uint8Array.of(0)))),
          ],
        }),
    ],
    [
      'issuing distribution point with an unknown field',
      () => mk({ exts: [ext(OID_CRL.idp, true, seq(tlv(0x86, Uint8Array.of(0))))] }),
    ],
    [
      'issuing distribution point with a bad boolean',
      () => mk({ exts: [ext(OID_CRL.idp, true, seq(tlv(0x81, Uint8Array.of(2))))] }),
    ],
    [
      'entry with certificateIssuer (indirect)',
      () => mk({ entries: [{ ...ENTRY, exts: [ext(OID_CRL.certIssuer, true, seq())] }] }),
    ],
    [
      'unknown critical entry extension',
      () => mk({ entries: [{ ...ENTRY, exts: [ext('1.2.3.4.5', true, seq())] }] }),
    ],
    [
      'reason removeFromCRL (only for delta lists)',
      () => mk({ entries: [{ ...ENTRY, reason: 8 }] }),
    ],
    ['reason 7', () => mk({ entries: [{ ...ENTRY, reason: 7 }] })],
    ['reason 11', () => mk({ entries: [{ ...ENTRY, reason: 11 }] })],
    [
      'reason that is no ENUMERATED',
      () =>
        mk({
          entries: [{ ...ENTRY, exts: [ext(OID_CRL.reason, false, tlv(2, Uint8Array.of(1)))] }],
        }),
    ],
    [
      'invalidity date as UTCTime',
      () =>
        mk({
          entries: [
            {
              ...ENTRY,
              exts: [
                ext(
                  OID_CRL.invalidity,
                  false,
                  tlv(0x17, new TextEncoder().encode('251205000000Z')),
                ),
              ],
            },
          ],
        }),
    ],
    [
      'the same entry extension twice',
      () =>
        mk({
          entries: [
            {
              ...ENTRY,
              exts: [
                ext(OID_CRL.reason, false, enumerated(1)),
                ext(OID_CRL.reason, false, enumerated(1)),
              ],
            },
          ],
        }),
    ],
    [
      'entry with a third element that is no extension list',
      () =>
        mk({
          entries: [
            {
              serial: 1,
              date: '',
              raw: seq(
                tlv(2, Uint8Array.of(7)),
                tlv(0x18, new TextEncoder().encode('20251210000000Z')),
                bool(true),
              ),
            },
          ],
        }),
    ],
    ['a certificate instead of a list', () => build().tsaCert],
    [
      'signature BIT STRING with unused bits',
      () => {
        const d = new Uint8Array(mk());
        // the last BIT STRING header: 03 len 00 <sig>; set the unused-bits byte
        const at = d.lastIndexOf(0x03, d.length - 60);
        d[at + 2] = 1;
        return d;
      },
    ],
  ];
  for (const [label, make] of flaws) {
    it(label, () => {
      const v = make();
      if (v === null) return;
      refused(v);
    });
  }
  it('an empty extension list is refused', () => {
    refused(
      (() => {
        // [0] { SEQUENCE {} } written by hand after the issuer and times
        const tbs = seq(
          tlv(2, Uint8Array.of(1)),
          seq(oidT('1.2.840.10045.4.3.2')),
          seq(set(seq(oidT('2.5.4.3'), tlv(0x0c, new TextEncoder().encode('CA'))))),
          tlv(0x18, new TextEncoder().encode('20251201000000Z')),
          tlv(0x18, new TextEncoder().encode('20260201000000Z')),
          tlv(0xa0, seq()),
        );
        return seq(tbs, seq(oidT('1.2.840.10045.4.3.2')), tlv(3, Uint8Array.of(0, 1)));
      })(),
    );
  });
  it('every truncation and every byte flip gives bad-crl or a list, never another error', () => {
    const good = mk({
      entries: [{ ...ENTRY, reason: 4 }],
      exts: [ext(OID_CRL.number, false, tlv(2, Uint8Array.of(5)))],
    });
    for (let n = 0; n < good.length; n += 1) refused(good.subarray(0, n));
    for (let i = 0; i < good.length; i += 1) {
      for (const v of [0, 0xff, good[i]! ^ 0x01]) {
        const copy = new Uint8Array(good);
        copy[i] = v;
        try {
          parseCrl(copy);
        } catch (e) {
          expect(e).toBeInstanceOf(ReaderError);
          expect((e as ReaderError).reason).toBe('bad-crl');
        }
      }
    }
  });
  it('more than 256 entries is bad-crl (the limit of the DER reader)', () => {
    const many = Array.from({ length: 257 }, (_, i) =>
      crlEntry({ serial: Uint8Array.of(1, i >> 8, i & 255), date: '20251210000000Z' }),
    );
    refused(mk({ revokedRaw: seq(...many) }));
    const ok256 = many.slice(0, 256);
    expect(parseCrl(mk({ revokedRaw: seq(...ok256) })).revoked.length).toBe(256);
  });
});
