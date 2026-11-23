import {
  parseCertificate,
  parsePemCertificates,
  readToken,
  verifyTimestampToken,
} from '../src/lib/index.ts';
import type { Reason } from '../src/lib/index.ts';
import { ctx, tlv } from '../src/lib/der.ts';
import { build, ext, int, octet, oidT, seq, type Opts } from './token-builder.ts';

const TIME = new Date('2026-01-01T00:00:00Z');

async function reason(o: Opts = {}, options: unknown = {}): Promise<Reason | 'ok'> {
  const t = build(o);
  const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem], options as object);
  return r.ok ? 'ok' : r.reason;
}

const TS = '1.3.6.1.5.5.7.3.8';

describe('the token builder', () => {
  it('builds a token that verifies', async () => {
    expect(await reason()).toBe('ok');
  });
});

describe('L1: extended key usage must be exactly id-kp-timeStamping', () => {
  it('refuses timeStamping plus another purpose', async () => {
    expect(await reason({ ekuOids: [TS, '1.3.6.1.5.5.7.3.2'] })).toBe('bad-eku');
    expect(await reason({ ekuOids: [TS, '2.5.29.37.0'] })).toBe('bad-eku');
  });
  it('refuses another single purpose and an empty list', async () => {
    expect(await reason({ ekuOids: ['1.3.6.1.5.5.7.3.2'] })).toBe('bad-eku');
    expect(await reason({ ekuOids: [] })).toBe('bad-eku');
  });
  it('still refuses a non-critical extension by default, allows it on request', async () => {
    expect(await reason({ ekuCritical: false })).toBe('bad-eku');
    expect(await reason({ ekuCritical: false }, { requireCriticalEku: false })).toBe('ok');
  });
});

describe('L2: critical unknown extension in a chain certificate', () => {
  const unknown = (critical: boolean) => ext('1.2.3.4.5.6', critical, octet(new Uint8Array(0)));
  it('refuses it in the signer certificate', async () => {
    expect(await reason({ extraTsaExts: [unknown(true)] })).toBe('bad-certificate');
  });
  it('accepts the same extension when it is not critical', async () => {
    expect(await reason({ extraTsaExts: [unknown(false)] })).toBe('ok');
  });
  it('accepts known critical extensions (subject alternative name)', async () => {
    expect(
      await reason({
        extraTsaExts: [ext('2.5.29.17', true, seq(tlv(0x82, new Uint8Array([97]))))],
      }),
    ).toBe('ok');
  });
  it('refuses a critical name constraint, which this library does not evaluate', async () => {
    expect(await reason({ extraTsaExts: [ext('2.5.29.30', true, seq())] })).toBe('bad-certificate');
  });
});

describe('L3: given options must be usable', () => {
  const bad: [string, unknown][] = [
    ['now: Invalid Date', { now: new Date(NaN) }],
    ['now: a string', { now: '2026-01-01' }],
    ['now: a number', { now: 0 }],
    ['now: null', { now: null }],
    ['at: Invalid Date', { at: new Date(NaN) }],
    ['maxSkewMs: NaN', { now: TIME, maxSkewMs: NaN }],
    ['maxSkewMs: a string', { now: TIME, maxSkewMs: '5' }],
    ['maxSkewMs: negative', { now: TIME, maxSkewMs: -1 }],
    ['maxSkewMs: null', { now: TIME, maxSkewMs: null }],
    ['options: null', null],
    ['options: a number', 5],
    ['options: a string', 'x'],
    ['options: an array', []],
    ['expectedNonce: null', { expectedNonce: null }],
    ['expectedNonce: 0', { expectedNonce: 0 }],
    ['expectedNonce: an empty string', { expectedNonce: '' }],
    ['expectedNonce: a string', { expectedNonce: 'abc' }],
    ['expectedNonce: NaN', { expectedNonce: NaN }],
    ['expectedNonce: false', { expectedNonce: false }],
    ['expectedNonce: an empty array', { expectedNonce: [] }],
    ['expectedNonce: a plain array of numbers', { expectedNonce: [1, 2] }],
    ['expectedNonce: empty bytes', { expectedNonce: new Uint8Array(0) }],
    ['expectedNonce: 17 bytes', { expectedNonce: new Uint8Array(17).fill(1) }],
    ['requireCriticalEku: null', { requireCriticalEku: null }],
    ['requireCriticalEku: 0', { requireCriticalEku: 0 }],
    ['requireCriticalEku: "false"', { requireCriticalEku: 'false' }],
  ];
  for (const [name, options] of bad) {
    it(`refuses ${name}`, async () => {
      expect(await reason({}, options)).toBe('bad-options');
    });
  }
  it('treats a now in 1970 as given (a token from the future is refused)', async () => {
    expect(await reason({}, { now: new Date(0) })).toBe('time-in-future');
  });
  it('treats undefined as not given', async () => {
    expect(await reason({}, undefined)).toBe('ok');
    expect(
      await reason(
        { nonceBytes: Uint8Array.of(5) },
        { expectedNonce: undefined, requireCriticalEku: undefined, now: undefined },
      ),
    ).toBe('ok');
  });
  it('checks a valid expectedNonce of 1 to 16 bytes', async () => {
    const ok16 = new Uint8Array(16).fill(7);
    expect(
      await reason({ nonceBytes: Uint8Array.of(5) }, { expectedNonce: Uint8Array.of(5) }),
    ).toBe('ok');
    expect(
      await reason({ nonceBytes: Uint8Array.of(5) }, { expectedNonce: Uint8Array.of(6) }),
    ).toBe('nonce-mismatch');
    expect(await reason({ nonceBytes: ok16 }, { expectedNonce: ok16 })).toBe('ok');
    expect(await reason({}, { expectedNonce: Uint8Array.of(5) })).toBe('nonce-mismatch');
  });
  it('allows an infinite skew', async () => {
    expect(await reason({}, { now: new Date(0), maxSkewMs: Infinity })).toBe('ok');
  });
});

describe('L4: readers throw nothing but ReaderError', () => {
  const emptyTbs = seq(seq(), seq(), tlv(3, Uint8Array.of(0)));
  const reasonOfThrow = (f: () => unknown): unknown => {
    try {
      f();
    } catch (e) {
      return e;
    }
    return null;
  };
  const isReader = (e: unknown) => e instanceof Error && e.name === 'Error' && 'reason' in e;
  it('parseCertificate with an empty TBS (30 00)', () => {
    const e = reasonOfThrow(() => parseCertificate(emptyTbs));
    expect(isReader(e)).toBe(true);
    expect((e as { reason: string }).reason).toBe('bad-certificate');
  });
  it('parseCertificate with too few fields or an empty validity', () => {
    const noValidity = seq(
      seq(
        tlv(ctx(0), int(2)),
        int(1),
        seq(oidT('1.2.840.10045.4.3.2')),
        seq(),
        seq(),
        seq(),
        seq(),
      ),
      seq(oidT('1.2.840.10045.4.3.2')),
      tlv(3, Uint8Array.of(0)),
    );
    for (const der of [emptyTbs, noValidity, seq(), seq(seq())]) {
      expect(isReader(reasonOfThrow(() => parseCertificate(der)))).toBe(true);
    }
  });
  it('parsePemCertificates with an empty TBS', () => {
    const pem = `-----BEGIN CERTIFICATE-----\n${Buffer.from(emptyTbs).toString('base64')}\n-----END CERTIFICATE-----\n`;
    expect(isReader(reasonOfThrow(() => parsePemCertificates(pem)))).toBe(true);
  });
  it('readToken and verify with such a certificate inside the token', async () => {
    const t = build({ tsaCertOverride: emptyTbs });
    expect(isReader(reasonOfThrow(() => readToken(t.token)))).toBe(true);
    const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem]);
    expect(r).toEqual({ ok: false, reason: 'bad-certificate' });
  });
  it('readToken on every truncation and single-byte change of a built token', () => {
    const { token } = build();
    for (let n = 0; n < token.length; n += 1) {
      const e = reasonOfThrow(() => readToken(token.subarray(0, n)));
      expect(isReader(e)).toBe(true);
    }
    for (let i = 0; i < token.length; i += 1) {
      const copy = Uint8Array.from(token);
      copy[i] = copy[i]! ^ 0xff;
      const e = reasonOfThrow(() => readToken(copy));
      if (e !== null) expect(isReader(e)).toBe(true);
    }
  });
});

describe('L5: negative INTEGERs are refused', () => {
  const NEG = Uint8Array.of(0x80);
  const POS = Uint8Array.of(0x00, 0x80);
  it('nonce', async () => {
    expect(await reason({ nonceBytes: NEG })).toBe('malformed');
    expect(await reason({ nonceBytes: POS })).toBe('ok');
  });
  it('TSTInfo serial number', async () => {
    expect(await reason({ tstSerialRaw: NEG })).toBe('malformed');
    expect(await reason({ tstSerialRaw: POS })).toBe('ok');
  });
  it('certificate serial number', async () => {
    const t = build({ serialRaw: NEG });
    expect(() => parseCertificate(t.tsaCert)).toThrow();
    expect(await reason({ serialRaw: NEG })).toBe('malformed');
    expect(await reason({ serialRaw: POS })).toBe('ok');
  });
  it('signer serial number', async () => {
    expect(await reason({ signerSerialRaw: NEG })).toBe('malformed');
  });
});

describe('L7: ECDSA signature structure', () => {
  const rawInts = (der: Uint8Array): Uint8Array[] => {
    // seq(len, 02 lr r, 02 ls s) of a P-256 signature (short or long length form is not needed here)
    const out: Uint8Array[] = [];
    let p = 2;
    while (p < der.length) {
      out.push(der.subarray(p + 2, p + 2 + der[p + 1]!));
      p += 2 + der[p + 1]!;
    }
    return out;
  };
  const withInts = (ints: Uint8Array[]) => seq(...ints.map((v) => tlv(2, v)));

  it('refuses a third child', async () => {
    expect(await reason({ sigMangle: (d) => withInts([...rawInts(d), Uint8Array.of(0)]) })).toBe(
      'signature-invalid',
    );
  });
  it('refuses a single child', async () => {
    expect(await reason({ sigMangle: (d) => withInts([rawInts(d)[0]!]) })).toBe(
      'signature-invalid',
    );
  });
  it('refuses r written as a negative integer (sign byte dropped)', async () => {
    let tried = 0;
    let seen = 0;
    while (seen < 3 && tried < 200) {
      tried += 1;
      let had = false;
      const r = await reason({
        sigMangle: (d) => {
          const [a, b] = rawInts(d);
          if (a![0] !== 0 || (a![1]! & 0x80) === 0) return d;
          had = true;
          return withInts([a!.subarray(1), b!]);
        },
      });
      if (had) {
        seen += 1;
        expect(r).toBe('signature-invalid');
      }
    }
    expect(seen).toBe(3);
  });
  it('still accepts the normal signatures', async () => {
    for (let i = 0; i < 10; i += 1) expect(await reason()).toBe('ok');
  });
});

describe('N7: chain building tries every signature-valid issuer candidate', () => {
  const unknownCrit = ext('1.2.3.4.5.6', true, octet(new Uint8Array(0)));
  const base = { intermediate: {} };
  it('verifies a chain through an intermediate', async () => {
    expect(await reason(base)).toBe('ok');
  });
  it('is not blocked by a twin with a critical unknown extension in front of the real one', async () => {
    expect(await reason({ ...base, twins: [{ extraExts: [unknownCrit] }] })).toBe('ok');
  });
  it('is not blocked by an expired twin in front of the real one', async () => {
    expect(
      await reason({ ...base, twins: [{ validity: ['20100101000000Z', '20150101000000Z'] }] }),
    ).toBe('ok');
  });
  it('is not blocked by a twin that is no CA in front of the real one', async () => {
    expect(await reason({ ...base, twins: [{ noCa: true }] })).toBe('ok');
  });
  it('is not blocked by several twins at once', async () => {
    expect(
      await reason({
        ...base,
        twins: [
          { noCa: true },
          { extraExts: [unknownCrit] },
          { validity: ['20100101000000Z', '20150101000000Z'] },
        ],
      }),
    ).toBe('ok');
  });
  it('a twin does not make an otherwise bad chain valid', async () => {
    // the real intermediate carries a critical unknown extension: still refused, twins or not
    const flawed = { intermediate: { extraExts: [unknownCrit] } };
    expect(await reason(flawed)).toBe('bad-certificate');
    expect(await reason({ ...flawed, twins: [{ extraExts: [unknownCrit] }] })).toBe(
      'bad-certificate',
    );
    expect(await reason({ ...flawed, twins: [{ noCa: true }] })).not.toBe('ok');
  });
  it('reports the first failure when every candidate is unusable', async () => {
    expect(
      await reason({
        ...base,
        intermediate: { extraExts: [unknownCrit] },
        twins: [{ noCa: true }],
      }),
    ).toBe('not-a-ca');
  });
});

describe('N3: the intermediate certificate and trust anchors', () => {
  const unknownCrit = ext('1.2.3.4.5.6', true, octet(new Uint8Array(0)));
  const unknownPlain = ext('1.2.3.4.5.6', false, octet(new Uint8Array(0)));
  it('refuses a critical unknown extension in the intermediate certificate', async () => {
    expect(await reason({ intermediate: { extraExts: [unknownCrit] } })).toBe('bad-certificate');
  });
  it('accepts the same extension in the intermediate when it is not critical', async () => {
    expect(await reason({ intermediate: { extraExts: [unknownPlain] } })).toBe('ok');
  });
  it('refuses a critical name constraint in the intermediate', async () => {
    expect(await reason({ intermediate: { extraExts: [ext('2.5.29.30', true, seq())] } })).toBe(
      'bad-certificate',
    );
  });
  it('keeps allowing a critical unknown extension in the trust anchor (the root)', async () => {
    expect(await reason({ caExts: [unknownCrit] })).toBe('ok');
    expect(await reason({ caExts: [unknownCrit], intermediate: {} })).toBe('ok');
  });
  it('keeps allowing it when the intermediate itself is the trust anchor', async () => {
    const t = build({ intermediate: { extraExts: [unknownCrit] } });
    const r = await verifyTimestampToken(t.token, t.imprint, [t.intPem]);
    expect(r.ok).toBe(true);
  });
});
