import {
  buildTimestampRequest,
  equalBytes,
  parseCertificate,
  parsePemCertificates,
  readToken,
  verifyTimestampToken,
} from '../src/lib/index.ts';
import type { Reason } from '../src/lib/index.ts';
import { ctx, tlv } from '../src/lib/der.ts';
import { sameName } from '../src/lib/x509.ts';
import { build, ext, int, nameWith, octet, oidT, seq, type Opts } from './token-builder.ts';

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

describe('E1: a named signature OID must agree with the digestAlgorithm of the SignerInfo', () => {
  it('refuses ecdsa-with-SHA384 next to digestAlgorithm SHA-256 although the signature is a valid SHA-384 one', async () => {
    expect(await reason({ signatureAlg: { oid: '1.2.840.10045.4.3.3', hash: 'sha384' } })).toBe(
      'signature-invalid',
    );
    expect(await reason({ signatureAlg: { oid: '1.2.840.10045.4.3.4', hash: 'sha512' } })).toBe(
      'signature-invalid',
    );
  });
  it('accepts the matching named OID (ecdsa-with-SHA256) and a bare id-ecPublicKey', async () => {
    expect(await reason({ signatureAlg: { oid: '1.2.840.10045.4.3.2', hash: 'sha256' } })).toBe(
      'ok',
    );
    expect(await reason({ signatureAlg: { oid: '1.2.840.10045.2.1', hash: 'sha256' } })).toBe('ok');
  });
  it('a named OID of another hash with a SHA-256 signature is refused as well', async () => {
    expect(await reason({ signatureAlg: { oid: '1.2.840.10045.4.3.3', hash: 'sha256' } })).toBe(
      'signature-invalid',
    );
  });
});

describe('ESSCertIDv2: the hash of the signing certificate attribute', () => {
  const SHA1 = '1.3.14.3.2.26';
  const SHA256 = '2.16.840.1.101.3.4.2.1';
  it('refuses SHA-1 in the v2 attribute (unsupported-hash), SHA-1 stays fine only in v1', async () => {
    expect(await reason({ essCertId: { v2Hash: SHA1 } })).toBe('unsupported-hash');
    expect(await reason({ essCertId: { v1: true } })).toBe('ok');
  });
  it('refuses an unknown hash OID in the v2 attribute: no silent fallback to SHA-256', async () => {
    // the attribute carries a correct SHA-256 of the certificate, so a fallback to SHA-256 would accept it
    expect(await reason({ essCertId: { v2Hash: '1.2.3.4' } })).toBe('unsupported-hash');
    expect(await reason({ essCertId: { v2Hash: '2.16.840.1.101.3.4.2.99' } })).toBe(
      'unsupported-hash',
    );
  });
  it('accepts the default (no algorithm) and an explicit SHA-256', async () => {
    expect(await reason()).toBe('ok');
    expect(await reason({ essCertId: { v2Hash: SHA256 } })).toBe('ok');
  });
  it('a named SHA-384 with the SHA-256 value is a mismatch, not a fallback', async () => {
    expect(await reason({ essCertId: { v2Hash: '2.16.840.1.101.3.4.2.2' } })).toBe(
      'signing-certificate-mismatch',
    );
  });
});

describe('the accuracy of a token', () => {
  const accuracyMs = async (accuracy?: Opts['accuracy']) => {
    const t = build(accuracy ? { accuracy } : {});
    const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem], {});
    if (!r.ok) throw new Error(r.reason);
    return r.value.accuracyMs;
  };
  it('adds seconds, milliseconds and microseconds: 1 s + 500 ms + 500 us = 1500.5 ms', async () => {
    expect(await accuracyMs({ sec: 1, millis: 500, micros: 500 })).toBe(1500.5);
  });
  it('reads each part alone and null when the token names none', async () => {
    expect(await accuracyMs({ sec: 2 })).toBe(2000);
    expect(await accuracyMs({ millis: 250 })).toBe(250);
    expect(await accuracyMs({ micros: 500 })).toBe(0.5);
    expect(await accuracyMs()).toBeNull();
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
  it('refuses a signer without any extended key usage extension (also when criticality is not required)', async () => {
    expect(await reason({ noEku: true })).toBe('bad-eku');
    expect(await reason({ noEku: true }, { requireCriticalEku: false })).toBe('bad-eku');
  });
  it('accepts exactly the timeStamping OID: its neighbours and look-alikes are refused', async () => {
    expect(await reason({ ekuOids: [TS] })).toBe('ok');
    expect(await reason({ ekuOids: ['1.3.6.1.5.5.7.3.9'] })).toBe('bad-eku'); // OCSPSigning, next value
    expect(await reason({ ekuOids: ['1.3.6.1.5.5.7.3.7'] })).toBe('bad-eku'); // previous value
    expect(await reason({ ekuOids: ['1.3.6.1.5.5.7.3.88'] })).toBe('bad-eku');
  });
  it('the signer certificate must be valid at the stamped time (before and after)', async () => {
    const short: [string, string] = ['20250101000000Z', '20260601000000Z'];
    expect(await reason({ tsaValidity: short })).toBe('ok');
    expect(await reason({ tsaValidity: short, genTime: '20240101000000Z' })).toBe(
      'certificate-not-valid-at-time',
    );
    expect(await reason({ tsaValidity: short, genTime: '20270101000000Z' })).toBe(
      'certificate-not-valid-at-time',
    );
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
    // an unreadable certificate in the token is skipped (B4); it was the signer's, so that one is missing
    expect(readToken(t.token).skippedCertificates).toBe(1);
    const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem]);
    expect(r).toEqual({ ok: false, reason: 'signer-certificate-missing' });
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
          // 00 ff 8x: without the 00 the INTEGER is negative AND not minimal (ff 8x): `malformed`, by chance; skip it
          if (a![0] !== 0 || (a![1]! & 0x80) === 0 || a![1] === 0xff) return d;
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

describe('R2: certificate times carry no fraction (RFC 5280), genTime keeps up to 9 digits', () => {
  const FRAC: [string, string] = ['20200101000000.5Z', '20400101000000Z'];
  const FRAC_END: [string, string] = ['20200101000000Z', '20400101000000.5Z'];
  it('refuses a fraction in notBefore or notAfter of the signer chain (intermediate)', async () => {
    // the intermediate is unreadable (`bad-time`), so it is skipped (B4) and the chain has no way up
    expect(await reason({ intermediate: { validity: FRAC } })).toBe('untrusted-chain');
    expect(await reason({ intermediate: { validity: FRAC_END } })).toBe('untrusted-chain');
  });
  it('refuses a fraction in the validity of a trust anchor and of a bare certificate', async () => {
    expect(await reason({ caValidity: FRAC })).toBe('bad-time');
    expect(await reason({ caValidity: FRAC_END })).toBe('bad-time');
    const t = build({ caValidity: FRAC });
    expect(() => parsePemCertificates(t.caPem)).toThrow(
      expect.objectContaining({ reason: 'bad-time' }),
    );
  });
  it('whole seconds in the same places stay fine', async () => {
    expect(
      await reason({ intermediate: { validity: ['20200101000000Z', '20400101000000Z'] } }),
    ).toBe('ok');
  });
  it('genTime of the TSTInfo keeps its fraction', async () => {
    expect(await reason({ genTime: '20260101000000.5Z' })).toBe('ok');
    expect(await reason({ genTime: '20260101000000.123456789Z' })).toBe('ok');
    expect(await reason({ genTime: '20260101000000.50Z' })).toBe('bad-time'); // trailing zero stays refused
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
    // the first candidate that was probed and unusable gives the reason: the twin comes before the real one
    expect(await reason({ ...flawed, twins: [{ noCa: true }] })).toBe('not-a-ca');
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

describe('Q1: an intermediate CA that names purposes must allow time stamping', () => {
  const eku = (...oids: string[]) => ext('2.5.29.37', false, seq(...oids.map(oidT)));
  const CODE = '1.3.6.1.5.5.7.3.3';
  const SERVER = '1.3.6.1.5.5.7.3.1';
  const ANY = '2.5.29.37.0';
  it('refuses an intermediate with only code signing or only server authentication', async () => {
    expect(await reason({ intermediate: { extraExts: [eku(CODE)] } })).toBe('bad-eku');
    expect(await reason({ intermediate: { extraExts: [eku(SERVER)] } })).toBe('bad-eku');
    expect(await reason({ intermediate: { extraExts: [eku(CODE, SERVER)] } })).toBe('bad-eku');
    expect(
      await reason({ intermediate: { extraExts: [ext('2.5.29.37', true, seq(oidT(CODE)))] } }),
    ).toBe('bad-eku');
  });
  it('refuses an intermediate with an empty extended key usage list', async () => {
    expect(await reason({ intermediate: { extraExts: [eku()] } })).toBe('bad-eku');
  });
  it('accepts timeStamping, anyExtendedKeyUsage, a list holding either, and no EKU at all', async () => {
    expect(await reason({ intermediate: { extraExts: [eku(TS)] } })).toBe('ok');
    expect(await reason({ intermediate: { extraExts: [eku(ANY)] } })).toBe('ok');
    expect(await reason({ intermediate: { extraExts: [eku(CODE, TS)] } })).toBe('ok');
    expect(await reason({ intermediate: { extraExts: [eku(SERVER, ANY)] } })).toBe('ok');
    expect(await reason({ intermediate: {} })).toBe('ok');
  });
  it('leaves the trust anchor alone: the root and an intermediate given as anchor may carry any EKU', async () => {
    expect(await reason({ caExts: [eku(CODE)] })).toBe('ok');
    expect(await reason({ caExts: [eku(CODE)], intermediate: {} })).toBe('ok');
    const t = build({ intermediate: { extraExts: [eku(CODE)] } });
    const r = await verifyTimestampToken(t.token, t.imprint, [t.intPem]);
    expect(r.ok).toBe(true);
    // the exemption needs the same bytes, not the same subject
    const sameName = build({ intermediate: {} });
    expect(await verifyTimestampToken(t.token, t.imprint, [sameName.intPem])).toEqual({
      ok: false,
      reason: 'bad-eku',
    });
  });
  it('is not blocked by a look-alike with a foreign EKU in front of the real intermediate', async () => {
    expect(await reason({ intermediate: {}, twins: [{ extraExts: [eku(CODE)] }] })).toBe('ok');
  });
  it('does not make a flawed chain valid, and the reason follows the first unusable candidate', async () => {
    const flawed = { intermediate: { extraExts: [eku(CODE)] } };
    expect(await reason({ ...flawed, twins: [{ extraExts: [eku(SERVER)] }] })).toBe('bad-eku');
    expect(await reason({ ...flawed, twins: [{ noCa: true }] })).toBe('not-a-ca'); // twin first
    // earlier flaws win over the EKU: an unknown critical extension is named first
    const unknownCrit = ext('1.2.3.4.5.6', true, octet(new Uint8Array(0)));
    expect(await reason({ intermediate: { extraExts: [eku(CODE), unknownCrit] } })).toBe(
      'bad-certificate',
    );
  });
});

/** Runs `f` and counts the signature verifications done through `crypto.subtle.verify`. */
async function countVerifies<T>(f: () => Promise<T>): Promise<{ value: T; count: number }> {
  const spy = vi.spyOn(crypto.subtle, 'verify');
  try {
    const value = await f();
    return { value, count: spy.mock.calls.length };
  } finally {
    spy.mockRestore();
  }
}

describe('C1: unusable twins cost neither candidate slots nor signature checks', () => {
  const unknownCrit = ext('1.2.3.4.5.6', true, octet(new Uint8Array(0)));
  const unusable = (n: number) =>
    Array.from({ length: n }, (_, i) => {
      const kind = i % 3;
      return kind === 0
        ? { noCa: true }
        : kind === 1
          ? { extraExts: [unknownCrit] }
          : { validity: ['20100101000000Z', '20150101000000Z'] as [string, string] };
    });
  it('keeps a token valid with the real intermediate and 14 unusable twins (the limit of 16 certificates)', async () => {
    expect(await reason({ intermediate: {}, twins: unusable(14) })).toBe('ok');
  });
  it('spends no signature checks on them', async () => {
    const t = build({ intermediate: {}, twins: unusable(14) });
    const { value, count } = await countVerifies(() =>
      verifyTimestampToken(t.token, t.imprint, [t.caPem]),
    );
    expect(value.ok).toBe(true);
    expect(count).toBeLessThanOrEqual(4); // signer, signer by INT, INT by root
  });
  it('still reports why when every candidate is unusable (one signature check per step for it)', async () => {
    const t = build({ intermediate: { noKeyCertSign: true }, twins: unusable(14) });
    const { value, count } = await countVerifies(() =>
      verifyTimestampToken(t.token, t.imprint, [t.caPem]),
    );
    expect(value).toEqual({ ok: false, reason: 'not-a-ca' });
    expect(count).toBeLessThanOrEqual(4);
  });
});

describe('C1/C5/C9: usable-looking fakes are a bounded availability problem', () => {
  // The `certificates` field is not signed: whoever can change the token can add certificates that look
  // usable (CA, keyCertSign, valid) and that are not signed by the real issuer. They are never accepted,
  // but 8 of them in front of the real intermediate use up the candidates of that step.
  it('7 forged look-alikes in front of the real intermediate do not hide it', async () => {
    const twins = Array.from({ length: 7 }, () => ({ forged: true }));
    expect(await reason({ intermediate: {}, twins })).toBe('ok');
  });
  it('8 forged look-alikes in front of it hide it: untrusted-chain, never ok (candidate limit)', async () => {
    const twins = Array.from({ length: 8 }, () => ({ forged: true }));
    expect(await reason({ intermediate: {}, twins })).toBe('untrusted-chain');
  });
  it('a maze of look-alikes ends after at most 64 signature checks (+1 for the signer)', async () => {
    const t = build({ ladder: { levels: 5, width: 3 } }); // 16 certificates, the limit of the token
    const { value, count } = await countVerifies(() =>
      verifyTimestampToken(t.token, t.imprint, [t.caPem]),
    );
    expect(value).toEqual({ ok: false, reason: 'untrusted-chain' }); // budget used up
    expect(count).toBeGreaterThan(60);
    expect(count).toBeLessThanOrEqual(65);
  });
});

describe('C4: chain rules, one test each', () => {
  const unknownCrit = ext('1.2.3.4.5.6', true, octet(new Uint8Array(0)));
  const OLD: [string, string] = ['20100101000000Z', '20150101000000Z'];
  it('a chain with 5 intermediates is accepted, with 6 it is too long', async () => {
    expect(await reason({ deepChain: 5 })).toBe('ok');
    expect(await reason({ deepChain: 6 })).toBe('chain-too-long');
  });
  it('an expired only intermediate: certificate-not-valid-at-time', async () => {
    expect(await reason({ intermediate: { validity: OLD } })).toBe('certificate-not-valid-at-time');
  });
  it('an intermediate without keyCertSign: not-a-ca', async () => {
    expect(await reason({ intermediate: { noKeyCertSign: true } })).toBe('not-a-ca');
  });
  it('an expired trust anchor still fails (direct issuer and behind an intermediate)', async () => {
    expect(await reason({ caValidity: OLD })).toBe('certificate-not-valid-at-time');
    expect(await reason({ caValidity: OLD, intermediate: {} })).toBe(
      'certificate-not-valid-at-time',
    );
  });
  it('the anchor exemption for critical unknown extensions needs the same bytes, not the same subject', async () => {
    const t = build({ intermediate: { extraExts: [unknownCrit] } });
    const sameName = build({ intermediate: {} }); // other key, same subject "INT"
    expect(await verifyTimestampToken(t.token, t.imprint, [sameName.intPem])).toEqual({
      ok: false,
      reason: 'bad-certificate',
    });
    const exact = await verifyTimestampToken(t.token, t.imprint, [t.intPem]);
    expect(exact.ok).toBe(true);
  });
});

describe('C2: a self-signed signer certificate that is no anchor', () => {
  it('gives untrusted-chain (not not-a-ca)', async () => {
    expect(await reason({ selfSignedSigner: true })).toBe('untrusted-chain');
  });
  it('is fine when the caller trusts exactly that certificate', async () => {
    const t = build({ selfSignedSigner: true });
    const r = await verifyTimestampToken(t.token, t.imprint, [t.tsaPem]);
    expect(r.ok).toBe(true);
  });
});

describe('C6/C7: options are read once, own properties only', () => {
  const noCritical = { ekuCritical: false };
  it('a getter that answers differently the second time cannot switch a check off', async () => {
    let reads = 0;
    const options = {
      get requireCriticalEku() {
        reads += 1;
        return reads === 1;
      },
    };
    expect(await reason(noCritical, options)).toBe('bad-eku');
    expect(reads).toBe(1);
  });
  it('a getter that throws gives bad-options', async () => {
    const options = {
      get now(): Date {
        throw new Error('boom');
      },
    };
    expect(await reason({}, options)).toBe('bad-options');
  });
  it('a proxy that throws gives bad-options', async () => {
    const options = new Proxy(
      {},
      {
        has() {
          throw new Error('boom');
        },
        getOwnPropertyDescriptor() {
          throw new Error('boom');
        },
      },
    );
    expect(await reason({}, options)).toBe('bad-options');
  });
  it('properties inherited from Object.prototype do not count', async () => {
    const proto = Object.prototype as Record<string, unknown>;
    try {
      proto.requireCriticalEku = false;
      expect(await reason(noCritical, {})).toBe('bad-eku');
      proto.expectedNonce = Uint8Array.of(1);
      expect(await reason({}, {})).toBe('ok');
      proto.now = new Date(0);
      expect(await reason({}, {})).toBe('ok');
    } finally {
      delete proto.requireCriticalEku;
      delete proto.expectedNonce;
      delete proto.now;
    }
  });
  it('refuses a function and an array with properties', async () => {
    expect(await reason({}, () => undefined)).toBe('bad-options');
    expect(await reason({}, Object.assign([], { requireCriticalEku: false }))).toBe('bad-options');
  });
});

describe('E1: a Date is read once, with the built-in getTime, and only a real Date counts', () => {
  const finiteThenNaN = (ms: number) => {
    let reads = 0;
    const d = new Date(ms);
    d.getTime = () => {
      reads += 1;
      return reads === 1 ? ms : NaN;
    };
    return { d, reads: () => reads };
  };
  it('a now whose getTime answers finite and then NaN cannot skip the future check', async () => {
    const { d, reads } = finiteThenNaN(0);
    expect(await reason({}, { now: d })).toBe('time-in-future');
    expect(reads()).toBe(0); // the overridden method is never called
  });
  it('an at whose getTime answers finite and then NaN is judged by its real time', async () => {
    const { d, reads } = finiteThenNaN(Date.parse('2030-01-01T00:00:00Z'));
    expect(await reason({}, { at: d })).toBe('ok');
    expect(reads()).toBe(0);
  });
  it('a getTime that always answers NaN does not change what the Date is', async () => {
    const d = new Date(0);
    d.getTime = () => NaN;
    expect(await reason({}, { now: d })).toBe('time-in-future');
  });
  it('refuses an object that only claims to be a Date through Symbol.toStringTag', async () => {
    const fake = { [Symbol.toStringTag]: 'Date', getTime: () => 0 };
    expect(await reason({}, { now: fake })).toBe('bad-options');
    expect(await reason({}, { at: fake })).toBe('bad-options');
    const nullProto = Object.assign(Object.create(null), { getTime: () => 0 });
    nullProto[Symbol.toStringTag] = 'Date';
    expect(await reason({}, { now: nullProto })).toBe('bad-options');
  });
  it('refuses a Date subclass and a Date with another prototype', async () => {
    class MyDate extends Date {}
    expect(await reason({}, { now: new MyDate(0) })).toBe('bad-options');
    expect(await reason({}, { at: new MyDate(0) })).toBe('bad-options');
    const other = new Date(0);
    Object.setPrototypeOf(other, Object.create(Date.prototype));
    expect(await reason({}, { now: other })).toBe('bad-options');
  });
});

describe('E2: options must be a plain object', () => {
  class Opts2 {
    requireCriticalEku = false;
  }
  it('refuses class instances, Map, Date, String and boxed values', async () => {
    const noCritical = { ekuCritical: false };
    expect(await reason(noCritical, new Opts2())).toBe('bad-options');
    expect(await reason({}, new Map())).toBe('bad-options');
    expect(await reason({}, new Date())).toBe('bad-options');
    expect(await reason({}, new String('x'))).toBe('bad-options');
    expect(await reason({}, new Uint8Array(1))).toBe('bad-options');
  });
  it('refuses a proxy whose prototype lookup throws', async () => {
    const p = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error('boom');
        },
      },
    );
    expect(await reason({}, p)).toBe('bad-options');
  });
  it('accepts a plain object, an object without prototype and the empty options', async () => {
    expect(await reason({}, { requireCriticalEku: true })).toBe('ok');
    expect(await reason({}, Object.create(null))).toBe('ok');
    expect(
      await reason(
        { ekuCritical: false },
        Object.assign(Object.create(null), { requireCriticalEku: false }),
      ),
    ).toBe('ok');
  });
});

describe('E5: the reason of a failure is searched for after the search, with a small budget', () => {
  const unusable = (n: number) => Array.from({ length: n }, () => ({ wrongKey: true, noCa: true })); // flawed, and verify nothing
  it('names the reason with at most 4 extra checks when the first look-alikes do not sign', async () => {
    const t = build({ intermediate: { noKeyCertSign: true }, twins: unusable(14) });
    const { value, count } = await countVerifies(() =>
      verifyTimestampToken(t.token, t.imprint, [t.caPem]),
    );
    expect(value).toEqual({ ok: false, reason: 'untrusted-chain' });
    expect(count).toBeLessThanOrEqual(1 + 4); // the token signature, then the reason budget
  });
  it('still names the reason when the look-alike that signed it is within the budget', async () => {
    const t = build({
      intermediate: { noKeyCertSign: true },
      twins: [...unusable(2), { noCa: true }],
    });
    const { value, count } = await countVerifies(() =>
      verifyTimestampToken(t.token, t.imprint, [t.caPem]),
    );
    expect(value).toEqual({ ok: false, reason: 'not-a-ca' });
    expect(count).toBeLessThanOrEqual(1 + 4);
  });
  it('spends nothing on the reason while a usable branch is still being searched', async () => {
    // a successful chain never works out a reason at all
    const t = build({ intermediate: {}, twins: unusable(6) });
    const { value, count } = await countVerifies(() =>
      verifyTimestampToken(t.token, t.imprint, [t.caPem]),
    );
    expect(value.ok).toBe(true);
    expect(count).toBeLessThanOrEqual(3);
  });
});

describe('E6: option edges', () => {
  const MAX = 8.64e15;
  it('inherited at and maxSkewMs (prototype pollution) do not count', async () => {
    const proto = Object.prototype as Record<string, unknown>;
    try {
      proto.at = new Date(0);
      expect(await reason({}, {})).toBe('ok');
      delete proto.at;
      proto.maxSkewMs = 0;
      expect(await reason({}, { now: new Date('2025-12-31T23:59:00Z') })).toBe('ok');
    } finally {
      delete proto.at;
      delete proto.maxSkewMs;
    }
  });
  it('at = Date(0) is given: the certificates are not valid in 1970', async () => {
    expect(await reason({}, { at: new Date(0) })).toBe('certificate-not-valid-at-time');
  });
  it('the extreme Dates are valid values with the expected effect', async () => {
    expect(await reason({}, { now: new Date(MAX) })).toBe('ok');
    expect(await reason({}, { now: new Date(-MAX) })).toBe('time-in-future');
    expect(await reason({}, { now: new Date(MAX), maxSkewMs: Infinity })).toBe('ok');
    expect(await reason({}, { at: new Date(MAX) })).toBe('certificate-not-valid-at-time');
    expect(await reason({}, { at: new Date(-MAX) })).toBe('certificate-not-valid-at-time');
  });
  it('one millisecond beyond the extremes is an Invalid Date: bad-options', async () => {
    expect(await reason({}, { now: new Date(MAX + 1) })).toBe('bad-options');
    expect(await reason({}, { at: new Date(-MAX - 1) })).toBe('bad-options');
  });
});

// A proxy around real bytes whose traps throw: the core functions answer with a code and never throw.
const hostile = (target: object, trap: 'getPrototypeOf' | 'get'): Uint8Array =>
  new Proxy(target, {
    [trap]() {
      throw new Error(`trap ${trap}`);
    },
  }) as Uint8Array;
const TRAPS = ['getPrototypeOf', 'get'] as const;

describe('G2: the core functions survive hostile proxies', () => {
  for (const trap of TRAPS) {
    it(`buildTimestampRequest: a proxy with a throwing ${trap} trap gives a code`, () => {
      const ok32 = new Uint8Array(32).fill(1);
      expect(buildTimestampRequest(hostile(ok32, trap), Uint8Array.of(1))).toEqual({
        ok: false,
        reason: 'bad-hash',
      });
      expect(buildTimestampRequest(ok32, hostile(Uint8Array.of(1), trap))).toEqual({
        ok: false,
        reason: 'bad-nonce',
      });
    });
    it(`equalBytes: a proxy with a throwing ${trap} trap is false`, () => {
      const a = Uint8Array.of(1, 2);
      expect(equalBytes(hostile(a, trap), a)).toBe(false);
      expect(equalBytes(a, hostile(a, trap))).toBe(false);
    });
    it(`verifyTimestampToken: a proxy with a throwing ${trap} trap resolves to a code`, async () => {
      const t = build();
      const run = (...a: Parameters<typeof verifyTimestampToken>) => verifyTimestampToken(...a);
      expect(await run(t.token, hostile(t.imprint, trap), [t.caPem])).toEqual({
        ok: false,
        reason: 'bad-hash',
      });
      expect(await run(hostile(t.token, trap), t.imprint, [t.caPem])).toEqual({
        ok: false,
        reason: 'malformed',
      });
      expect(
        await run(t.token, t.imprint, [t.caPem], {
          expectedNonce: hostile(Uint8Array.of(1), trap),
        }),
      ).toEqual({ ok: false, reason: 'bad-options' });
    });
  }
});

describe('G3: trust must be an array', () => {
  it('a proxy of an array whose get trap throws gives bad-options, not a rejection', async () => {
    const t = build();
    expect(
      await verifyTimestampToken(t.token, t.imprint, hostile([t.caPem], 'get') as never),
    ).toEqual({
      ok: false,
      reason: 'bad-options',
    });
  });
  const t = build();
  const cases: [string, unknown][] = [
    ['undefined', undefined],
    ['null', null],
    ['a string (the PEM itself)', t.caPem],
    ['an object', { 0: t.caPem, length: 1 }],
    ['a Set', new Set([t.caPem])],
    ['a number', 1],
  ];
  for (const [name, trust] of cases) {
    it(`refuses ${name} with bad-options`, async () => {
      expect(await verifyTimestampToken(t.token, t.imprint, trust as never)).toEqual({
        ok: false,
        reason: 'bad-options',
      });
    });
  }
  it('still accepts an array, also an empty one (then untrusted-chain)', async () => {
    expect((await verifyTimestampToken(t.token, t.imprint, [t.caPem])).ok).toBe(true);
    expect(await verifyTimestampToken(t.token, t.imprint, [])).toEqual({
      ok: false,
      reason: 'untrusted-chain',
    });
  });
});

describe('G4: mutation guards', () => {
  const KU = (...bytes: number[]) => Uint8Array.of(...bytes);
  it('the signer key usage must allow signing: digitalSignature or nonRepudiation', async () => {
    expect(await reason({ tsaKeyUsage: KU(0, 0x80) })).toBe('ok'); // digitalSignature
    expect(await reason({ tsaKeyUsage: KU(6, 0x40) })).toBe('ok'); // nonRepudiation alone
    expect(await reason({ tsaKeyUsage: KU(5, 0xc0) })).toBe('ok');
  });
  it('refuses a signer whose key usage allows neither (keyEncipherment, keyCertSign, none)', async () => {
    expect(await reason({ tsaKeyUsage: KU(5, 0x20) })).toBe('bad-eku'); // keyEncipherment
    expect(await reason({ tsaKeyUsage: KU(2, 0x04) })).toBe('bad-eku'); // keyCertSign
    expect(await reason({ tsaKeyUsage: KU(7, 0x00) })).toBe('bad-eku'); // no bit
    expect(await reason({ tsaKeyUsage: KU(5, 0x3f) })).toBe('bad-eku'); // everything but the two
  });
  it('anchors come first in the pool: cross-signed twins of the anchor do not hide it', async () => {
    expect(await reason({ anchorTwins: 8 })).toBe('ok');
    expect(await reason({ anchorTwins: 14 })).toBe('ok');
  });
  it('the reason is the one of the FIRST failed branch, not of the last', async () => {
    // branch 1: a forged look-alike of INT (verifies the signer, no anchor above it): untrusted-chain;
    // branch 2: the real INT, whose issuer, the anchor, is expired: certificate-not-valid-at-time
    const expired: [string, string] = ['20100101000000Z', '20150101000000Z'];
    expect(await reason({ intermediate: {}, twins: [{ forged: true }], caValidity: expired })).toBe(
      'untrusted-chain',
    );
    // without the look-alike in front, the real INT is the first branch
    expect(await reason({ intermediate: {}, caValidity: expired })).toBe(
      'certificate-not-valid-at-time',
    );
  });
  it('an expected nonce with leading zero bytes is the same number', async () => {
    const five = { nonceBytes: Uint8Array.of(5) };
    expect(await reason(five, { expectedNonce: Uint8Array.of(0, 0, 5) })).toBe('ok');
    expect(await reason(five, { expectedNonce: Uint8Array.of(0, 5) })).toBe('ok');
    expect(
      await reason({ nonceBytes: Uint8Array.of(0) }, { expectedNonce: Uint8Array.of(0, 0) }),
    ).toBe('ok');
    expect(await reason(five, { expectedNonce: Uint8Array.of(0, 0, 6) })).toBe('nonce-mismatch');
  });
});

describe('G9: a search cut short by a limit always says untrusted-chain', () => {
  it('even when a flawed look-alike of the anchor signed one of the failed branches', async () => {
    const t = build({ ladder: { levels: 5, width: 3, topTwin: true } });
    const { value, count } = await countVerifies(() =>
      verifyTimestampToken(t.token, t.imprint, [t.caPem]),
    );
    expect(value).toEqual({ ok: false, reason: 'untrusted-chain' });
    expect(count).toBeGreaterThan(60);
  });
  it('and still names the exact reason when no limit was reached', async () => {
    expect(await reason({ intermediate: { noKeyCertSign: true }, twins: [{ noCa: true }] })).toBe(
      'not-a-ca',
    );
  });
});

describe('B1: a trust anchor without basicConstraints (X.509 v1 root) may be a CA', () => {
  it('a v1 root handed over as anchor verifies, directly and above an intermediate', async () => {
    expect(await reason({ rootV1: true })).toBe('ok');
    expect(await reason({ rootV1: true, intermediate: {} })).toBe('ok');
  });
  it('an anchor that says cA=false stays refused', async () => {
    expect(await reason({ rootNotCa: true })).toBe('not-a-ca');
    expect(await reason({ rootNotCa: true, intermediate: {} })).toBe('not-a-ca');
  });
  it('an intermediate without basicConstraints (not an anchor) stays refused', async () => {
    expect(await reason({ intermediate: { noBasicConstraints: true } })).toBe('not-a-ca');
  });
  it("the same intermediate handed over as anchor is the caller's decision", async () => {
    const t = build({ intermediate: { noBasicConstraints: true } });
    const r = await verifyTimestampToken(t.token, t.imprint, [t.intPem]);
    expect(r.ok).toBe(true);
  });
  it('a v1 root is read without extensions', () => {
    const t = build({ rootV1: true });
    expect(parsePemCertificates(t.caPem)[0]!.isCa).toBeNull();
  });
});

describe('B2: issuer names are matched by the simplified rule of RFC 5280 § 7.1', () => {
  const STRINGS = [
    ['PrintableString', 0x13],
    ['IA5String', 0x16],
    ['TeletexString', 0x14],
    ['BMPString', 0x1e],
    ['UTF8String', 0x0c],
  ] as const;
  for (const [label, tag] of STRINGS) {
    it(`${label} against UTF8String: same text, other case, spaces around`, async () => {
      for (const text of ['CA', 'ca', 'Ca', '  ca ']) {
        expect(await reason({ tsaIssuerName: { tag, text } })).toBe('ok');
        expect(await reason({ sidIssuerName: { tag, text } })).toBe('ok');
      }
    });
  }
  it('a really different name stays untrusted / not found', async () => {
    const cb = { tag: 0x13, text: 'CB' };
    expect(await reason({ tsaIssuerName: cb, sidIssuerName: cb })).toBe('untrusted-chain');
    expect(await reason({ sidIssuerName: { tag: 0x13, text: 'CB' } })).toBe(
      'signer-certificate-missing',
    );
    const spaced = { tag: 0x13, text: 'C A' };
    expect(await reason({ tsaIssuerName: spaced, sidIssuerName: spaced })).toBe('untrusted-chain');
  });
  it('sameName: inner runs of spaces count as one, other letters and attribute types do not', () => {
    const n = (tag: number, text: string) => nameWith(tag, text);
    expect(sameName(n(0x0c, 'Foo   Bar'), n(0x13, ' foo bar'))).toBe(true);
    expect(sameName(n(0x0c, 'Foo Bar'), n(0x0c, 'FooBar'))).toBe(false);
    expect(sameName(n(0x0c, 'a'), n(0x0c, 'b'))).toBe(false);
    // other attribute type, same value
    const ou = seq(tlv(0x31, seq(oidT('2.5.4.10'), tlv(0x0c, new TextEncoder().encode('CA')))));
    expect(sameName(ou, n(0x0c, 'CA'))).toBe(false);
  });
  it('sameName: only ASCII letters fold, a non-ASCII letter does not', () => {
    expect(sameName(nameWith(0x0c, 'Ä'), nameWith(0x0c, 'ä'))).toBe(false);
  });
  it('sameName: an unknown value type is compared by its bytes', () => {
    expect(sameName(nameWith(0x1c, 'CA'), nameWith(0x1c, 'CA'))).toBe(true);
    expect(sameName(nameWith(0x1c, 'CA'), nameWith(0x1c, 'ca'))).toBe(false);
    expect(sameName(nameWith(0x1c, 'CA'), nameWith(0x0c, 'CA'))).toBe(false);
  });
  it('sameName: a name that cannot be read is compared byte for byte', () => {
    const junk = Uint8Array.of(1, 2, 3);
    expect(sameName(junk, Uint8Array.of(1, 2, 3))).toBe(true);
    expect(sameName(junk, Uint8Array.of(1, 2, 4))).toBe(false);
    expect(sameName(junk, nameWith(0x0c, 'CA'))).toBe(false);
  });
  it('sameName: a multi-valued RDN is a set (order does not matter)', () => {
    const cn = seq(oidT('2.5.4.3'), tlv(0x0c, new TextEncoder().encode('X')));
    const o = seq(oidT('2.5.4.10'), tlv(0x13, new TextEncoder().encode('x')));
    expect(sameName(seq(tlv(0x31, cn, o)), seq(tlv(0x31, o, cn)))).toBe(true);
  });
  it('case-different twins count against the candidate limits like equal ones', async () => {
    const seven = Array.from({ length: 7 }, () => ({ forged: true, subject: 'int' }));
    expect(await reason({ intermediate: {}, twins: seven })).toBe('ok');
    const eight = Array.from({ length: 8 }, () => ({ forged: true, subject: 'int' }));
    expect(await reason({ intermediate: {}, twins: eight })).toBe('untrusted-chain');
    // and an unusable (no CA) twin of another spelling still costs nothing
    const unusable = Array.from({ length: 14 }, () => ({ noCa: true, subject: ' Int' }));
    expect(await reason({ intermediate: {}, twins: unusable })).toBe('ok');
  });
  it('the name only selects candidates: a look-alike with the right name and a wrong key is refused', async () => {
    expect(
      await reason({
        intermediate: {},
        twins: [{ forged: true, subject: 'int' }],
        tsaIssuerName: { tag: 0x13, text: 'int' },
      }),
    ).toBe('ok'); // the real intermediate is still found behind the forged twin
  });
});

describe('B4: unreadable extra certificates in the token are skipped', () => {
  const NEG = Uint8Array.of(0x80);
  const negativeSerial = () => build({ serialRaw: NEG }).tsaCert; // a real certificate nobody can read
  const garbage = seq(int(1)); // a SEQUENCE that is no certificate
  it('a certificate with a negative serial number does not fail the token', async () => {
    expect(await reason({ junkCerts: [negativeSerial()] })).toBe('ok');
  });
  it('a SEQUENCE that is no certificate is skipped too, and is only counted', async () => {
    expect(await reason({ junkCerts: [garbage, negativeSerial(), garbage] })).toBe('ok');
    const t = build({ junkCerts: [garbage, negativeSerial()] });
    const token = readToken(t.token);
    expect(token.skippedCertificates).toBe(2);
    expect(token.certificates).toHaveLength(1);
    expect(readToken(build().token).skippedCertificates).toBe(0);
  });
  it('a skipped certificate is never a candidate and never makes a chain valid', async () => {
    expect(await reason({ intermediate: {}, junkCerts: [negativeSerial(), garbage] })).toBe('ok');
    expect(
      await reason({ intermediate: { noKeyCertSign: true }, junkCerts: [negativeSerial()] }),
    ).toBe('not-a-ca');
  });
  it('an unreadable signer certificate is signer-certificate-missing', async () => {
    expect(await reason({ serialRaw: NEG, signerSerialRaw: Uint8Array.of(7) })).toBe(
      'signer-certificate-missing',
    );
  });
  it('the signer info with a negative serial number stays malformed', async () => {
    expect(await reason({ signerSerialRaw: NEG })).toBe('malformed');
  });
  it('an unreadable trust anchor stays a hard error', async () => {
    const bad = build({ serialRaw: NEG });
    const t = build();
    const pem = `-----BEGIN CERTIFICATE-----\n${Buffer.from(bad.tsaCert).toString('base64')}\n-----END CERTIFICATE-----\n`;
    const r = await verifyTimestampToken(t.token, t.imprint, [pem]);
    expect(r).toEqual({ ok: false, reason: 'malformed' });
  });
  it('the limit of 16 certificates counts the skipped ones', async () => {
    expect(await reason({ junkCerts: Array.from({ length: 15 }, () => garbage) })).toBe('ok');
    expect(await reason({ junkCerts: Array.from({ length: 16 }, () => garbage) })).toBe(
      'too-large',
    );
  });
});
