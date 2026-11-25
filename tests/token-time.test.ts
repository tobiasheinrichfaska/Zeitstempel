import { parseCertificate, parsePemCertificates, verifyTimestampToken } from '../src/lib/index.ts';
import type { Reason, VerifyOptions } from '../src/lib/index.ts';
import { build, type Opts } from './token-builder.ts';
import { fixture, fixtureText, sha256 } from './helpers.ts';
import { readTimestampResponse } from '../src/lib/index.ts';

async function result(o: Opts = {}, options: unknown = {}) {
  const t = build(o);
  return verifyTimestampToken(t.token, t.imprint, [t.caPem], options as VerifyOptions);
}
async function reason(o: Opts = {}, options: unknown = {}): Promise<Reason | 'ok'> {
  const r = await result(o, options);
  return r.ok ? 'ok' : r.reason;
}

// Befund 1b: freshness is only checked when the caller names a lower bound
describe('minGenTime: a token older than the caller allows is refused', () => {
  it('without minGenTime a token from 2021 verifies: freshness is NOT checked (docs/grenzen.md)', async () => {
    expect(await reason({ genTime: '20210101000000Z' })).toBe('ok');
  });
  it('refuses a genTime before minGenTime (time-too-old), accepts it at the edge and after', async () => {
    const edge = new Date('2026-01-01T00:00:00Z'); // the built genTime
    expect(await reason({}, { minGenTime: edge })).toBe('ok'); // equal is fine
    expect(await reason({}, { minGenTime: new Date(edge.getTime() + 1) })).toBe('time-too-old');
    expect(await reason({}, { minGenTime: new Date(edge.getTime() - 1) })).toBe('ok');
    expect(await reason({ genTime: '20210101000000Z' }, { minGenTime: edge })).toBe('time-too-old');
  });
  it('works with now and the skew: the window [minGenTime, now + skew]', async () => {
    const options = {
      minGenTime: new Date('2025-12-31T23:59:00Z'),
      now: new Date('2026-01-01T00:00:30Z'),
      maxSkewMs: 60_000,
    };
    expect(await reason({}, options)).toBe('ok');
    expect(await reason({ genTime: '20251231235800Z' }, options)).toBe('time-too-old');
    expect(await reason({ genTime: '20260101000200Z' }, options)).toBe('time-in-future');
  });
  it('the recorded FreeTSA token (13:05:56): too old for a later bound, fine for an earlier one', async () => {
    const r = readTimestampResponse(fixture('freetsa.tsr'));
    if (!r.ok) throw new Error(r.reason);
    const run = (minGenTime: Date) =>
      verifyTimestampToken(r.value.token, sha256('probe'), [fixtureText('cacert.pem')], {
        minGenTime,
      });
    expect(await run(new Date('2026-11-23T13:05:57Z'))).toEqual({
      ok: false,
      reason: 'time-too-old',
    });
    expect((await run(new Date('2026-11-23T13:05:56Z'))).ok).toBe(true);
  });
  const bad: [string, unknown][] = [
    ['an Invalid Date', new Date(NaN)],
    ['a string', '2026-01-01'],
    ['a number', 0],
    ['null', null],
    ['a Date subclass', new (class extends Date {})(0)],
    ['an object that claims to be a Date', { [Symbol.toStringTag]: 'Date', getTime: () => 0 }],
    ['a Date beyond the range', new Date(8.64e15 + 1)],
  ];
  for (const [name, value] of bad) {
    it(`refuses minGenTime as ${name} (bad-options, never a skipped check)`, async () => {
      expect(await reason({}, { minGenTime: value })).toBe('bad-options');
    });
  }
  it('undefined means not given; the extreme dates are valid values', async () => {
    expect(await reason({}, { minGenTime: undefined })).toBe('ok');
    expect(await reason({}, { minGenTime: new Date(8.64e15) })).toBe('time-too-old');
    expect(await reason({}, { minGenTime: new Date(-8.64e15) })).toBe('ok');
  });
  it('is read once with the built-in getTime; an inherited minGenTime does not count', async () => {
    const d = new Date('2030-01-01T00:00:00Z');
    let reads = 0;
    d.getTime = () => (reads++ === 0 ? 0 : NaN); // a lying method is never called
    expect(await reason({}, { minGenTime: d })).toBe('time-too-old');
    expect(reads).toBe(0);
    const proto = Object.prototype as Record<string, unknown>;
    try {
      proto.minGenTime = new Date('2030-01-01T00:00:00Z');
      expect(await reason({}, {})).toBe('ok');
    } finally {
      delete proto.minGenTime;
    }
  });
});

// Befund 2: the validity of the signer certificate is part of the result
describe('signerNotBefore and signerNotAfter', () => {
  it('report the validity of the signer certificate as ISO text', async () => {
    const r = await result({ tsaValidity: ['20250101000000Z', '20260601120000Z'] });
    if (!r.ok) throw new Error(r.reason);
    expect(r.value.signerNotBefore).toBe('2025-01-01T00:00:00.000Z');
    expect(r.value.signerNotAfter).toBe('2026-06-01T12:00:00.000Z');
  });
  it('are those of the signer, not of the root or an intermediate', async () => {
    const r = await result({
      tsaValidity: ['20250101000000Z', '20300101000000Z'],
      intermediate: { validity: ['20220101000000Z', '20290101000000Z'] },
    });
    if (!r.ok) throw new Error(r.reason);
    expect(r.value.signerNotAfter).toBe('2030-01-01T00:00:00.000Z');
  });
  it('match the certificate of the recorded FreeTSA token', async () => {
    const r = readTimestampResponse(fixture('freetsa.tsr'));
    if (!r.ok) throw new Error(r.reason);
    const v = await verifyTimestampToken(r.value.token, sha256('probe'), [
      fixtureText('cacert.pem'),
    ]);
    if (!v.ok) throw new Error(v.reason);
    const cert = parseCertificate(parsePemCertificates(fixtureText('tsa.crt'))[0]!.raw);
    expect(v.value.signerNotBefore).toBe(new Date(cert.notBefore).toISOString());
    expect(v.value.signerNotAfter).toBe(new Date(cert.notAfter).toISOString());
    expect(Date.parse(v.value.signerNotAfter)).toBeGreaterThan(Date.parse(v.value.genTime));
  });
});

// Befund 3: `at` is an additional moment, it does not replace genTime
describe('at: the certificates must be valid at genTime AND at `at`', () => {
  const y2025_2027: [string, string] = ['20250101000000Z', '20270101000000Z'];
  it('signer valid 2025-2027, genTime 2021, at 2026: refused (it was not valid at genTime)', async () => {
    const o: Opts = { tsaValidity: y2025_2027, genTime: '20210101000000Z' };
    expect(await reason(o)).toBe('certificate-not-valid-at-time'); // without `at`, as before
    expect(await reason(o, { at: new Date('2026-06-01T00:00:00Z') })).toBe(
      'certificate-not-valid-at-time',
    );
  });
  it('signer valid at genTime but not at `at`: refused; valid at both: accepted', async () => {
    const o: Opts = { tsaValidity: y2025_2027, genTime: '20260101000000Z' };
    expect(await reason(o)).toBe('ok'); // without `at`: unchanged
    expect(await reason(o, { at: new Date('2026-06-01T00:00:00Z') })).toBe('ok');
    expect(await reason(o, { at: new Date('2028-01-01T00:00:00Z') })).toBe(
      'certificate-not-valid-at-time',
    );
    expect(await reason(o, { at: new Date('2024-06-01T00:00:00Z') })).toBe(
      'certificate-not-valid-at-time',
    );
  });
  it('the chain too: an intermediate valid at `at` but not at genTime is refused (and the other way round)', async () => {
    const lateIntermediate: Opts = {
      intermediate: { validity: ['20260301000000Z', '20400101000000Z'] },
    };
    expect(await reason(lateIntermediate)).toBe('certificate-not-valid-at-time'); // genTime 2026-01-01
    expect(await reason(lateIntermediate, { at: new Date('2026-06-01T00:00:00Z') })).toBe(
      'certificate-not-valid-at-time',
    );
    const earlyIntermediate: Opts = {
      intermediate: { validity: ['20200101000000Z', '20260601000000Z'] },
    };
    expect(await reason(earlyIntermediate)).toBe('ok');
    expect(await reason(earlyIntermediate, { at: new Date('2026-03-01T00:00:00Z') })).toBe('ok');
    expect(await reason(earlyIntermediate, { at: new Date('2027-01-01T00:00:00Z') })).toBe(
      'certificate-not-valid-at-time',
    );
  });
  it('the recorded tokens: `at` between genTime and the end of the certificates is fine', async () => {
    const r = readTimestampResponse(fixture('freetsa.tsr'));
    if (!r.ok) throw new Error(r.reason);
    const v = await verifyTimestampToken(
      r.value.token,
      sha256('probe'),
      [fixtureText('cacert.pem')],
      {
        at: new Date('2026-12-01T00:00:00Z'),
      },
    );
    expect(v.ok).toBe(true);
  });
});
