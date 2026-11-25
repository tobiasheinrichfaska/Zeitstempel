// pathLenConstraint, "the signer is no CA" and expectedPolicy, each against `openssl ts -verify` (measured with
// OpenSSL 3.0.13; a visible skip without OpenSSL 3) and against our own verdict and reason.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ReaderError, parseCertificate, verifyTimestampToken } from '../src/index.ts';
import type { Reason } from '../src/lib/index.ts';
import { tlv } from '../src/lib/der.ts';
import { build, ext, int, seq, type Opts } from './token-builder.ts';

const probe = spawnSync('openssl', ['version'], { encoding: 'utf8' });
const major = Number(/^OpenSSL (\d+)/.exec(probe.stdout ?? '')?.[1] ?? 0);
const canCompare = probe.status === 0 && major >= 3;
const bool = (b: boolean) => tlv(1, Uint8Array.of(b ? 0xff : 0));
const ATTIME = '1767225600'; // 2026-01-01T00:00:00Z, the genTime of the builder's tokens

let tmp = '';
const path = (name: string) => join(tmp, name);
beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), 'zeitstempel-chain-'));
});
afterAll(() => {
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

function opensslVerify(
  t: ReturnType<typeof build>,
  extra: string[] = [],
): { ok: boolean; stderr: string } {
  writeFileSync(path('row.tok'), t.token);
  writeFileSync(path('row.ca.pem'), t.caPem);
  const r = spawnSync(
    'openssl',
    [
      'ts',
      '-verify',
      '-in',
      path('row.tok'),
      '-token_in',
      ...(extra.includes('-queryfile') ? [] : ['-digest', Buffer.from(t.imprint).toString('hex')]),
      '-CAfile',
      path('row.ca.pem'),
      '-attime',
      ATTIME,
      ...extra,
    ],
    { encoding: 'utf8' },
  );
  return { ok: r.status === 0, stderr: r.stderr ?? '' };
}

async function ours(t: ReturnType<typeof build>, options: object = {}): Promise<Reason | 'ok'> {
  const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem], options);
  return r.ok ? 'ok' : r.reason;
}

interface Row {
  label: string;
  opts: Opts;
  openssl: boolean;
  ours: Reason | 'ok';
}

const KU = (unused: number, bits: number) => Uint8Array.of(unused, bits);
const CA_TRUE = (critical = true, rest: Uint8Array[] = []) =>
  ext('2.5.29.19', critical, seq(bool(true), ...rest));

const ROWS: Row[] = [
  // pathLenConstraint of intermediate certificates (the signer hangs below the last one)
  {
    label: 'one intermediate with pathLen 0',
    opts: { deepChain: 1, deepPathLens: [0] },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'two intermediates, the first has pathLen 0',
    opts: { deepChain: 2, deepPathLens: [0] },
    openssl: false,
    ours: 'chain-too-long',
  },
  {
    label: 'two intermediates, the first has pathLen 1',
    opts: { deepChain: 2, deepPathLens: [1] },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'three intermediates, the second has pathLen 0',
    opts: { deepChain: 3, deepPathLens: [undefined, 0] },
    openssl: false,
    ours: 'chain-too-long',
  },
  {
    label: 'three intermediates, the first has pathLen 1 (two below)',
    opts: { deepChain: 3, deepPathLens: [1] },
    openssl: false,
    ours: 'chain-too-long',
  },
  {
    label: 'three intermediates, the first has pathLen 2',
    opts: { deepChain: 3, deepPathLens: [2] },
    openssl: true,
    ours: 'ok',
  },
  {
    label:
      'an intermediate with pathLen 0 directly above the signer (the signer is no CA and does not count)',
    opts: { intermediate: { pathLen: 0 } },
    openssl: true,
    ours: 'ok',
  },
  // the trust anchor's own pathLen also limits the chain (the caller chose the anchor, and the anchor said so)
  {
    label: 'root with pathLen 0, no intermediate',
    opts: { rootPathLen: 0 },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'root with pathLen 0, one intermediate',
    opts: { deepChain: 1, rootPathLen: 0 },
    openssl: false,
    ours: 'chain-too-long',
  },
  {
    label: 'root with pathLen 1, two intermediates',
    opts: { deepChain: 2, rootPathLen: 1 },
    openssl: false,
    ours: 'chain-too-long',
  },
  {
    label: 'root with pathLen 2, two intermediates',
    opts: { deepChain: 2, rootPathLen: 2 },
    openssl: true,
    ours: 'ok',
  },
  // the signer is an end entity
  {
    label: 'signer with cA=TRUE',
    opts: { extraTsaExts: [CA_TRUE()] },
    openssl: true,
    ours: 'bad-certificate',
  },
  {
    label: 'signer with cA=TRUE, not critical',
    opts: { extraTsaExts: [CA_TRUE(false)] },
    openssl: true,
    ours: 'bad-certificate',
  },
  {
    label: 'signer with cA=TRUE and pathLen 0',
    opts: { extraTsaExts: [CA_TRUE(true, [int(0)])] },
    openssl: true,
    ours: 'bad-certificate',
  },
  {
    label: 'signer with cA=TRUE and keyCertSign next to digitalSignature',
    opts: { extraTsaExts: [CA_TRUE()], tsaKeyUsage: KU(2, 0x84) },
    openssl: false,
    ours: 'bad-certificate',
  },
  {
    label: 'signer with keyCertSign next to digitalSignature, no basicConstraints',
    opts: { tsaKeyUsage: KU(2, 0x84) },
    openssl: false,
    ours: 'bad-certificate',
  },
  {
    label: 'signer with keyCertSign only (no signing bit at all)',
    opts: { tsaKeyUsage: KU(2, 0x04) },
    openssl: false,
    ours: 'bad-eku',
  },
  {
    label: 'signer with an explicit cA=FALSE',
    opts: { extraTsaExts: [ext('2.5.29.19', true, seq(bool(false)))] },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'signer with an empty basicConstraints',
    opts: { extraTsaExts: [ext('2.5.29.19', true, seq())] },
    openssl: true,
    ours: 'ok',
  },
];

describe.skipIf(!canCompare)('chain rules against openssl ts -verify', () => {
  for (const r of ROWS) {
    const same = r.openssl === (r.ours === 'ok');
    it(`${same ? 'same' : 'DIFFERENT'}: ${r.label}: openssl ${r.openssl ? 'accepts' : 'refuses'}, we ${r.ours === 'ok' ? 'accept' : `refuse (${r.ours})`}`, async () => {
      const t = build(r.opts);
      expect(opensslVerify(t).ok).toBe(r.openssl);
      expect(await ours(t)).toBe(r.ours);
    });
  }
});

describe('chain rules (our verdicts only)', () => {
  it('the verdict does not depend on openssl: every row above gives its reason', async () => {
    for (const r of ROWS) expect(await ours(build(r.opts)), r.label).toBe(r.ours);
  });

  it('a self-issued intermediate does not count against a pathLen (RFC 5280 § 6.1.4 (l))', async () => {
    // root(pathLen 0) -> self-issued CA (same name, new key) -> signer: openssl cannot build this path (it picks
    // the issuer by name and fails on the signature), so there is no comparison; the rule is the RFC's
    expect(await ours(build({ rollover: {}, rootPathLen: 0 }))).toBe('ok');
    expect(await ours(build({ rollover: { pathLen: 0 } }))).toBe('ok');
    expect(await ours(build({ rollover: {} }))).toBe('ok');
  });

  it('a pathLen next to cA FALSE is ignored (the certificate is no CA anyway)', () => {
    const t = build({ extraTsaExts: [ext('2.5.29.19', true, seq(int(0)))] });
    const cert = parseCertificate(t.tsaCert);
    expect(cert.isCa).toBe(false);
    expect(cert.pathLen).toBeNull();
  });

  it('parseCertificate reads the pathLen; a negative one or extra elements are unreadable (bad-certificate)', () => {
    const read = (bc: Uint8Array) =>
      parseCertificate(build({ extraTsaExts: [ext('2.5.29.19', true, bc)] }).tsaCert);
    expect(read(seq(bool(true), int(0))).pathLen).toBe(0);
    expect(read(seq(bool(true), int(5))).pathLen).toBe(5);
    expect(read(seq(bool(true))).pathLen).toBeNull();
    expect(read(seq(bool(true), tlv(2, Uint8Array.of(1, 0, 0, 0, 0, 0, 0, 0)))).pathLen).toBe(
      Number.MAX_SAFE_INTEGER,
    ); // beyond any chain: clamped, not unreadable
    for (const bad of [
      seq(bool(true), tlv(2, Uint8Array.of(0xff))), // negative
      seq(bool(true), int(1), int(2)), // an element too many
      seq(bool(true), tlv(4, Uint8Array.of(1))), // not an INTEGER
      seq(int(1), bool(true)), // wrong order
    ]) {
      let thrown: unknown;
      try {
        read(bad);
      } catch (e) {
        thrown = e;
      }
      expect(thrown).toBeInstanceOf(ReaderError);
      expect((thrown as ReaderError).reason).toMatch(/^(bad-certificate|malformed)$/);
    }
  });

  it('a signer handed over as the trust anchor itself may be a CA (the caller chose it)', async () => {
    const t = build({ extraTsaExts: [CA_TRUE()] });
    const r = await verifyTimestampToken(t.token, t.imprint, [t.tsaPem]);
    expect(r.ok).toBe(true);
  });

  it('an intermediate used as the trust anchor keeps its own pathLen out of the way when nothing is below', async () => {
    const t = build({ intermediate: { pathLen: 0 } });
    const r = await verifyTimestampToken(t.token, t.imprint, [t.intPem]);
    expect(r.ok).toBe(true);
  });
});

describe('expectedPolicy', () => {
  const t = build({ tstPolicy: '1.2.3.4' });
  const verify = async (options: unknown) => {
    const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem], options as object);
    return r.ok ? 'ok' : r.reason;
  };

  it('accepts the policy of the token (a string or a list) and refuses any other with policy-mismatch', async () => {
    expect(await verify({ expectedPolicy: '1.2.3.4' })).toBe('ok');
    expect(await verify({ expectedPolicy: ['1.2.3.5', '1.2.3.4'] })).toBe('ok');
    expect(await verify({ expectedPolicy: '1.2.3.5' })).toBe('policy-mismatch');
    expect(await verify({ expectedPolicy: ['1.2.3.5', '2.5.29.32.0'] })).toBe('policy-mismatch');
    expect(await verify({ expectedPolicy: '1.2.3' })).toBe('policy-mismatch'); // no prefix match
    expect(await verify({ expectedPolicy: '1.2.3.4.5' })).toBe('policy-mismatch');
    expect(await verify({ expectedPolicy: '1.2.3.40' })).toBe('policy-mismatch');
  });

  it('without the option the policy is not checked; undefined means "not given"', async () => {
    expect(await verify({})).toBe('ok');
    expect(await verify({ expectedPolicy: undefined })).toBe('ok');
  });

  it('refuses a bad value with bad-options, never a silent skip', async () => {
    const bad: unknown[] = [
      null,
      1,
      true,
      {},
      [],
      '',
      ' 1.2.3.4',
      '1.2.3.4 ',
      '1.2.3.',
      '.1.2.3',
      '1..2',
      '1',
      'a.b.c',
      '1.2.03',
      '3.1.2',
      '1.40.1',
      '0.40.1',
      '1.2.3.-4',
      '1.2.3.4\n',
      '1.2.3.4' + '.1'.repeat(40),
      [1],
      ['1.2.3.4', 2],
      ['1.2.3.4', ''],
      new Set(['1.2.3.4']),
      new String('1.2.3.4'),
      Array.from({ length: 17 }, () => '1.2.3.4'),
    ];
    for (const value of bad)
      expect(await verify({ expectedPolicy: value }), String(value)).toBe('bad-options');
    // a hostile array: a length or element that throws
    const hostile = new Proxy(['1.2.3.4'], {
      get(target, key, receiver) {
        if (key === 'length' || key === '0') throw new Error('boom');
        return Reflect.get(target, key, receiver);
      },
    });
    expect(await verify({ expectedPolicy: hostile })).toBe('bad-options');
  });

  it('allows the arcs of the standard anyPolicy and long arcs', async () => {
    const any = build({ tstPolicy: '2.5.29.32.0' });
    const r = await verifyTimestampToken(any.token, any.imprint, [any.caPem], {
      expectedPolicy: ['2.5.29.32.0'],
    });
    expect(r.ok).toBe(true);
    const long = build({ tstPolicy: '1.3.6.1.4.1.311.21.7' });
    expect(
      (
        await verifyTimestampToken(long.token, long.imprint, [long.caPem], {
          expectedPolicy: '1.3.6.1.4.1.311.21.7',
        })
      ).ok,
    ).toBe(true);
  });

  it('the reported policy is still the one of the token', async () => {
    const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem], {
      expectedPolicy: '1.2.3.4',
    });
    expect(r.ok && r.value.policy).toBe('1.2.3.4');
  });

  describe.skipIf(!canCompare)(
    'against openssl ts -verify with a request that names a policy',
    () => {
      for (const [wanted, accepts] of [
        ['1.2.3.4', true],
        ['1.2.3.5', false],
        ['1.2.3', false],
        ['1.2.3.4.5', false],
      ] as const) {
        it(`request policy ${wanted}: openssl ${accepts ? 'accepts' : 'refuses'}, so do we`, async () => {
          const q = spawnSync(
            'openssl',
            [
              'ts',
              '-query',
              '-digest',
              Buffer.from(t.imprint).toString('hex'),
              '-no_nonce',
              '-cert',
              '-tspolicy',
              wanted,
              '-out',
              path('policy.tsq'),
            ],
            { encoding: 'utf8' },
          );
          expect(q.status, q.stderr).toBe(0);
          const theirs = opensslVerify(t, ['-queryfile', path('policy.tsq')]);
          expect(theirs.ok, theirs.stderr).toBe(accepts);
          if (!accepts) expect(theirs.stderr).toContain('policy mismatch'); // refused for this reason
          expect(await verify({ expectedPolicy: wanted })).toBe(accepts ? 'ok' : 'policy-mismatch');
        });
      }
    },
  );
});
