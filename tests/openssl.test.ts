// Cross-check against an independent implementation: `openssl ts -verify` must agree with ours on the
// recorded answers, and must refuse what we refuse. Skipped (and reported as skipped) without openssl.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readTimestampResponse, verifyTimestampToken } from '../src/index.ts';
import { fixture, sha256 } from './helpers.ts';
import { build, type Opts } from './token-builder.ts';

const probe = spawnSync('openssl', ['version'], { encoding: 'utf8' });
const major = Number(/^OpenSSL (\d+)/.exec(probe.stdout ?? '')?.[1] ?? 0);
const hasOpenssl = probe.status === 0;
// `-attime` (judge the certificates at the stamped time, not today) needs OpenSSL 3; older ones skip visibly.
const canJudgeAtTime = hasOpenssl && major >= 3;
let tmp = '';
const path = (name: string) => join(tmp, name);

const CASES = [
  { file: 'freetsa.tsr', anchor: 'freetsa-root' },
  { file: 'sectigo.tsr', anchor: 'usertrust-rsa' },
  { file: 'digicert.tsr', anchor: 'digicert-trusted-root-g4' },
  { file: 'certum.tsr', anchor: 'certum-trusted-network-ca-2' },
];

function openssl(args: string[]): { ok: boolean; stderr: string } {
  const r = spawnSync('openssl', args, { encoding: 'utf8' });
  return { ok: r.status === 0, stderr: r.stderr ?? '' };
}

/** The time the service stamped, in whole seconds since 1970, as read by our own verifier. */
async function stampedAt(file: string, anchor: string): Promise<string> {
  const parsed = readTimestampResponse(fixture(file));
  if (!parsed.ok) throw new Error(`cannot read ${file}`);
  const r = await verifyTimestampToken(parsed.value.token, sha256('probe'), [
    readFileSync(anchor, 'utf8'),
  ]);
  if (!r.ok) throw new Error(`cannot verify ${file}: ${r.reason}`);
  return String(Math.floor(Date.parse(r.value.genTime) / 1000));
}

const anchorPath = (id: string) =>
  new URL(`../anchors/${id}.pem`, import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');

/** Writes the token's certificates as one PEM file (the "untrusted" intermediates for openssl). */
function chainPem(tsr: string): string {
  const token = path(`${tsr}.token`);
  openssl(['ts', '-reply', '-in', path(tsr), '-token_out', '-out', token]);
  const out = spawnSync('openssl', ['pkcs7', '-inform', 'DER', '-in', token, '-print_certs'], {
    encoding: 'utf8',
  });
  writeFileSync(path(`${tsr}.chain.pem`), out.stdout);
  return path(`${tsr}.chain.pem`);
}

if (hasOpenssl && !canJudgeAtTime) {
  it.skip('agreement with openssl ts -verify (needs OpenSSL 3 for -attime; this one is older)', () => {});
}
describe.skipIf(!canJudgeAtTime)('agreement with openssl ts -verify', () => {
  beforeAll(() => {
    tmp = mkdtempSync(join(tmpdir(), 'zeitstempel-openssl-'));
    for (const c of CASES) writeFileSync(path(c.file), fixture(c.file));
    writeFileSync(path('request.tsq'), fixture('freetsa.tsq'));
  });
  afterAll(() => {
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  });

  for (const c of CASES) {
    it(`${c.file}: both accept the recorded answer`, async () => {
      const anchor = anchorPath(c.anchor);
      const theirs = openssl([
        'ts',
        '-verify',
        '-in',
        path(c.file),
        '-queryfile',
        path('request.tsq'),
        '-CAfile',
        anchor,
        '-untrusted',
        chainPem(c.file),
        '-attime',
        await stampedAt(c.file, anchor),
      ]);
      const parsed = readTimestampResponse(fixture(c.file));
      const ours =
        parsed.ok &&
        (
          await verifyTimestampToken(parsed.value.token, sha256('probe'), [
            readFileSync(anchor, 'utf8'),
          ])
        ).ok;
      expect(theirs.ok, theirs.stderr).toBe(true);
      expect(ours).toBe(true);
    });
  }

  it('both refuse the answer for another request (hash differs)', async () => {
    const other = path('other.tsq');
    writeFileSync(other, new Uint8Array(0));
    const made = spawnSync('openssl', [
      'ts',
      '-query',
      '-data',
      path('request.tsq'),
      '-sha256',
      '-cert',
      '-out',
      other,
    ]);
    expect(made.status).toBe(0); // a request for different data (the request file itself)
    const anchor = anchorPath('freetsa-root');
    const theirs = openssl([
      'ts',
      '-verify',
      '-in',
      path('freetsa.tsr'),
      '-queryfile',
      other,
      '-CAfile',
      anchor,
      '-untrusted',
      chainPem('freetsa.tsr'),
      '-attime',
      await stampedAt('freetsa.tsr', anchor),
    ]);
    const parsed = readTimestampResponse(fixture('freetsa.tsr'));
    const ours =
      parsed.ok &&
      (
        await verifyTimestampToken(parsed.value.token, sha256('another thing'), [
          readFileSync(anchor, 'utf8'),
        ])
      ).ok;
    expect(theirs.ok).toBe(false);
    expect(theirs.stderr).toContain('message imprint mismatch'); // refused for this reason, not another
    expect(ours).toBe(false);
  });

  it("both refuse a trust anchor that is not the signer's root (the chain does not lead there)", async () => {
    const wrong = anchorPath('usertrust-rsa');
    const right = anchorPath('freetsa-root');
    const theirs = openssl([
      'ts',
      '-verify',
      '-in',
      path('freetsa.tsr'),
      '-queryfile',
      path('request.tsq'),
      '-CAfile',
      wrong,
      '-untrusted',
      chainPem('freetsa.tsr'),
      '-attime',
      await stampedAt('freetsa.tsr', right),
    ]);
    const parsed = readTimestampResponse(fixture('freetsa.tsr'));
    const ours =
      parsed.ok &&
      (
        await verifyTimestampToken(parsed.value.token, sha256('probe'), [
          readFileSync(wrong, 'utf8'),
        ])
      ).ok;
    expect(theirs.ok).toBe(false);
    expect(theirs.stderr).toContain('certificate verify error');
    // the cause, not just any verify error: the chain ends in a self-signed root that is not the given one
    expect(theirs.stderr).toContain('self-signed certificate in certificate chain');
    expect(ours).toBe(false);
  });

  // Built tokens: both must agree on the names, the v1 root and an unreadable extra certificate.
  const SHAPES: [string, Opts, boolean][] = [
    [
      'issuer PrintableString "ca" against UTF8String "CA"',
      { tsaIssuerName: { tag: 0x13, text: 'ca' } },
      true,
    ],
    [
      'sid issuer IA5String " Ca " against UTF8String "CA"',
      { sidIssuerName: { tag: 0x16, text: ' Ca ' } },
      true,
    ],
    [
      'another name',
      { tsaIssuerName: { tag: 0x13, text: 'cb' }, sidIssuerName: { tag: 0x13, text: 'cb' } },
      false,
    ],
    ['a v1 root without extensions as anchor', { rootV1: true }, true],
    ['an anchor with cA=false', { rootNotCa: true }, false],
    [
      'an unreadable extra certificate in the token',
      { junkCerts: [build({ serialRaw: Uint8Array.of(0x80) }).tsaCert] },
      true,
    ],
  ];
  for (const [label, shape, accepted] of SHAPES) {
    it(`both ${accepted ? 'accept' : 'refuse'}: ${label}`, async () => {
      const t = build(shape);
      writeFileSync(path('built.tok'), t.token);
      writeFileSync(path('built.ca.pem'), t.caPem);
      const theirs = openssl([
        'ts',
        '-verify',
        '-in',
        path('built.tok'),
        '-token_in',
        '-digest',
        Buffer.from(t.imprint).toString('hex'),
        '-CAfile',
        path('built.ca.pem'),
        '-attime',
        '1767225600', // 2026-01-01, the built genTime
      ]);
      const ours = (await verifyTimestampToken(t.token, t.imprint, [t.caPem])).ok;
      expect(theirs.ok, theirs.stderr).toBe(accepted);
      expect(ours).toBe(accepted);
    });
  }
});
