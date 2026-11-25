// Cross-check against an independent implementation: `openssl ts -verify` must agree with ours on the
// recorded answers, and must refuse what we refuse. Skipped (and reported as skipped) without openssl.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readTimestampResponse, readToken, verifyTimestampToken } from '../src/index.ts';
import { fixture, sha256 } from './helpers.ts';
import type { Reason } from '../src/lib/index.ts';
import { tlv } from '../src/lib/der.ts';
import { build, ext, nameWith, octet, oidT, seq, type Opts } from './token-builder.ts';

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
    [
      'ecdsa-with-SHA384 named, digestAlgorithm SHA-256, signed with SHA-384 (hash of the OID differs)',
      { signatureAlg: { oid: '1.2.840.10045.4.3.3', hash: 'sha384' } },
      false,
    ],
    [
      'a bare id-ecPublicKey signature OID takes the hash of the digestAlgorithm',
      { signatureAlg: { oid: '1.2.840.10045.2.1', hash: 'sha256' } },
      true,
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
  // ---- The measured differences (docs/grenzen.md, table "Abgleich mit OpenSSL"): one row per case, with the
  // outcome of OpenSSL 3 (`openssl ts -verify`) AND ours written down, so a change on either side is noticed.
  // Rows where both agree show that a rule is the same; rows where they differ are the documented deviations.
  const bool = (b: boolean) => tlv(1, Uint8Array.of(b ? 0xff : 0));
  const utf8 = (text: string) => new TextEncoder().encode(text);
  const dir = (cn: string) => tlv(0xa0, tlv(0xa4, nameWith(0x0c, cn))); // tsa [0] directoryName
  const gn = (tag: number, bytes: Uint8Array) => tlv(0xa0, tlv(tag, bytes));
  const san = (...names: Uint8Array[]) => [ext('2.5.29.17', false, seq(...names))];
  const accuracy = (...parts: Uint8Array[]) => seq(...parts);
  const secs = (n: number) => tlv(2, Uint8Array.of(n));
  const part = (tag: number, n: number) =>
    tlv(tag, n < 128 ? Uint8Array.of(n) : Uint8Array.of(n >> 8, n & 0xff));
  const nonce = (n: number) => tlv(2, Uint8Array.of(n));
  const exts = (...e: Uint8Array[]) => tlv(0xa1, ...e);
  const anExt = (critical?: boolean) =>
    critical === undefined
      ? seq(oidT('1.2.3.4.5'), octet(tlv(5, new Uint8Array())))
      : seq(oidT('1.2.3.4.5'), bool(critical), octet(tlv(5, new Uint8Array())));
  const SHA256_ALG = '2.16.840.1.101.3.4.2.1';
  const x = build().imprint; // the hash every built token carries unless told otherwise
  const patchAt = (t: Uint8Array, f: (a: Uint8Array) => Uint8Array) => f(Uint8Array.from(t));

  interface Row {
    label: string;
    opts: Opts;
    patch?: (token: Uint8Array) => Uint8Array;
    /** Does `openssl ts -verify` accept it? */
    openssl: boolean;
    /** Do we accept it (default options)? */
    ours: boolean;
    reason?: Reason;
  }
  const row = (
    label: string,
    opts: Opts,
    openssl: boolean,
    ours: boolean,
    reason?: Reason,
    patch?: Row['patch'],
  ): Row => ({
    label,
    opts,
    openssl,
    ours,
    ...(reason ? { reason } : {}),
    ...(patch ? { patch } : {}),
  });
  const ROWS: Row[] = [
    // F1: the tsa field
    row('tsa names the signer subject (directoryName)', { tstExtra: [dir('TSA')] }, true, true),
    row(
      'tsa names another directoryName',
      { tstExtra: [dir('Other')] },
      false,
      false,
      'tsa-mismatch',
    ),
    row(
      'tsa names the issuer, not the signer',
      { tstExtra: [dir('CA')] },
      false,
      false,
      'tsa-mismatch',
    ),
    row(
      'tsa directoryName found in the subjectAltName',
      { tstExtra: [dir('Other Name')], extraTsaExts: san(tlv(0xa4, nameWith(0x0c, 'Other Name'))) },
      true,
      true,
    ),
    row(
      'tsa dNSName equal to a subjectAltName dNSName',
      {
        tstExtra: [gn(0x82, utf8('tsa.example.org'))],
        extraTsaExts: san(tlv(0x82, utf8('tsa.example.org'))),
      },
      true,
      true,
    ),
    row(
      'tsa dNSName in other case than the subjectAltName (RFC 5280 § 7.2: DNS names ignore case)',
      {
        tstExtra: [gn(0x82, utf8('TSA.Example.ORG'))],
        extraTsaExts: san(tlv(0x82, utf8('tsa.example.org'))),
      },
      false,
      true,
    ),
    row(
      'tsa dNSName not in the subjectAltName',
      {
        tstExtra: [gn(0x82, utf8('o.example.org'))],
        extraTsaExts: san(tlv(0x82, utf8('tsa.example.org'))),
      },
      false,
      false,
      'tsa-mismatch',
    ),
    row(
      'tsa dNSName and no subjectAltName',
      { tstExtra: [gn(0x82, utf8('tsa.example.org'))] },
      false,
      false,
      'tsa-mismatch',
    ),
    row(
      'tsa rfc822Name equal',
      {
        tstExtra: [gn(0x81, utf8('ts@example.org'))],
        extraTsaExts: san(tlv(0x81, utf8('ts@example.org'))),
      },
      true,
      true,
    ),
    row(
      'tsa rfc822Name in other case (exact)',
      {
        tstExtra: [gn(0x81, utf8('TS@example.org'))],
        extraTsaExts: san(tlv(0x81, utf8('ts@example.org'))),
      },
      false,
      false,
      'tsa-mismatch',
    ),
    row(
      'tsa URI equal',
      {
        tstExtra: [gn(0x86, utf8('https://t.example.org/'))],
        extraTsaExts: san(tlv(0x86, utf8('https://t.example.org/'))),
      },
      true,
      true,
    ),
    row(
      'tsa iPAddress equal',
      {
        tstExtra: [gn(0x87, Uint8Array.of(192, 0, 2, 1))],
        extraTsaExts: san(tlv(0x87, Uint8Array.of(192, 0, 2, 1))),
      },
      true,
      true,
    ),
    row(
      'tsa iPAddress other',
      {
        tstExtra: [gn(0x87, Uint8Array.of(192, 0, 2, 2))],
        extraTsaExts: san(tlv(0x87, Uint8Array.of(192, 0, 2, 1))),
      },
      false,
      false,
      'tsa-mismatch',
    ),
    row(
      'tsa registeredID equal',
      {
        tstExtra: [gn(0x88, Uint8Array.of(0x2a, 3, 4))],
        extraTsaExts: san(tlv(0x88, Uint8Array.of(0x2a, 3, 4))),
      },
      true,
      true,
    ),
    row(
      'tsa dNSName against a URI entry with the same text',
      {
        tstExtra: [gn(0x82, utf8('a.example.org'))],
        extraTsaExts: san(tlv(0x86, utf8('a.example.org'))),
      },
      false,
      false,
      'tsa-mismatch',
    ),
    row('tsa [0] empty', { tstExtra: [tlv(0xa0)] }, false, false, 'bad-tst-info'),
    row(
      'tsa with an undefined GeneralName tag',
      { tstExtra: [tlv(0xa0, tlv(0x89, utf8('x')))] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'tsa with two names',
      { tstExtra: [tlv(0xa0, tlv(0x82, utf8('a')), tlv(0x82, utf8('b')))] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'tsa needs a subjectAltName that cannot be read',
      {
        tstExtra: [gn(0x82, utf8('a.example.org'))],
        extraTsaExts: [ext('2.5.29.17', false, tlv(5, new Uint8Array()))],
      },
      false,
      false,
      'bad-certificate',
    ),
    // F2: the TSTInfo as a schema
    row(
      'every optional field, in the order of the schema',
      {
        tstFields: [
          accuracy(secs(1), part(0x80, 5), part(0x81, 5)),
          bool(true),
          nonce(7),
          dir('TSA'),
          exts(anExt(), anExt(true)),
        ],
      },
      true,
      true,
    ),
    row('ordering twice', { tstFields: [bool(true), bool(true)] }, false, false, 'bad-tst-info'),
    row(
      'accuracy twice',
      { tstFields: [accuracy(secs(1)), accuracy(secs(2))] },
      false,
      false,
      'bad-tst-info',
    ),
    row('nonce twice', { tstFields: [nonce(1), nonce(2)] }, false, false, 'bad-tst-info'),
    row('tsa twice', { tstFields: [dir('TSA'), dir('TSA')] }, false, false, 'bad-tst-info'),
    row(
      'extensions twice',
      { tstFields: [exts(anExt()), exts(anExt())] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'accuracy after nonce',
      { tstFields: [nonce(7), accuracy(secs(1))] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'accuracy after ordering',
      { tstFields: [bool(true), accuracy(secs(1))] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'ordering after nonce',
      { tstFields: [nonce(7), bool(true)] },
      false,
      false,
      'bad-tst-info',
    ),
    row('nonce after tsa', { tstFields: [dir('TSA'), nonce(7)] }, false, false, 'bad-tst-info'),
    row(
      'tsa after extensions',
      { tstFields: [exts(anExt()), dir('TSA')] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'an element of no field (NULL, OCTET STRING, [2], bare [0])',
      { tstFields: [tlv(5, new Uint8Array())] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'a bare [0] where the tsa SEQUENCE should be',
      { tstFields: [tlv(0x80, Uint8Array.of(1))] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'ordering FALSE written out (DER leaves a DEFAULT out)',
      { tstFields: [bool(false)] },
      true,
      false,
      'bad-tst-info',
    ),
    row(
      'accuracy millis before seconds',
      { tstFields: [accuracy(part(0x80, 5), secs(1))] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'accuracy micros before millis',
      { tstFields: [accuracy(part(0x81, 5), part(0x80, 5))] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'accuracy seconds twice',
      { tstFields: [accuracy(secs(1), secs(2))] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'accuracy millis twice',
      { tstFields: [accuracy(part(0x80, 5), part(0x80, 6))] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'accuracy with an undefined [2]',
      { tstFields: [accuracy(secs(1), tlv(0x82, Uint8Array.of(1)))] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'accuracy with a NULL',
      { tstFields: [accuracy(tlv(5, new Uint8Array()))] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'accuracy millis 1000 (range 1..999)',
      { tstFields: [accuracy(secs(1), part(0x80, 1000))] },
      true,
      false,
      'bad-tst-info',
    ),
    row(
      'accuracy millis 0',
      { tstFields: [accuracy(secs(1), part(0x80, 0))] },
      true,
      false,
      'bad-tst-info',
    ),
    row(
      'accuracy micros 1000',
      { tstFields: [accuracy(secs(1), part(0x81, 1000))] },
      true,
      false,
      'bad-tst-info',
    ),
    row(
      'accuracy micros 0',
      { tstFields: [accuracy(secs(1), part(0x81, 0))] },
      true,
      false,
      'bad-tst-info',
    ),
    row(
      'accuracy with every part empty (the schema allows it)',
      { tstFields: [accuracy()] },
      true,
      true,
    ),
    row('accuracy of micros only', { tstFields: [accuracy(part(0x81, 5))] }, true, true),
    row('extensions [1] empty (SIZE 1..MAX)', { tstFields: [exts()] }, true, false, 'bad-tst-info'),
    row(
      'extensions [1] holding garbage',
      { tstFields: [tlv(0xa1, tlv(5, new Uint8Array()))] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'an extension without a value',
      { tstFields: [exts(seq(oidT('1.2.3')))] },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'an extension with four parts',
      {
        tstFields: [
          exts(
            seq(oidT('1.2.3'), bool(true), octet(Uint8Array.of(5, 0)), octet(Uint8Array.of(5, 0))),
          ),
        ],
      },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'extension critical FALSE written out',
      { tstFields: [exts(anExt(false))] },
      true,
      false,
      'bad-tst-info',
    ),
    row(
      'a critical extension this library does not know (not judged)',
      { tstFields: [exts(anExt(true))] },
      true,
      true,
    ),
    row(
      'messageImprint with three parts',
      { tstImprintRaw: seq(seq(oidT(SHA256_ALG)), octet(x), octet(x)) },
      false,
      false,
      'bad-tst-info',
    ),
    row(
      'hash algorithm with a NULL parameter',
      { tstImprintRaw: seq(seq(oidT(SHA256_ALG), tlv(5, new Uint8Array())), octet(x)) },
      true,
      true,
    ),
    row(
      'hash algorithm with an INTEGER parameter (any parameter is allowed by the schema)',
      { tstImprintRaw: seq(seq(oidT(SHA256_ALG), tlv(2, Uint8Array.of(1))), octet(x)) },
      true,
      false,
      'bad-tst-info',
    ),
    // F3: weak RSA keys
    row('RSA 2048 signer', { rsa: { tsa: 2048 } }, true, true),
    row('RSA 1024 signer', { rsa: { tsa: 1024 } }, true, false, 'weak-key'),
    row('RSA 512 signer', { rsa: { tsa: 512 } }, true, false, 'weak-key'),
    row('RSA 1024 intermediate', { intermediate: {}, rsa: { int: 1024 } }, true, false, 'weak-key'),
    row('RSA 1024 root as the trust anchor', { rsa: { ca: 1024 } }, true, true),
    // measured with OpenSSL 3.0.13: its default security level does not look at the signature hash of a CA
    row(
      'intermediate signed with ecdsa-with-SHA1 (SHA-1 is no signature hash here)',
      { intermediate: { sha1Signed: true } },
      true,
      false,
      'untrusted-chain',
    ),
    // other measured differences (F6, F12, F14 and others of the benchmark)
    // F6: openssl accepts a signer with cA=TRUE; we refuse it (the rows with more cases are in tests/chain-rules.test.ts)
    row(
      'the signer certificate is a CA itself (basicConstraints cA=TRUE)',
      { extraTsaExts: [ext('2.5.29.19', true, seq(bool(true)))] },
      true,
      false,
      'bad-certificate',
    ),
    row('signer serial number 0', { serialRaw: Uint8Array.of(0) }, true, true),
    row(
      'signer serial number of 21 octets',
      { serialRaw: Uint8Array.from({ length: 21 }, (_, i) => (i === 0 ? 1 : 2)) },
      true,
      true,
    ),
    row('TSTInfo serial number 0', { tstSerialRaw: Uint8Array.of(0) }, true, true),
    row('nonce 0', { nonceBytes: Uint8Array.of(0) }, true, true),
    row('SignedData version 1 instead of 3', {}, true, false, 'unsupported-version', (t) =>
      patchAt(t, (a) => {
        for (let i = 0; i < a.length - 2; i += 1) {
          if (a[i] === 2 && a[i + 1] === 1 && a[i + 2] === 3) {
            a[i + 2] = 1;
            break;
          }
        }
        return a;
      }),
    ),
    row('one byte after the token', {}, true, false, 'trailing-bytes', (t) =>
      Uint8Array.from([...t, 0]),
    ),
    row(
      'outer ContentInfo in BER (indefinite length)',
      {},
      true,
      false,
      'indefinite-length',
      (t) => {
        const header = t[1]! & 0x80 ? 2 + (t[1]! & 0x7f) : 2;
        return Uint8Array.from([0x30, 0x80, ...t.subarray(header), 0, 0]);
      },
    ),
  ];
  for (const r of ROWS) {
    const verdict = `openssl ${r.openssl ? 'accepts' : 'refuses'}, we ${r.ours ? 'accept' : 'refuse'}${r.reason ? ` (${r.reason})` : ''}`;
    it(`${r.openssl === r.ours ? 'same' : 'DIFFERENT'}: ${r.label}: ${verdict}`, async () => {
      const t = build(r.opts);
      const token = r.patch ? r.patch(t.token) : t.token;
      writeFileSync(path('row.tok'), token);
      writeFileSync(path('row.ca.pem'), t.caPem);
      const theirs = openssl([
        'ts',
        '-verify',
        '-in',
        path('row.tok'),
        '-token_in',
        '-digest',
        Buffer.from(t.imprint).toString('hex'),
        '-CAfile',
        path('row.ca.pem'),
        '-attime',
        '1767225600',
      ]);
      const ours = await verifyTimestampToken(token, t.imprint, [t.caPem]);
      expect(theirs.ok, theirs.stderr).toBe(r.openssl);
      expect(ours.ok).toBe(r.ours);
      if (!ours.ok && r.reason) expect(ours.reason).toBe(r.reason);
    });
  }

  // ---- F4: the signer named by subjectKeyIdentifier (SignerInfo version 3). `openssl ts -verify` reads the token
  // as PKCS#7 and cannot read that form at all (parse error); `openssl cms -verify` can, so it is the comparison
  // here. Measured with OpenSSL 3.0.13: CMS ignores the SignerInfo version, takes the first certificate with the
  // identifier (no search among several), finds no certificate without the extension (nothing is computed from
  // the key) and refuses a critical extension. Where we differ the row says so.
  const skiId = Uint8Array.from({ length: 20 }, (_, i) => i + 1);
  interface SkiRow {
    label: string;
    opts: Opts;
    /** `openssl ts -verify` accepts it (PKCS#7 reading). */
    ts: boolean;
    /** `openssl cms -verify -purpose timestampsign` accepts it. */
    cms: boolean;
    /** Our verdict: 'ok' or the reason. */
    ours: Reason | 'ok';
  }
  const SKI_ROWS: SkiRow[] = [
    { label: 'signer by key identifier', opts: { sid: 'ski' }, ts: false, cms: true, ours: 'ok' },
    {
      label: 'signer by key identifier, below an intermediate',
      opts: { sid: 'ski', intermediate: {} },
      ts: false,
      cms: true,
      ours: 'ok',
    },
    {
      label: 'identifier fits no certificate',
      opts: { sid: 'ski', sidSki: skiId },
      ts: false,
      cms: false,
      ours: 'signer-certificate-missing',
    },
    {
      label:
        'signer certificate without the extension (identifier = SHA-1 of the key, not computed by either)',
      opts: { sid: 'ski', tsaSki: null },
      ts: false,
      cms: false,
      ours: 'signer-certificate-missing',
    },
    {
      label: 'a look-alike with the same identifier and another key comes first',
      opts: { sid: 'ski', tsaSki: skiId, skiTwins: [{ wrongKey: true }] },
      ts: false,
      cms: false,
      ours: 'ok',
    },
    {
      label: 'version 3 with issuer and serial number (ignored by OpenSSL)',
      opts: { signerVersion: 3 },
      ts: true,
      cms: true,
      ours: 'unsupported-version',
    },
    {
      label: 'version 1 with a key identifier (ignored by CMS)',
      opts: { sid: 'ski', signerVersion: 1 },
      ts: false,
      cms: true,
      ours: 'unsupported-version',
    },
    {
      label: 'identifier of 0 bytes in the SignerInfo',
      opts: { sid: 'ski', sidSki: new Uint8Array(0) },
      ts: false,
      cms: false,
      ours: 'bad-structure',
    },
    {
      label: 'identifier of 65 bytes in the SignerInfo and in the certificate',
      opts: { sid: 'ski', tsaSki: new Uint8Array(65).fill(7) },
      ts: false,
      cms: true,
      ours: 'bad-structure',
    },
    {
      label: 'critical subjectKeyIdentifier in the signer certificate',
      opts: { sid: 'ski', tsaSkiCritical: true },
      ts: false,
      cms: false,
      ours: 'ok',
    },
  ];
  for (const r of SKI_ROWS) {
    const same = r.cms === (r.ours === 'ok');
    it(`${same ? 'same' : 'DIFFERENT'} (CMS ${r.cms ? 'accepts' : 'refuses'}, ts ${r.ts ? 'accepts' : 'refuses'}, we ${r.ours}): ${r.label}`, async () => {
      const t = build(r.opts);
      writeFileSync(path('ski.tok'), t.token);
      writeFileSync(path('ski.ca.pem'), t.caPem);
      const ts = openssl([
        'ts',
        '-verify',
        '-in',
        path('ski.tok'),
        '-token_in',
        '-digest',
        Buffer.from(t.imprint).toString('hex'),
        '-CAfile',
        path('ski.ca.pem'),
        '-attime',
        '1767225600',
      ]);
      const cms = openssl([
        'cms',
        '-verify',
        '-inform',
        'DER',
        '-in',
        path('ski.tok'),
        '-CAfile',
        path('ski.ca.pem'),
        '-attime',
        '1767225600',
        '-purpose',
        'timestampsign',
        '-out',
        path('ski.out'),
      ]);
      const ours = await verifyTimestampToken(t.token, t.imprint, [t.caPem]);
      expect(ts.ok, ts.stderr).toBe(r.ts);
      expect(cms.ok, cms.stderr).toBe(r.cms);
      expect(ours.ok ? 'ok' : ours.reason).toBe(r.ours);
    });
  }
  it('ts -verify refuses a key identifier because it cannot read the form (not for a rule of ours)', () => {
    const t = build({ sid: 'ski' });
    writeFileSync(path('ski2.tok'), t.token);
    writeFileSync(path('ski2.ca.pem'), t.caPem);
    const ts = openssl([
      'ts',
      '-verify',
      '-in',
      path('ski2.tok'),
      '-token_in',
      '-digest',
      Buffer.from(t.imprint).toString('hex'),
      '-CAfile',
      path('ski2.ca.pem'),
      '-attime',
      '1767225600',
    ]);
    expect(ts.stderr).toContain('PKCS7_ISSUER_AND_SERIAL');
  });
  it('a critical subjectKeyIdentifier in a signer with issuer and serial number: openssl ts refuses, we accept (same difference)', async () => {
    const t = build({ tsaSki: skiId, tsaSkiCritical: true });
    writeFileSync(path('ski3.tok'), t.token);
    writeFileSync(path('ski3.ca.pem'), t.caPem);
    const ts = openssl([
      'ts',
      '-verify',
      '-in',
      path('ski3.tok'),
      '-token_in',
      '-digest',
      Buffer.from(t.imprint).toString('hex'),
      '-CAfile',
      path('ski3.ca.pem'),
      '-attime',
      '1767225600',
    ]);
    expect(ts.ok, ts.stderr).toBe(false);
    expect((await verifyTimestampToken(t.token, t.imprint, [t.caPem])).ok).toBe(true);
  });

  // A token signed by OpenSSL itself with `cms -sign -keyid` (certificates made by OpenSSL, the identifier
  // computed by it as `subjectKeyIdentifier=hash`): the form really occurs outside our own builder. OpenSSL adds
  // no signingCertificate attribute, so the verification gets as far as that attribute and stops there.
  describe('a SignerInfo written by OpenSSL', () => {
    const run = (args: string[]) => spawnSync('openssl', args, { encoding: 'utf8' });
    let made = false;
    beforeAll(() => {
      writeFileSync(
        path('o.cnf'),
        [
          '[ca]',
          'basicConstraints=critical,CA:TRUE',
          'keyUsage=critical,keyCertSign',
          'subjectKeyIdentifier=hash',
          '[tsa]',
          'keyUsage=critical,digitalSignature',
          'extendedKeyUsage=critical,timeStamping',
          'subjectKeyIdentifier=hash',
          '[tsa_none]',
          'keyUsage=critical,digitalSignature',
          'extendedKeyUsage=critical,timeStamping',
          'subjectKeyIdentifier=none',
          '',
        ].join('\n'),
      );
      const steps = [
        ['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', path('o.ca.key')],
        ['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', path('o.tsa.key')],
        [
          'req',
          '-x509',
          '-new',
          '-key',
          path('o.ca.key'),
          '-subj',
          '/CN=CA',
          '-days',
          '20000',
          '-extensions',
          'ca',
          '-config',
          path('o.cnf'),
          '-out',
          path('o.ca.pem'),
        ],
        ['req', '-new', '-key', path('o.tsa.key'), '-subj', '/CN=TSA', '-out', path('o.tsa.csr')],
        [
          'x509',
          '-req',
          '-in',
          path('o.tsa.csr'),
          '-CA',
          path('o.ca.pem'),
          '-CAkey',
          path('o.ca.key'),
          '-CAcreateserial',
          '-days',
          '20000',
          '-extfile',
          path('o.cnf'),
          '-extensions',
          'tsa',
          '-out',
          path('o.tsa.pem'),
        ],
        [
          'x509',
          '-req',
          '-in',
          path('o.tsa.csr'),
          '-CA',
          path('o.ca.pem'),
          '-CAkey',
          path('o.ca.key'),
          '-CAcreateserial',
          '-days',
          '20000',
          '-extfile',
          path('o.cnf'),
          '-extensions',
          'tsa_none',
          '-out',
          path('o.none.pem'),
        ],
      ];
      for (const a of steps) if (run(a).status !== 0) return;
      const t = build();
      writeFileSync(path('o.tst'), t.tst);
      made = true;
    });
    const sign = (cert: string, out: string) =>
      run([
        'cms',
        '-sign',
        '-binary',
        '-inform',
        'DER',
        '-in',
        path('o.tst'),
        '-signer',
        path(cert),
        '-inkey',
        path('o.tsa.key'),
        '-certfile',
        path('o.ca.pem'),
        '-keyid',
        '-econtent_type',
        'id-smime-ct-TSTInfo',
        '-outform',
        'DER',
        '-nodetach',
        '-md',
        'sha256',
        '-out',
        path(out),
      ]);
    it('openssl writes version 3 with a key identifier; we read it and find the signer certificate by it', async () => {
      expect(made).toBe(true);
      expect(sign('o.tsa.pem', 'o.cms').status).toBe(0);
      const token = new Uint8Array(readFileSync(path('o.cms')));
      const parsed = readToken(token);
      expect(parsed.signer.sid.kind).toBe('subjectKeyIdentifier');
      expect(parsed.certificates).toHaveLength(2);
      const t = build();
      const r = await verifyTimestampToken(token, t.imprint, [
        readFileSync(path('o.ca.pem'), 'utf8'),
      ]);
      // the signer was found by its key identifier; OpenSSL writes no signingCertificate attribute
      expect(r).toEqual({ ok: false, reason: 'signing-certificate-missing' });
    });
    it('openssl itself cannot name a signer without the extension by key identifier (it does not compute one)', () => {
      expect(made).toBe(true);
      const r = sign('o.none.pem', 'o.none.cms');
      expect(r.status).not.toBe(0);
      expect(r.stderr).toContain('certificate has no keyid');
    });
  });
});
