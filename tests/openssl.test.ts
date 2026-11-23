// Cross-check against an independent implementation: `openssl ts -verify` must agree with ours on the
// recorded answers, and must refuse what we refuse. Skipped (and reported as skipped) without openssl.
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { readTimestampResponse, verifyTimestampToken } from '../src/index.ts';
import { fixture, sha256 } from './helpers.ts';

const probe = spawnSync('openssl', ['version']);
const hasOpenssl = probe.status === 0;
const TMP = new URL('../.tmp/openssl/', import.meta.url);
const path = (name: string) => new URL(name, TMP).pathname.replace(/^\/([A-Za-z]:)/, '$1');

const CASES = [
  { file: 'freetsa.tsr', anchor: 'freetsa-root' },
  { file: 'sectigo.tsr', anchor: 'usertrust-rsa' },
  { file: 'digicert.tsr', anchor: 'digicert-trusted-root-g4' },
  { file: 'certum.tsr', anchor: 'certum-trusted-network-ca-2' },
];

function openssl(args: string[]): boolean {
  return spawnSync('openssl', args, { encoding: 'utf8' }).status === 0;
}

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

describe.skipIf(!hasOpenssl)('agreement with openssl ts -verify', () => {
  beforeAll(() => {
    mkdirSync(new URL(TMP), { recursive: true });
    for (const c of CASES) writeFileSync(path(c.file), fixture(c.file));
    writeFileSync(path('request.tsq'), fixture('freetsa.tsq'));
  });

  for (const c of CASES) {
    it(`${c.file}: both accept the recorded answer`, async () => {
      const anchor = new URL(`../anchors/${c.anchor}.pem`, import.meta.url).pathname.replace(
        /^\/([A-Za-z]:)/,
        '$1',
      );
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
      ]);
      const parsed = readTimestampResponse(fixture(c.file));
      const ours =
        parsed.ok &&
        (
          await verifyTimestampToken(parsed.value.token, sha256('probe'), [
            readFileSync(anchor, 'utf8'),
          ])
        ).ok;
      expect(theirs).toBe(true);
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
    const anchor = new URL('../anchors/freetsa-root.pem', import.meta.url).pathname.replace(
      /^\/([A-Za-z]:)/,
      '$1',
    );
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
    ]);
    const parsed = readTimestampResponse(fixture('freetsa.tsr'));
    const ours =
      parsed.ok &&
      (
        await verifyTimestampToken(parsed.value.token, sha256('another thing'), [
          readFileSync(anchor, 'utf8'),
        ])
      ).ok;
    expect(theirs).toBe(false);
    expect(ours).toBe(false);
  });
});
