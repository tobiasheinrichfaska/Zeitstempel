// Cross-check of the renewal chain against OpenSSL: the imprint of every link is computed by `openssl dgst`
// (not by this library), and every link is verified alone with `openssl ts -verify -attime` at the time of the
// NEXT link, the way verifyRenewalChain judges it. Skipped visibly without OpenSSL 3.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyRenewalChain } from '../src/index.ts';
import { BASE, HASH, TRUST, makeChain, type Step } from './renewal-helpers.ts';

const probe = spawnSync('openssl', ['version'], { encoding: 'utf8' });
const major = Number(/^OpenSSL (\d+)/.exec(probe.stdout ?? '')?.[1] ?? 0);
const canRun = probe.status === 0 && major >= 3;
if (probe.status === 0 && !canRun)
  it.skip('renewal chain against openssl (needs OpenSSL 3)', () => {});

let tmp = '';
const path = (name: string) => join(tmp, name);
const secs = (iso: string) => String(Math.floor(Date.parse(iso) / 1000));

/** SHA-256 of a file by OpenSSL, as a hex text. */
function dgst(file: string): string {
  const r = spawnSync('openssl', ['dgst', '-sha256', '-r', file], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(r.stderr);
  return r.stdout.split(' ')[0]!;
}

describe.skipIf(!canRun)('renewal chain against openssl ts -verify', () => {
  beforeAll(() => {
    tmp = mkdtempSync(join(tmpdir(), 'zeitstempel-renewal-'));
    writeFileSync(path('ca.pem'), BASE.caPem);
  });
  afterAll(() => {
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  });

  const STEPS: Step[] = [
    { at: '2026-01-01T00:00:00Z', validity: ['20200101000000Z', '20260701000000Z'] },
    { at: '2026-06-01T00:00:00Z', validity: ['20200101000000Z', '20261201000000Z'] },
    { at: '2026-11-01T00:00:00Z' },
  ];
  const verifyOne = (token: Uint8Array, digestHex: string, attime: string) => {
    writeFileSync(path('link.tok'), token);
    const r = spawnSync(
      'openssl',
      [
        'ts',
        '-verify',
        '-in',
        path('link.tok'),
        '-token_in',
        '-digest',
        digestHex,
        '-CAfile',
        path('ca.pem'),
        '-attime',
        attime,
      ],
      { encoding: 'utf8' },
    );
    return { ok: r.status === 0, stderr: r.stderr ?? '' };
  };

  it('every link verifies alone over the imprint OpenSSL computes, at the time of the next link', async () => {
    const links = await makeChain(HASH, STEPS);
    expect((await verifyRenewalChain({ hash: HASH, links, trust: TRUST })).ok).toBe(true);
    let state = Buffer.from(HASH).toString('hex');
    for (const [i, link] of links.entries()) {
      // what link i must have stamped: i = 0 the hash, else the imprint of the chain before it
      const next = i < links.length - 1 ? STEPS[i + 1]!.at : STEPS[i]!.at;
      const own = verifyOne(link.token, state, secs(next));
      expect(own.ok, `link ${i}: ${own.stderr}`).toBe(true);
      // the same link refuses any other digest
      const wrong = verifyOne(link.token, '00'.repeat(32), secs(next));
      expect(wrong.ok, `link ${i} with another digest`).toBe(false);
      writeFileSync(path('tok.bin'), link.token);
      const tokenHash = dgst(path('tok.bin'));
      // RFC 4998 section 5.2: the next link stamps the hash of the token before it
      state = tokenHash;
    }
  });
  it('the first link alone says no when judged at a time after its certificate ended (renewal-too-late)', async () => {
    const links = await makeChain(HASH, [
      { at: '2026-01-01T00:00:00Z', validity: ['20200101000000Z', '20260301000000Z'] },
      { at: '2026-04-01T00:00:00Z' },
    ]);
    const hex = Buffer.from(HASH).toString('hex');
    expect(verifyOne(links[0]!.token, hex, secs('2026-01-01T00:00:00Z')).ok).toBe(true);
    expect(verifyOne(links[0]!.token, hex, secs('2026-04-01T00:00:00Z')).ok).toBe(false);
    const ours = await verifyRenewalChain({ hash: HASH, links, trust: TRUST });
    expect(ours).toMatchObject({ ok: false, reason: 'renewal-too-late', detail: 'link 0' });
    // one second before it ends both accept; AT the second it ends only we do (validity inclusive, docs/grenzen.md, "Gültigkeit inklusive")
    expect(verifyOne(links[0]!.token, hex, secs('2026-02-28T23:59:59Z')).ok).toBe(true);
    expect(verifyOne(links[0]!.token, hex, secs('2026-03-01T00:00:00Z')).ok).toBe(false);
  });
});
