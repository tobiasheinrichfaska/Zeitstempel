// Spike: one request per service in services.json, answer checked by our library AND by openssl.
//   npm run spike
// Only the SHA-256 of a short test text is sent; one request per service (be gentle with free services).
import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import {
  buildTimestampRequest,
  readTimestampResponse,
  verifyTimestampToken,
} from '../src/index.ts';
import { loadServices } from '../relay/load.ts';
import { networkUpstream } from '../relay/upstream.ts';

const DIR = new URL('../.tmp/spike/', import.meta.url);
mkdirSync(DIR, { recursive: true });
const path = (name: string) => new URL(name, DIR).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const root = (rel: string) =>
  new URL(`../${rel}`, import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const hasOpenssl = spawnSync('openssl', ['version']).status === 0;

const text = `spike ${new Date().toISOString()}`;
const hash = new Uint8Array(createHash('sha256').update(text).digest());
const rows: Record<string, string>[] = [];

for (const s of loadServices()) {
  const row: Record<string, string> = {
    service: s.id,
    transport: new URL(s.url).protocol.replace(':', ''),
    answer: '-',
    ms: '-',
    time: '-',
    chain: '-',
    own: '-',
    openssl: hasOpenssl ? '-' : 'n/a',
  };
  rows.push(row);
  const nonce = new Uint8Array(randomBytes(8));
  const request = buildTimestampRequest(hash, nonce);
  if (!request.ok) continue;
  const started = Date.now();
  let body: Uint8Array;
  try {
    const answer = await networkUpstream(s, request.value);
    row.ms = String(Date.now() - started);
    row.answer = `${answer.status} ${answer.contentType || '(no type)'}`;
    if (answer.status !== 200) continue;
    body = answer.body;
  } catch (e) {
    row.ms = String(Date.now() - started);
    row.answer = `error: ${(e as { kind?: string }).kind ?? 'failed'}`;
    continue;
  }
  const response = readTimestampResponse(body);
  if (!response.ok) {
    row.own = `unreadable: ${response.reason}`;
    continue;
  }
  const own = await verifyTimestampToken(response.value.token, hash, s.anchorPems, {
    expectedNonce: nonce,
    now: new Date(),
  });
  row.own = own.ok ? 'OK' : `FAILED: ${own.reason}`;
  if (own.ok) {
    row.time = own.value.genTime;
    row.chain = String(own.value.chainLength);
  }
  if (hasOpenssl) {
    writeFileSync(path(`${s.id}.tsr`), body);
    writeFileSync(path(`${s.id}.tsq`), request.value);
    spawnSync('openssl', [
      'ts',
      '-reply',
      '-in',
      path(`${s.id}.tsr`),
      '-token_out',
      '-out',
      path(`${s.id}.token`),
    ]);
    const pem = spawnSync(
      'openssl',
      ['pkcs7', '-inform', 'DER', '-in', path(`${s.id}.token`), '-print_certs'],
      { encoding: 'utf8' },
    );
    writeFileSync(path(`${s.id}.chain.pem`), pem.stdout);
    const args = [
      'ts',
      '-verify',
      '-in',
      path(`${s.id}.tsr`),
      '-queryfile',
      path(`${s.id}.tsq`),
      '-untrusted',
      path(`${s.id}.chain.pem`),
    ];
    for (const a of s.anchors) args.push('-CAfile', root(a));
    // `openssl ts -verify` takes one -CAfile; each shipped service names exactly one anchor, so this adds one
    const result = spawnSync('openssl', args, { encoding: 'utf8' });
    row.openssl =
      result.status === 0
        ? 'OK'
        : `FAILED: ${(result.stderr || result.stdout).trim().split('\n').pop()}`;
  }
}

console.table(rows);
const bad = rows.filter((r) => r.own !== 'OK' || (hasOpenssl && r.openssl !== 'OK'));
console.log(bad.length ? `${bad.length} service(s) not fully OK` : 'all services OK');
process.exit(0);
