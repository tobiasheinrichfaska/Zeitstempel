import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { UpstreamCredentials } from '../relay/credentials.ts';
import { makeNetworkUpstream, UpstreamError } from '../relay/upstream.ts';

// The one way out, against a stub service over TLS on 127.0.0.1 with a certificate made for this run (openssl; the
// tests are visibly skipped without it). The relay's real upstream is the code under test, nothing is mocked.

const have = spawnSync('openssl', ['version']).status === 0;
let dir = '';
let cert = '';
let key = '';
const MARKER = 'MARKER-net-5b7d';

interface Seen {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}
let seen: Seen[] = [];
let plainConnections = 0;
let server: https.Server;
let plain: http.Server;
let base = '';
let plainBase = '';
let reply: (req: http.IncomingMessage, res: http.ServerResponse) => void = (_q, res) => {
  res.writeHead(200, { 'Content-Type': 'application/timestamp-reply' });
  res.end('ok');
};

beforeAll(async () => {
  if (!have) return;
  dir = mkdtempSync(join(tmpdir(), 'zs-upstream-'));
  const made = spawnSync('openssl', [
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:prime256v1',
    '-nodes',
    '-keyout',
    join(dir, 'key.pem'),
    '-out',
    join(dir, 'cert.pem'),
    '-days',
    '1',
    '-subj',
    '/CN=localhost',
    '-addext',
    'subjectAltName=IP:127.0.0.1,DNS:localhost',
  ]);
  if (made.status !== 0) throw new Error('openssl could not make the test certificate');
  cert = readFileSync(join(dir, 'cert.pem'), 'utf8');
  key = readFileSync(join(dir, 'key.pem'), 'utf8');
  server = https.createServer({ key, cert }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      seen.push({
        method: req.method ?? '',
        url: req.url ?? '',
        headers: req.headers,
        body: Buffer.concat(chunks).toString('latin1'),
      });
      reply(req, res);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
  plain = http.createServer((_q, res) => res.end('x'));
  plain.on('connection', () => (plainConnections += 1));
  await new Promise<void>((r) => plain.listen(0, '127.0.0.1', r));
  plainBase = `http://127.0.0.1:${(plain.address() as AddressInfo).port}`;
});
afterAll(async () => {
  if (!have) return;
  server.closeAllConnections();
  plain.closeAllConnections();
  await Promise.all([new Promise((r) => server.close(r)), new Promise((r) => plain.close(r))]);
  rmSync(dir, { recursive: true, force: true });
});
beforeEach(() => {
  seen = [];
  plainConnections = 0;
  reply = (_q, res) => {
    res.writeHead(200, { 'Content-Type': 'application/timestamp-reply' });
    res.end('ok');
  };
});

const body = new Uint8Array([1, 2, 3]);
const call = (creds?: UpstreamCredentials, url = `${base}/tsr`) =>
  makeNetworkUpstream(2000, { ca: cert })({ url }, body, creds);

describe.skipIf(!have)(
  'the network upstream sets the credentials of the service (stub over TLS)',
  () => {
    it('without credentials nothing is added: no Authorization, only the fixed headers', async () => {
      const a = await call();
      expect(a.status).toBe(200);
      expect(seen).toHaveLength(1);
      const h = seen[0]!.headers;
      expect(h.authorization).toBeUndefined();
      expect(h['content-type']).toBe('application/timestamp-query');
      expect(h['user-agent']).toBe('zeitstempel-relay');
      expect(seen[0]!.method).toBe('POST');
      expect(seen[0]!.url).toBe('/tsr');
    });
    it('basic: Authorization is "Basic " and the base64 of user:password (RFC 7617)', async () => {
      await call({ kind: 'basic', user: 'Aladdin', password: 'open sesame' });
      expect(seen[0]!.headers.authorization).toBe('Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==');
      seen = [];
      await call({ kind: 'basic', user: 'u', password: 'p:with:colons "and" \\ quotes' });
      expect(seen[0]!.headers.authorization).toBe(
        `Basic ${Buffer.from('u:p:with:colons "and" \\ quotes').toString('base64')}`,
      );
    });
    it('bearer: Authorization is "Bearer " and the token', async () => {
      await call({ kind: 'bearer', token: 'abc.DEF_123-~+/=' });
      expect(seen[0]!.headers.authorization).toBe('Bearer abc.DEF_123-~+/=');
    });
    it('header: the named header carries the token and Authorization is not set', async () => {
      await call({ kind: 'header', header: 'X-Api-Key', token: 'k-123' });
      expect(seen[0]!.headers['x-api-key']).toBe('k-123');
      expect(seen[0]!.headers.authorization).toBeUndefined();
      expect(seen[0]!.headers['content-type']).toBe('application/timestamp-query');
    });
    it('malformed credentials never reach the wire: CR/LF, a forbidden header name, a colon in the user', async () => {
      const bad: UpstreamCredentials[] = [
        { kind: 'bearer', token: 'a\r\nX-Evil: 1' },
        { kind: 'bearer', token: 'a\nb' },
        { kind: 'basic', user: 'a:b', password: 'p' },
        { kind: 'basic', user: 'u', password: 'p\r\nq' },
        { kind: 'header', header: 'Content-Type', token: 'x' },
        { kind: 'header', header: 'Host', token: 'x' },
        { kind: 'header', header: 'X-Api-Key\r\nX-Evil', token: 'x' },
        { kind: 'header', header: 'X-Api-Key', token: 'ä' },
        { kind: 'bearer', token: '' },
      ];
      for (const c of bad) {
        await expect(call(c), JSON.stringify(c)).rejects.toMatchObject({ kind: 'failed' });
      }
      expect(seen).toHaveLength(0);
    });
    it('credentials never go over plain http: the call fails before any connection is made', async () => {
      for (const c of [
        { kind: 'basic', user: 'u', password: 'p' },
        { kind: 'bearer', token: 't' },
        { kind: 'header', header: 'X-Api-Key', token: 't' },
      ] as UpstreamCredentials[]) {
        const e = await call(c, `${plainBase}/tsr`).catch((x: unknown) => x);
        expect(e).toBeInstanceOf(UpstreamError);
        expect((e as UpstreamError).kind).toBe('failed');
      }
      expect(plainConnections).toBe(0);
      // without credentials http is still what it was
      expect((await call(undefined, `${plainBase}/tsr`)).status).toBe(200);
      expect(plainConnections).toBe(1);
    });
    it('a redirect is not followed and the credentials are not sent on: one request, status 302', async () => {
      reply = (_q, res) => {
        res.writeHead(302, { Location: `${base}/elsewhere` });
        res.end();
      };
      const a = await call({ kind: 'bearer', token: MARKER });
      expect(a.status).toBe(302);
      expect(seen).toHaveLength(1);
      expect(seen[0]!.url).toBe('/tsr');
    });
    it('a refusal of the service (401) comes back as a status; no credential is in any error of the call', async () => {
      reply = (_q, res) => {
        res.writeHead(401, { 'Content-Type': 'text/plain' });
        res.end('no');
      };
      expect((await call({ kind: 'bearer', token: MARKER })).status).toBe(401);
      // a service nobody listens on, and a deadline: the errors are codes without text of the request
      const down = await makeNetworkUpstream(300, { ca: cert })(
        { url: 'https://127.0.0.1:1/tsr' },
        body,
        { kind: 'basic', user: MARKER, password: MARKER },
      ).catch((x: unknown) => x);
      expect(down).toBeInstanceOf(UpstreamError);
      expect(
        JSON.stringify(down) + String((down as Error).message) + String((down as Error).stack),
      ).not.toContain(MARKER);
      reply = () => undefined; // never answers
      const slow = await makeNetworkUpstream(200, { ca: cert })({ url: `${base}/tsr` }, body, {
        kind: 'bearer',
        token: MARKER,
      }).catch((x: unknown) => x);
      expect((slow as UpstreamError).kind).toBe('timeout');
      expect(String((slow as Error).stack)).not.toContain(MARKER);
    });
    it('without the test anchor the certificate of the stub is refused (the TLS check is on)', async () => {
      const e = await makeNetworkUpstream(2000)({ url: `${base}/tsr` }, body, {
        kind: 'bearer',
        token: 't',
      }).catch((x: unknown) => x);
      expect((e as UpstreamError).kind).toBe('failed');
      expect(seen).toHaveLength(0);
    });
  },
);
