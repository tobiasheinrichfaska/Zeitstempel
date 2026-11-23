import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { toBase64Url, verifyTimestampToken, fromBase64Url } from '../src/index.ts';
import { loadServices } from '../relay/load.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import { createRelayServer } from '../relay/server.ts';
import {
  UpstreamError,
  makeNetworkUpstream,
  networkUpstream,
  type Upstream,
} from '../relay/upstream.ts';
import { FREETSA_NONCE, fixture, fixtureText, sha256 } from './helpers.ts';

const SERVICES = loadServices();
const RECORDED = fixture('freetsa.tsr');
const ORIGIN = 'https://app.example';
const NOW = Date.parse('2026-11-23T13:10:00Z');

interface Harness {
  base: string;
  close: () => Promise<void>;
  calls: Uint8Array[];
  stats: () => { stamped: number; refused: Record<string, number> };
  clock: { now: number };
}

async function start(
  over: { upstream?: Upstream; allowPlainHttp?: boolean; services?: typeof SERVICES } = {},
): Promise<Harness> {
  const calls: Uint8Array[] = [];
  const clock = { now: NOW };
  const stand: Upstream = async (_t, body) => {
    calls.push(body);
    return { status: 200, contentType: 'application/timestamp-reply', body: RECORDED };
  };
  const { server, relay } = createRelayServer({
    services: over.services ?? SERVICES,
    origins: [ORIGIN],
    allowPlainHttp: over.allowPlainHttp ?? false,
    upstream: over.upstream ?? stand,
    random: () => FREETSA_NONCE,
    now: () => clock.now,
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  return {
    base: `http://127.0.0.1:${port}`,
    close: () => new Promise((r) => (server.closeAllConnections(), server.close(() => r()))),
    calls,
    stats: relay.stats,
    clock,
  };
}

const post = (
  h: Harness,
  path: string,
  body: BodyInit,
  type: string,
  headers: Record<string, string> = {},
) => fetch(h.base + path, { method: 'POST', body, headers: { 'Content-Type': type, ...headers } });
const hashJson = (h: Uint8Array) => JSON.stringify({ hash: toBase64Url(h) });

describe('relay: stamping', () => {
  let h: Harness;
  beforeEach(async () => (h = await start()));
  afterEach(() => h.close());

  it('stamps a hash sent as JSON and returns a token the app can verify itself', async () => {
    const res = await post(h, '/v1/stamp/freetsa', hashJson(sha256('probe')), 'application/json');
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    const body = (await res.json()) as { service: string; genTime: string; token: string };
    expect(body).toMatchObject({ service: 'freetsa', genTime: '2026-11-23T13:05:56.000Z' });
    const token = fromBase64Url(body.token)!;
    const again = await verifyTimestampToken(token, sha256('probe'), [fixtureText('cacert.pem')]);
    expect(again.ok).toBe(true);
    expect(h.stats().stamped).toBe(1);
  });

  it('stamps a hash sent as 32 raw bytes', async () => {
    const res = await post(
      h,
      '/v1/stamp/freetsa',
      Buffer.from(sha256('probe')),
      'application/octet-stream',
    );
    expect(res.status).toBe(200);
  });

  it('builds the upstream request itself: only the hash and a nonce go out', async () => {
    await post(h, '/v1/stamp/freetsa', hashJson(sha256('probe')), 'application/json');
    expect(h.calls).toHaveLength(1);
    expect(Buffer.from(h.calls[0]!).equals(Buffer.from(fixture('freetsa.tsq')))).toBe(true);
  });

  it('refuses an answer whose token is for another hash (the service or a middleman cheated)', async () => {
    const res = await post(h, '/v1/stamp/freetsa', hashJson(sha256('other')), 'application/json');
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ error: 'upstream-invalid', reason: 'imprint-mismatch' });
    expect(h.stats().stamped).toBe(0);
  });

  it('refuses a token that does not chain to the service anchors', async () => {
    const other = SERVICES.map((s) => ({ ...s, anchorPems: [fixtureText('other-root.pem')] }));
    const h2 = await start({ services: other });
    const res = await post(h2, '/v1/stamp/freetsa', hashJson(sha256('probe')), 'application/json');
    expect(await res.json()).toEqual({ error: 'upstream-invalid', reason: 'untrusted-chain' });
    await h2.close();
  });

  it('refuses a token from the future', async () => {
    h.clock.now = NOW - RELAY_LIMITS.maxSkewMs - 3 * 3_600_000;
    const res = await post(h, '/v1/stamp/freetsa', hashJson(sha256('probe')), 'application/json');
    expect(await res.json()).toEqual({ error: 'upstream-invalid', reason: 'time-in-future' });
  });
});

describe('relay: input', () => {
  let h: Harness;
  beforeEach(async () => (h = await start()));
  afterEach(() => h.close());
  const code = async (res: Response) => ((await res.json()) as { error: string }).error;

  it('refuses a hash of the wrong size, bad base64url, extra members and non-objects', async () => {
    expect(
      await code(await post(h, '/v1/stamp/freetsa', Buffer.alloc(31), 'application/octet-stream')),
    ).toBe('bad-hash');
    expect(
      await code(await post(h, '/v1/stamp/freetsa', '{"hash":"AAAA"}', 'application/json')),
    ).toBe('bad-hash');
    expect(
      await code(
        await post(
          h,
          '/v1/stamp/freetsa',
          `{"hash":"${toBase64Url(sha256('x'))}=="}`,
          'application/json',
        ),
      ),
    ).toBe('bad-hash');
    expect(
      await code(
        await post(
          h,
          '/v1/stamp/freetsa',
          `{"hash":"${toBase64Url(sha256('x'))}","x":1}`,
          'application/json',
        ),
      ),
    ).toBe('bad-hash');
    expect(await code(await post(h, '/v1/stamp/freetsa', '[]', 'application/json'))).toBe(
      'bad-hash',
    );
    expect(await code(await post(h, '/v1/stamp/freetsa', 'not json', 'application/json'))).toBe(
      'bad-hash',
    );
    expect(h.calls).toHaveLength(0);
  });
  it('refuses other content types and methods', async () => {
    const res = await post(h, '/v1/stamp/freetsa', 'x', 'text/plain');
    expect(res.status).toBe(415);
    const get = await fetch(`${h.base}/v1/stamp/freetsa`);
    expect(get.status).toBe(405);
    expect(get.headers.get('allow')).toBe('POST');
  });
  it('refuses a body over the limit with 413, before and without a length', async () => {
    const res = await post(
      h,
      '/v1/stamp/freetsa',
      'x'.repeat(RELAY_LIMITS.bodyBytes + 1),
      'application/json',
    );
    expect(res.status).toBe(413);
    expect(h.calls).toHaveLength(0);
  });
  it('knows only the services it offers, and no query strings', async () => {
    expect(
      (await post(h, '/v1/stamp/nope', hashJson(sha256('p')), 'application/json')).status,
    ).toBe(404);
    expect(
      (await post(h, '/v1/stamp/../../etc', hashJson(sha256('p')), 'application/json')).status,
    ).toBe(404);
    expect(
      (
        await post(
          h,
          '/v1/stamp/freetsa?url=http://evil',
          hashJson(sha256('p')),
          'application/json',
        )
      ).status,
    ).toBe(400);
    expect((await fetch(`${h.base}/other`)).status).toBe(404);
    expect(h.calls).toHaveLength(0);
  });
  it('lists only what it offers', async () => {
    const res = await fetch(`${h.base}/v1/services`);
    const body = (await res.json()) as { services: { id: string; qualified: boolean }[] };
    expect(body.services.map((s) => s.id)).toEqual(['freetsa', 'sectigo']);
    expect(body.services.every((s) => s.qualified === false)).toBe(true);
    expect(await (await fetch(`${h.base}/health`)).json()).toEqual({
      ok: true,
      services: ['freetsa', 'sectigo'],
    });
  });
  it('offers the http-only services only when told to', async () => {
    const h2 = await start({ allowPlainHttp: true });
    const ids = ((await (await fetch(`${h2.base}/health`)).json()) as { services: string[] })
      .services;
    expect(ids).toEqual(['freetsa', 'sectigo', 'digicert', 'certum']);
    await h2.close();
  });
});

describe('relay: origins (CORS)', () => {
  let h: Harness;
  beforeEach(async () => (h = await start()));
  afterEach(() => h.close());

  it('answers the preflight for the configured origin only', async () => {
    const ok = await fetch(`${h.base}/v1/stamp/freetsa`, {
      method: 'OPTIONS',
      headers: { Origin: ORIGIN },
    });
    expect(ok.status).toBe(204);
    expect(ok.headers.get('access-control-allow-origin')).toBe(ORIGIN);
    expect(ok.headers.get('access-control-allow-headers')).toBe('Content-Type');
    const bad = await fetch(`${h.base}/v1/stamp/freetsa`, {
      method: 'OPTIONS',
      headers: { Origin: 'https://evil.example' },
    });
    expect(bad.status).toBe(403);
    expect(bad.headers.get('access-control-allow-origin')).toBeNull();
  });
  it('refuses a call from another origin without asking the service', async () => {
    const res = await post(h, '/v1/stamp/freetsa', hashJson(sha256('probe')), 'application/json', {
      Origin: 'https://evil.example',
    });
    expect(res.status).toBe(403);
    expect(h.calls).toHaveLength(0);
  });
  it('shows the allowed origin on answers and errors', async () => {
    const res = await post(h, '/v1/stamp/freetsa', hashJson(sha256('probe')), 'application/json', {
      Origin: ORIGIN,
    });
    expect(res.headers.get('access-control-allow-origin')).toBe(ORIGIN);
    const err = await post(h, '/v1/stamp/nope', '{}', 'application/json', { Origin: ORIGIN });
    expect(err.headers.get('access-control-allow-origin')).toBe(ORIGIN);
  });
  it('answers a caller without an Origin header (not a browser)', async () => {
    const res = await post(h, '/v1/stamp/freetsa', hashJson(sha256('probe')), 'application/json');
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
    expect(res.status).toBe(200);
  });
});

describe('relay: limits and upstream failures', () => {
  it('limits requests per service and minute, then frees them again', async () => {
    const h = await start();
    const per = Math.floor(RELAY_LIMITS.windowMs / SERVICES[0]!.minIntervalMs);
    for (let i = 0; i < per; i += 1) {
      expect(
        (await post(h, '/v1/stamp/freetsa', hashJson(sha256('probe')), 'application/json')).status,
      ).toBe(200);
    }
    const limited = await post(
      h,
      '/v1/stamp/freetsa',
      hashJson(sha256('probe')),
      'application/json',
    );
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get('retry-after'))).toBeGreaterThan(0);
    expect(
      (await post(h, '/v1/stamp/sectigo', hashJson(sha256('probe')), 'application/json')).status,
    ).toBe(502); // another service has its own count (token anchors differ)
    h.clock.now += RELAY_LIMITS.windowMs;
    expect(
      (await post(h, '/v1/stamp/freetsa', hashJson(sha256('probe')), 'application/json')).status,
    ).toBe(200);
    await h.close();
  });
  it('limits the total per minute over all services', async () => {
    const many = Array.from({ length: 20 }, (_, i) => ({
      ...SERVICES[0]!,
      id: `s${i}`,
      minIntervalMs: 1000,
    }));
    const h = await start({ services: many });
    let limited = 0;
    for (let i = 0; i < 70; i += 1) {
      const r = await post(
        h,
        `/v1/stamp/s${i % 20}`,
        hashJson(sha256('probe')),
        'application/json',
      );
      if (r.status === 429) limited += 1;
    }
    expect(limited).toBe(70 - RELAY_LIMITS.perMinuteTotal);
    await h.close();
  });
  const failing =
    (e: unknown): Upstream =>
    async () => {
      throw e;
    };
  it('maps upstream failures to 502 and 504 without leaking details', async () => {
    const cases: [Upstream, number, string][] = [
      [failing(new UpstreamError('timeout')), 504, 'upstream-timeout'],
      [failing(new UpstreamError('failed')), 502, 'upstream-failed'],
      [failing(new UpstreamError('too-large')), 502, 'upstream-too-large'],
      [failing(new Error('boom with secrets')), 502, 'upstream-failed'],
      [
        async () => ({ status: 500, contentType: 'text/html', body: new Uint8Array() }),
        502,
        'upstream-refused',
      ],
      [
        async () => ({ status: 302, contentType: 'text/html', body: new Uint8Array() }),
        502,
        'upstream-refused',
      ],
      [
        async () => ({ status: 200, contentType: 'text/html', body: RECORDED }),
        502,
        'upstream-refused',
      ],
    ];
    for (const [upstream, status, error] of cases) {
      const h = await start({ upstream });
      const res = await post(h, '/v1/stamp/freetsa', hashJson(sha256('probe')), 'application/json');
      expect(res.status).toBe(status);
      expect(await res.json()).toEqual({ error });
      await h.close();
    }
  });
  it('refuses garbage from the service', async () => {
    const h = await start({
      upstream: async () => ({
        status: 200,
        contentType: 'application/timestamp-reply',
        body: Uint8Array.of(1, 2, 3),
      }),
    });
    const res = await post(h, '/v1/stamp/freetsa', hashJson(sha256('probe')), 'application/json');
    expect(res.status).toBe(502);
    expect(((await res.json()) as { error: string }).error).toBe('upstream-invalid');
    await h.close();
  });
  it('counts refusals by kind and keeps nothing else', async () => {
    const h = await start();
    await post(h, '/v1/stamp/nope', '{}', 'application/json');
    await post(h, '/v1/stamp/freetsa', 'x', 'text/plain');
    expect(h.stats()).toEqual({
      stamped: 0,
      refused: { 'unknown-service': 1, 'unsupported-media-type': 1 },
    });
    await h.close();
  });
});

describe('relay: the real way out against a local stand-in service', () => {
  async function standIn(handler: http.RequestListener) {
    const server = http.createServer(handler);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/tsr`;
    return {
      url,
      close: () =>
        new Promise<void>((r) => (server.closeAllConnections(), server.close(() => r()))),
    };
  }

  it('posts the request, takes the answer, checks the content type', async () => {
    let seen: { method: string | undefined; type: string | undefined; length: number } = {
      method: undefined,
      type: undefined,
      length: 0,
    };
    const s = await standIn((req, res) => {
      const parts: Buffer[] = [];
      req.on('data', (c: Buffer) => parts.push(c));
      req.on('end', () => {
        seen = {
          method: req.method,
          type: req.headers['content-type'],
          length: Buffer.concat(parts).length,
        };
        res.writeHead(200, { 'Content-Type': 'application/timestamp-reply' });
        res.end(Buffer.from(RECORDED));
      });
    });
    const answer = await networkUpstream({ url: s.url }, fixture('freetsa.tsq'));
    expect(answer.status).toBe(200);
    expect(answer.contentType).toBe('application/timestamp-reply');
    expect(Buffer.from(answer.body).equals(Buffer.from(RECORDED))).toBe(true);
    expect(seen).toEqual({
      method: 'POST',
      type: 'application/timestamp-query',
      length: fixture('freetsa.tsq').length,
    });
    await s.close();
  });
  it('does not follow a redirect', async () => {
    const s = await standIn((_req, res) => {
      res.writeHead(302, { Location: 'http://127.0.0.1:1/' });
      res.end();
    });
    const answer = await networkUpstream({ url: s.url }, new Uint8Array(1));
    expect(answer.status).toBe(302);
    await s.close();
  });
  it('stops at the size cap', async () => {
    const s = await standIn((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/timestamp-reply' });
      res.end(Buffer.alloc(RELAY_LIMITS.upstreamBytes + 1));
    });
    await expect(networkUpstream({ url: s.url }, new Uint8Array(1))).rejects.toMatchObject({
      kind: 'too-large',
    });
    await s.close();
  });
  it('gives up at the deadline when the service never answers', async () => {
    const s = await standIn(() => undefined); // accepts the request and stays silent
    const started = Date.now();
    await expect(makeNetworkUpstream(200)({ url: s.url }, new Uint8Array(1))).rejects.toMatchObject(
      { kind: 'timeout' },
    );
    expect(Date.now() - started).toBeLessThan(3000);
    await s.close();
  });
  it('gives up at the deadline when the service answers slowly in pieces', async () => {
    const s = await standIn((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/timestamp-reply' });
      const t = setInterval(() => res.write('x'), 50);
      res.on('close', () => clearInterval(t));
    });
    await expect(makeNetworkUpstream(300)({ url: s.url }, new Uint8Array(1))).rejects.toMatchObject(
      { kind: 'timeout' },
    );
    await s.close();
  });
  it('fails (not hangs) when the service is unreachable', async () => {
    await expect(
      networkUpstream({ url: 'http://127.0.0.1:1/' }, new Uint8Array(1)),
    ).rejects.toMatchObject({ kind: 'failed' });
  });
});
