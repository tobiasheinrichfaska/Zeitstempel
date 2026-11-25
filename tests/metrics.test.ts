import { spawn, type ChildProcess } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import net from 'node:net';
import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import { networkInterfaces } from 'node:os';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { toBase64Url } from '../src/index.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import { loadServices } from '../relay/load.ts';
import { readConfig, readSettings, serverLimits } from '../relay/main.ts';
import { createMetrics, isLoopbackPeer } from '../relay/metrics.ts';
import type { RelayKey } from '../relay/keys.ts';
import type { RelayStats } from '../relay/relay.ts';
import { createRelayServer } from '../relay/server.ts';
import type { Upstream } from '../relay/upstream.ts';
import { TEST_AUDIENCE, makeTestKey, nodeAuthHeaderMs } from './auth-helpers.ts';
import { FREETSA_NONCE, fixture, sha256 } from './helpers.ts';

// GET /metrics: off by default, loopback peers only, GET only, counters and gauges without anything a request carries.

const SERVICES = loadServices().filter((s) => s.id === 'freetsa');
const RECORDED = fixture('freetsa.tsr');
const NOW = Date.parse('2026-11-23T13:06:00Z');
const KEY = makeTestKey('kid-zq7x-secret');
const KEYS: RelayKey[] = [{ id: KEY.id, publicKey: KEY.publicKey }];
const ORIGIN = 'https://app.example';

interface Reply {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

function request(
  port: number,
  method: string,
  path: string,
  headers: Record<string, string> = {},
  body?: string | Uint8Array,
  host = '127.0.0.1',
): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host, port, path, method, headers }, (res) => {
      const parts: Buffer[] = [];
      res.on('data', (c: Buffer) => parts.push(c));
      res.on('end', () =>
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers,
          body: Buffer.concat(parts).toString('utf8'),
        }),
      );
    });
    req.on('error', reject);
    req.end(body);
  });
}

interface Harness {
  port: number;
  clock: { t: number };
  /** Resolves a held upstream call (see `hold`). */
  release: () => void;
  hold: { on: boolean };
  get: (path: string, headers?: Record<string, string>) => Promise<Reply>;
  stamp: (hash: Uint8Array) => Promise<Reply>;
  close: () => Promise<void>;
  seenHash: string[];
}

const open: Harness[] = [];
afterEach(async () => {
  while (open.length > 0) await open.pop()!.close();
});

async function start(
  over: {
    metrics?: boolean;
    peer?: string;
    host?: string;
    keys?: readonly RelayKey[] | 'off';
  } = {},
): Promise<Harness> {
  const clock = { t: 1_000_000 };
  const hold = { on: false };
  let releaseNow: () => void = () => {};
  const seenHash: string[] = [];
  const upstream: Upstream = async () => {
    if (hold.on) await new Promise<void>((r) => (releaseNow = r));
    return { status: 200, contentType: 'application/timestamp-reply', body: RECORDED };
  };
  const keys = over.keys ?? KEYS;
  const { server } = createRelayServer(
    {
      services: SERVICES,
      origins: [ORIGIN],
      allowPlainHttp: false,
      upstream,
      random: () => FREETSA_NONCE,
      now: () => NOW,
      monotonicNow: () => clock.t,
      keys,
      ...(keys === 'off' ? {} : { audience: TEST_AUDIENCE }),
    },
    {
      ...(over.metrics === false ? {} : { metrics: true }),
      ...(over.peer === undefined ? {} : { peerAddress: () => over.peer }),
      ...(over.host === undefined ? {} : { host: over.host }),
    },
  );
  await new Promise<void>((r) => server.listen(0, over.host ?? '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  const h: Harness = {
    port,
    clock,
    hold,
    release: () => releaseNow(),
    get: (path, headers) => request(port, 'GET', path, headers),
    stamp: (hash) => {
      const body = new TextEncoder().encode(JSON.stringify({ hash: toBase64Url(hash) }));
      seenHash.push(toBase64Url(hash), Buffer.from(hash).toString('hex'));
      const path = '/v1/stamp/freetsa';
      return request(
        port,
        'POST',
        path,
        {
          'Content-Type': 'application/json',
          ...(keys === 'off'
            ? {}
            : { 'X-Zeitstempel-Auth': nodeAuthHeaderMs(KEY, KEY.id, 'POST', path, NOW, body) }),
        },
        body,
      );
    },
    close: () =>
      new Promise((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
    seenHash,
  };
  open.push(h);
  return h;
}

/** The value of one series, or undefined. */
const value = (text: string, series: string): number | undefined => {
  const line = text.split('\n').find((l) => l.startsWith(series + ' '));
  return line === undefined ? undefined : Number(line.slice(series.length + 1));
};

const LINE =
  /^(?:# HELP [a-z_]+ [ -~]+|# TYPE [a-z_]+ (?:counter|gauge)|[a-z_]+(?:\{[a-z_]+="[a-z0-9-]+"(?:,[a-z_]+="[a-z0-9-]+")*\})? \d+)$/;

describe('RELAY_METRICS is read strictly', () => {
  const base = { RELAY_SERVICES: 'freetsa', RELAY_AUTH: 'off' };
  it('not set and 0 are off, 1 is on', () => {
    expect(readSettings({ ...base }).metrics).toBe(false);
    expect(readSettings({ ...base, RELAY_METRICS: '0' }).metrics).toBe(false);
    expect(readSettings({ ...base, RELAY_METRICS: '1' }).metrics).toBe(true);
  });
  it.each(['', ' 1', '1 ', 'true', 'yes', 'on', '2', '01', '-1', '1e0'])(
    'the value %j ends the start',
    (v) => {
      expect(() => readSettings({ ...base, RELAY_METRICS: v })).toThrow(/^RELAY_METRICS: ungültig/);
    },
  );
  it('the server gets `metrics` only when on', () => {
    expect(serverLimits({ host: '127.0.0.1', metrics: false })).not.toHaveProperty('metrics');
    expect(serverLimits({ host: '127.0.0.1' })).not.toHaveProperty('metrics');
    expect(serverLimits({ host: '127.0.0.1', metrics: true })).toMatchObject({ metrics: true });
  });
  it('a binding outside loopback with metrics on gives a warning, loopback does not', () => {
    const env = { ...base, RELAY_METRICS: '1' };
    const load = () => SERVICES;
    expect(readConfig({ ...env, RELAY_HOST: '127.0.0.1' }, load).warnings.join(' ')).not.toMatch(
      /RELAY_METRICS/,
    );
    expect(readConfig({ ...env }, load).warnings.join(' ')).not.toMatch(/RELAY_METRICS/);
    // RELAY_AUTH=off refuses a non-loopback host, so the warning is looked at with a key file setting instead
    const withKeys = {
      RELAY_SERVICES: 'freetsa',
      RELAY_METRICS: '1',
      RELAY_HOST: '0.0.0.0',
      RELAY_KEYS_FILE: 'x',
      RELAY_AUDIENCE: TEST_AUDIENCE,
    };
    const warned = readConfig(
      withKeys,
      load,
      () => KEYS as RelayKey[],
      () => null,
    ).warnings;
    expect(warned.join(' ')).toMatch(/RELAY_METRICS=1 bei einer Bindung außerhalb von Loopback/);
    const quiet = readConfig(
      { ...withKeys, RELAY_METRICS: '0' },
      load,
      () => KEYS as RelayKey[],
      () => null,
    ).warnings;
    expect(quiet.join(' ')).not.toMatch(/RELAY_METRICS/);
  });
});

describe('isLoopbackPeer', () => {
  it.each(['127.0.0.1', '127.5.5.5', '127.255.255.255', '::1', '::ffff:127.0.0.1'])(
    '%s is loopback',
    (a) => expect(isLoopbackPeer(a)).toBe(true),
  );
  it.each([
    undefined,
    '',
    'localhost',
    '128.0.0.1',
    '126.0.0.1',
    '127.0.0.256',
    '127.0.0.1.evil',
    '127.0.0',
    '10.0.0.1',
    '::2',
    '::',
    '::ffff:10.0.0.1',
    '::1%eth0',
    '0:0:0:0:0:0:0:1',
    ' 127.0.0.1',
  ])('%j is not', (a) => expect(isLoopbackPeer(a)).toBe(false));
});

describe('the route: off, and loopback only', () => {
  it('off (the default): 404 not-found like any unknown route, nothing says the route exists', async () => {
    const h = await start({ metrics: false });
    const m = await h.get('/metrics');
    const other = await h.get('/no-such-route');
    expect(m.status).toBe(404);
    expect(m.body).toBe('{"error":"not-found"}');
    expect(m.body).toBe(other.body);
    expect({ ...m.headers, date: '' }).toEqual({ ...other.headers, date: '' });
  });

  it('on, from loopback: 200, text format, no CORS, not cached', async () => {
    const h = await start();
    const m = await h.get('/metrics');
    expect(m.status).toBe(200);
    expect(m.headers['content-type']).toBe('text/plain; version=0.0.4; charset=utf-8');
    expect(m.headers['cache-control']).toBe('no-store');
    expect(m.headers['x-content-type-options']).toBe('nosniff');
    expect(Object.keys(m.headers).filter((k) => k.startsWith('access-control'))).toEqual([]);
    expect(Number(m.headers['content-length'])).toBe(Buffer.byteLength(m.body));
  });

  it('a peer that is not loopback gets exactly the answer of an unknown route', async () => {
    const h = await start({ peer: '203.0.113.9' });
    const m = await h.get('/metrics');
    const other = await h.get('/no-such-route');
    expect(m.status).toBe(404);
    expect(m.body).toBe(other.body);
    expect({ ...m.headers, date: '' }).toEqual({ ...other.headers, date: '' });
    // and no scrape was counted behind the 404
  });

  const external = Object.values(networkInterfaces())
    .flat()
    .find((i) => i !== undefined && i.family === 'IPv4' && !i.internal)?.address;
  it.skipIf(external === undefined)(
    "a real connection from a non-loopback address (this machine's own) gets 404",
    async () => {
      const h = await start({ host: '0.0.0.0' });
      const viaLoopback = await request(h.port, 'GET', '/metrics', {}, undefined, '127.0.0.1');
      expect(viaLoopback.status).toBe(200);
      const viaOwn = await request(h.port, 'GET', '/metrics', {}, undefined, external);
      expect(viaOwn.status).toBe(404);
      expect(viaOwn.body).toBe('{"error":"not-found"}');
    },
  );

  it('a proxy header cannot make a peer loopback (X-Forwarded-For is not read)', async () => {
    const h = await start({ peer: '203.0.113.9' });
    const m = await h.get('/metrics', {
      'X-Forwarded-For': '127.0.0.1',
      Forwarded: 'for=127.0.0.1',
    });
    expect(m.status).toBe(404);
  });

  it('only GET: every other method is answered by the usual routes (404, the preflight 204)', async () => {
    const h = await start();
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
      const r = await request(h.port, method, '/metrics', { 'Content-Length': '0' });
      expect(r.status, method).toBe(404);
      expect(r.body, method).toBe('{"error":"not-found"}');
    }
    const head = await request(h.port, 'HEAD', '/metrics');
    expect(head.status).toBe(404);
    expect(head.body).toBe('');
    const pre = await request(h.port, 'OPTIONS', '/metrics');
    expect(pre.status).toBe(204);
    const unknownPre = await request(h.port, 'OPTIONS', '/no-such-route');
    expect(pre.status).toBe(unknownPre.status);
  });

  it('only the exact target: no query, no trailing slash, no other spelling', async () => {
    const h = await start();
    expect((await h.get('/metrics?x=1')).status).toBe(400); // the relay's own rule: no query
    expect((await h.get('/metrics?')).status).toBe(400);
    for (const path of [
      '/metrics/',
      '/Metrics',
      '/METRICS',
      '/%6detrics',
      '/metrics%2f',
      '//metrics',
      '/metrics/x',
      '/./metrics',
    ]) {
      const r = await h.get(path);
      expect(r.status, path).not.toBe(200);
      expect(r.body, path).not.toContain('zeitstempel_');
    }
  });

  it('a request with an Origin header (a browser page) is not served; the usual origin rule answers', async () => {
    const h = await start();
    const allowed = await h.get('/metrics', { Origin: ORIGIN });
    expect(allowed.status).toBe(404);
    const foreign = await h.get('/metrics', { Origin: 'https://evil.example' });
    expect(foreign.status).toBe(403);
    expect(foreign.body).toBe('{"error":"origin-not-allowed"}');
    expect(allowed.body + foreign.body).not.toContain('zeitstempel_');
  });
});

describe('the content', () => {
  it('every line is well formed, every series appears once, HELP and TYPE come before the series', async () => {
    const h = await start();
    await h.stamp(sha256('probe'));
    const text = (await h.get('/metrics')).body;
    expect(text.endsWith('\n')).toBe(true);
    const lines = text.trimEnd().split('\n');
    for (const l of lines) expect(l, l).toMatch(LINE);
    const series = lines
      .filter((l) => !l.startsWith('#'))
      .map((l) => l.slice(0, l.lastIndexOf(' ')));
    expect(new Set(series).size).toBe(series.length);
    const typed = new Set(lines.filter((l) => l.startsWith('# TYPE ')).map((l) => l.split(' ')[2]));
    for (const s of series) expect(typed.has(s.replace(/\{.*/, '')), s).toBe(true);
  });

  it('counts the answers by service and status, the last success and a refusal by its code', async () => {
    const h = await start();
    const before = (await h.get('/metrics')).body;
    expect(value(before, 'zeitstempel_service_success_seen{service="freetsa"}')).toBe(0);
    expect(value(before, 'zeitstempel_stamp_inflight{service="freetsa"}')).toBe(0);
    h.clock.t += 20_000;
    expect((await h.stamp(sha256('probe'))).status).toBe(200);
    // a request with a bad signature: 401
    const bad = await request(
      h.port,
      'POST',
      '/v1/stamp/freetsa',
      {
        'Content-Type': 'application/json',
        'X-Zeitstempel-Auth': 'v3.nokey.1.x.y',
      },
      '{"hash":"x"}',
    );
    expect(bad.status).toBe(401);
    h.clock.t += 7_500;
    const text = (await h.get('/metrics')).body;
    expect(value(text, 'zeitstempel_stamp_responses_total{service="freetsa",status="200"}')).toBe(
      1,
    );
    expect(value(text, 'zeitstempel_stamp_responses_total{service="freetsa",status="401"}')).toBe(
      1,
    );
    expect(value(text, 'zeitstempel_http_responses_total{status="200"}')).toBe(1);
    expect(value(text, 'zeitstempel_http_responses_total{status="401"}')).toBe(1);
    expect(value(text, 'zeitstempel_refused_total{reason="unauthorized"}')).toBe(1);
    expect(value(text, 'zeitstempel_stamps_total')).toBe(1);
    expect(value(text, 'zeitstempel_service_success_seen{service="freetsa"}')).toBe(1);
    // the last success was at +20000 ms of the clock, the scrape at +27500
    expect(value(text, 'zeitstempel_service_last_success_age_seconds{service="freetsa"}')).toBe(7);
    expect(value(text, 'zeitstempel_relay_uptime_seconds')).toBe(27);
    expect(value(text, 'zeitstempel_stamp_inflight{service="freetsa"}')).toBe(0);
  });

  it('the age counts from the start while no stamp succeeded', async () => {
    const h = await start();
    h.clock.t += 125_000;
    const text = (await h.get('/metrics')).body;
    expect(value(text, 'zeitstempel_service_last_success_age_seconds{service="freetsa"}')).toBe(
      125,
    );
    expect(value(text, 'zeitstempel_service_success_seen{service="freetsa"}')).toBe(0);
  });

  it('a request in progress counts as in flight, and a client that goes away is counted as `none`', async () => {
    const h = await start();
    h.hold.on = true;
    const body = new TextEncoder().encode(JSON.stringify({ hash: toBase64Url(sha256('slow')) }));
    const path = '/v1/stamp/freetsa';
    const req = http.request({
      host: '127.0.0.1',
      port: h.port,
      path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Zeitstempel-Auth': nodeAuthHeaderMs(KEY, KEY.id, 'POST', path, NOW, body),
      },
    });
    req.on('error', () => {});
    req.end(body);
    let text = '';
    for (let i = 0; i < 100; i++) {
      text = (await h.get('/metrics')).body;
      if (value(text, 'zeitstempel_stamp_inflight{service="freetsa"}') === 1) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(value(text, 'zeitstempel_stamp_inflight{service="freetsa"}')).toBe(1);
    req.destroy();
    for (let i = 0; i < 100; i++) {
      text = (await h.get('/metrics')).body;
      if (value(text, 'zeitstempel_stamp_inflight{service="freetsa"}') === 0) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(value(text, 'zeitstempel_stamp_inflight{service="freetsa"}')).toBe(0);
    h.release();
    for (let i = 0; i < 100; i++) {
      text = (await h.get('/metrics')).body;
      if (value(text, 'zeitstempel_http_responses_total{status="none"}') === 1) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(value(text, 'zeitstempel_http_responses_total{status="none"}')).toBe(1);
    expect(value(text, 'zeitstempel_service_success_seen{service="freetsa"}')).toBe(0);
  });

  it('an unknown service id and other paths make no series of their own', async () => {
    const h = await start();
    for (const p of ['/v1/stamp/zzz-attacker', '/v1/stamp/' + 'a'.repeat(32), '/x', '/health']) {
      await request(h.port, 'POST', p, { 'Content-Length': '0' });
    }
    const text = (await h.get('/metrics')).body;
    expect(text).not.toContain('zzz-attacker');
    expect(text).not.toContain('aaaaaaaa');
    expect(text.match(/service="([^"]*)"/g)!.every((s) => s === 'service="freetsa"')).toBe(true);
  });

  it('counts its own scrapes, and the scrape itself is not one of the answers', async () => {
    const h = await start();
    await h.get('/metrics');
    await h.get('/metrics');
    const text = (await h.get('/metrics')).body;
    expect(value(text, 'zeitstempel_metrics_scrapes_total')).toBe(3);
    expect(value(text, 'zeitstempel_http_responses_total{status="200"}')).toBeUndefined();
  });
});

describe('nothing a request carries ever appears', () => {
  it('no key id, hash, token, signature, jti, address, audience, path or service address in the text', async () => {
    const h = await start();
    const hash = sha256('probe');
    const path = '/v1/stamp/freetsa';
    const body = new TextEncoder().encode(JSON.stringify({ hash: toBase64Url(hash) }));
    const head = nodeAuthHeaderMs(KEY, KEY.id, 'POST', path, NOW, body);
    const ok = await request(
      h.port,
      'POST',
      path,
      { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': head },
      body,
    );
    expect(ok.status).toBe(200);
    // replay of the same head, a bad hash, a head of an unknown key, a wrong audience
    const replay = await request(
      h.port,
      'POST',
      path,
      { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': head },
      body,
    );
    expect(replay.status).toBe(401);
    const bad = new TextEncoder().encode('{"hash":"AAAA-not-a-hash-AAAA"}');
    await request(
      h.port,
      'POST',
      path,
      {
        'Content-Type': 'application/json',
        'X-Zeitstempel-Auth': nodeAuthHeaderMs(KEY, KEY.id, 'POST', path, NOW, bad),
      },
      bad,
    );
    await request(
      h.port,
      'POST',
      path,
      {
        'Content-Type': 'application/json',
        'X-Zeitstempel-Auth': nodeAuthHeaderMs(KEY, 'kid-other-unknown', 'POST', path, NOW, body),
      },
      body,
    );
    h.clock.t += 10_000;
    await h.stamp(sha256('another'));
    const text = (await h.get('/metrics')).body;

    const [, , ts, jti, sig] = head.split('.');
    const token = (JSON.parse(ok.body) as { token: string }).token;
    const forbidden = [
      KEY.id,
      'kid-zq7x',
      'kid-other-unknown',
      toBase64Url(hash),
      Buffer.from(hash).toString('hex'),
      toBase64Url(sha256('another')),
      ...h.seenHash,
      token.slice(0, 40),
      Buffer.from(RECORDED).toString('base64').slice(0, 40),
      ts!,
      jti!,
      sig!.slice(0, 20),
      TEST_AUDIENCE,
      'relay.test',
      '127.0.0.1',
      '::1',
      String(h.port),
      SERVICES[0]!.url,
      'freetsa.org',
      'AAAA-not-a-hash',
      'v3.',
      '/v1/stamp/',
      'X-Zeitstempel-Auth',
    ];
    for (const f of forbidden) expect(text, f).not.toContain(f);
    // the labels are the closed ones: service, status, reason
    const labels = new Set([...text.matchAll(/([a-z_]+)="/g)].map((m) => m[1]));
    expect([...labels].sort()).toEqual(['reason', 'service', 'status']);
    const seriesText = text
      .split('\n')
      .filter((l) => !l.startsWith('#'))
      .join('\n');
    // the names of the counters of the key file are sums (`zeitstempel_key_*_total`): no label, no id
    expect(seriesText).not.toMatch(/kid|key_id|\{[^}]*key/);
  });

  it('no series is per key: the sums only (the names say it, the labels are closed)', async () => {
    const h = await start();
    const text = (await h.get('/metrics')).body;
    for (const l of text.split('\n').filter((x) => x.includes('{'))) {
      expect(l, l).toMatch(
        /^zeitstempel_(?:refused_total\{reason=|http_responses_total\{status=|stamp_responses_total\{service=|stamp_attempts_total\{service=|stamp_inflight\{service=|service_last_success_age_seconds\{service=|service_success_seen\{service=)/,
      );
    }
  });
});

describe('the size is bounded', () => {
  const metricsFor = (stats: RelayStats, serviceIds: string[] = ['freetsa']) =>
    createMetrics({ serviceIds, stats: () => stats, mono: () => 0 });

  it('hostile refusal codes (many, odd, huge counts) cannot grow the text or break a line', () => {
    const refused: Record<string, number> = {};
    for (let i = 0; i < 20_000; i++) refused[`code-${i}`] = i;
    refused['a"}\nzeitstempel_stamps_total 999'] = 5;
    refused['UPPER'] = 1;
    refused[''] = 1;
    refused['x'.repeat(5000)] = 1;
    refused['ok-code'] = Number.NaN;
    refused['neg'] = -3;
    refused['big'] = 1e300;
    const text = metricsFor({ stamped: 2, refused }).render({ stamped: 2, refused });
    expect(Buffer.byteLength(text)).toBeLessThanOrEqual(RELAY_LIMITS.metricsMaxBytes);
    for (const l of text.trimEnd().split('\n')) expect(l, l.slice(0, 80)).toMatch(LINE);
    const reasons = [...text.matchAll(/zeitstempel_refused_total\{reason="([^"]+)"\}/g)].map(
      (m) => m[1]!,
    );
    expect(reasons.length).toBeLessThanOrEqual(RELAY_LIMITS.metricsMaxReasons + 1);
    expect(reasons).toContain('other');
    expect(value(text, 'zeitstempel_stamps_total')).toBe(2); // the injected line did not become a series
    expect(text).not.toContain('999');
  });

  it('a long list of services is cut at a line end and says so', () => {
    const ids = Array.from({ length: 2000 }, (_, i) => `svc-${i}`);
    const text = metricsFor({ stamped: 0, refused: {} }, ids).render({ stamped: 0, refused: {} });
    expect(Buffer.byteLength(text)).toBeLessThanOrEqual(RELAY_LIMITS.metricsMaxBytes);
    expect(text.endsWith('\n# truncated\n')).toBe(true);
    for (const l of text.trimEnd().split('\n').slice(0, -1)) expect(l).toMatch(LINE);
  });

  it('the text of the shipped four services is far below the bound', () => {
    const all = loadServices().map((s) => s.id);
    const text = metricsFor({ stamped: 0, refused: {} }, all).render({ stamped: 0, refused: {} });
    expect(Buffer.byteLength(text)).toBeLessThan(RELAY_LIMITS.metricsMaxBytes / 2);
  });

  it('non-numbers in the counters are written as 0, not as NaN or a negative', () => {
    const text = metricsFor({} as RelayStats).render({
      stamped: Number.NaN,
      refused: {},
      keyReloadFailed: -1,
      batched: Infinity,
    });
    expect(text).not.toMatch(/NaN|Infinity|-1/);
    expect(value(text, 'zeitstempel_key_reload_failed_total')).toBe(0);
  });
});

// ---- audit 12 ----------------------------------------------------------------------------------------------------------

/** A request and its answer without a network: `finish()` closes the answer the way Node does. */
function fake(url: string, status: number, finished = true) {
  const res = Object.assign(new EventEmitter(), { statusCode: status, writableFinished: finished });
  return {
    req: { url } as IncomingMessage,
    res: res as unknown as ServerResponse,
    finish: () => void res.emit('close'),
  };
}
const unit = (ids: string[] = ['freetsa']) => {
  const clock = { t: 0 };
  const m = createMetrics({
    serviceIds: ids,
    stats: () => ({ stamped: 0, refused: {} }),
    mono: () => clock.t,
  });
  return { m, clock, text: () => m.render({ stamped: 0, refused: {} }) };
};
const answer = (m: ReturnType<typeof unit>['m'], url: string, status: number, finished = true) => {
  const f = fake(url, status, finished);
  m.observe(f.req, f.res);
  f.finish();
};
const raw = (port: number, bytes: string | Buffer, version = 'close'): Promise<string> =>
  new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1', () => s.write(bytes));
    let got = '';
    s.on('data', (c: Buffer) => (got += c.toString('latin1')));
    s.on('close', () => resolve(got));
    s.on('error', () => resolve(got));
    setTimeout(() => s.destroy(), version === 'close' ? 3000 : 500).unref();
  });

describe('audit 12: the Host header (DNS rebinding)', () => {
  const same = async (h: Harness, host: string): Promise<boolean> => {
    const m = await request(h.port, 'GET', '/metrics', { Host: host });
    const twin = await request(h.port, 'GET', '/no-such-route', { Host: host });
    if (m.status !== 200) {
      expect(m.status).toBe(404);
      expect(m.body).toBe(twin.body);
      expect({ ...m.headers, date: '' }).toEqual({ ...twin.headers, date: '' });
    }
    return m.status === 200;
  };

  it('only 127.0.0.1, localhost and [::1] (any case, optional port) are served', async () => {
    const h = await start();
    for (const host of [
      '127.0.0.1',
      `127.0.0.1:${h.port}`,
      'localhost',
      'LocalHost:9090',
      '[::1]',
      '[::1]:8080',
    ])
      expect(await same(h, host), host).toBe(true);
  });

  it('every other Host is answered like an unknown route (404, byte-equal), no scrape counted', async () => {
    const h = await start();
    for (const host of [
      'evil.example',
      'evil.example:8080',
      '127.0.0.1.evil.example',
      'localhost.evil.example:80',
      '127.0.0.2',
      'localhost:',
      '[::1]x',
      '127.0.0.1:123456',
      '10.0.0.1',
    ])
      expect(await same(h, host), host).toBe(false);
    expect(value((await h.get('/metrics')).body, 'zeitstempel_metrics_scrapes_total')).toBe(1);
  });

  it('HTTP/1.0 without a Host header is not served', async () => {
    const h = await start();
    const answer = await raw(h.port, 'GET /metrics HTTP/1.0\r\n\r\n');
    expect(answer.startsWith('HTTP/1.1 404')).toBe(true);
  });
});

describe('audit 12: every counter has its own series', () => {
  it('each field of the statistics ends up under its own name (no two swapped)', () => {
    const values: Record<string, [string, number]> = {
      stamped: ['zeitstempel_stamps_total', 2],
      batched: ['zeitstempel_batched_total', 3],
      solo: ['zeitstempel_solo_total', 5],
      soloDenied: ['zeitstempel_solo_denied_total', 7],
      keyReloads: ['zeitstempel_key_reloads_total', 11],
      keyReloadFailed: ['zeitstempel_key_reload_failed_total', 13],
      keyFileWritable: ['zeitstempel_key_file_writable_total', 17],
      keyRevoked: ['zeitstempel_key_revoked_total', 19],
      keyExpired: ['zeitstempel_key_expired_total', 23],
      serviceDenied: ['zeitstempel_service_denied_total', 29],
      shareDenied: ['zeitstempel_share_denied_total', 31],
    };
    const stats = { refused: {} } as Record<string, unknown>;
    for (const [field, [, v]] of Object.entries(values)) stats[field] = v;
    const text = unit().m.render(stats as unknown as RelayStats);
    for (const [field, [name, v]] of Object.entries(values))
      expect(value(text, name), field).toBe(v);
  });
});

describe('audit 12: counting the answers', () => {
  it('every status of the relay has its own label, any other number is `other`, an unfinished answer is `none`', () => {
    const { m, text } = unit();
    const known = [200, 204, 400, 401, 403, 404, 405, 408, 413, 415, 429, 431, 500, 502, 503, 504];
    for (const s of known) answer(m, '/v1/stamp/freetsa', s);
    answer(m, '/v1/stamp/freetsa', 418);
    answer(m, '/v1/stamp/freetsa', 200, false);
    const t = text();
    for (const s of known) {
      expect(value(t, `zeitstempel_http_responses_total{status="${s}"}`), String(s)).toBe(1);
      expect(
        value(t, `zeitstempel_stamp_responses_total{service="freetsa",status="${s}"}`),
        String(s),
      ).toBe(1);
    }
    expect(value(t, 'zeitstempel_http_responses_total{status="other"}')).toBe(1);
    expect(value(t, 'zeitstempel_http_responses_total{status="none"}')).toBe(1);
  });

  it('only a finished 200 sets the last success: 4xx, 5xx and a cut answer do not', () => {
    const { m, clock, text } = unit();
    clock.t = 5000;
    for (const s of [201, 204, 400, 401, 429, 500, 502, 503, 504])
      answer(m, '/v1/stamp/freetsa', s);
    answer(m, '/v1/stamp/freetsa', 200, false);
    let t = text();
    expect(value(t, 'zeitstempel_service_success_seen{service="freetsa"}')).toBe(0);
    expect(value(t, 'zeitstempel_service_last_success_age_seconds{service="freetsa"}')).toBe(5);
    clock.t = 7000;
    answer(m, '/v1/stamp/freetsa', 200);
    clock.t = 9000;
    answer(m, '/v1/stamp/freetsa', 500); // does not reset the age
    t = text();
    expect(value(t, 'zeitstempel_service_success_seen{service="freetsa"}')).toBe(1);
    expect(value(t, 'zeitstempel_service_last_success_age_seconds{service="freetsa"}')).toBe(2);
  });

  it('a made-up service name creates no state at all (memory is bounded by the list of services)', () => {
    const { m } = unit(['freetsa', 'sectigo']);
    expect(m.trackedSeries()).toBe(0);
    for (let i = 0; i < 300; i++) answer(m, `/v1/stamp/fake-${i}`, 404);
    answer(m, '/v1/stamp/freetsa-x', 404);
    answer(m, '/x', 404);
    expect(m.trackedSeries()).toBe(0);
    answer(m, '/v1/stamp/freetsa', 200);
    expect(m.trackedSeries()).toBeGreaterThan(0);
    for (let i = 0; i < 300; i++) answer(m, `/v1/stamp/fake-${i}`, 200);
    expect(m.trackedSeries()).toBeLessThanOrEqual(4 * 2);
  });
});

describe('audit 12: stamp attempts (the base of the alarm "service without success")', () => {
  const counted = [200, 429, 500, 502, 503, 504];
  const notCounted = [400, 401, 403, 404, 405, 413, 415];
  it('counts the answers of requests that were let through to the service, not the refusals at the door', () => {
    const { m, text } = unit();
    for (const s of [...counted, ...notCounted]) answer(m, '/v1/stamp/freetsa', s);
    answer(m, '/v1/stamp/freetsa', 200, false); // cut off: no answer, no attempt
    const t = text();
    expect(value(t, 'zeitstempel_stamp_attempts_total{service="freetsa"}')).toBe(counted.length);
  });

  it('a hostile mix of requests without a key does not move it; a stamp does', async () => {
    const h = await start();
    await request(h.port, 'POST', '/v1/stamp/freetsa', { 'Content-Length': '0' }); // 401
    await request(h.port, 'GET', '/v1/stamp/freetsa'); // 405
    await request(h.port, 'POST', '/v1/stamp/zzz', { 'Content-Length': '0' }); // 404
    const series = 'zeitstempel_stamp_attempts_total{service="freetsa"}';
    expect(value((await h.get('/metrics')).body, series)).toBe(0);
    h.clock.t += 20_000;
    expect((await h.stamp(sha256('probe'))).status).toBe(200);
    expect(value((await h.get('/metrics')).body, series)).toBe(1);
  });
});

describe('audit 12: answers the server writes itself', () => {
  it('a broken request line (400) and a huge header (431) are counted by status', async () => {
    const h = await start();
    expect(
      (await raw(h.port, 'get /x HTTP/1.1\r\nHost: a\r\n\r\n')).startsWith('HTTP/1.1 400'),
    ).toBe(true);
    const big = await raw(h.port, `GET /x HTTP/1.1\r\nHost: a\r\nX: ${'a'.repeat(20_000)}\r\n\r\n`);
    expect(big.startsWith('HTTP/1.1 431')).toBe(true);
    const text = (await h.get('/metrics')).body;
    expect(value(text, 'zeitstempel_http_responses_total{status="400"}')).toBe(1);
    expect(value(text, 'zeitstempel_http_responses_total{status="431"}')).toBe(1);
  });
});

describe('audit 12: a failure while serving /metrics', () => {
  it('is answered by the usual routes (404), the server keeps working', async () => {
    const clock = { t: 1 };
    const { server } = createRelayServer(
      {
        services: SERVICES,
        origins: [ORIGIN],
        allowPlainHttp: false,
        upstream: async () => ({ status: 200, contentType: 'x', body: RECORDED }),
        random: () => FREETSA_NONCE,
        now: () => NOW,
        monotonicNow: () => clock.t,
        keys: 'off',
      },
      {
        metrics: true,
        peerAddress: () => {
          throw new Error('boom');
        },
      },
    );
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as AddressInfo).port;
    try {
      const m = await request(port, 'GET', '/metrics');
      expect(m.status).toBe(404);
      expect(m.body).toBe('{"error":"not-found"}');
      expect((await request(port, 'GET', '/health')).status).toBe(200);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});

describe('audit 12: the cap of refusal codes', () => {
  it('holds every code the relay can send, with a reserve', () => {
    const relay = readFileSync(new URL('../relay/relay.ts', import.meta.url), 'utf8');
    const upstream = readFileSync(new URL('../relay/upstream.ts', import.meta.url), 'utf8');
    const codes = new Set<string>();
    for (const m of relay.matchAll(/error: '([a-z][a-z0-9-]*)'/g)) codes.add(m[1]!);
    for (const m of relay.matchAll(/(?:refused\[|countOnce\()'([a-z][a-z0-9-]*)'/g))
      codes.add(m[1]!);
    const kinds = /readonly kind: ([^;]+);/.exec(upstream)![1]!;
    for (const m of kinds.matchAll(/'([a-z-]+)'/g)) codes.add(`upstream-${m[1]}`);
    expect(codes.has('unauthorized')).toBe(true);
    expect(codes.has('upstream-timeout')).toBe(true);
    expect(codes.size).toBeGreaterThan(20);
    expect(codes.size + 16).toBeLessThan(RELAY_LIMITS.metricsMaxReasons);
  });

  it('beyond the cap the alphabetically last codes are folded, whatever the insertion order', () => {
    const cap = RELAY_LIMITS.metricsMaxReasons;
    const refused: Record<string, number> = { unauthorized: 4 };
    for (let i = cap + 5; i >= 0; i--) refused[`c-${String(i).padStart(3, '0')}`] = 1;
    const text = unit().m.render({ stamped: 0, refused });
    const reasons = [...text.matchAll(/zeitstempel_refused_total\{reason="([^"]+)"\} (\d+)/g)];
    const names = reasons.map((r) => r[1]!);
    const kept = names.filter((n) => n !== 'other');
    expect(kept).toEqual(Array.from({ length: cap }, (_, i) => `c-${String(i).padStart(3, '0')}`));
    expect(value(text, 'zeitstempel_refused_total{reason="other"}')).toBe(10); // c-cap .. c-(cap+5) once each, unauthorized 4 times;
  });

  it('no series `other` while nothing overflows', () => {
    const text = unit().m.render({ stamped: 0, refused: { busy: 2, unauthorized: 1 } });
    expect(text).not.toContain('reason="other"');
    expect(value(text, 'zeitstempel_refused_total{reason="busy"}')).toBe(2);
  });
});

describe('the process', () => {
  const children: ChildProcess[] = [];
  afterEach(() => {
    while (children.length > 0) children.pop()!.kill('SIGKILL');
  });

  async function startMain(env: Record<string, string>): Promise<{ port: number }> {
    const probe = http.createServer();
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
    const port = (probe.address() as AddressInfo).port;
    await new Promise<void>((r) => probe.close(() => r()));
    const child = spawn(process.execPath, ['relay/main.ts'], {
      cwd: new URL('..', import.meta.url).pathname,
      env: {
        PATH: process.env.PATH ?? '',
        PORT: String(port),
        RELAY_SERVICES: 'freetsa',
        RELAY_AUTH: 'off',
        ...env,
      },
    });
    children.push(child);
    await new Promise<void>((resolve, reject) => {
      let out = '';
      child.stdout!.on('data', (c: Buffer) => {
        out += c.toString('utf8');
        if (out.includes('"event":"start"')) resolve();
      });
      child.on('exit', () => reject(new Error('relay ended')));
    });
    return { port };
  }

  it('RELAY_METRICS=1: the started relay answers on loopback; without it the route is 404', async () => {
    const on = await startMain({ RELAY_METRICS: '1' });
    const m = await request(on.port, 'GET', '/metrics');
    expect(m.status).toBe(200);
    expect(m.body).toContain('zeitstempel_relay_uptime_seconds');
    const off = await startMain({});
    expect((await request(off.port, 'GET', '/metrics')).status).toBe(404);
    const zero = await startMain({ RELAY_METRICS: '0' });
    expect((await request(zero.port, 'GET', '/metrics')).status).toBe(404);
  }, 30_000);

  it('an invalid RELAY_METRICS ends the start with a config-error and exit code 1', async () => {
    const child = spawn(process.execPath, ['relay/main.ts'], {
      cwd: new URL('..', import.meta.url).pathname,
      env: {
        PATH: process.env.PATH ?? '',
        RELAY_SERVICES: 'freetsa',
        RELAY_AUTH: 'off',
        RELAY_METRICS: 'yes',
      },
    });
    children.push(child);
    let err = '';
    child.stderr!.on('data', (c: Buffer) => (err += c.toString('utf8')));
    const code = await new Promise((r) => child.on('exit', (c) => r(c)));
    expect(code).toBe(1);
    expect(err).toContain('"event":"config-error"');
    expect(err).toContain('RELAY_METRICS: ungültig');
  }, 15_000);
});
