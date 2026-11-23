import { verify, verify as nodeVerify } from 'node:crypto';
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net, { type AddressInfo } from 'node:net';
import {
  toBase64Url,
  verifyTimestampToken,
  fromBase64Url,
  signRelayRequest,
} from '../src/index.ts';
import type { RelayKey } from '../relay/keys.ts';
import { loadServices } from '../relay/load.ts';
import { keyFilePermissionWarning, listenOn, readConfig } from '../relay/main.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import type { RelayOptions } from '../relay/relay.ts';
import { createRelayServer } from '../relay/server.ts';
import {
  UpstreamError,
  makeNetworkUpstream,
  networkUpstream,
  type Upstream,
} from '../relay/upstream.ts';
import {
  makeTestKey,
  nodeAuthHeader,
  nodeSignature,
  authMessage,
  twinSignature,
  type TestKey,
} from './auth-helpers.ts';
import { FREETSA_NONCE, fixture, fixtureText, sha256 } from './helpers.ts';

const SERVICES = loadServices();
const RECORDED = fixture('freetsa.tsr');
const ORIGIN = 'https://app.example';
const NOW = Date.parse('2026-11-23T13:10:00Z');

// Random per run: the repo holds no key material.
const KEY_A = makeTestKey('app-a');
const KEY_B = makeTestKey('app-b');
const KEYS: RelayKey[] = [KEY_A, KEY_B].map((k) => ({ id: k.id, publicKey: k.publicKey }));

interface Harness {
  base: string;
  /** Header value for a request made now (offset in seconds), signed with key A unless told otherwise. */
  sign: (
    path: string,
    body: Uint8Array,
    over?: { ts?: number; key?: TestKey; kid?: string },
  ) => string;
  close: () => Promise<void>;
  calls: Uint8Array[];
  stats: () => { stamped: number; refused: Record<string, number> };
  clock: { now: number };
}

async function start(
  over: {
    upstream?: Upstream;
    allowPlainHttp?: boolean;
    services?: typeof SERVICES;
    random?: (n: number) => Uint8Array;
    keys?: readonly RelayKey[] | 'off';
    authReplayEntries?: number;
    /** The relay's clock at its creation (the process start); default NOW. */
    clockStart?: number;
    verifySignature?: RelayOptions['verifySignature'];
  } = {},
): Promise<Harness> {
  const calls: Uint8Array[] = [];
  const clock = { now: over.clockStart ?? NOW };
  const stand: Upstream = async (_t, body) => {
    calls.push(body);
    return { status: 200, contentType: 'application/timestamp-reply', body: RECORDED };
  };
  const { server, relay } = createRelayServer({
    services: over.services ?? SERVICES,
    origins: [ORIGIN],
    allowPlainHttp: over.allowPlainHttp ?? false,
    upstream: over.upstream ?? stand,
    random: over.random ?? (() => FREETSA_NONCE),
    now: () => clock.now,
    keys: over.keys ?? KEYS,
    ...(over.verifySignature === undefined ? {} : { verifySignature: over.verifySignature }),
    ...(over.authReplayEntries === undefined ? {} : { authReplayEntries: over.authReplayEntries }),
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  let n = 0;
  return {
    sign: (path, body, o = {}) =>
      nodeAuthHeader(
        o.key ?? KEY_A,
        o.kid ?? 'app-a',
        'POST',
        path,
        // Every call gets its own second inside the window (not before the start second), so equal requests are no replays.
        o.ts ?? Math.floor(clock.now / 1000) + ((n++ % 59) - 1),
        body,
      ),
    base: `http://127.0.0.1:${port}`,
    close: () => new Promise((r) => (server.closeAllConnections(), server.close(() => r()))),
    calls,
    stats: relay.stats,
    clock,
  };
}

const bytesOf = (body: string | Buffer): Uint8Array =>
  typeof body === 'string' ? new TextEncoder().encode(body) : new Uint8Array(body);

/** POST, signed for the harness key unless the call brings its own `X-Zeitstempel-Auth`. */
const post = (
  h: Harness,
  path: string,
  body: string | Buffer,
  type: string,
  headers: Record<string, string> = {},
) =>
  fetch(h.base + path, {
    method: 'POST',
    body: typeof body === 'string' ? body : new Uint8Array(body),
    headers: {
      'Content-Type': type,
      ...('X-Zeitstempel-Auth' in headers
        ? {}
        : { 'X-Zeitstempel-Auth': h.sign(path.split('?')[0]!, bytesOf(body)) }),
      ...headers,
    },
  });
const hashJson = (h: Uint8Array) => JSON.stringify({ hash: toBase64Url(h) });

/** Sends the request target as given (fetch would normalise `//` and friends). */
function rawGet(h: Harness, path: string): Promise<{ status: number; body: string }> {
  const port = Number(new URL(h.base).port);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: 'GET' }, (res) => {
      const parts: Buffer[] = [];
      res.on('data', (c: Buffer) => parts.push(c));
      res.on('end', () =>
        resolve({ status: res.statusCode ?? 0, body: Buffer.concat(parts).toString('utf8') }),
      );
    });
    req.on('error', reject);
    req.end();
  });
}

/** Sends method, request target and body exactly as given (fetch would normalise the target). */
function rawRequest(
  h: Harness,
  method: string,
  path: string,
  headers: Record<string, string>,
  body: string,
): Promise<{ status: number; body: string }> {
  const port = Number(new URL(h.base).port);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers }, (res) => {
      const parts: Buffer[] = [];
      res.on('data', (c: Buffer) => parts.push(c));
      res.on('end', () =>
        resolve({ status: res.statusCode ?? 0, body: Buffer.concat(parts).toString('utf8') }),
      );
    });
    req.on('error', reject);
    req.end(body);
  });
}

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
    const early = await start({ clockStart: NOW - RELAY_LIMITS.maxSkewMs - 3 * 3_600_000 });
    const res = await post(
      early,
      '/v1/stamp/freetsa',
      hashJson(sha256('probe')),
      'application/json',
    );
    expect(await res.json()).toEqual({ error: 'upstream-invalid', reason: 'time-in-future' });
    await early.close();
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
  it('answers request targets that are not URLs with 400 and keeps running', async () => {
    for (const path of ['//', '//[', '//:', '///']) {
      const res = await rawGet(h, path);
      expect(res.status, path).toBe(400);
      expect(JSON.parse(res.body), path).toEqual({ error: 'bad-request' });
    }
    expect((await fetch(`${h.base}/health`)).status).toBe(200);
  });
  it('answers 500 with a code when the relay itself breaks, and keeps running', async () => {
    const h2 = await start({
      random: () => {
        throw new Error('no entropy, with secrets');
      },
    });
    const res = await post(h2, '/v1/stamp/freetsa', hashJson(sha256('probe')), 'application/json');
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: 'internal' });
    expect((await fetch(`${h2.base}/health`)).status).toBe(200);
    await h2.close();
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

describe('relay: start configuration', () => {
  const OFF = { RELAY_AUTH: 'off' };
  it('names an unknown service id in RELAY_SERVICES and refuses to start', () => {
    expect(() => readConfig({ ...OFF, RELAY_SERVICES: 'freetsa,nope' }, () => SERVICES)).toThrow(
      /nope/,
    );
    expect(() => readConfig({ ...OFF, RELAY_SERVICES: 'nope' }, () => SERVICES)).toThrow(
      /nicht angeboten/,
    );
  });
  it('refuses an id the relay would not offer (http-only without RELAY_ALLOW_PLAIN_HTTP)', () => {
    expect(() => readConfig({ ...OFF, RELAY_SERVICES: 'digicert' }, () => SERVICES)).toThrow(
      /digicert/,
    );
    expect(
      readConfig(
        { ...OFF, RELAY_SERVICES: 'digicert', RELAY_ALLOW_PLAIN_HTTP: '1' },
        () => SERVICES,
      ).services.map((s) => s.id),
    ).toEqual(['digicert']);
  });
  it('refuses to start with no services at all', () => {
    expect(() => readConfig(OFF, () => [])).toThrow(/keine Dienste/);
    expect(() => readConfig({ ...OFF, RELAY_SERVICES: 'freetsa' }, () => [])).toThrow(
      /nicht angeboten/,
    );
  });
  it('offers all loaded services, or the chosen ones', () => {
    expect(readConfig(OFF, () => SERVICES).services.map((s) => s.id)).toEqual([
      'freetsa',
      'sectigo',
    ]);
    expect(
      readConfig({ ...OFF, RELAY_SERVICES: ' sectigo ' }, () => SERVICES).services.map((s) => s.id),
    ).toEqual(['sectigo']);
  });
  it('warns when the key file can be written by group or others, and only then', () => {
    const at = (mode: number) => () => ({ mode });
    // readable is fine: the file holds public keys only
    for (const mode of [0o100600, 0o100400, 0o100644, 0o100640, 0o100604, 0o100444]) {
      expect(keyFilePermissionWarning('/k.json', at(mode), 'linux'), mode.toString(8)).toBeNull();
    }
    for (const mode of [0o100620, 0o100602, 0o100664, 0o100666, 0o100660, 0o100606, 0o100622]) {
      const text = keyFilePermissionWarning('/k.json', at(mode), 'linux');
      expect(text, mode.toString(8)).toMatch(/schreibbar/);
      expect(text).toContain('/k.json');
      expect(text).toContain(`Modus ${(mode & 0o777).toString(8)}`);
    }
    expect(keyFilePermissionWarning('/k.json', at(0o100666), 'win32')).toBeNull();
    expect(
      keyFilePermissionWarning('/k.json', () => {
        throw new Error('gone');
      }),
    ).toBeNull();
  });
  it.skipIf(process.platform === 'win32')(
    'judges a real file by its mode: 666 and 664 warn, 644 and 600 do not (path and mode only)',
    () => {
      const dir = new URL('../.tmp/keyfile-mode/', import.meta.url);
      mkdirSync(dir, { recursive: true });
      const file = new URL('keys.json', dir).pathname;
      const MARKER = 'PUBLIC-KEY-MARKER-0123456789';
      writeFileSync(file, MARKER);
      const warn = (mode: number) => {
        chmodSync(file, mode);
        return keyFilePermissionWarning(file);
      };
      for (const mode of [0o666, 0o664, 0o662, 0o646]) {
        const text = warn(mode);
        expect(text, mode.toString(8)).not.toBeNull();
        expect(text).toContain(file);
        expect(text).toContain(`Modus ${mode.toString(8)}`);
        expect(text).not.toContain(MARKER);
      }
      for (const mode of [0o644, 0o640, 0o600, 0o400]) {
        expect(warn(mode), mode.toString(8)).toBeNull();
      }
    },
  );
  it('hands the permission warning to the start (no key data in it)', () => {
    const env = { RELAY_KEYS_FILE: '/etc/z/keys.json' };
    const warned = readConfig(
      env,
      () => SERVICES,
      () => KEYS,
      () => 'warn',
    );
    expect(warned.warnings).toEqual(['warn']);
    expect(
      readConfig(
        env,
        () => SERVICES,
        () => KEYS,
        () => null,
      ).warnings,
    ).toEqual([]);
    const real = readConfig(
      env,
      () => SERVICES,
      () => KEYS,
      (p) => keyFilePermissionWarning(p, () => ({ mode: 0o100664 }), 'linux'),
    );
    expect(real.warnings[0]).toContain('/etc/z/keys.json');
    expect(real.warnings[0]).not.toContain(toBase64Url(KEYS[0]!.publicKey));
  });
  it('with RELAY_AUTH=off it listens on 127.0.0.1 only and warns; with keys it does not narrow', async () => {
    const off = readConfig({ RELAY_AUTH: 'off' }, () => SERVICES);
    expect(off.settings.host).toBe('127.0.0.1');
    expect(off.warnings).toHaveLength(1);
    expect(off.warnings[0]).toContain('auth off, loopback only');
    expect(() => readConfig({ RELAY_AUTH: 'off', RELAY_HOST: '0.0.0.0' }, () => SERVICES)).toThrow(
      /Loopback/,
    );
    const keyed = readConfig(
      { RELAY_KEYS_FILE: '/k.json' },
      () => SERVICES,
      () => KEYS,
      () => null,
    );
    expect(keyed.settings.host).toBeUndefined();
    expect(keyed.warnings).toEqual([]);
    // the real bind: the address the server ends up on
    const { server } = createRelayServer({
      services: SERVICES,
      origins: [],
      allowPlainHttp: false,
      upstream: async () => {
        throw new Error('unused');
      },
      random: () => FREETSA_NONCE,
      now: () => NOW,
      keys: 'off',
    });
    await new Promise<void>((r) => listenOn(server, 0, off.settings.host, r));
    expect((server.address() as AddressInfo).address).toBe('127.0.0.1');
    await new Promise<void>((r) => server.close(() => r()));
  });
  it('limits the open connections: the third socket is closed, the first two stay', async () => {
    const { server } = createRelayServer(
      {
        services: SERVICES,
        origins: [ORIGIN],
        allowPlainHttp: false,
        upstream: networkUpstream,
        random: () => FREETSA_NONCE,
        now: () => NOW,
        keys: 'off',
      },
      { maxConnections: 2 },
    );
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as AddressInfo).port;
    const sockets: net.Socket[] = [];
    const closed: boolean[] = [];
    const open = (i: number) =>
      new Promise<void>((resolve) => {
        const s = net.connect(port, '127.0.0.1', () => resolve());
        s.on('error', () => undefined);
        s.on('close', () => (closed[i] = true));
        sockets.push(s);
      });
    try {
      await open(0);
      await open(1);
      await open(2);
      await new Promise((r) => setTimeout(r, 300));
      expect(closed[2]).toBe(true);
      expect(closed[0]).toBeFalsy();
      expect(closed[1]).toBeFalsy();
    } finally {
      for (const s of sockets) s.destroy();
      await new Promise<void>((r) => (server.closeAllConnections(), server.close(() => r())));
    }
  });
  it('answers 408 and closes when a request does not arrive in time', async () => {
    const { server } = createRelayServer(
      {
        services: SERVICES,
        origins: [ORIGIN],
        allowPlainHttp: false,
        upstream: networkUpstream,
        random: () => FREETSA_NONCE,
        now: () => NOW,
        keys: 'off',
      },
      { requestTimeoutMs: 300 },
    );
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as AddressInfo).port;
    const text = await new Promise<string>((resolve) => {
      const s = net.connect(port, '127.0.0.1', () =>
        s.write('POST /v1/stamp/freetsa HTTP/1.1\r\nHost: x\r\n'),
      );
      let got = '';
      s.on('data', (c) => (got += c.toString('utf8')));
      s.on('error', () => undefined);
      s.on('close', () => resolve(got));
    });
    expect(text).toMatch(/^HTTP\/1\.1 408 /);
    await new Promise<void>((r) => (server.closeAllConnections(), server.close(() => r())));
  });
  it('configures the deadlines and the limit from the shared limits', () => {
    const { server } = createRelayServer({
      services: SERVICES,
      origins: [ORIGIN],
      allowPlainHttp: false,
      upstream: networkUpstream,
      random: () => FREETSA_NONCE,
      now: () => NOW,
      keys: 'off',
    });
    expect(server.maxConnections).toBe(RELAY_LIMITS.maxConnections);
    expect(server.requestTimeout).toBe(RELAY_LIMITS.requestTimeoutMs);
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
    expect(ok.headers.get('access-control-allow-headers')).toBe('Content-Type, X-Zeitstempel-Auth');
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
  it('lets the browser read Retry-After (exposed), also on a 429', async () => {
    const h2 = await start();
    const per = Math.floor(RELAY_LIMITS.windowMs / SERVICES[0]!.minIntervalMs);
    let last: Response | undefined;
    for (let i = 0; i <= per; i += 1)
      last = await post(h2, '/v1/stamp/freetsa', hashJson(sha256('probe')), 'application/json', {
        Origin: ORIGIN,
      });
    expect(last!.status).toBe(429);
    expect(last!.headers.get('access-control-expose-headers')).toBe('Retry-After');
    await h2.close();
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
    const h = await start({ services: many, keys: 'off' });
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

describe('relay: authentication', () => {
  const PATH = '/v1/stamp/freetsa';
  const BODY = hashJson(sha256('probe'));
  const secondsNow = () => Math.floor(NOW / 1000);
  let h: Harness;
  beforeEach(async () => (h = await start()));
  afterEach(() => h.close());
  // twenty services whose own limit (60 per minute) is no obstacle, to reach the key and total limits
  const MANY = Array.from({ length: 20 }, (_, i) => ({
    ...SERVICES[0]!,
    id: `s${i}`,
    minIntervalMs: 1000,
  }));

  const withHeader = (value: string | undefined, body = BODY, path = PATH) =>
    fetch(h.base + path, {
      method: 'POST',
      body,
      headers: {
        'Content-Type': 'application/json',
        ...(value === undefined ? {} : { 'X-Zeitstempel-Auth': value }),
      },
    });
  const unauthorized = async (res: Response) => {
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'unauthorized' });
    expect(h.calls).toHaveLength(0);
  };

  it('lets a request signed by the library through (the private key is never sent)', async () => {
    const signed = await signRelayRequest({
      privateKey: KEY_A.privateKey,
      keyId: 'app-a',
      method: 'POST',
      path: PATH,
      body: new TextEncoder().encode(BODY),
      nowMs: NOW,
    });
    if (!signed.ok) throw new Error('sign');
    expect(signed.value).not.toContain(toBase64Url(KEY_A.privateKey));
    const res = await withHeader(signed.value);
    expect(res.status).toBe(200);
    expect(h.calls).toHaveLength(1);
  });
  it('lets a request signed independently with node:crypto through (the format of the specification)', async () => {
    const header = nodeAuthHeader(
      KEY_A,
      'app-a',
      'POST',
      PATH,
      secondsNow(),
      new TextEncoder().encode(BODY),
    );
    expect(header).toMatch(/^v2\.app-a\.\d+\.[A-Za-z0-9_-]{86}$/);
    expect((await withHeader(header)).status).toBe(200);
  });
  it('refuses the version 1 header (HMAC), also when it is well formed', async () => {
    const v1 = `v1.app-a.${secondsNow()}.${toBase64Url(new Uint8Array(32).fill(7))}`;
    await unauthorized(await withHeader(v1));
  });
  it('accepts the second key as well', async () => {
    const body = new TextEncoder().encode(BODY);
    const res = await withHeader(h.sign(PATH, body, { key: KEY_B, kid: 'app-b' }));
    expect(res.status).toBe(200);
  });
  it('refuses a request without the header', async () => {
    await unauthorized(await withHeader(undefined));
  });
  it('refuses a header of the wrong form', async () => {
    const good = h.sign(PATH, new TextEncoder().encode(BODY), { ts: secondsNow() });
    const [v, kid, ts, sig] = good.split('.') as [string, string, string, string];
    const forms = [
      '',
      'v2',
      `v3.${kid}.${ts}.${sig}`,
      `${v}.${kid.toUpperCase()}.${ts}.${sig}`,
      `${v}.${kid}.0${ts}.${sig}`,
      `${v}.${kid}.${ts}.${sig.slice(1)}`,
      `${v}.${kid}.${ts}.${sig}x`,
      `${v}.${kid}.${ts}.${sig}.extra`,
      `${v}.${kid}.${ts}.${sig.slice(0, 85)}=`,
      `${v}.${kid}.-${ts}.${sig}`,
      `${v}.${kid}.${ts}.${sig.replace(/[A-Za-z0-9_-]$/, '*')}`,
    ];
    for (const form of forms) {
      await unauthorized(await withHeader(form));
    }
  });
  it('refuses a wrong signature', async () => {
    const good = h.sign(PATH, new TextEncoder().encode(BODY), { ts: secondsNow() });
    // Flip one bit of the decoded signature and encode it again: the form stays valid, so only the
    // verification of the signature itself can refuse it.
    const parts = good.split('.');
    const sig = Buffer.from(parts[3]!, 'base64url');
    sig[10] = sig[10]! ^ 0x01;
    const forged = [...parts.slice(0, 3), sig.toString('base64url')].join('.');
    expect(forged).toMatch(/^v2\.app-a\.\d+\.[A-Za-z0-9_-]{86}$/);
    expect(forged).not.toBe(good);
    await unauthorized(await withHeader(forged));
  });
  it('refuses a signature made for another path', async () => {
    const other = h.sign('/v1/stamp/sectigo', new TextEncoder().encode(BODY));
    await unauthorized(await withHeader(other));
  });
  it('refuses a signature made for another body', async () => {
    const header = h.sign(PATH, new TextEncoder().encode(hashJson(sha256('other'))));
    await unauthorized(await withHeader(header));
  });
  it('refuses a time too old or too new, accepts the edge of the window', async () => {
    const body = new TextEncoder().encode(BODY);
    const w = RELAY_LIMITS.authWindowSeconds;
    h.clock.now = NOW + w * 1000; // a minute after the start, so the past edge is not before the start
    const now = secondsNow() + w;
    await unauthorized(await withHeader(h.sign(PATH, body, { ts: now - w - 1 })));
    await unauthorized(await withHeader(h.sign(PATH, body, { ts: now + w + 1 })));
    expect((await withHeader(h.sign(PATH, body, { ts: now - w }))).status).toBe(200);
    expect((await withHeader(h.sign(PATH, body, { ts: now + w }))).status).toBe(200);
  });
  it('decides on the time before it reads the body', async () => {
    const body = new TextEncoder().encode(BODY);
    const stale = h.sign(PATH, body, { ts: secondsNow() - 600 });
    // too large AND too old: the time check comes first, so this is 401 and not 413
    const res = await withHeader(stale, 'x'.repeat(RELAY_LIMITS.bodyBytes + 1));
    expect(res.status).toBe(401);
  });
  it('answers an unknown key id exactly like a wrong signature', async () => {
    const body = new TextEncoder().encode(BODY);
    const wrongMac = h.sign(PATH, body, { key: makeTestKey('other') }); // known id, wrong key
    const unknownKid = h.sign(PATH, body, { kid: 'nobody' });
    const a = await withHeader(wrongMac);
    const b = await withHeader(unknownKid);
    expect(b.status).toBe(a.status);
    expect(await b.text()).toBe(await a.text());
    expect([...b.headers.entries()].filter(([k]) => k !== 'date')).toEqual(
      [...a.headers.entries()].filter(([k]) => k !== 'date'),
    );
    expect(h.calls).toHaveLength(0);
  });
  it('refuses a replay of the same request', async () => {
    const header = h.sign(PATH, new TextEncoder().encode(BODY));
    expect((await withHeader(header)).status).toBe(200);
    await unauthorized(
      await (async () => {
        h.calls.length = 0;
        return withHeader(header);
      })(),
    );
  });
  it('lets a replayed request stay refused until its time leaves the window, then it is refused by the time', async () => {
    const header = h.sign(PATH, new TextEncoder().encode(BODY), { ts: secondsNow() });
    expect((await withHeader(header)).status).toBe(200);
    h.clock.now += 30_000;
    expect((await withHeader(header)).status).toBe(401);
    h.clock.now += 40_000;
    expect((await withHeader(header)).status).toBe(401);
  });
  it('answers 429 with Retry-After when the replay cache is full, and frees it as entries expire', async () => {
    const small = await start({ authReplayEntries: 3 });
    const body = new TextEncoder().encode(BODY);
    const go = (ts: number, second = false) =>
      fetch(small.base + PATH, {
        method: 'POST',
        body: BODY,
        headers: {
          'Content-Type': 'application/json',
          'X-Zeitstempel-Auth': small.sign(
            PATH,
            body,
            second ? { ts, key: KEY_B, kid: 'app-b' } : { ts },
          ),
        },
      });
    const t = Math.floor(small.clock.now / 1000);
    for (let i = 0; i < 3; i += 1) expect((await go(t + i, i === 2)).status).toBe(200);
    const full = await go(t + 3, true);
    expect(full.status).toBe(429);
    expect(await full.json()).toEqual({ error: 'rate-limited' });
    expect(Number(full.headers.get('retry-after'))).toBeGreaterThan(0);
    expect(small.calls).toHaveLength(3);
    // the oldest entry (second t, kept for window + request timeout = 70 s) is out after 70 s
    expect(full.headers.get('retry-after')).toBe('70');
    small.clock.now += 70_000;
    expect((await go(Math.floor(small.clock.now / 1000), true)).status).toBe(429); // still full
    small.clock.now += 1_000;
    expect((await go(Math.floor(small.clock.now / 1000), true)).status).toBe(200); // the oldest is gone
    await small.close();
  });
  it('does not let a forged request fill the replay cache', async () => {
    const small = await start({ authReplayEntries: 2 });
    const body = new TextEncoder().encode(BODY);
    const t = Math.floor(small.clock.now / 1000);
    for (let i = 0; i < 5; i += 1) {
      const forged = small.sign(PATH, body, { ts: t - i, key: makeTestKey('other') });
      const res = await fetch(small.base + PATH, {
        method: 'POST',
        body: BODY,
        headers: { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': forged },
      });
      expect(res.status).toBe(401);
    }
    expect((await post(small, PATH, BODY, 'application/json')).status).toBe(200);
    await small.close();
  });
  it('counts per key as well: one key cannot use up the budget of another', async () => {
    const many = Array.from({ length: 20 }, (_, i) => ({
      ...SERVICES[0]!,
      id: `s${i}`,
      minIntervalMs: 1000,
    }));
    const m = await start({ services: many });
    const go = (i: number, key: TestKey, kid: string) => {
      const path = `/v1/stamp/s${i % 20}`;
      return fetch(m.base + path, {
        method: 'POST',
        body: BODY,
        headers: {
          'Content-Type': 'application/json',
          'X-Zeitstempel-Auth': m.sign(path, new TextEncoder().encode(BODY), { key, kid }),
        },
      });
    };
    for (let i = 0; i < RELAY_LIMITS.perMinutePerKey; i += 1) {
      expect((await go(i, KEY_A, 'app-a')).status, `a ${i}`).toBe(200);
    }
    const over = await go(RELAY_LIMITS.perMinutePerKey, KEY_A, 'app-a');
    expect(over.status).toBe(429);
    expect(Number(over.headers.get('retry-after'))).toBeGreaterThan(0);
    expect((await go(0, KEY_B, 'app-b')).status).toBe(200);
    m.clock.now += RELAY_LIMITS.windowMs;
    expect((await go(1, KEY_A, 'app-a')).status).toBe(200);
    await m.close();
  });
  it('keeps the global limit on top of the per-key limit (four keys: 4 x 20 > 60)', async () => {
    const four = [KEY_A, KEY_B, makeTestKey('app-c'), makeTestKey('app-d')];
    const m = await start({
      services: MANY,
      keys: four.map((k) => ({ id: k.id, publicKey: k.publicKey })),
    });
    const statuses: number[] = [];
    for (let i = 0; i < RELAY_LIMITS.perMinuteTotal + 4; i += 1) {
      const key = four[i % 4]!;
      const path = `/v1/stamp/s${i % 20}`;
      const res = await fetch(m.base + path, {
        method: 'POST',
        body: BODY,
        headers: {
          'Content-Type': 'application/json',
          'X-Zeitstempel-Auth': m.sign(path, new TextEncoder().encode(BODY), {
            key,
            kid: key.id,
          }),
        },
      });
      statuses.push(res.status);
    }
    expect(RELAY_LIMITS.perMinutePerKey * 3).toBeLessThanOrEqual(RELAY_LIMITS.perMinuteTotal);
    expect(statuses.filter((s) => s === 200)).toHaveLength(RELAY_LIMITS.perMinuteTotal);
    expect(statuses.filter((s) => s === 429)).toHaveLength(4);
    await m.close();
  });
  it('lets three keys use up the total, so that a fourth is locked out until the window moves (documented)', async () => {
    const three = [KEY_A, KEY_B, makeTestKey('app-c'), makeTestKey('app-d')];
    const m = await start({
      services: MANY,
      keys: three.map((k) => ({ id: k.id, publicKey: k.publicKey })),
    });
    const go = (i: number, key: TestKey) => {
      const path = `/v1/stamp/s${i % 20}`;
      return fetch(m.base + path, {
        method: 'POST',
        body: BODY,
        headers: {
          'Content-Type': 'application/json',
          'X-Zeitstempel-Auth': m.sign(path, bytesOf(BODY), { key, kid: key.id }),
        },
      });
    };
    for (let i = 0; i < 60; i += 1) expect((await go(i, three[i % 3]!)).status).toBe(200);
    expect((await go(0, three[3]!)).status).toBe(429); // key d has not stamped at all
    await m.close();
  });
  it('refuses the twin signature (r, n - s) of an accepted request as a replay', async () => {
    const body = bytesOf(BODY);
    const t = secondsNow();
    const message = authMessage('POST', PATH, t, body);
    const sig = nodeSignature(KEY_A, message);
    const twin = twinSignature(sig);
    // the twin is a valid signature of the very same message: that is why the cache must not use signatures
    expect(twin.equals(sig)).toBe(false);
    expect(
      verify(
        'sha256',
        Buffer.from(message),
        { key: KEY_A.object, dsaEncoding: 'ieee-p1363' },
        twin,
      ),
    ).toBe(true);
    const header = (b: Buffer) => `v2.app-a.${t}.${b.toString('base64url')}`;
    expect((await withHeader(header(sig))).status).toBe(200);
    h.calls.length = 0;
    await unauthorized(await withHeader(header(twin)));
    expect(h.stats().stamped).toBe(1);
  });
  it('refuses the original signature after its twin was accepted', async () => {
    const body = bytesOf(BODY);
    const t = secondsNow() - 1;
    const sig = nodeSignature(KEY_A, authMessage('POST', PATH, t, body));
    const header = (b: Buffer) => `v2.app-a.${t}.${b.toString('base64url')}`;
    expect((await withHeader(header(twinSignature(sig)))).status).toBe(200);
    h.calls.length = 0;
    await unauthorized(await withHeader(header(sig)));
  });
  it('dies on a replay before the budget: 401, the budget and the stamp count stay, whatever Content-Type or body check would follow', async () => {
    const m = await start({ services: MANY });
    const path = '/v1/stamp/s0';
    const body = bytesOf(BODY);
    const header = m.sign(path, body, { ts: Math.floor(m.clock.now / 1000) });
    const go = (type: string | null, h2: string) =>
      fetch(m.base + path, {
        method: 'POST',
        body: new Uint8Array(body),
        headers: { ...(type === null ? {} : { 'Content-Type': type }), 'X-Zeitstempel-Auth': h2 },
      });
    expect((await go('application/json', header)).status).toBe(200);
    // as JSON it would be fine, as raw bytes it is no 32-byte hash (400), as text it is a 415: all 401
    const types = ['application/json', 'application/octet-stream', 'text/plain', null];
    let replays = 0;
    for (let round = 0; round < 12; round += 1) {
      for (const type of types) {
        const res = await go(type, header);
        expect([res.status, await res.json()], String(type)).toEqual([
          401,
          { error: 'unauthorized' },
        ]);
        replays += 1;
      }
    }
    expect(m.calls).toHaveLength(1);
    expect(m.stats()).toEqual({ stamped: 1, refused: { unauthorized: replays } });
    // the budget of the key is still 19 requests of 20: exactly 19 more are served, the 20th is refused
    for (let i = 1; i < RELAY_LIMITS.perMinutePerKey; i += 1) {
      expect(
        (await post(m, `/v1/stamp/s${i}`, BODY, 'application/json')).status,
        `fresh ${i}`,
      ).toBe(200);
    }
    expect((await post(m, '/v1/stamp/s0', BODY, 'application/json')).status).toBe(429);
    expect(m.stats().stamped).toBe(RELAY_LIMITS.perMinutePerKey);
    await m.close();
  });
  it('never lets a 429 caused by the replay cache spend budget: another key still has the service budget', async () => {
    // one service with 6 requests per minute; replay cache of 8 entries, so 4 per key
    const six = [{ ...SERVICES[0]!, id: 's0', minIntervalMs: 10_000 }];
    const m = await start({ services: six, authReplayEntries: 8 });
    const path = '/v1/stamp/s0';
    // the stand-in service answers for one hash only: requests differ in their second, not their body
    const go = (i: number, key: TestKey) =>
      fetch(m.base + path, {
        method: 'POST',
        body: BODY,
        headers: {
          'Content-Type': 'application/json',
          'X-Zeitstempel-Auth': m.sign(path, bytesOf(BODY), {
            key,
            kid: key.id,
            ts: Math.floor(m.clock.now / 1000) + i,
          }),
        },
      });
    for (let i = 0; i < 4; i += 1) expect((await go(i, KEY_A)).status).toBe(200); // key A holds its share
    for (let i = 4; i < 14; i += 1) {
      const res = await go(i, KEY_A);
      expect(res.status, `a ${i}`).toBe(429);
      expect(Number(res.headers.get('retry-after'))).toBeGreaterThan(0);
    }
    expect(m.stats().stamped).toBe(4);
    // 4 of the 6 requests of the service are spent; the ten refusals cost nothing: key B gets the last two
    expect((await go(20, KEY_B)).status).toBe(200);
    expect((await go(21, KEY_B)).status).toBe(200);
    expect((await go(22, KEY_B)).status).toBe(429); // now it is really spent
    await m.close();
  });
  it('tells the longest wait of all limits that apply (key, service, total, replay cache)', async () => {
    // key A: 1 request at t, 9 at t+1..t+9, 4 on s0 at t+10..t+13 (s0 is then full), 6 more up to 20
    const services = MANY.map((s, i) => (i === 0 ? { ...s, minIntervalMs: 15_000 } : s));
    const m = await start({ services });
    const t0 = m.clock.now;
    const at = (sec: number) => (m.clock.now = t0 + sec * 1000);
    const go = async (i: number) => {
      const path = `/v1/stamp/s${i}`;
      return fetch(m.base + path, {
        method: 'POST',
        body: BODY,
        headers: {
          'Content-Type': 'application/json',
          'X-Zeitstempel-Auth': m.sign(path, bytesOf(BODY), { ts: Math.floor(m.clock.now / 1000) }),
        },
      });
    };
    at(0);
    expect((await go(1)).status).toBe(200);
    for (let s = 1; s <= 9; s += 1) {
      at(s);
      expect((await go(2)).status).toBe(200);
    }
    for (let s = 10; s <= 13; s += 1) {
      at(s);
      expect((await go(0)).status).toBe(200);
    }
    for (let s = 14; s <= 19; s += 1) {
      at(s);
      expect((await go(3)).status).toBe(200);
    }
    at(30);
    const refused = await go(0);
    expect(refused.status).toBe(429);
    // the key could stamp again at t+30 (its oldest request is from t), but s0 only at t+50 (its oldest
    // is from t+10): the answer must say 40, not 30
    expect(refused.headers.get('retry-after')).toBe('40');
    at(30 + 40);
    expect((await go(0)).status).toBe(200);
    await m.close();
  });
  it('tells the replay cache wait when it is longer than the budget wait', async () => {
    // one request per minute for the service; a replay cache that holds one entry per key
    const one = [{ ...SERVICES[0]!, id: 's0', minIntervalMs: 60_000 }];
    const m = await start({ services: one, authReplayEntries: 2 });
    const path = '/v1/stamp/s0';
    const t = Math.floor(m.clock.now / 1000);
    const go = (ts: number) =>
      fetch(m.base + path, {
        method: 'POST',
        body: BODY,
        headers: {
          'Content-Type': 'application/json',
          'X-Zeitstempel-Auth': m.sign(path, bytesOf(BODY), { ts }),
        },
      });
    expect((await go(t + 50)).status).toBe(200); // its entry lives until t + 120 s
    m.clock.now += 10_000;
    const res = await go(t + 60); // budget: 50 s more; cache: 110 s more
    expect(res.status).toBe(429);
    expect(res.headers.get('retry-after')).toBe('110');
    await m.close();
  });
  it('keeps the replay cache within the bound that the limits give, and the default is above it', async () => {
    const lifetimeMs = 2 * RELAY_LIMITS.authWindowSeconds * 1000 + RELAY_LIMITS.requestTimeoutMs;
    const bound = RELAY_LIMITS.perMinuteTotal * Math.ceil(lifetimeMs / RELAY_LIMITS.windowMs);
    expect(bound).toBe(180);
    expect(RELAY_LIMITS.authReplayEntries).toBeGreaterThanOrEqual(bound);
    // the worst case in practice: three batches of 60 stamped seconds ahead, at now = 0, 60 and 120 s;
    // at 130 s the first entries are still alive. With room for exactly `bound` entries all are served,
    // with one entry less the last request of the third batch has to wait.
    const run = async (room: number): Promise<number[]> => {
      const keys = [KEY_A, KEY_B, makeTestKey('app-c')];
      const m = await start({
        services: MANY,
        keys: keys.map((k) => ({ id: k.id, publicKey: k.publicKey })),
        authReplayEntries: room,
      });
      const t0 = m.clock.now;
      const statuses: number[] = [];
      for (let batch = 0; batch < 3; batch += 1) {
        m.clock.now = t0 + batch * 60_000;
        for (let i = 0; i < 60; i += 1) {
          const key = keys[i % 3]!;
          const path = `/v1/stamp/s${i % 20}`;
          const res = await fetch(m.base + path, {
            method: 'POST',
            body: BODY,
            headers: {
              'Content-Type': 'application/json',
              'X-Zeitstempel-Auth': m.sign(path, bytesOf(BODY), {
                key,
                kid: key.id,
                ts: Math.floor(m.clock.now / 1000) + 60,
              }),
            },
          });
          statuses.push(res.status);
        }
      }
      await m.close();
      return statuses;
    };
    const roomy = await run(bound);
    expect(roomy.filter((s) => s !== 200)).toEqual([]);
    const tight = await run(bound - 2); // a share of ceil(0.5 * 178) = 89 per key stays above 60
    expect(tight.filter((s) => s === 429).length).toBeGreaterThan(0);
  }, 60_000);
  it('answers the preflight without authentication and allows the header', async () => {
    const res = await fetch(`${h.base}${PATH}`, { method: 'OPTIONS', headers: { Origin: ORIGIN } });
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-headers')).toContain('X-Zeitstempel-Auth');
    expect(res.headers.get('access-control-allow-headers')).toContain('Content-Type');
  });
  it('needs no authentication for /health and /v1/services (they stamp nothing)', async () => {
    expect((await fetch(`${h.base}/health`)).status).toBe(200);
    expect((await fetch(`${h.base}/v1/services`)).status).toBe(200);
  });
  it('answers an unauthorized call from a foreign origin with 403 first', async () => {
    const res = await fetch(h.base + PATH, {
      method: 'POST',
      body: BODY,
      headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' },
    });
    expect(res.status).toBe(403);
  });
  it('counts failures as refused.unauthorized and keeps no key id, time or signature', async () => {
    const body = new TextEncoder().encode(BODY);
    const header = h.sign(PATH, body, { kid: 'nobody-special' });
    await withHeader(header);
    await withHeader(undefined);
    const stats = h.stats();
    expect(stats).toEqual({ stamped: 0, refused: { unauthorized: 2 } });
    const sig = header.split('.')[3]!;
    expect(JSON.stringify(stats)).not.toContain('nobody-special');
    expect(JSON.stringify(stats)).not.toContain(sig);
  });
  it('writes nothing about a failed or successful call to the console', async () => {
    const spies = [vi.spyOn(console, 'log'), vi.spyOn(console, 'error'), vi.spyOn(console, 'warn')];
    const out = vi.spyOn(process.stdout, 'write');
    const err = vi.spyOn(process.stderr, 'write');
    try {
      await withHeader(undefined);
      await withHeader(h.sign(PATH, new TextEncoder().encode(BODY)));
      for (const s of spies) expect(s).not.toHaveBeenCalled();
      const wrote = [...out.mock.calls, ...err.mock.calls].map((c) => String(c[0])).join('');
      expect(wrote).not.toContain('app-a');
    } finally {
      vi.restoreAllMocks();
    }
  });
  it('writes a request down only after the body and the budget passed: refused tries cannot lock out other keys', async () => {
    const t = Math.floor(NOW / 1000);
    const sendBad = (i: number) => {
      const body = `{"hash":"bad${i}"}`; // a different body, so a different valid signature each time
      return fetch(h.base + PATH, {
        method: 'POST',
        body,
        headers: {
          'Content-Type': 'application/json',
          'X-Zeitstempel-Auth': nodeAuthHeader(KEY_A, 'app-a', 'POST', PATH, t, bytesOf(body)),
        },
      });
    };
    const total = RELAY_LIMITS.authReplayEntries + 104; // more than the whole cache
    let bad = 0;
    for (let from = 0; from < total; from += 50) {
      const batch = await Promise.all(
        Array.from({ length: Math.min(50, total - from) }, (_, k) => sendBad(from + k)),
      );
      for (const res of batch) if (res.status === 400) bad += 1;
    }
    expect(bad).toBe(total);
    // key B (and key A itself) can still be served
    expect((await post(h, PATH, BODY, 'application/json')).status).toBe(200);
    const b = await post(h, PATH, BODY, 'application/json', {
      'X-Zeitstempel-Auth': h.sign(PATH, bytesOf(BODY), { key: KEY_B, kid: 'app-b', ts: t + 1 }),
    });
    expect(b.status).toBe(200);
  }, 60_000);
  it('does not remember a request the rate limit refused: the same header works after the wait', async () => {
    const one = [{ ...SERVICES[0]!, minIntervalMs: 60_000 }]; // one request per minute
    const m = await start({ services: one });
    const body = bytesOf(BODY);
    const t = Math.floor(m.clock.now / 1000);
    const first = m.sign(PATH, body, { ts: t });
    const second = m.sign(PATH, body, { ts: t + 30 }); // stays inside the window for a minute
    const go = (header: string) =>
      fetch(m.base + PATH, {
        method: 'POST',
        body: BODY,
        headers: { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': header },
      });
    expect((await go(first)).status).toBe(200);
    expect((await go(second)).status).toBe(429);
    m.clock.now += RELAY_LIMITS.windowMs; // the budget is free again, `second` is still in its window
    expect((await go(second)).status).toBe(200); // not a replay: the refused try wrote nothing down
    await m.close();
  });
  it('rechecks the window after the body: a head at +59.9 s with a body at +61 s is refused', async () => {
    const body = bytesOf(BODY);
    const t = Math.floor(NOW / 1000);
    const header = h.sign(PATH, body, { ts: t - 60 }); // edge of the window at NOW
    h.clock.now = NOW - 100 + 0; // 59.9 s after the stamped second: the head passes
    const port = Number(new URL(h.base).port);
    const status = await new Promise<number>((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port,
          path: PATH,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': String(body.length),
            'X-Zeitstempel-Auth': header,
          },
        },
        (res) => {
          res.resume();
          res.on('end', () => resolve(res.statusCode ?? 0));
        },
      );
      req.on('error', reject);
      req.flushHeaders();
      setTimeout(() => {
        h.clock.now = NOW + 1_000; // the body arrives 61 s after the stamped second
        req.end(Buffer.from(body));
      }, 100);
    });
    expect(status).toBe(401);
    expect(h.calls).toHaveLength(0);
  });
  it('keeps an entry until ts + window + request timeout, not only until the window ends', async () => {
    const small = await start({ authReplayEntries: 1 });
    const body = bytesOf(BODY);
    const t = Math.floor(small.clock.now / 1000);
    const go = (ts: number) =>
      fetch(small.base + PATH, {
        method: 'POST',
        body: BODY,
        headers: {
          'Content-Type': 'application/json',
          'X-Zeitstempel-Auth': small.sign(PATH, body, { ts }),
        },
      });
    expect((await go(t)).status).toBe(200);
    small.clock.now += 61_000; // the window of the first one is over, its entry is not
    const res = await go(t + 61);
    expect(res.status).toBe(429);
    expect(res.headers.get('retry-after')).toBe('9'); // 70 s after t
    small.clock.now += 10_000; // the entry lives while `until >= now`, so one more second
    expect((await go(t + 71)).status).toBe(200);
    await small.close();
  });
  it('lets one key hold only its share of the replay cache', async () => {
    const small = await start({ authReplayEntries: 4 }); // a share of 0.5: two entries per key
    const body = bytesOf(BODY);
    const t = Math.floor(small.clock.now / 1000);
    const go = (ts: number, other = false) =>
      fetch(small.base + PATH, {
        method: 'POST',
        body: BODY,
        headers: {
          'Content-Type': 'application/json',
          'X-Zeitstempel-Auth': small.sign(
            PATH,
            body,
            other ? { ts, key: KEY_B, kid: 'app-b' } : { ts },
          ),
        },
      });
    expect((await go(t)).status).toBe(200);
    expect((await go(t + 1)).status).toBe(200);
    expect((await go(t + 2)).status).toBe(429); // key A holds its share
    expect((await go(t, true)).status).toBe(200); // key B is not locked out
    await small.close();
  });
  it('answers an unknown key id with 401 even when the signature is valid for a known key', async () => {
    // The signed message does not contain the key id: key A's valid signature under the id of nobody
    // is checked against the dummy key and refused; under the id of key B it is checked against B.
    const body = bytesOf(BODY);
    const t = secondsNow();
    const good = nodeAuthHeader(KEY_A, 'app-a', 'POST', PATH, t, body);
    const sig = good.split('.')[3]!;
    await unauthorized(await withHeader(`v2.nobody.${t}.${sig}`));
    await unauthorized(await withHeader(`v2.app-b.${t}.${sig}`));
    expect((await withHeader(good)).status).toBe(200); // the original was not harmed by the tries
  });
  it('answers 401 without a header for a known service, 404 for an unknown one (public things only)', async () => {
    await unauthorized(await withHeader(undefined));
    const res = await withHeader(undefined, BODY, '/v1/stamp/nope');
    expect(res.status).toBe(404);
  });
  it('refuses a head signed before the process started, also after a restart with the same clock', async () => {
    const body = bytesOf(BODY);
    const old = h.sign(PATH, body, { ts: secondsNow() - 10 }); // within the window of the first process
    // not possible for the first process either: it started at NOW, 10 s later than the head
    await unauthorized(await withHeader(old));
    const first = await start({ clockStart: NOW - 30_000 });
    const head = first.sign(PATH, body, { ts: secondsNow() - 10 });
    const ok = await post(first, PATH, BODY, 'application/json', { 'X-Zeitstempel-Auth': head });
    expect(ok.status).toBe(200);
    // restart: a new instance, later clock; the replay cache is empty, but the old head is refused
    const second = await start({ clockStart: NOW });
    const again = await post(second, PATH, BODY, 'application/json', {
      'X-Zeitstempel-Auth': head,
    });
    expect(again.status).toBe(401);
    expect(await again.json()).toEqual({ error: 'unauthorized' });
    expect(second.calls).toHaveLength(0);
    // one second before the start is still fine, two are not
    const edge = (ts: number) =>
      post(second, PATH, BODY, 'application/json', {
        'X-Zeitstempel-Auth': second.sign(PATH, body, { ts }),
      });
    expect((await edge(secondsNow() - 2)).status).toBe(401);
    expect((await edge(secondsNow() - 1)).status).toBe(200);
    await first.close();
    await second.close();
  });
  it('does one signature verification for every well-formed head: unknown id, wrong signature, valid', async () => {
    let count = 0;
    const counting = await start({
      verifySignature: ((...args: Parameters<typeof nodeVerify>) => {
        count += 1;
        return nodeVerify(...args);
      }) as typeof nodeVerify,
    });
    const body = bytesOf(BODY);
    const go = (header: string) =>
      post(counting, PATH, BODY, 'application/json', { 'X-Zeitstempel-Auth': header });
    expect((await go(counting.sign(PATH, body, { kid: 'nobody' }))).status).toBe(401);
    expect(count).toBe(1);
    expect((await go(counting.sign(PATH, bytesOf('other')))).status).toBe(401); // wrong signature
    expect(count).toBe(2);
    expect((await go(counting.sign(PATH, body))).status).toBe(200);
    expect(count).toBe(3);
    await counting.close();
  });
  it('refuses a request target that is not the canonical path, so the signature binds the path literally', async () => {
    const body = bytesOf(BODY);
    const headers = (): Record<string, string> => ({
      'Content-Type': 'application/json',
      'X-Zeitstempel-Auth': h.sign(PATH, body),
    });
    for (const target of [
      '/v1/stamp/./freetsa',
      '/v1/stamp/x/../freetsa',
      '/v1/stamp\\freetsa',
      '/v1\\stamp/freetsa',
      `http://relay.invalid${PATH}`,
      `${PATH}?`,
    ]) {
      const res = await rawRequest(h, 'POST', target, headers(), BODY);
      expect(res.status, target).toBe(400);
      expect(JSON.parse(res.body).error, target).toMatch(/^(bad-request|no-query)$/);
    }
    expect(h.calls).toHaveLength(0);
    // the same head with the canonical target still works (it was never admitted)
    const ok = await rawRequest(h, 'POST', PATH, headers(), BODY);
    expect(ok.status).toBe(200);
    expect(JSON.parse((await rawRequest(h, 'GET', '/health/.', {}, '')).body)).toEqual({
      error: 'bad-request',
    });
  });
  it('throws at the start when two keys share an id', async () => {
    const dup: RelayKey[] = [KEYS[0]!, { id: KEYS[0]!.id, publicKey: KEYS[1]!.publicKey }];
    await expect(start({ keys: dup })).rejects.toThrow(/unique/);
  });
  it('is off only when expressly started without keys', async () => {
    const open = await start({ keys: 'off' });
    const res = await fetch(open.base + PATH, {
      method: 'POST',
      body: BODY,
      headers: { 'Content-Type': 'application/json' },
    });
    expect(res.status).toBe(200);
    await open.close();
  });
});
