import { randomBytes } from 'node:crypto';
import { fastMonotonic } from './fast-mono.ts';
import type { AddressInfo } from 'node:net';
import { fromBase64Url, readServices, toBase64Url, verifyBatchedTimestamp } from '../src/index.ts';
import { isAuthHeaderName } from '../src/lib/services.ts';
import {
  credentialHeader,
  credentialIdentity,
  credentialsFromClient,
  credentialsFromText,
  type UpstreamCredentials,
} from '../relay/credentials.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import { readConfig, readUpstreamAuth, upstreamAuthVariable } from '../relay/main.ts';
import { createRelay, type RelayOptions, type RelayService } from '../relay/relay.ts';
import { createRelayServer } from '../relay/server.ts';
import { UpstreamError, type Upstream } from '../relay/upstream.ts';
import type { RelayKey } from '../relay/keys.ts';
import { makeTestKey, nodeAuthHeader } from './auth-helpers.ts';
import { sha256 } from './helpers.ts';
import { build, int, seq } from './token-builder.ts';
import { children, integerBytes, octets, parseDer } from '../src/lib/der.ts';

const SIGNER = build();
const ORIGIN = 'https://app.example';
const NOW = Date.parse('2026-11-23T13:06:00Z');
const KEY_A = makeTestKey('app-a');
const KEY_B = makeTestKey('app-b');
const KEY_S = makeTestKey('app-solo');
const KEYS: RelayKey[] = [
  { id: KEY_A.id, publicKey: KEY_A.publicKey },
  { id: KEY_B.id, publicKey: KEY_B.publicKey },
  { id: KEY_S.id, publicKey: KEY_S.publicKey, solo: true },
];
const MARKER = 'MARKER-9d41c7e2-secret';

const base = {
  hash: 'sha256' as const,
  anchors: [],
  anchorPems: [SIGNER.caPem],
  qualified: false,
  minIntervalMs: 5000,
  intendedUse: 'test',
  terms: 'test',
};
const SERVICES: RelayService[] = [
  { ...base, id: 'free', name: 'Free', url: 'https://free.example/tsr' },
  {
    ...base,
    id: 'paid-relay',
    name: 'Paid, credentials of the relay',
    url: 'https://relay-creds.example/tsr',
    auth: { kind: 'basic', source: 'relay' },
  },
  {
    ...base,
    id: 'paid-client',
    name: 'Paid, bearer from the client',
    url: 'https://client-creds.example/tsr',
    auth: { kind: 'bearer', source: 'client' },
  },
  {
    ...base,
    id: 'paid-basic',
    name: 'Paid, basic from the client',
    url: 'https://basic-creds.example/tsr',
    auth: { kind: 'basic', source: 'client' },
  },
  {
    ...base,
    id: 'paid-either',
    name: 'Paid, header from either',
    url: 'https://either-creds.example/tsr',
    auth: { kind: 'header', header: 'X-Api-Key', source: 'either' },
  },
];
const RELAY_CREDS = new Map<string, UpstreamCredentials>([
  ['paid-relay', { kind: 'basic', user: 'relay-user', password: 'relay-pass' }],
  ['paid-either', { kind: 'header', header: 'X-Api-Key', token: 'relay-token' }],
]);

const genTimeText = (ms: number) =>
  new Date(ms)
    .toISOString()
    .replace(/[-:T]/g, '')
    .replace(/\.\d+Z$/, 'Z');

function replyFor(request: Uint8Array, atMs: number): Uint8Array {
  const parts = children(parseDer(request));
  const hash = octets(children(parts[1]!)[1]!);
  const nonceBytes = integerBytes(parts[2]!);
  const made = build({ keys: SIGNER.keys, hash, nonceBytes, genTime: genTimeText(atMs) });
  return seq(seq(int(0)), made.token);
}
const imprintOf = (request: Uint8Array): Uint8Array =>
  octets(children(children(parseDer(request))[1]!)[1]!);

interface Call {
  url: string;
  /** The third argument as the stub saw it (`undefined`: the relay passed none). */
  creds: UpstreamCredentials | undefined;
  imprint: Uint8Array;
  /** The real time of the call (the clock of the relay is a fake one in these tests). */
  at: number;
}
interface Harness {
  base: string;
  calls: Call[];
  clock: { now: number };
  relay: ReturnType<typeof createRelayServer>['relay'];
  post: (
    id: string,
    body: unknown,
    over?: { key?: typeof KEY_A; signedText?: string; mode?: 'json' | 'bytes' },
  ) => Promise<Response>;
  close: () => Promise<void>;
}

async function start(
  over: {
    services?: RelayService[];
    batch?: { windowMs: number; max: number };
    upstream?: Upstream;
    upstreamAuth?: Map<string, UpstreamCredentials>;
    upstreamIdentities?: number;
    maxWaitMs?: number;
  } = {},
): Promise<Harness> {
  const calls: Call[] = [];
  const clock = { now: NOW };
  const stub: Upstream = async (target, body, creds) => {
    calls.push({ url: target.url, creds, imprint: imprintOf(body), at: Date.now() });
    return {
      status: 200,
      contentType: 'application/timestamp-reply',
      body: replyFor(body, clock.now),
    };
  };
  const options: RelayOptions = {
    services: over.services ?? SERVICES,
    origins: [ORIGIN],
    allowPlainHttp: false,
    upstream: over.upstream ?? stub,
    random: (n) => new Uint8Array(randomBytes(n)),
    now: () => clock.now,
    // single operation: the minimum distance has its own tests (single-spacing.test.ts); collecting operation: the planner
    // runs on the monotonic clock, which here follows the clock of the test (it moves it to let budgets expire)
    monotonicNow: over.batch ? () => clock.now : fastMonotonic(),
    keys: KEYS,
    upstreamAuth: over.upstreamAuth ?? RELAY_CREDS,
    ...(over.batch ? { batch: over.batch } : {}),
    ...(over.upstreamIdentities === undefined
      ? {}
      : { upstreamIdentities: over.upstreamIdentities }),
    ...(over.maxWaitMs === undefined ? {} : { maxWaitMs: over.maxWaitMs }),
  };
  const { server, relay } = createRelayServer(options);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  let n = 0;
  return {
    base,
    calls,
    clock,
    relay,
    post: (id, body, o = {}) => {
      const path = `/v1/stamp/${id}`;
      const text = typeof body === 'string' ? body : JSON.stringify(body);
      const key = o.key ?? KEY_A;
      const head = nodeAuthHeader(
        key,
        key.id,
        'POST',
        path,
        Math.floor(clock.now / 1000) + (n++ % 30),
        new TextEncoder().encode(o.signedText ?? text),
      );
      return fetch(base + path, {
        method: 'POST',
        body: text,
        headers: { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': head },
      });
    },
    close: () =>
      new Promise((r) => {
        relay.close();
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}

const without = (...ids: string[]) => SERVICES.filter((s) => !ids.includes(s.id));
const hashText = (tag: string) => toBase64Url(sha256(tag));
const withUpstream = (tag: string, upstream: unknown, extra: object = {}) => ({
  hash: hashText(tag),
  ...extra,
  upstream,
});
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('services.json: the auth member is read strictly', () => {
  const entry = (auth?: unknown, url = 'https://paid.example/tsr') => ({
    id: 'paid',
    name: 'Paid',
    url,
    hash: 'sha256',
    anchors: ['anchors/x.pem'],
    qualified: true,
    minIntervalMs: 5000,
    intendedUse: 'x',
    terms: 'x',
    ...(auth === undefined ? {} : { auth }),
  });
  const read = (auth?: unknown, url?: string) =>
    readServices({ version: 1, services: [entry(auth, url)] });

  it('no auth member is fine and stays absent; none is accepted as written', () => {
    const r = read();
    expect(r.ok).toBe(true);
    if (r.ok) expect('auth' in r.value[0]!).toBe(false);
    const n = read({ kind: 'none' });
    expect(n.ok && n.value[0]!.auth).toEqual({ kind: 'none' });
  });
  it('the three kinds with each source', () => {
    for (const source of ['relay', 'client', 'either']) {
      for (const kind of ['basic', 'bearer']) {
        expect(read({ kind, source }).ok, `${kind}/${source}`).toBe(true);
      }
      const h = read({ kind: 'header', header: 'X-Api-Key', source });
      expect(h.ok && h.value[0]!.auth).toEqual({ kind: 'header', header: 'X-Api-Key', source });
    }
  });
  it('refuses unknown members and values, missing members and wrong types (hostile input)', () => {
    const hostile: unknown[] = [
      null,
      undefined,
      'basic',
      7,
      [],
      {},
      { kind: 'none', source: 'relay' }, // none takes no source
      { kind: 'none', extra: 1 },
      { kind: 'basic' },
      { kind: 'basic', source: 'nobody' },
      { kind: 'basic', source: 'relay', extra: 1 },
      { kind: 'basic', source: 'relay', header: 'X-Api-Key' }, // header only for kind header
      { kind: 'bearer', source: 'relay', header: 'X-Api-Key' },
      { kind: 'Basic', source: 'relay' },
      { kind: 'digest', source: 'relay' },
      { kind: 'header', source: 'relay' }, // header name missing
      { kind: 'header', header: 7, source: 'relay' },
      { kind: 'header', header: '', source: 'relay' },
      { kind: 'header', header: 'X'.repeat(41), source: 'relay' },
      { kind: 'header', header: 'X Api', source: 'relay' },
      { kind: 'header', header: 'X-Api:', source: 'relay' },
      { kind: 'header', header: 'X-Api\r\nEvil: 1', source: 'relay' },
      { kind: 'header', header: 'X-Api-Schlüssel', source: 'relay' },
      { kind: 'header', header: 'X-Api-Key', source: 'relay', kind2: 1 },
      JSON.parse('{"kind":"basic","source":"relay","__proto__":{"kind":"none"}}'), // an own member of that name
    ];
    for (const auth of hostile) {
      const r = readServices({ version: 1, services: [{ ...entry(), auth }] });
      expect(r, JSON.stringify(auth)).toEqual({ ok: false, reason: 'bad-services' });
    }
  });
  it('refuses forbidden and hop-by-hop header names, in any letter case', () => {
    for (const name of [
      'Authorization',
      'authorization',
      'Host',
      'Content-Type',
      'content-length',
      'Transfer-Encoding',
      'Connection',
      'Upgrade',
      'TE',
      'Cookie',
      'Set-Cookie',
      'Proxy-Authorization',
      'Proxy-Anything',
      'Sec-Fetch-Mode',
      'If-Match',
      'X-Forwarded-For',
      'Access-Control-Allow-Origin',
      'X-Zeitstempel-Auth',
      'User-Agent',
      'Accept',
      'Date',
      'Origin',
    ]) {
      expect(isAuthHeaderName(name), name).toBe(false);
      expect(read({ kind: 'header', header: name, source: 'relay' }).ok, name).toBe(false);
    }
    for (const name of ['X-Api-Key', 'api-key', 'Ocp-Apim-Subscription-Key', 'X-Auth-Token']) {
      expect(isAuthHeaderName(name), name).toBe(true);
    }
  });
  it('credentials only for an https address (basic, bearer, header); none is fine over http', () => {
    const http = 'http://plain.example/tsr';
    expect(read({ kind: 'basic', source: 'relay' }, http).ok).toBe(false);
    expect(read({ kind: 'bearer', source: 'client' }, http).ok).toBe(false);
    expect(read({ kind: 'header', header: 'X-Api-Key', source: 'either' }, http).ok).toBe(false);
    expect(read({ kind: 'none' }, http).ok).toBe(true);
    expect(read(undefined, http).ok).toBe(true);
  });
  it('a getter or proxy on auth gives bad-services, never a throw', () => {
    const bad = { ...entry() } as Record<string, unknown>;
    Object.defineProperty(bad, 'auth', {
      enumerable: true,
      get() {
        throw new Error('boom');
      },
    });
    expect(readServices({ version: 1, services: [bad] })).toEqual({
      ok: false,
      reason: 'bad-services',
    });
  });
});

describe('credentials: strict reading, the header, the identity', () => {
  const basic = { kind: 'basic', source: 'client' } as const;
  const bearer = { kind: 'bearer', source: 'client' } as const;
  const header = { kind: 'header', header: 'X-Api-Key', source: 'client' } as const;

  it('accepts the documented forms', () => {
    expect(credentialsFromClient(basic, { user: 'u', password: 'p w"\\' })).toEqual({
      kind: 'basic',
      user: 'u',
      password: 'p w"\\',
    });
    expect(credentialsFromClient(bearer, { token: 'abc.DEF-123_~+/=' })).toEqual({
      kind: 'bearer',
      token: 'abc.DEF-123_~+/=',
    });
    expect(credentialsFromClient(header, { token: 'k' })).toEqual({
      kind: 'header',
      header: 'X-Api-Key',
      token: 'k',
    });
  });
  it('refuses control characters, CR, LF, NUL, DEL, non-ASCII, empty and too long values', () => {
    const bad = [
      '',
      'a\r\nX-Evil: 1',
      'a\nb',
      'a\rb',
      'a\0b',
      'a\x7fb',
      'a\tb',
      'äö',
      'a b',
      '\u0085',
    ];
    for (const v of bad) {
      expect(credentialsFromClient(bearer, { token: v }), JSON.stringify(v)).toBeNull();
      expect(credentialsFromClient(header, { token: v }), JSON.stringify(v)).toBeNull();
      expect(
        credentialsFromClient(basic, { user: v, password: 'p' }),
        JSON.stringify(v),
      ).toBeNull();
      expect(
        credentialsFromClient(basic, { user: 'u', password: v }),
        JSON.stringify(v),
      ).toBeNull();
    }
    expect(credentialsFromClient(bearer, { token: 'a b' })).toBeNull(); // no space in a token
    expect(credentialsFromClient(bearer, { token: 'a"b' })).toBeNull();
    expect(credentialsFromClient(bearer, { token: 'a\\b' })).toBeNull();
    const L = RELAY_LIMITS;
    expect(credentialsFromClient(bearer, { token: 'x'.repeat(L.upstreamTokenMax) })).not.toBeNull();
    expect(credentialsFromClient(bearer, { token: 'x'.repeat(L.upstreamTokenMax + 1) })).toBeNull();
    expect(
      credentialsFromClient(basic, { user: 'u'.repeat(L.upstreamUserMax), password: 'p' }),
    ).not.toBeNull();
    expect(
      credentialsFromClient(basic, { user: 'u'.repeat(L.upstreamUserMax + 1), password: 'p' }),
    ).toBeNull();
    expect(
      credentialsFromClient(basic, { user: 'u', password: 'p'.repeat(L.upstreamPasswordMax) }),
    ).not.toBeNull();
    expect(
      credentialsFromClient(basic, { user: 'u', password: 'p'.repeat(L.upstreamPasswordMax + 1) }),
    ).toBeNull();
  });
  it('a colon in the user name of basic is refused (RFC 7617), a colon in the password is fine', () => {
    expect(credentialsFromClient(basic, { user: 'a:b', password: 'p' })).toBeNull();
    expect(credentialsFromClient(basic, { user: ':', password: 'p' })).toBeNull();
    expect(credentialsFromClient(basic, { user: 'ab', password: 'p:q:r' })).not.toBeNull();
  });
  it('refuses wrong shapes: other members, missing members, wrong types, arrays, classes, null', () => {
    const shapes: unknown[] = [
      undefined,
      null,
      'tok',
      7,
      true,
      [],
      ['tok'],
      {},
      { tok: 'x' },
      { token: 'x', extra: 1 },
      { token: 7 },
      { token: ['x'] },
      { token: { toString: () => 'x' } },
      { token: null },
      Object.create({ token: 'x' }), // inherited, not own
      new (class T {
        token = 'x';
      })(),
      new Map([['token', 'x']]),
    ];
    for (const v of shapes) {
      expect(credentialsFromClient(bearer, v), String(v)).toBeNull();
      expect(credentialsFromClient(header, v), String(v)).toBeNull();
    }
    const basics: unknown[] = [
      { user: 'u' },
      { password: 'p' },
      { user: 'u', password: 'p', extra: 1 },
      { user: 'u', password: 7 },
      { user: 7, password: 'p' },
      { token: 'x' },
      { user: ['u'], password: 'p' },
    ];
    for (const v of basics) expect(credentialsFromClient(basic, v), JSON.stringify(v)).toBeNull();
    // none takes nothing at all
    expect(credentialsFromClient({ kind: 'none' }, { token: 'x' })).toBeNull();
  });
  it('the header: Basic is base64 of user:password, Bearer, a named header; malformed credentials never produce one', () => {
    expect(credentialHeader({ kind: 'basic', user: 'Aladdin', password: 'open sesame' })).toEqual([
      'Authorization',
      'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==', // the example of RFC 7617
    ]);
    expect(credentialHeader({ kind: 'bearer', token: 'tok' })).toEqual([
      'Authorization',
      'Bearer tok',
    ]);
    expect(credentialHeader({ kind: 'header', header: 'X-Api-Key', token: 'tok' })).toEqual([
      'X-Api-Key',
      'tok',
    ]);
    expect(() => credentialHeader({ kind: 'bearer', token: 'a\r\nB: c' })).toThrow();
    expect(() => credentialHeader({ kind: 'header', header: 'Host', token: 'x' })).toThrow();
    expect(() => credentialHeader({ kind: 'basic', user: 'a:b', password: 'p' })).toThrow();
  });
  it('the identity tells different credentials apart, also at the field borders, and is a digest', () => {
    const id = (c: UpstreamCredentials) => credentialIdentity(c);
    expect(id({ kind: 'basic', user: 'ab', password: 'c' })).not.toBe(
      id({ kind: 'basic', user: 'a', password: 'bc' }),
    );
    expect(id({ kind: 'bearer', token: 'x' })).not.toBe(
      id({ kind: 'header', header: 'H', token: 'x' }),
    );
    expect(id({ kind: 'bearer', token: 'x' })).toBe(id({ kind: 'bearer', token: 'x' }));
    expect(id({ kind: 'bearer', token: 'x' })).toMatch(/^[0-9a-f]{64}$/);
    expect(id({ kind: 'bearer', token: MARKER })).not.toContain(MARKER);
  });
  it('the relay own form: user:password splits at the first colon; a token as it is', () => {
    expect(credentialsFromText(basic, 'u:p:q')).toEqual({
      kind: 'basic',
      user: 'u',
      password: 'p:q',
    });
    expect(credentialsFromText(basic, 'nocolon')).toBeNull();
    expect(credentialsFromText(basic, ':p')).toBeNull();
    expect(credentialsFromText(bearer, 'a b')).toBeNull();
    expect(credentialsFromText(bearer, 'tok')).toEqual({ kind: 'bearer', token: 'tok' });
  });
  it('the largest credentials still fit into the 512 bytes of body that signRelayRequest signs (worst case: every character escaped)', () => {
    const L = RELAY_LIMITS;
    const h = hashText('x');
    const shapes: unknown[] = [
      { user: '"'.repeat(L.upstreamUserMax), password: '\\'.repeat(L.upstreamPasswordMax) },
      { token: '~'.repeat(L.upstreamTokenMax) },
    ];
    for (const upstream of shapes) {
      const text = JSON.stringify({ hash: h, mode: 'solo', upstream });
      expect(new TextEncoder().encode(text).length).toBeLessThanOrEqual(L.bodyBytes);
    }
  });
});

describe('the relay sends the credentials as the service says (stub service)', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('bearer from the client: the stub receives exactly the token, the stamp is a normal 200', async () => {
    h = await start();
    const r = await h.post('paid-client', withUpstream('a', { token: 'client-token' }));
    expect(r.status).toBe(200);
    expect(h.calls).toHaveLength(1);
    expect(h.calls[0]!.creds).toEqual({ kind: 'bearer', token: 'client-token' });
    expect(h.calls[0]!.url).toBe('https://client-creds.example/tsr'); // the address is the file's, nothing else
    expect(Object.keys((await r.json()) as object).sort()).toEqual([
      'accuracyMs',
      'genTime',
      'serial',
      'service',
      'token',
    ]); // no credentials in the answer
  });
  it('basic from the client', async () => {
    h = await start();
    const r = await h.post('paid-basic', withUpstream('a', { user: 'me', password: 'p:w d' }));
    expect(r.status).toBe(200);
    expect(h.calls[0]!.creds).toEqual({ kind: 'basic', user: 'me', password: 'p:w d' });
  });
  it('a header service from the client: the header name comes from the file, never from the client', async () => {
    h = await start({ services: without('paid-relay'), upstreamAuth: new Map() });
    expect((await h.post('paid-either', withUpstream('a', { token: 'k1' }))).status).toBe(200);
    expect(h.calls[0]!.creds).toEqual({ kind: 'header', header: 'X-Api-Key', token: 'k1' });
    // a header name in the body is an unknown member
    const r = await h.post('paid-either', withUpstream('b', { token: 'k', header: 'Host' }));
    expect(r.status).toBe(400);
    expect(await r.json()).toEqual({ error: 'bad-upstream' });
  });
  it('a free service gets no credentials: a body with upstream is 400 and the service is not called', async () => {
    h = await start();
    const ok = await h.post('free', { hash: hashText('a') });
    expect(ok.status).toBe(200);
    expect(h.calls[0]!.creds).toBeUndefined();
    const bad = await h.post('free', withUpstream('b', { token: 'x' }));
    expect(bad.status).toBe(400);
    expect(await bad.json()).toEqual({ error: 'bad-upstream' });
    expect((await h.post('free', withUpstream('c', null))).status).toBe(400);
    expect(h.calls).toHaveLength(1);
  });
  it('the mode may come with upstream (solo, collecting operation): all three members', async () => {
    h = await start({ batch: { windowMs: 50, max: 10 } });
    const r = await h.post('paid-client', withUpstream('a', { token: 't' }, { mode: 'solo' }), {
      key: KEY_S,
    });
    expect(r.status).toBe(200);
    expect(h.calls[0]!.creds).toEqual({ kind: 'bearer', token: 't' });
    expect(h.calls).toHaveLength(1);
  });
});

describe('where the credentials come from: relay, client or either', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('source relay: a client value is 400 bad-upstream (never taken, never used), the relay own are sent', async () => {
    h = await start();
    const r = await h.post('paid-relay', withUpstream('a', { user: 'x', password: 'y' }));
    expect(r.status).toBe(400);
    expect(await r.json()).toEqual({ error: 'bad-upstream' });
    expect(h.calls).toHaveLength(0);
    const ok = await h.post('paid-relay', { hash: hashText('b') });
    expect(ok.status).toBe(200);
    expect(h.calls[0]!.creds).toEqual(RELAY_CREDS.get('paid-relay'));
  });
  it('source client: the value is mandatory; without it 400 bad-upstream and no call', async () => {
    h = await start();
    for (const id of ['paid-client', 'paid-basic']) {
      const r = await h.post(id, { hash: hashText('a') });
      expect(r.status, id).toBe(400);
      expect(await r.json()).toEqual({ error: 'bad-upstream' });
    }
    expect(h.calls).toHaveLength(0);
  });
  it('source either: the client value wins, else the relay own, else 400', async () => {
    h = await start();
    await h.post('paid-either', withUpstream('a', { token: 'from-client' }));
    await h.post('paid-either', { hash: hashText('b') });
    expect(h.calls.map((c) => c.creds)).toEqual([
      { kind: 'header', header: 'X-Api-Key', token: 'from-client' },
      { kind: 'header', header: 'X-Api-Key', token: 'relay-token' },
    ]);
    await h.close();
    h = await start({ services: without('paid-relay'), upstreamAuth: new Map() }); // the relay holds nothing for it
    const none = await h.post('paid-either', { hash: hashText('c') });
    expect(none.status).toBe(400);
    expect(await none.json()).toEqual({ error: 'bad-upstream' });
    expect(h.calls).toHaveLength(0);
  });
  it('raw bytes (no JSON) carry no upstream: fine for a free or relay service, bad-upstream where the client must give one', async () => {
    h = await start();
    let n = 0;
    const raw = (id: string) => {
      const path = `/v1/stamp/${id}`;
      const bytes = sha256(`raw${n}`);
      const head = nodeAuthHeader(
        KEY_A,
        KEY_A.id,
        'POST',
        path,
        Math.floor(NOW / 1000) + n++,
        bytes,
      );
      return fetch(h.base + path, {
        method: 'POST',
        body: Buffer.from(bytes),
        headers: { 'Content-Type': 'application/octet-stream', 'X-Zeitstempel-Auth': head },
      });
    };
    expect((await raw('free')).status).toBe(200);
    expect((await raw('paid-relay')).status).toBe(200);
    expect((await raw('paid-either')).status).toBe(200); // the relay own credentials
    const need = await raw('paid-client');
    expect(need.status).toBe(400);
    expect(await need.json()).toEqual({ error: 'bad-upstream' });
    expect(h.calls.map((c) => c.creds?.kind)).toEqual([undefined, 'basic', 'header']);
  });
});

describe('the credentials are bound by the signature', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('a token changed after signing is 401, and the service is never called', async () => {
    h = await start();
    const signed = JSON.stringify(withUpstream('a', { token: 'signed-token' }));
    const sent = JSON.stringify(withUpstream('a', { token: 'other-token' }));
    const r = await h.post('paid-client', sent, { signedText: signed });
    expect(r.status).toBe(401);
    expect(await r.json()).toEqual({ error: 'unauthorized' });
    expect(h.calls).toHaveLength(0);
  });
  it('upstream added to, or removed from, a signed body is 401', async () => {
    h = await start();
    const plain = JSON.stringify({ hash: hashText('a') });
    const withIt = JSON.stringify(withUpstream('a', { token: 't' }));
    expect((await h.post('paid-either', withIt, { signedText: plain })).status).toBe(401);
    expect((await h.post('paid-either', plain, { signedText: withIt })).status).toBe(401);
    expect(h.calls).toHaveLength(0);
  });
  it('the same signed request twice is a replay (401), also with credentials', async () => {
    h = await start();
    const path = '/v1/stamp/paid-client';
    const text = JSON.stringify(withUpstream('r', { token: 't' }));
    const head = nodeAuthHeader(
      KEY_A,
      KEY_A.id,
      'POST',
      path,
      Math.floor(NOW / 1000),
      new TextEncoder().encode(text),
    );
    const send = () =>
      fetch(h.base + path, {
        method: 'POST',
        body: text,
        headers: { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': head },
      });
    expect((await send()).status).toBe(200);
    expect((await send()).status).toBe(401);
    expect(h.calls).toHaveLength(1);
  });
  it('without a valid key no request is served, whatever it carries (the key stays mandatory)', async () => {
    h = await start();
    const rogue = makeTestKey('app-a'); // same id, another private key
    const r = await h.post('paid-client', withUpstream('a', { token: 't' }), { key: rogue });
    expect(r.status).toBe(401);
    expect(h.calls).toHaveLength(0);
  });
});

describe('hostile upstream members: all 400 bad-upstream, nothing leaves the relay', () => {
  let h: Harness;
  afterEach(() => h.close());
  it('a table of bad values for each kind', async () => {
    h = await start();
    const cases: [string, unknown][] = [
      ['paid-client', { token: 'a\r\nX-Evil: 1' }],
      ['paid-client', { token: 'a\nb' }],
      ['paid-client', { token: 'a b' }],
      ['paid-client', { token: '' }],
      ['paid-client', { token: 'x'.repeat(RELAY_LIMITS.upstreamTokenMax + 1) }],
      ['paid-client', { token: 7 }],
      ['paid-client', { token: 'x', extra: 'y' }],
      ['paid-client', { user: 'u', password: 'p' }], // the other kind
      ['paid-client', 'x'],
      ['paid-client', null],
      ['paid-client', []],
      ['paid-client', {}],
      ['paid-basic', { user: 'a:b', password: 'p' }],
      ['paid-basic', { user: 'a\r\nb', password: 'p' }],
      ['paid-basic', { user: 'u', password: 'p\r\nSet-Cookie: x=1' }],
      ['paid-basic', { user: 'ü', password: 'p' }],
      ['paid-basic', { user: 'u' }],
      ['paid-basic', { token: 'x' }],
      ['paid-either', { token: 'a\u0000b' }],
      ['paid-either', { token: 'ä' }],
    ];
    let n = 0;
    for (const [id, upstream] of cases) {
      const r = await h.post(id, withUpstream(`h${n++}`, upstream));
      expect(r.status, `${id} ${JSON.stringify(upstream)}`).toBe(400);
      expect(await r.json()).toEqual({ error: 'bad-upstream' });
    }
    expect(h.calls).toHaveLength(0);
    // and the counters hold the code only
    expect(h.relay.stats().refused).toEqual({ 'bad-upstream': cases.length });
  });
  it('an upstream that would break the JSON or hides an inherited member is read as plain data', async () => {
    h = await start();
    const text = `{"hash":"${hashText('a')}","upstream":{"token":"t","__proto__":{"token":"x"}}}`;
    const r = await h.post('paid-client', text);
    expect(r.status).toBe(400);
    const dup = `{"hash":"${hashText('b')}","upstream":{"token":"first","token":"second"}}`;
    const r2 = await h.post('paid-client', dup);
    expect(r2.status).toBe(200); // JSON takes the last one: the one value that was signed and read
    expect(h.calls[0]!.creds).toEqual({ kind: 'bearer', token: 'second' });
  });
  it('a bad hash or mode is still the first complaint; upstream follows', async () => {
    h = await start();
    expect((await h.post('paid-client', { hash: 'x', upstream: { token: 't' } })).status).toBe(400);
    const m = await h.post('paid-client', withUpstream('a', { token: 't' }, { mode: 'nope' }));
    expect(await m.json()).toEqual({ error: 'bad-mode' });
  });
});

describe('credentials never go to plain http, and the relay refuses a bad setup at start', () => {
  const paid = SERVICES[1]!;
  const baseOptions = {
    origins: [],
    allowPlainHttp: true,
    upstream: (async () => ({ status: 500, contentType: '', body: new Uint8Array() })) as Upstream,
    random: (n: number) => new Uint8Array(n),
    now: () => NOW,
    keys: 'off' as const,
    upstreamAuth: new Map([['paid-relay', RELAY_CREDS.get('paid-relay')!]]),
  };
  const mk = (over: Partial<RelayService>, auth?: Map<string, UpstreamCredentials>) =>
    createRelay({
      ...baseOptions,
      services: [{ ...paid, ...over }],
      upstreamAuth: auth ?? baseOptions.upstreamAuth,
    });

  it('a service with credentials at an http address ends the start, even with RELAY_ALLOW_PLAIN_HTTP', () => {
    expect(() => mk({ url: 'http://plain.example/tsr' })).toThrow(/not https/);
    expect(() => mk({ url: 'https://ok.example/tsr' })).not.toThrow();
  });
  it('relay credentials missing for source relay, present for none or client, or not fitting the kind: start refused', () => {
    expect(() => mk({}, new Map())).toThrow(/no credentials of the relay/);
    expect(() => mk({ auth: { kind: 'none' } })).toThrow(/takes no credentials/);
    const plain: RelayService = { ...paid };
    delete plain.auth;
    expect(() => createRelay({ ...baseOptions, services: [plain] })).toThrow(
      /takes no credentials/,
    );
    expect(() => mk({ auth: { kind: 'basic', source: 'client' } })).toThrow(/client only/);
    expect(() => mk({ auth: { kind: 'bearer', source: 'relay' } })).toThrow(/do not fit/);
    expect(() =>
      mk(
        { auth: { kind: 'header', header: 'X-Api-Key', source: 'relay' } },
        new Map([['paid-relay', { kind: 'header', header: 'X-Other', token: 't' }]]),
      ),
    ).toThrow(/do not fit/);
    expect(() =>
      mk({}, new Map([['paid-relay', { kind: 'basic', user: 'a:b', password: 'p' }]])),
    ).toThrow(/do not fit/);
    expect(() =>
      mk(
        {},
        new Map([
          ['paid-relay', RELAY_CREDS.get('paid-relay')!],
          ['stranger', { kind: 'bearer', token: 't' }],
        ]),
      ),
    ).toThrow(/not offered/);
    expect(() => mk({ auth: { kind: 'header', header: 'Host', source: 'relay' } })).toThrow(
      /header name/,
    );
  });
  it('the error text of a bad setup names the service, never a credential', () => {
    try {
      mk({}, new Map([['paid-relay', { kind: 'basic', user: MARKER, password: 'a\r\nb' }]]));
      expect.unreachable();
    } catch (e) {
      expect((e as Error).message).not.toContain(MARKER);
    }
  });
});

describe('the identities: collecting operation keeps credentials apart', () => {
  let h: Harness;
  afterEach(() => h.close());

  const receiptVerifies = async (res: Response, hash: Uint8Array) => {
    const body = (await res.json()) as { token: string; batch: never };
    return verifyBatchedTimestamp(
      { token: fromBase64Url(body.token)!, hash, batch: body.batch },
      [SIGNER.caPem],
      { now: new Date(NOW), minGenTime: new Date(NOW - 60_000) },
    );
  };

  it('two identities at one service: two windows, two calls, each with its own credentials, never mixed', async () => {
    h = await start({ batch: { windowMs: 300, max: 100 } });
    const a = ['a1', 'a2'].map((t) => sha256(t));
    const b = [sha256('b1')];
    const sent = await Promise.all([
      h.post('paid-client', withUpstream('a1', { token: 'tok-A' })),
      h.post('paid-client', withUpstream('b1', { token: 'tok-B' })),
      h.post('paid-client', withUpstream('a2', { token: 'tok-A' })),
    ]);
    expect(sent.map((r) => r.status)).toEqual([200, 200, 200]);
    expect(h.calls).toHaveLength(2); // one stamp per identity, not one for all
    const byToken = new Map(h.calls.map((c) => [(c.creds as { token: string }).token, c]));
    expect([...byToken.keys()].sort()).toEqual(['tok-A', 'tok-B']);
    // the receipts: A's two hashes share a tree of two, B's hash a tree of one
    const bodies = (await Promise.all(sent.map((r) => r.json()))) as { batch: { size: number } }[];
    expect(bodies.map((x) => x.batch.size)).toEqual([2, 1, 2]);
    expect((await receiptVerifies(new Response(JSON.stringify(bodies[0])), a[0]!)).ok).toBe(true);
    expect((await receiptVerifies(new Response(JSON.stringify(bodies[2])), a[1]!)).ok).toBe(true);
    expect((await receiptVerifies(new Response(JSON.stringify(bodies[1])), b[0]!)).ok).toBe(true);
    // B's hash is not in A's tree: A's receipt does not verify for it
    expect((await receiptVerifies(new Response(JSON.stringify(bodies[0])), b[0]!)).ok).toBe(false);
  });
  it('a type 1 solo request is refused at once with 403, with any credentials: no call, no window, no identity', async () => {
    h = await start({ batch: { windowMs: 300, max: 100 } });
    const rider = h.post('paid-client', withUpstream('r1', { token: 'tok-A' }));
    await sleep(40);
    const started = Date.now();
    const answers = await Promise.all([
      // the identity of the rider, another identity, and none that was seen before: the credentials play no part
      h.post('paid-client', withUpstream('s1', { token: 'tok-A' }, { mode: 'solo' }), {
        key: KEY_A,
      }),
      h.post('paid-client', withUpstream('s2', { token: 'tok-B' }, { mode: 'solo' }), {
        key: KEY_A,
      }),
      h.post('paid-client', withUpstream('s3', { token: 'tok-C' }, { mode: 'solo' }), {
        key: KEY_B,
      }),
    ]);
    expect(answers.map((r) => r.status)).toEqual([403, 403, 403]);
    expect(Date.now() - started).toBeLessThan(200); // not after the window (260 ms to go)
    expect(await answers[0]!.json()).toEqual({ error: 'solo-not-allowed' });
    const got = await rider;
    expect(got.status).toBe(200);
    expect(((await got.json()) as { batch: { size: number } }).batch.size).toBe(1);
    expect(h.calls).toHaveLength(1); // the rider's window only
    for (const tag of ['s1', 's2', 's3']) {
      expect(h.calls.some((c) => Buffer.from(c.imprint).equals(Buffer.from(sha256(tag))))).toBe(
        false,
      );
    }
    expect(h.relay.stats()).toMatchObject({ soloDenied: 3, refused: { 'solo-not-allowed': 3 } });
  });
  it('the relay own credentials and a client identity of an either service are separate lanes too', async () => {
    h = await start({ batch: { windowMs: 300, max: 100 } });
    const sent = await Promise.all([
      h.post('paid-either', withUpstream('a', { token: 'c1' })),
      h.post('paid-either', { hash: hashText('b') }),
      h.post('paid-either', { hash: hashText('c') }),
    ]);
    expect(sent.map((r) => r.status)).toEqual([200, 200, 200]);
    expect(h.calls).toHaveLength(2);
    const tokens = h.calls.map((c) => (c.creds as { token: string }).token).sort();
    expect(tokens).toEqual(['c1', 'relay-token']);
  });
  it('the service budget counts per identity: one used-up identity does not hold another back', async () => {
    const slow = SERVICES.map((s) => ({ ...s, minIntervalMs: 60_000 })); // one slot a minute
    h = await start({ services: slow, batch: { windowMs: 100, max: 100 } });
    expect((await h.post('paid-client', withUpstream('a', { token: 'A' }))).status).toBe(200);
    const again = await h.post('paid-client', withUpstream('b', { token: 'A' }));
    expect(again.status).toBe(429); // identity A: its slot is gone
    expect(again.headers.get('retry-after')).not.toBeNull();
    expect((await h.post('paid-client', withUpstream('c', { token: 'B' }))).status).toBe(200);
    expect(h.calls).toHaveLength(2);
  });
  it('without collecting operation the budget per identity holds too', async () => {
    const slow = SERVICES.map((s) => ({ ...s, minIntervalMs: 60_000 }));
    h = await start({ services: slow });
    expect((await h.post('paid-client', withUpstream('a', { token: 'A' }))).status).toBe(200);
    expect((await h.post('paid-client', withUpstream('b', { token: 'A' }))).status).toBe(429);
    expect((await h.post('paid-client', withUpstream('c', { token: 'B' }))).status).toBe(200);
  });
  it('a free service is unchanged: one lane, one budget for everybody', async () => {
    const slow = SERVICES.map((s) => ({ ...s, minIntervalMs: 60_000 }));
    h = await start({ services: slow });
    expect((await h.post('free', { hash: hashText('a') })).status).toBe(200);
    expect((await h.post('free', { hash: hashText('b') }, { key: KEY_B })).status).toBe(429);
  });
  it('the whole relay stays bound by perMinuteTotal, whatever the number of identities', async () => {
    h = await start({ upstreamIdentities: 1000 });
    const statuses: number[] = [];
    for (let i = 0; i < RELAY_LIMITS.perMinuteTotal + 5; i += 1) {
      const key = [KEY_A, KEY_B][i % 2]!; // perMinutePerKey (20) is not what stops it here
      const r = await h.post('paid-client', withUpstream(`t${i}`, { token: `tok-${i}` }), { key });
      statuses.push(r.status);
      if (i % 10 === 9) h.clock.now += 1; // distinct heads
    }
    expect(statuses.filter((s) => s === 200).length).toBeLessThanOrEqual(
      RELAY_LIMITS.perMinuteTotal,
    );
    expect(statuses).toContain(429);
  });
  it('a refused solo request of type 1 opens no identity: the table of identities is not touched', async () => {
    h = await start({ batch: { windowMs: 100, max: 100 }, upstreamIdentities: 2 });
    for (const t of ['a', 'b', 'c', 'd', 'e']) {
      const r = await h.post(
        'paid-client',
        withUpstream(t, { token: `tok-${t}` }, { mode: 'solo' }),
        {
          key: KEY_A,
        },
      );
      expect(r.status).toBe(403); // never 503 busy (the table holds two)
    }
    expect((await h.post('paid-client', withUpstream('n1', { token: 'N1' }))).status).toBe(200);
    expect((await h.post('paid-client', withUpstream('n2', { token: 'N2' }))).status).toBe(200);
    expect(h.relay.stats().refused['busy']).toBeUndefined();
  });
  it('the minimum distance of solo stamps is kept per identity: another identity does not hold one back, the same does', async () => {
    const M = 400;
    const quick = SERVICES.map((s) => ({ ...s, minIntervalMs: M }));
    h = await start({ services: quick, batch: { windowMs: 100, max: 100 } });
    // a clock that runs (the relay waits for the distance by it)
    const tick = setInterval(() => (h.clock.now += 10), 10);
    try {
      const t0 = Date.now();
      const send = (tag: string, token: string) =>
        h.post('paid-client', withUpstream(tag, { token }, { mode: 'solo' }), { key: KEY_S });
      const answers = await Promise.all([send('a1', 'A'), send('b1', 'B'), send('a2', 'A')]);
      expect(answers.map((r) => r.status)).toEqual([200, 200, 200]);
      const at = (token: string) =>
        h.calls.filter((c) => (c.creds as { token: string }).token === token).map((c) => c.at - t0);
      const [a, b] = [at('A'), at('B')];
      expect(a).toHaveLength(2);
      expect(b).toHaveLength(1);
      expect(Math.min(a[0]!, b[0]!)).toBeLessThan(150);
      expect(Math.max(a[0]!, b[0]!)).toBeLessThan(150); // B did not wait for A: its own lane
      expect(a[1]! - a[0]!).toBeGreaterThanOrEqual(M - 40); // the same identity waited for the distance
    } finally {
      clearInterval(tick);
    }
  });
});

describe('the table of identities is limited, and idle identities are dropped', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('a new identity beyond the limit is 503 busy with Retry-After; known ones still go; room is made after a window', async () => {
    h = await start({ upstreamIdentities: 3 });
    for (const t of ['A', 'B', 'C']) {
      expect((await h.post('paid-client', withUpstream(`x${t}`, { token: t }))).status).toBe(200);
    }
    const d = await h.post('paid-client', withUpstream('xD', { token: 'D' }));
    expect(d.status).toBe(503);
    expect(await d.json()).toEqual({ error: 'busy' });
    expect(Number(d.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    expect(Number(d.headers.get('retry-after'))).toBeLessThanOrEqual(60);
    expect(h.calls).toHaveLength(3); // the refused one never reached the service
    // a known identity is not a new one
    expect((await h.post('paid-client', withUpstream('xA2', { token: 'A' }))).status).toBe(200);
    // another service has its own table
    expect(
      (await h.post('paid-basic', withUpstream('y', { user: 'u', password: 'p' }))).status,
    ).toBe(200);
    // a window later the idle ones are dropped and D is taken
    h.clock.now += 61_000;
    expect((await h.post('paid-client', withUpstream('xD2', { token: 'D' }))).status).toBe(200);
  });
  it('a refused request leaves no identity behind (a new identity costs nothing when it is refused)', async () => {
    h = await start({
      upstreamIdentities: 2,
      services: SERVICES.map((s) => ({ ...s, minIntervalMs: 1000 })), // 60 a minute: the key limit (20) comes first
    });
    // exhaust the per-key budget with identity A... then new identities are refused by the key limit and must not fill the table
    for (let i = 0; i < RELAY_LIMITS.perMinutePerKey; i += 1) {
      h.clock.now += 0;
      await h.post('free', { hash: hashText(`f${i}`) });
    }
    const refused = await h.post('paid-client', withUpstream('n1', { token: 'N1' }));
    expect(refused.status).toBe(429);
    const refused2 = await h.post('paid-client', withUpstream('n2', { token: 'N2' }));
    expect(refused2.status).toBe(429);
    // key B is not limited: two identities fit although two refused ones came before
    expect(
      (await h.post('paid-client', withUpstream('n3', { token: 'N3' }), { key: KEY_B })).status,
    ).toBe(200);
    expect(
      (await h.post('paid-client', withUpstream('n4', { token: 'N4' }), { key: KEY_B })).status,
    ).toBe(200);
  });
  it('without a setting the table holds exactly `upstreamIdentitiesMax` identities per service; the next one is 503 busy', async () => {
    // Identities in flight never expire, so they can be held side by side although the budgets (per key, in total)
    // let only a few requests through a minute: the first half is sent, the minute passes, the second half is sent.
    const max = RELAY_LIMITS.upstreamIdentitiesMax;
    const gate: { open: () => void; opened: Promise<void> } = {
      open: () => undefined,
      opened: Promise.resolve(),
    };
    gate.opened = new Promise<void>((r) => (gate.open = r));
    let clockForReply = NOW;
    let reached = 0;
    const upstream: Upstream = async (_t, body) => {
      reached += 1;
      await gate.opened;
      return {
        status: 200,
        contentType: 'application/timestamp-reply',
        body: replyFor(body, clockForReply),
      };
    };
    h = await start({ upstream });
    const keys = [KEY_A, KEY_B, KEY_S];
    const sent: Promise<Response>[] = [];
    const wave = (from: number, to: number) => {
      for (let i = from; i < to; i += 1) {
        sent.push(
          h.post('paid-client', withUpstream(`i${i}`, { token: `T${i}` }), { key: keys[i % 3]! }),
        );
      }
    };
    wave(0, 30);
    await sleep(300);
    h.clock.now += 61_000; // the first wave left the budgets of the minute
    clockForReply = h.clock.now;
    wave(30, max);
    await sleep(300);
    const next = await h.post('paid-client', withUpstream('one-too-many', { token: 'T-extra' }), {
      key: KEY_A,
    });
    expect(next.status).toBe(503);
    expect(await next.json()).toEqual({ error: 'busy' });
    gate.open();
    const answered = await Promise.all(sent);
    expect(answered.map((r) => r.status).filter((x) => x !== 200)).toEqual([]);
    expect(reached).toBe(max); // the refused one never reached the service
  }, 20_000);
});

describe('the lifetime of an identity (credentials of the app)', () => {
  let h: Harness;
  afterEach(() => h.close());

  /** An upstream that answers when the test says so (the request stays in flight until then). */
  function held() {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    let clock: { now: number } = { now: NOW };
    const upstream: Upstream = async (_t, body) => {
      await gate;
      return {
        status: 200,
        contentType: 'application/timestamp-reply',
        body: replyFor(body, clock.now),
      };
    };
    return {
      upstream,
      release: () => release(),
      follow: (c: { now: number }) => void (clock = c),
    };
  }
  const post = (tag: string, token: string, key = KEY_A) =>
    h.post('paid-client', withUpstream(tag, { token }), { key });

  it('an identity with a request in flight does not expire, however long it takes', async () => {
    const slow = held();
    h = await start({ upstream: slow.upstream, upstreamIdentities: 1 });
    slow.follow(h.clock);
    const inFlight = post('x1', 'X');
    await sleep(200);
    h.clock.now += 61_000; // longer than a window: idle would be gone, but a request is still in flight
    const refused = await post('y1', 'Y', KEY_B);
    expect(refused.status).toBe(503); // X still holds the only place
    expect(await refused.json()).toEqual({ error: 'busy' });
    slow.release();
    expect((await inFlight).status).toBe(200);
  });

  it('the identity lives a whole window after its last ANSWER, not after its start', async () => {
    const slow = held();
    h = await start({ upstream: slow.upstream, upstreamIdentities: 1 });
    slow.follow(h.clock);
    const inFlight = post('x1', 'X');
    await sleep(200);
    h.clock.now += 50_000; // the request takes 50 s
    slow.release();
    expect((await inFlight).status).toBe(200); // answered at t0 + 50 s
    h.clock.now += 50_000; // t0 + 100 s: 100 s after the start, 50 s after the answer
    const refused = await post('y1', 'Y', KEY_B);
    expect(refused.status).toBe(503); // X is still known
    h.clock.now += 11_000; // 61 s after the answer
    expect((await post('y2', 'Y', KEY_B)).status).toBe(200); // X is gone, Y takes its place
  });

  it('a dropped identity takes its budget with it (a new one with the same credentials starts empty)', async () => {
    h = await start({ upstreamIdentities: 2 });
    const limit = Math.floor(60_000 / 5000); // the lane of an identity: 12 stamps a minute
    for (let i = 0; i < limit; i += 1) {
      expect((await post(`b${i}`, 'X', i % 2 ? KEY_B : KEY_A)).status).toBe(200);
    }
    expect((await post('b-over', 'X', KEY_S)).status).toBe(429); // X has used its minute
    h.clock.now += 61_000;
    expect((await post('y', 'Y', KEY_S)).status).toBe(200); // a new identity: the idle X is dropped now
    h.clock.now -= 50_000; // the clock is set back: the old stamps of X would count again if they were kept
    expect((await post('x-again', 'X', KEY_S)).status).toBe(200);
  });
});

describe('nothing of the credentials is ever output: no log, no error, no counter', () => {
  let h: Harness;
  afterEach(() => h.close());

  /** Everything written to the console and the process streams while `run` runs. */
  async function captured(run: () => Promise<void>): Promise<string> {
    const lines: string[] = [];
    const take = (...a: unknown[]) =>
      void lines.push(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' '));
    const spies = (['log', 'error', 'warn', 'info', 'debug'] as const).map((m) =>
      vi.spyOn(console, m).mockImplementation(take),
    );
    const out = vi
      .spyOn(process.stdout, 'write')
      .mockImplementation(((c: unknown) => (take(String(c)), true)) as never);
    const err = vi
      .spyOn(process.stderr, 'write')
      .mockImplementation(((c: unknown) => (take(String(c)), true)) as never);
    try {
      await run();
    } finally {
      for (const s of [...spies, out, err]) s.mockRestore();
    }
    return lines.join('\n');
  }

  const identityOf = (c: UpstreamCredentials) => credentialIdentity(c);
  const forbidden = (c: UpstreamCredentials, text: string) => {
    expect(text).not.toContain(MARKER);
    expect(text).not.toContain(Buffer.from(MARKER).toString('base64').slice(0, 12));
    expect(text).not.toContain(identityOf(c));
    expect(text).not.toContain(identityOf(c).slice(0, 8));
  };

  const marked: [string, UpstreamCredentials, unknown][] = [
    ['paid-client', { kind: 'bearer', token: MARKER }, { token: MARKER }],
    [
      'paid-basic',
      { kind: 'basic', user: MARKER, password: `${MARKER}-pw` },
      { user: MARKER, password: `${MARKER}-pw` },
    ],
    ['paid-either', { kind: 'header', header: 'X-Api-Key', token: MARKER }, { token: MARKER }],
  ];
  const failures: [string, Upstream][] = [
    [
      'timeout',
      async () => {
        throw new UpstreamError('timeout');
      },
    ],
    [
      'failed',
      async () => {
        throw new UpstreamError('failed');
      },
    ],
    [
      'too-large',
      async () => {
        throw new UpstreamError('too-large');
      },
    ],
    [
      'refused (401 from the service)',
      async () => ({
        status: 401,
        contentType: 'text/plain',
        body: new TextEncoder().encode(MARKER),
      }),
    ],
    [
      'garbage answer',
      async (_t, _b, c) => ({
        status: 200,
        contentType: 'application/timestamp-reply',
        body: new TextEncoder().encode(JSON.stringify(c)),
      }),
    ],
    [
      'a stub that throws an error that holds the credentials',
      async (_t, _b, c) => {
        throw new Error(`failed with ${JSON.stringify(c)}`);
      },
    ],
  ];

  for (const [name, upstream] of failures) {
    it(`upstream failure (${name}): the answer, the counters and every output are free of the credentials`, async () => {
      for (const batch of [undefined, { windowMs: 60, max: 10 }]) {
        h = await start({ upstream, ...(batch ? { batch } : {}) });
        for (const [id, creds, upstreamBody] of marked) {
          const text = await captured(async () => {
            const r = await h.post(id, withUpstream('m', upstreamBody));
            expect([200, 500, 502, 504]).toContain(r.status);
            const body = await r.text();
            forbidden(creds, body + JSON.stringify([...r.headers]));
            forbidden(creds, JSON.stringify(h.relay.stats()));
          });
          forbidden(creds, text);
        }
        await h.close();
      }
    });
  }
  it('a bad upstream (the body of a refusal) and a successful stamp leave nothing either', async () => {
    h = await start();
    const creds: UpstreamCredentials = { kind: 'bearer', token: `${MARKER}\r\nX: 1` };
    const text = await captured(async () => {
      const r = await h.post('paid-client', withUpstream('m', { token: `${MARKER}\r\nX: 1` }));
      expect(r.status).toBe(400);
      forbidden(creds, await r.text());
      const ok = await h.post('paid-client', withUpstream('n', { token: MARKER }));
      expect(ok.status).toBe(200);
      forbidden({ kind: 'bearer', token: MARKER }, await ok.text());
      forbidden({ kind: 'bearer', token: MARKER }, JSON.stringify(h.relay.stats()));
    });
    expect(text).not.toContain(MARKER);
    expect(Object.keys(h.relay.stats().refused)).toEqual(['bad-upstream']);
  });
  it('the start: a bad or unknown variable is named, its value is not', () => {
    const services = SERVICES;
    const name = upstreamAuthVariable('paid-relay');
    expect(name).toBe('RELAY_UPSTREAM_AUTH_PAID_RELAY');
    for (const env of [
      { [name]: `${MARKER}-no-colon` },
      { [name]: `${MARKER}:p\r\nq` },
      { [name]: 'u:p', RELAY_UPSTREAM_AUTH_PAID_CLIENT: MARKER }, // a client-only service holds none
      { [name]: 'u:p', RELAY_UPSTREAM_AUTH_TYPO: MARKER },
    ]) {
      try {
        readUpstreamAuth(env, services);
        expect.unreachable('should throw');
      } catch (e) {
        expect((e as Error).message).not.toContain(MARKER);
        expect((e as Error).message).toContain('RELAY_UPSTREAM_AUTH_');
      }
    }
  });
});

describe('the relay own credentials: the environment, strictly', () => {
  it('read for source relay (mandatory) and either (optional), by variable name', () => {
    const got = readUpstreamAuth({ RELAY_UPSTREAM_AUTH_PAID_RELAY: 'u:p:q' }, SERVICES);
    expect([...got.keys()]).toEqual(['paid-relay']);
    expect(got.get('paid-relay')).toEqual({ kind: 'basic', user: 'u', password: 'p:q' });
    const both = readUpstreamAuth(
      { RELAY_UPSTREAM_AUTH_PAID_RELAY: 'u:p', RELAY_UPSTREAM_AUTH_PAID_EITHER: 'tok' },
      SERVICES,
    );
    expect(both.get('paid-either')).toEqual({ kind: 'header', header: 'X-Api-Key', token: 'tok' });
  });
  it('a missing or empty value for source relay ends the start; for either it is fine', () => {
    expect(() => readUpstreamAuth({}, SERVICES)).toThrow(/RELAY_UPSTREAM_AUTH_PAID_RELAY fehlt/);
    expect(() => readUpstreamAuth({ RELAY_UPSTREAM_AUTH_PAID_RELAY: '' }, SERVICES)).toThrow(
      /fehlt/,
    );
    expect(
      readUpstreamAuth({ RELAY_UPSTREAM_AUTH_PAID_RELAY: 'u:p' }, SERVICES).has('paid-either'),
    ).toBe(false);
  });
  it('a variable of a service that is not chosen, of a free one, or a lower-case or misspelled name is refused', () => {
    const ok = { RELAY_UPSTREAM_AUTH_PAID_RELAY: 'u:p' };
    for (const extra of [
      'RELAY_UPSTREAM_AUTH_FREE',
      'RELAY_UPSTREAM_AUTH_PAID_BASIC',
      'RELAY_UPSTREAM_AUTH_PAID-RELAY',
      'RELAY_UPSTREAM_AUTH_',
      'RELAY_UPSTREAM_AUTH_paid_relay',
    ]) {
      expect(() => readUpstreamAuth({ ...ok, [extra]: 'x' }, SERVICES), extra).toThrow(extra);
    }
  });
  it('readConfig takes the credentials with the services and refuses a start without a mandatory one', () => {
    const load = () => SERVICES.filter((s) => s.id === 'paid-relay');
    const env = { RELAY_SERVICES: 'paid-relay', RELAY_AUTH: 'off' };
    expect(() => readConfig(env, load)).toThrow(/RELAY_UPSTREAM_AUTH_PAID_RELAY fehlt/);
    const cfg = readConfig({ ...env, RELAY_UPSTREAM_AUTH_PAID_RELAY: 'u:p' }, load);
    expect(cfg.upstreamAuth.get('paid-relay')).toEqual({ kind: 'basic', user: 'u', password: 'p' });
    // the free services of the file need nothing
    const free = readConfig({ RELAY_SERVICES: 'free', RELAY_AUTH: 'off' }, () => [SERVICES[0]!]);
    expect(free.upstreamAuth.size).toBe(0);
  });
});

describe('/v1/services tells what an app has to send, and nothing else', () => {
  it('lists auth (kind, header, source) for the paid services only; the free ones look as before', async () => {
    const h = await start();
    try {
      const list = (await (await fetch(`${h.base}/v1/services`)).json()) as {
        services: Record<string, unknown>[];
      };
      const by = new Map(list.services.map((s) => [s.id as string, s]));
      expect(Object.keys(by.get('free')!).sort()).toEqual([
        'id',
        'intendedUse',
        'name',
        'qualified',
      ]);
      expect(by.get('paid-relay')!.auth).toEqual({ kind: 'basic', source: 'relay' });
      expect(by.get('paid-either')!.auth).toEqual({
        kind: 'header',
        header: 'X-Api-Key',
        source: 'either',
      });
      const text = JSON.stringify(list);
      for (const c of RELAY_CREDS.values()) {
        expect(text).not.toContain('relay-pass');
        expect(text).not.toContain('relay-token');
        void c;
      }
    } finally {
      await h.close();
    }
  });
});
