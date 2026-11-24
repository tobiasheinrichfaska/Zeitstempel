import { readFileSync } from 'node:fs';
import {
  CLIENT_LIMITS,
  createRelayClient,
  parseRelayAnswer,
  parseServiceList,
  readTimestampResponse,
  toBase64Url,
  verifyTimestampToken,
  type FetchInit,
  type FetchLike,
  type FetchResponse,
  type RelayClientOptions,
} from '../src/lib/index.ts';
import { fixture, sha256 } from './helpers.ts';

const freetsaRoot = readFileSync(new URL('../anchors/freetsa-root.pem', import.meta.url), 'utf8');
const otherRoot = readFileSync(new URL('./fixtures/other-root.pem', import.meta.url), 'utf8');
const HASH = sha256('probe');
const parsed = readTimestampResponse(fixture('freetsa.tsr'));
if (!parsed.ok) throw new Error('fixture unreadable');
const TOKEN = parsed.value.token;
const verified = await verifyTimestampToken(TOKEN, HASH, [freetsaRoot]);
if (!verified.ok) throw new Error('fixture does not verify');
const SERIAL = verified.value.serial;

const goodAnswer = (over: Record<string, unknown> = {}) => ({
  service: 'freetsa',
  genTime: verified.ok ? verified.value.genTime : '',
  accuracyMs: null,
  serial: SERIAL,
  token: toBase64Url(TOKEN),
  ...over,
});

const reply = (
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): FetchResponse => ({
  status,
  headers: { get: (n) => headers[n] ?? null },
  json: async () => {
    if (body === undefined) throw new Error('not json');
    return body;
  },
});

interface Call {
  url: string;
  init: FetchInit;
}
type Handler = (url: string, init: FetchInit) => FetchResponse | Promise<FetchResponse>;

function setup(handler: Handler, extra: Partial<RelayClientOptions> = {}) {
  const calls: Call[] = [];
  let clock = 0;
  const fetchFake: FetchLike = async (url, init) => {
    calls.push({ url, init });
    return handler(url, init);
  };
  const client = createRelayClient({
    relay: 'https://relay.example/',
    fetch: fetchFake,
    now: () => clock,
    trusted: new Map([['freetsa', [freetsaRoot]]]),
    ...extra,
  });
  return { client, calls, setClock: (ms: number) => (clock = ms) };
}

const list = (...ids: string[]) => ({ services: ids.map((id) => ({ id, name: id })) });
const routes =
  (stamp: Handler, ids = ['freetsa']): Handler =>
  (url, init) =>
    url.endsWith('/v1/services') ? reply(200, list(...ids)) : stamp(url, init);

describe('relay client: success', () => {
  it('stamps, sends only the hash, and verifies the real recorded token', async () => {
    const { client, calls } = setup(routes(() => reply(200, goodAnswer())));
    const r = await client.stamp(HASH);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.serviceId).toBe('freetsa');
    expect(r.value.serial).toBe(SERIAL);
    expect(r.value.genTime.startsWith('2026-11-23T')).toBe(true);
    expect(r.value.token).toEqual(TOKEN);
    expect(calls.map((c) => c.url)).toEqual([
      'https://relay.example/v1/services',
      'https://relay.example/v1/stamp/freetsa',
    ]);
    const post = calls[1]!.init;
    expect(post.method).toBe('POST');
    expect(JSON.parse(post.body!)).toEqual({ hash: toBase64Url(HASH) });
    expect(toBase64Url(HASH)).toHaveLength(43);
    expect(post.headers).toEqual({ 'Content-Type': 'application/json' });
    for (const c of calls) {
      expect(c.init).toMatchObject({
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        cache: 'no-store',
        redirect: 'error',
      });
    }
  });
  it('lists the relay services', async () => {
    const { client } = setup(() => reply(200, list('a', 'b')));
    expect(await client.services()).toEqual({ ok: true, value: ['a', 'b'] });
  });
  it('uses an injected verify', async () => {
    const seen: unknown[] = [];
    const { client } = setup(
      routes(() => reply(200, goodAnswer({ serial: 'ab' }))),
      {
        verify: async (token, hash, anchors) => {
          seen.push(token, hash, anchors);
          return { ok: true, value: { ...verified.value!, serial: 'ab' } };
        },
      },
    );
    const r = await client.stamp(HASH);
    expect(r.ok).toBe(true);
    expect(seen[2]).toEqual([freetsaRoot]);
  });
  it('refuses a hash that is not 32 bytes without a call', async () => {
    const { client, calls } = setup(() => reply(200, {}));
    expect(await client.stamp(new Uint8Array(31))).toMatchObject({ ok: false, reason: 'bad-hash' });
    expect(calls).toHaveLength(0);
  });
});

describe('relay client: refusals', () => {
  it('refuses an untrusted service id (never asks it)', async () => {
    const { client, calls } = setup(routes(() => reply(200, goodAnswer()), ['evil']));
    expect(await client.stamp(HASH)).toMatchObject({ ok: false, reason: 'no-trusted-service' });
    expect(calls).toHaveLength(1);
  });
  it('asks only trusted ids, in the relay order', async () => {
    const { client, calls } = setup(routes(() => reply(200, goodAnswer()), ['x', 'freetsa']));
    expect((await client.stamp(HASH)).ok).toBe(true);
    expect(calls[1]!.url).toBe('https://relay.example/v1/stamp/freetsa');
  });
  it('refuses an answer for another service id', async () => {
    const { client } = setup(routes(() => reply(200, goodAnswer({ service: 'sectigo' }))));
    expect(await client.stamp(HASH)).toMatchObject({ ok: false, reason: 'relay-bad-response' });
  });
  it('refuses a wrong serial', async () => {
    const { client } = setup(routes(() => reply(200, goodAnswer({ serial: 'abc123' }))));
    const r = await client.stamp(HASH);
    expect(r).toMatchObject({
      ok: false,
      reason: 'relay-bad-response',
      detail: 'serial differs from the token',
    });
  });
  it('refuses an extra or a missing field', async () => {
    for (const body of [
      goodAnswer({ extra: 1 }),
      Object.fromEntries(Object.entries(goodAnswer()).filter(([k]) => k !== 'serial')),
    ]) {
      const { client } = setup(routes(() => reply(200, body)));
      expect(await client.stamp(HASH)).toMatchObject({ ok: false, reason: 'relay-bad-response' });
    }
  });
  it('refuses a token for another hash or from an unknown root', async () => {
    const wrongHash = setup(routes(() => reply(200, goodAnswer())));
    expect(await wrongHash.client.stamp(sha256('other'))).toMatchObject({
      ok: false,
      reason: 'imprint-mismatch',
    });
    const wrongRoot = setup(
      routes(() => reply(200, goodAnswer())),
      {
        trusted: new Map([['freetsa', [otherRoot]]]),
      },
    );
    expect(await wrongRoot.client.stamp(HASH)).toMatchObject({
      ok: false,
      reason: 'untrusted-chain',
    });
  });
  it('turns a throwing verify into a code', async () => {
    const { client } = setup(
      routes(() => reply(200, goodAnswer())),
      {
        verify: async () => {
          throw new Error('boom');
        },
      },
    );
    expect(await client.stamp(HASH)).toMatchObject({
      ok: false,
      reason: 'malformed',
      detail: 'boom',
    });
  });
  it('reports other statuses with the relay code and a bad service list', async () => {
    const a = setup(routes(() => reply(400, { error: 'bad-hash' })));
    expect(await a.client.stamp(HASH)).toMatchObject({
      ok: false,
      reason: 'relay-refused',
      detail: 'status 400, bad-hash',
    });
    const b = setup(() => reply(200, { services: [{ id: 'Bad Id' }] }));
    expect(await b.client.stamp(HASH)).toMatchObject({ ok: false, reason: 'relay-bad-response' });
    const c = setup(() => reply(503, undefined));
    expect(await c.client.services()).toMatchObject({ ok: false, reason: 'relay-refused' });
  });
  it('reports a network error', async () => {
    const { client } = setup(() => {
      throw new TypeError('network down');
    });
    expect(await client.stamp(HASH)).toMatchObject({
      ok: false,
      reason: 'relay-unreachable',
      detail: 'network down',
    });
  });
});

describe('relay client: 502, 504, timeout', () => {
  it('tries the next service on 502 and on 504', async () => {
    for (const status of [502, 504]) {
      const { client, calls } = setup(
        routes(
          (url) =>
            url.endsWith('/freetsa')
              ? reply(200, goodAnswer())
              : reply(status, { error: 'upstream-failed' }),
          ['one', 'freetsa'],
        ),
        {
          trusted: new Map([
            ['one', [freetsaRoot]],
            ['freetsa', [freetsaRoot]],
          ]),
        },
      );
      expect((await client.stamp(HASH)).ok).toBe(true);
      expect(calls.map((c) => c.url.split('/').pop())).toEqual(['services', 'one', 'freetsa']);
    }
  });
  it('gives relay-unreachable after at most three services', async () => {
    const ids = ['a', 'b', 'c', 'd'];
    const { client, calls } = setup(
      routes(() => reply(504, { error: 'upstream-timeout' }), ids),
      {
        trusted: new Map(ids.map((id) => [id, [freetsaRoot]])),
      },
    );
    expect(await client.stamp(HASH)).toMatchObject({
      ok: false,
      reason: 'relay-unreachable',
      detail: 'status 504, upstream-timeout',
    });
    expect(calls).toHaveLength(1 + CLIENT_LIMITS.maxServicesTried);
  });
  it('aborts after the deadline', async () => {
    vi.useFakeTimers();
    try {
      let signal: AbortSignal | undefined;
      const { client } = setup(
        (_url, init) => {
          signal = init.signal;
          return new Promise<FetchResponse>((_res, rej) => {
            init.signal.addEventListener('abort', () => rej(new Error('aborted')));
          });
        },
        { timeoutMs: 1000 },
      );
      const pending = client.stamp(HASH);
      await vi.advanceTimersByTimeAsync(1001);
      expect(await pending).toMatchObject({
        ok: false,
        reason: 'relay-timeout',
        detail: 'timeout',
      });
      expect(signal?.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('relay client: 429', () => {
  const limited = (headers: Record<string, string> = {}) =>
    routes(() => reply(429, { error: 'rate-limited' }, headers));

  it('pauses, sends nothing during the pause, and goes on afterwards', async () => {
    let answer: Handler = limited({ 'Retry-After': '30' });
    const { client, calls, setClock } = setup((u, i) => answer(u, i));
    expect(await client.stamp(HASH)).toMatchObject({
      ok: false,
      reason: 'relay-rate-limited',
      detail: 'retry in 30 s',
    });
    const sent = calls.length;
    expect(client.pausedForMs()).toBe(30_000);
    setClock(10_000);
    expect(await client.stamp(HASH)).toMatchObject({
      reason: 'relay-rate-limited',
      detail: 'retry in 20 s',
    });
    expect(calls).toHaveLength(sent);
    setClock(30_000);
    answer = routes(() => reply(200, goodAnswer()));
    expect((await client.stamp(HASH)).ok).toBe(true);
    expect(client.pausedForMs()).toBe(0);
  });
  it('uses 60 s without a usable Retry-After and caps at 3600 s', async () => {
    for (const [header, seconds] of [
      [undefined, 60],
      ['soon', 60],
      ['0', 60],
      ['-5', 60],
      ['1.5', 60],
      ['999999', 3600],
    ] as const) {
      const { client } = setup(limited(header === undefined ? {} : { 'Retry-After': header }));
      await client.stamp(HASH);
      expect(client.pausedForMs()).toBe(seconds * 1000);
    }
  });
  it('a clock that went back does not stretch the pause', async () => {
    const { client, calls, setClock } = setup(limited({ 'Retry-After': '3600' }));
    setClock(1_000_000_000);
    await client.stamp(HASH);
    expect(client.pausedForMs()).toBe(3_600_000);
    setClock(0); // far back: remaining would be longer than the longest pause
    expect(client.pausedForMs()).toBe(0);
    const before = calls.length;
    await client.stamp(HASH);
    expect(calls.length).toBeGreaterThan(before); // asked again
  });
});

describe('strict readers', () => {
  it('parseServiceList', () => {
    expect(parseServiceList(list('a', 'b-1'))).toEqual({ ok: true, value: ['a', 'b-1'] });
    for (const bad of [
      null,
      [],
      {},
      { services: 'x' },
      { services: [{}] },
      { services: [{ id: 'A' }] },
    ]) {
      expect(parseServiceList(bad)).toMatchObject({ ok: false, reason: 'relay-bad-response' });
    }
    const many = Array.from({ length: 33 }, (_, i) => ({ id: `s${i}` }));
    expect(parseServiceList({ services: many }).ok).toBe(false);
  });
  it('parseRelayAnswer limits', () => {
    expect(parseRelayAnswer(goodAnswer()).ok).toBe(true);
    expect(parseRelayAnswer(goodAnswer({ accuracyMs: 1000 })).ok).toBe(true);
    const bads = [
      null,
      [],
      goodAnswer({ service: 'Bad' }),
      goodAnswer({ genTime: 'yesterday' }),
      goodAnswer({ accuracyMs: -1 }),
      goodAnswer({ accuracyMs: 1.5 }),
      goodAnswer({ serial: 'ABC' }),
      goodAnswer({ serial: 'a'.repeat(CLIENT_LIMITS.maxSerialChars + 1) }),
      goodAnswer({ token: '' }),
      goodAnswer({ token: 'AAAAA' }),
      goodAnswer({ token: 'AA==' }),
      goodAnswer({ token: 'A'.repeat(CLIENT_LIMITS.maxTokenChars + 4) }),
    ];
    for (const b of bads)
      expect(parseRelayAnswer(b)).toMatchObject({ ok: false, reason: 'relay-bad-response' });
  });
});
