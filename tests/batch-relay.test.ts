import { randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { fromBase64Url, toBase64Url, verifyBatchedTimestamp } from '../src/index.ts';
import type { RelayKey } from '../relay/keys.ts';
import { loadServices } from '../relay/load.ts';
import { readConfig, readSettings, startEvent } from '../relay/main.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import { createRelay, type RelayOptions } from '../relay/relay.ts';
import { createRelayServer } from '../relay/server.ts';
import { UpstreamError, type Upstream } from '../relay/upstream.ts';
import { BATCH_LIMITS } from '../src/lib/batch.ts';
import { TEST_AUDIENCE, makeTestKey, nodeAuthHeaderMs } from './auth-helpers.ts';
import { sha256 } from './helpers.ts';
import { build, int, seq } from './token-builder.ts';
import { children, integerBytes, octets, parseDer } from '../src/lib/der.ts';

const SERVICES = loadServices();
const SIGNER = build();
const ORIGIN = 'https://app.example';
const NOW = Date.parse('2026-11-23T13:06:00Z');
const KEY_A = makeTestKey('app-a');
const KEY_B = makeTestKey('app-b');
const KEYS: RelayKey[] = [KEY_A, KEY_B].map((k) => ({ id: k.id, publicKey: k.publicKey }));
const TRUST = [SIGNER.caPem];

const genTimeText = (ms: number) =>
  new Date(ms)
    .toISOString()
    .replace(/[-:T]/g, '')
    .replace(/\.\d+Z$/, 'Z');

/** What a service would answer: a token over the imprint and the nonce of the request, signed by `SIGNER`. */
function replyFor(request: Uint8Array, atMs: number): Uint8Array {
  const parts = children(parseDer(request));
  const hash = octets(children(parts[1]!)[1]!);
  const nonceBytes = integerBytes(parts[2]!);
  const made = build({ keys: SIGNER.keys, hash, nonceBytes, genTime: genTimeText(atMs) });
  return seq(seq(int(0)), made.token);
}

interface Harness {
  base: string;
  calls: Uint8Array[];
  clock: { now: number };
  relay: ReturnType<typeof createRelayServer>['relay'];
  stats: () => ReturnType<ReturnType<typeof createRelayServer>['relay']['stats']>;
  /** POST one hash (base64url JSON), signed by `key`. */
  stamp: (
    hash: Uint8Array,
    over?: { id?: string; key?: typeof KEY_A; signal?: AbortSignal },
  ) => Promise<Response>;
  close: () => Promise<void>;
}

async function start(
  over: {
    batch?: { windowMs: number; max: number } | null;
    services?: typeof SERVICES;
    upstream?: Upstream;
    random?: (n: number) => Uint8Array;
    stampDelayMs?: number;
    budgetWindowMs?: number;
    maxWaitMs?: number;
  } = {},
): Promise<Harness> {
  const calls: Uint8Array[] = [];
  const clock = { now: NOW };
  const stub: Upstream = async (_t, body) => {
    calls.push(body);
    if (over.stampDelayMs) await new Promise((r) => setTimeout(r, over.stampDelayMs));
    return {
      status: 200,
      contentType: 'application/timestamp-reply',
      body: replyFor(body, clock.now),
    };
  };
  const batch = over.batch === undefined ? { windowMs: 150, max: 100 } : over.batch;
  const options: RelayOptions = {
    services: (over.services ?? SERVICES).map((s) => ({
      ...s,
      anchorPems: [...s.anchorPems, SIGNER.caPem],
    })),
    origins: [ORIGIN],
    allowPlainHttp: false,
    upstream: over.upstream ?? stub,
    random: over.random ?? ((n) => new Uint8Array(randomBytes(n))),
    now: () => clock.now,
    keys: KEYS,
    audience: TEST_AUDIENCE,
    ...(batch === null ? {} : { batch }),
    ...(over.budgetWindowMs === undefined ? {} : { budgetWindowMs: over.budgetWindowMs }),
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
    stats: relay.stats,
    stamp: (hash, o = {}) => {
      const id = o.id ?? 'freetsa';
      const path = `/v1/stamp/${id}`;
      const text = JSON.stringify({ hash: toBase64Url(hash) });
      const key = o.key ?? KEY_A;
      const head = nodeAuthHeaderMs(
        key,
        key.id,
        'POST',
        path,
        clock.now + (n++ % 30) * 1000,
        new TextEncoder().encode(text),
      );
      return fetch(base + path, {
        method: 'POST',
        body: text,
        headers: { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': head },
        ...(o.signal ? { signal: o.signal } : {}),
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

interface Receipt {
  service: string;
  genTime: string;
  accuracyMs: number | null;
  serial: string;
  token: string;
  batch: { v: 1; size: number; index: number; salt: string; path: string[] };
}

const hashes = (n: number, tag = 'x') => Array.from({ length: n }, (_, i) => sha256(`${tag}${i}`));

async function verifies(r: Receipt, hash: Uint8Array) {
  return verifyBatchedTimestamp({ token: fromBase64Url(r.token)!, hash, batch: r.batch }, TRUST, {
    now: new Date(NOW),
    minGenTime: new Date(NOW - 60_000),
  });
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('relay, collecting operation: one stamp for a window', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('five parallel requests: exactly one call to the service, every receipt verifies', async () => {
    h = await start();
    const list = hashes(5);
    const answers = await Promise.all(list.map((x) => h.stamp(x)));
    expect(answers.map((a) => a.status)).toEqual([200, 200, 200, 200, 200]);
    expect(h.calls).toHaveLength(1);
    const bodies = (await Promise.all(answers.map((a) => a.json()))) as Receipt[];
    for (const [i, body] of bodies.entries()) {
      expect(Object.keys(body).sort()).toEqual([
        'accuracyMs',
        'batch',
        'genTime',
        'serial',
        'service',
        'token',
      ]);
      expect(Object.keys(body.batch)).toEqual(['v', 'size', 'index', 'salt', 'path']);
      expect(body.batch).toMatchObject({ v: 1, size: 5 });
      const r = await verifies(body, list[i]!);
      expect(r.ok, `receipt ${i}`).toBe(true);
      if (r.ok) expect(r.value.batch).toEqual({ size: 5, index: body.batch.index });
    }
    expect(bodies.map((b) => b.batch.index).sort()).toEqual([0, 1, 2, 3, 4]);
    expect(new Set(bodies.map((b) => b.batch.salt)).size).toBe(5); // a salt of its own for each
    expect(new Set(bodies.map((b) => b.token)).size).toBe(1); // one token for all
    expect(h.stats()).toEqual({ stamped: 1, refused: {}, batched: 5 });
  });

  it('a receipt does not verify for another hash, and the service saw only the imprint', async () => {
    h = await start();
    const list = hashes(3);
    const bodies = (await Promise.all(
      (await Promise.all(list.map((x) => h.stamp(x)))).map((a) => a.json()),
    )) as Receipt[];
    expect((await verifies(bodies[0]!, list[1]!)).ok).toBe(false);
    const asked = Buffer.from(h.calls[0]!);
    for (const x of list) expect(asked.includes(Buffer.from(x))).toBe(false);
  });

  it('the answer comes after the window, not at once (latency), and a second request joins the same window', async () => {
    h = await start({ batch: { windowMs: 400, max: 100 } });
    const t0 = Date.now();
    const first = h.stamp(sha256('a')).then((r) => ({ r, at: Date.now() - t0 }));
    await sleep(150);
    const second = h.stamp(sha256('b')).then((r) => ({ r, at: Date.now() - t0 }));
    const [a, b] = await Promise.all([first, second]);
    expect(a.at).toBeGreaterThanOrEqual(380); // the window opened with the first request
    expect(a.at).toBeLessThan(2_000);
    expect(Math.abs(a.at - b.at)).toBeLessThan(120); // one window: both are answered together
    expect(((await b.r.json()) as Receipt).batch.size).toBe(2);
    expect(h.calls).toHaveLength(1);
  });

  it('a single request in a window is a tree of one: the path is empty and it verifies', async () => {
    h = await start();
    const x = sha256('alone');
    const body = (await (await h.stamp(x)).json()) as Receipt;
    expect(body.batch).toMatchObject({ v: 1, size: 1, index: 0, path: [] });
    expect((await verifies(body, x)).ok).toBe(true);
  });

  it('the window closes when RELAY_BATCH_MAX is reached; the next request opens a new one', async () => {
    h = await start({ batch: { windowMs: 30_000, max: 3 } });
    const t0 = Date.now();
    const answers = await Promise.all(hashes(6).map((x) => h.stamp(x)));
    expect(Date.now() - t0).toBeLessThan(10_000); // far below the window of 30 s
    const sizes = ((await Promise.all(answers.map((a) => a.json()))) as Receipt[]).map(
      (b) => b.batch.size,
    );
    expect(sizes).toEqual([3, 3, 3, 3, 3, 3]);
    expect(h.calls).toHaveLength(2);
    expect(h.stats()).toMatchObject({ stamped: 2, batched: 6 });
  });

  it('the leaves are shuffled: the position tells nothing about the arrival', async () => {
    // all draws of four bytes are zero: the Fisher-Yates shuffle is then the known permutation [1,2,3,0]
    // (tree position -> arrival), so arrival 0 stands at index 3, arrival 1 at 0, 2 at 1, 3 at 2
    h = await start({
      random: (n) => (n === 4 ? new Uint8Array(4) : new Uint8Array(randomBytes(n))),
      batch: { windowMs: 500, max: 100 },
    });
    const list = hashes(4);
    const pending: Promise<Response>[] = [];
    for (const x of list) {
      pending.push(h.stamp(x));
      await sleep(60); // arrival in this order
    }
    const bodies = (await Promise.all(
      (await Promise.all(pending)).map((a) => a.json()),
    )) as Receipt[];
    expect(bodies.map((b) => b.batch.index)).toEqual([3, 0, 1, 2]);
    for (const [i, body] of bodies.entries())
      expect((await verifies(body, list[i]!)).ok).toBe(true);
  });

  it('a service that fails: every request of the window gets the same 502', async () => {
    h = await start({
      upstream: async () => {
        throw new UpstreamError('failed');
      },
    });
    const answers = await Promise.all(hashes(4).map((x) => h.stamp(x)));
    expect(answers.map((a) => a.status)).toEqual([502, 502, 502, 502]);
    for (const a of answers) expect(await a.json()).toEqual({ error: 'upstream-failed' });
    expect(h.stats()).toEqual({ stamped: 0, refused: { 'upstream-failed': 4 }, batched: 0 });
  });

  it('a timeout is a 504 for all; a refusing service a 502 for all', async () => {
    h = await start({
      upstream: async () => {
        throw new UpstreamError('timeout');
      },
    });
    const a = await Promise.all(hashes(3).map((x) => h.stamp(x)));
    expect(a.map((r) => r.status)).toEqual([504, 504, 504]);
    await h.close();
    h = await start({
      upstream: async () => ({ status: 500, contentType: 'text/plain', body: new Uint8Array() }),
    });
    const b = await Promise.all(hashes(3).map((x) => h.stamp(x)));
    for (const r of b) expect(await r.json()).toEqual({ error: 'upstream-refused' });
  });

  it('a token for another value (the check against the imprint fails): the same 502 for all', async () => {
    h = await start({
      upstream: async (_t, body) => {
        const parts = children(parseDer(body));
        const wrong = build({
          keys: SIGNER.keys,
          hash: sha256('not the imprint'),
          nonceBytes: integerBytes(parts[2]!),
          genTime: genTimeText(NOW),
        });
        return {
          status: 200,
          contentType: 'application/timestamp-reply',
          body: seq(seq(int(0)), wrong.token),
        };
      },
    });
    const answers = await Promise.all(hashes(3).map((x) => h.stamp(x)));
    for (const a of answers) {
      expect(a.status).toBe(502);
      expect(await a.json()).toEqual({ error: 'upstream-invalid', reason: 'imprint-mismatch' });
    }
  });

  it('a token that is too old is counted once, for the window', async () => {
    h = await start({
      upstream: async (_t, body) => ({
        status: 200,
        contentType: 'application/timestamp-reply',
        body: replyFor(body, NOW - 10 * 60_000),
      }),
    });
    const answers = await Promise.all(hashes(3).map((x) => h.stamp(x)));
    for (const a of answers) expect(await a.json()).toMatchObject({ reason: 'time-too-old' });
    expect(h.stats().refused['upstream-too-old']).toBe(1);
  });

  it('the service budget counts one stamp per window, the key budget every request', async () => {
    // two stamps per second for the service (a window of 100 ms at a distance of 500 ms: the second window waits for it)
    const slow = SERVICES.map((s) => ({ ...s, minIntervalMs: 500 }));
    h = await start({
      services: slow,
      batch: { windowMs: 100, max: 100 },
      budgetWindowMs: 1000,
      maxWaitMs: 200, // the slot of a third window is 500 ms away: later than that
    });
    const w1 = await Promise.all(hashes(5, 'a').map((x) => h.stamp(x)));
    expect(w1.map((a) => a.status)).toEqual([200, 200, 200, 200, 200]); // five requests, one stamp
    const w2 = await Promise.all(hashes(3, 'b').map((x) => h.stamp(x)));
    expect(w2.map((a) => a.status)).toEqual([200, 200, 200]);
    const w3 = await h.stamp(sha256('c'));
    expect(w3.status).toBe(429); // the third window: the service is used up
    expect(Number(w3.headers.get('retry-after'))).toBeGreaterThan(0);
    expect(h.calls).toHaveLength(2);
    await h.close();
    // the key: perMinutePerKey counts every request, also inside one window
    h = await start({ batch: { windowMs: 400, max: 100 } });
    const n = RELAY_LIMITS.perMinutePerKey + 1;
    const answers = await Promise.all(hashes(n).map((x) => h.stamp(x, { key: KEY_A })));
    expect(answers.filter((a) => a.status === 200)).toHaveLength(RELAY_LIMITS.perMinutePerKey);
    expect(answers.filter((a) => a.status === 429)).toHaveLength(1);
    const ok = await Promise.all(
      answers.filter((a) => a.status === 200).map((a) => a.json() as Promise<Receipt>),
    );
    expect(ok[0]!.batch.size).toBe(RELAY_LIMITS.perMinutePerKey); // the refused request is not in the tree
    expect(h.calls).toHaveLength(1);
    // another key still gets in (a new window; the service allows 12 stamps per minute)
    const other = await h.stamp(sha256('b-key'), { key: KEY_B });
    expect(other.status).toBe(200);
  });

  it('two services: two windows, two calls, each receipt for its own service', async () => {
    const two = [SERVICES[0]!, { ...SERVICES[0]!, id: 'second' }];
    h = await start({ services: two });
    const answers = await Promise.all([
      h.stamp(sha256('1'), { id: 'freetsa' }),
      h.stamp(sha256('2'), { id: 'second' }),
      h.stamp(sha256('3'), { id: 'freetsa' }),
      h.stamp(sha256('4'), { id: 'second' }),
    ]);
    const bodies = (await Promise.all(answers.map((a) => a.json()))) as Receipt[];
    expect(bodies.map((b) => b.service)).toEqual(['freetsa', 'second', 'freetsa', 'second']);
    expect(bodies.map((b) => b.batch.size)).toEqual([2, 2, 2, 2]);
    expect(h.calls).toHaveLength(2);
    expect(bodies[0]!.token).not.toBe(bodies[1]!.token);
  });

  it('closing: waiting requests are answered with 503, nothing hangs, a new request is refused', async () => {
    h = await start({ batch: { windowMs: 60_000, max: 100 } });
    const waiting = hashes(3).map((x) => h.stamp(x));
    await sleep(200);
    h.relay.close();
    const answers = await Promise.all(waiting);
    expect(answers.map((a) => a.status)).toEqual([503, 503, 503]);
    for (const a of answers) expect(await a.json()).toEqual({ error: 'shutting-down' });
    expect((await h.stamp(sha256('late'))).status).toBe(503);
    expect(h.calls).toHaveLength(0);
    expect(h.stats().refused['shutting-down']).toBe(4);
  });

  it('closing while the service is being asked: that window still finishes', async () => {
    h = await start({ batch: { windowMs: 100, max: 100 }, stampDelayMs: 400 });
    const list = hashes(2);
    const running = list.map((x) => h.stamp(x));
    await sleep(300); // the window is closed and the call is running
    h.relay.close();
    const answers = await Promise.all(running);
    expect(answers.map((a) => a.status)).toEqual([200, 200]);
  });

  it('a client that goes away while it waits: its leaf stays in the tree, the others are served', async () => {
    h = await start({ batch: { windowMs: 400, max: 100 } });
    const abort = new AbortController();
    const gone = h.stamp(sha256('gone'), { signal: abort.signal }).catch(() => null);
    const stays = h.stamp(sha256('stays'));
    await sleep(100);
    abort.abort();
    await gone;
    const body = (await (await stays).json()) as Receipt;
    expect(body.batch.size).toBe(2);
    expect((await verifies(body, sha256('stays'))).ok).toBe(true);
    await sleep(50);
    expect(h.stats().refused['client-aborted']).toBe(1);
  });

  it('a random source of the wrong length ends the window with a 500 for all, never a hang', async () => {
    h = await start({ random: () => new Uint8Array(8) });
    const answers = await Promise.all(hashes(2).map((x) => h.stamp(x)));
    expect(answers.map((a) => a.status)).toEqual([500, 500]);
  });

  it('single stamps stay the default: no batch field, no batched counter, one call each', async () => {
    // 300 ms distance: the second of two requests at once waits for it (single operation keeps the minimum distance)
    h = await start({ batch: null, services: SERVICES.map((s) => ({ ...s, minIntervalMs: 300 })) });
    const answers = await Promise.all(hashes(2).map((x) => h.stamp(x)));
    const bodies = (await Promise.all(answers.map((a) => a.json()))) as Record<string, unknown>[];
    for (const b of bodies) expect('batch' in b).toBe(false);
    expect(h.calls).toHaveLength(2);
    expect(h.stats()).toEqual({ stamped: 2, refused: {} });
    h.relay.close(); // single operation ends too: nothing is stamped after the close
    const after = await h.stamp(sha256('after'));
    expect(after.status).toBe(503);
    expect(await after.json()).toEqual({ error: 'shutting-down' });
    expect(h.calls).toHaveLength(2);
  });
});

describe('relay, collecting operation: settings', () => {
  const base = { RELAY_AUTH: 'off', RELAY_SERVICES: 'freetsa' };
  it('off when not set, empty or 0; the default maximum is 128', () => {
    for (const v of [undefined, '', '0']) {
      const s = readSettings({ ...base, ...(v === undefined ? {} : { RELAY_BATCH_MS: v }) });
      expect(s.batchMs, String(v)).toBeUndefined();
      expect(s.batchMax).toBe(128);
    }
  });
  it('takes whole numbers from 1000 to 60000 and refuses everything else with a German message', () => {
    for (const v of ['1000', '5000', '60000']) {
      expect(readSettings({ ...base, RELAY_BATCH_MS: v }).batchMs).toBe(Number(v));
    }
    for (const v of [
      '999',
      '60001',
      '1.5',
      'abc',
      '-1',
      ' 5000',
      '5000 ',
      '1e4',
      '00',
      '0x1000',
      '5s',
      '١٢٣٤٥',
    ]) {
      expect(() => readSettings({ ...base, RELAY_BATCH_MS: v }), v).toThrow(
        /^RELAY_BATCH_MS: ungültig/,
      );
    }
  });
  it('RELAY_BATCH_MAX: 2 to 1024, default 128, strictly read', () => {
    expect(readSettings({ ...base, RELAY_BATCH_MS: '5000', RELAY_BATCH_MAX: '2' }).batchMax).toBe(
      2,
    );
    expect(
      readSettings({ ...base, RELAY_BATCH_MS: '5000', RELAY_BATCH_MAX: '1024' }).batchMax,
    ).toBe(1024);
    expect(readSettings({ ...base, RELAY_BATCH_MAX: '' }).batchMax).toBe(128);
    for (const v of ['1', '0', '1025', '-3', '2.5', 'x', ' 8', '1e2']) {
      expect(
        () => readSettings({ ...base, RELAY_BATCH_MS: '5000', RELAY_BATCH_MAX: v }),
        v,
      ).toThrow(/^RELAY_BATCH_MAX: ungültig/);
    }
  });
  it('the start refuses a window shorter than the interval of a chosen service', () => {
    const env = { ...base, RELAY_ALLOW_PLAIN_HTTP: '1' };
    expect(readConfig({ ...env, RELAY_BATCH_MS: '5000' }, () => SERVICES).settings.batchMs).toBe(
      5000,
    );
    expect(() => readConfig({ ...env, RELAY_BATCH_MS: '4000' }, () => SERVICES)).toThrow(
      /RELAY_BATCH_MS \(4000\).*freetsa \(5000\)/,
    );
    // sectigo asks for 15 s: 5 s is too short for it, 15 s is fine
    const both = { ...env, RELAY_SERVICES: 'freetsa,sectigo' };
    expect(() => readConfig({ ...both, RELAY_BATCH_MS: '5000' }, () => SERVICES)).toThrow(
      /sectigo \(15000\)/,
    );
    expect(readConfig({ ...both, RELAY_BATCH_MS: '15000' }, () => SERVICES).settings.batchMs).toBe(
      15000,
    );
    // off: no such check
    expect(readConfig({ ...both }, () => SERVICES).settings.batchMs).toBeUndefined();
  });
  it('the start line says the window, and nothing else changes', () => {
    expect(startEvent(8080, SERVICES, 'off')).not.toHaveProperty('batchMs');
    expect(startEvent(8080, SERVICES, 'off', 5000)).toMatchObject({ batchMs: 5000 });
  });
  it('the relay refuses invalid batch options at its creation', () => {
    const options = (batch: { windowMs: number; max: number }): RelayOptions => ({
      services: [],
      origins: [],
      allowPlainHttp: false,
      upstream: async () => {
        throw new Error('unused');
      },
      random: () => new Uint8Array(8),
      now: () => NOW,
      keys: 'off',
      batch,
    });
    expect(() => createRelay(options({ windowMs: 0, max: 4 }))).toThrow();
    expect(() => createRelay(options({ windowMs: 100, max: 1 }))).toThrow();
    expect(() => createRelay(options({ windowMs: 100, max: 1025 }))).toThrow();
    expect(() => createRelay(options({ windowMs: 1.5, max: 4 }))).toThrow();
    expect(() => createRelay(options({ windowMs: 100, max: 1024 }))).not.toThrow();
  });
  it('the limits of the settings are the limits of the library and of the documentation', () => {
    expect(RELAY_LIMITS.batchMaxMax).toBe(BATCH_LIMITS.MAX_SIZE);
    expect(RELAY_LIMITS.batchMaxDefault).toBeLessThanOrEqual(RELAY_LIMITS.batchMaxMax);
    expect(SERVICES.find((s) => s.id === 'freetsa')!.minIntervalMs).toBe(5000);
  });
});
