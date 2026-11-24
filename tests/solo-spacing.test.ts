import { randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { toBase64Url } from '../src/index.ts';
import type { RelayKey } from '../relay/keys.ts';
import { loadServices } from '../relay/load.ts';
import type { RelayOptions } from '../relay/relay.ts';
import { createRelayServer } from '../relay/server.ts';
import type { Upstream } from '../relay/upstream.ts';
import { makeTestKey, nodeAuthHeader, type TestKey } from './auth-helpers.ts';
import { sha256 } from './helpers.ts';
import { build, int, seq } from './token-builder.ts';
import { children, integerBytes, octets, parseDer } from '../src/lib/der.ts';

// The minimum spacing: two calls of the relay to one service (one identity) are at least `minIntervalMs` apart,
// whether the one before was a window or a solo stamp of key type 2 (on top of the sliding budget). A stub service
// records the time of every call. Real clock; `minIntervalMs` 600 ms, so a test takes a few seconds at most.

const SERVICES = loadServices().filter((s) => s.id === 'freetsa');
const SIGNER = build();
const ORIGIN = 'https://app.example';
const KEY_A = makeTestKey('app-a'); // type 1
const KEY_B = makeTestKey('app-b'); // type 2
const KEY_F = makeTestKey('app-f'); // type 1
const KEY_C = makeTestKey('app-c'); // type 2
const KEY_D = makeTestKey('app-d'); // type 2
const asRelayKey = (k: TestKey, solo: boolean): RelayKey => ({
  id: k.id,
  publicKey: k.publicKey,
  ...(solo ? { solo: true } : {}),
});
const KEYS: RelayKey[] = [
  asRelayKey(KEY_A, false),
  asRelayKey(KEY_B, true),
  asRelayKey(KEY_C, true),
  asRelayKey(KEY_D, true),
  asRelayKey(KEY_F, false),
];

const genTimeText = (ms: number) =>
  new Date(ms)
    .toISOString()
    .replace(/[-:T]/g, '')
    .replace(/\.\d+Z$/, 'Z');

/** The imprint a request to a service carries (what the service is asked to stamp). */
function imprintOf(request: Uint8Array): Uint8Array {
  return octets(children(children(parseDer(request))[1]!)[1]!);
}

function replyFor(request: Uint8Array): Uint8Array {
  const parts = children(parseDer(request));
  const made = build({
    keys: SIGNER.keys,
    hash: imprintOf(request),
    nonceBytes: integerBytes(parts[2]!),
    genTime: genTimeText(Date.now()),
  });
  return seq(seq(int(0)), made.token);
}

interface Harness {
  calls: { imprint: Uint8Array; at: number }[];
  /** The relay's clock is the real one plus `offset` ms (the tests set it back); requests are signed with it. */
  clock: { offset: number };
  relay: ReturnType<typeof createRelayServer>['relay'];
  stats: ReturnType<typeof createRelayServer>['relay']['stats'];
  stamp: (
    hash: Uint8Array,
    over?: {
      key?: TestKey;
      body?: unknown;
      raw?: string;
      signedRaw?: string;
      type?: string;
      head?: string;
    },
  ) => Promise<Response>;
  /** Like `stamp`, plus the time until the answer. */
  timed: (hash: Uint8Array, over?: { key?: TestKey; body?: unknown }) => Promise<Timed>;
  close: () => Promise<void>;
}
interface Timed {
  res: Response;
  at: number;
}

async function start(
  over: {
    batch?: { windowMs: number; max: number } | null;
    minIntervalMs?: number;
    budgetWindowMs?: number;
    maxWaitMs?: number;
    stampDelayMs?: number;
    keys?: RelayKey[];
  } = {},
): Promise<Harness> {
  const calls: Harness['calls'] = [];
  const clock = { offset: 0 };
  const t0 = Date.now();
  const stub: Upstream = async (_t, body) => {
    calls.push({ imprint: imprintOf(body), at: Date.now() - t0 });
    if (over.stampDelayMs) await new Promise((r) => setTimeout(r, over.stampDelayMs));
    return { status: 200, contentType: 'application/timestamp-reply', body: replyFor(body) };
  };
  const batch = over.batch === undefined ? { windowMs: 100, max: 100 } : over.batch;
  const options: RelayOptions = {
    services: SERVICES.map((s) => ({
      ...s,
      minIntervalMs: over.minIntervalMs ?? 1000,
      anchorPems: [...s.anchorPems, SIGNER.caPem],
    })),
    origins: [ORIGIN],
    allowPlainHttp: false,
    upstream: stub,
    random: (n) => new Uint8Array(randomBytes(n)),
    now: () => Date.now() + clock.offset,
    keys: over.keys ?? KEYS,
    ...(batch === null ? {} : { batch }),
    ...(over.maxWaitMs === undefined ? {} : { maxWaitMs: over.maxWaitMs }),
    ...(over.budgetWindowMs === undefined ? {} : { budgetWindowMs: over.budgetWindowMs }),
  };
  const { server, relay } = createRelayServer(options);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const stamp: Harness['stamp'] = (hash, o = {}) => {
    const path = '/v1/stamp/freetsa';
    const key = o.key ?? KEY_A;
    const text = o.raw ?? JSON.stringify(o.body ?? { hash: toBase64Url(hash) });
    const head =
      o.head ??
      nodeAuthHeader(
        key,
        key.id,
        'POST',
        path,
        Math.floor((Date.now() + clock.offset) / 1000),
        new TextEncoder().encode(o.signedRaw ?? text),
      );
    return fetch(base + path, {
      method: 'POST',
      body: text,
      headers: { 'Content-Type': o.type ?? 'application/json', 'X-Zeitstempel-Auth': head },
    });
  };
  return {
    calls,
    clock,
    relay,
    stats: relay.stats,
    stamp,
    timed: async (hash, o = {}) => {
      const started = Date.now();
      const res = await stamp(hash, o);
      return { res, at: Date.now() - started };
    },
    close: () =>
      new Promise((r) => {
        relay.close();
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}

const solo = (hash: Uint8Array) => ({ hash: toBase64Url(hash), mode: 'solo' });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const same = (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));

const M = 600; // minIntervalMs
const TOL = 40; // timers and the clock of the test process are not exact

/** The gaps between the calls the service saw, in the order of the calls. */
function gaps(calls: { at: number }[]): number[] {
  const times = calls.map((c) => c.at).sort((a, b) => a - b);
  return times.slice(1).map((t, i) => t - times[i]!);
}
const expectSpaced = (calls: { at: number }[]) => {
  for (const g of gaps(calls)) expect(g).toBeGreaterThanOrEqual(M - TOL);
};

describe('minimum spacing between two calls to one service (key type 2 solo, windows)', () => {
  let h: Harness;
  afterEach(() => h.close());
  const full = { windowMs: M, max: 2 }; // two requests close a window at once

  it('a solo stamp right after a window keeps the distance', async () => {
    h = await start({
      batch: { windowMs: M, max: 100 },
      minIntervalMs: M,
      budgetWindowMs: 4 * M,
      maxWaitMs: 8000,
    });
    expect((await h.stamp(sha256('w'), { key: KEY_F })).status).toBe(200); // the window stamps at about M
    const x = sha256('solo-after-window');
    const t = await h.timed(x, { key: KEY_B, body: solo(x) });
    expect(t.res.status).toBe(200);
    expect(h.calls).toHaveLength(2);
    expect(same(h.calls[1]!.imprint, x)).toBe(true);
    expectSpaced(h.calls);
    expect(t.at).toBeGreaterThanOrEqual(M - 2 * TOL); // it waited for the distance (the window was stamped just before)
  });

  it('a window right after a solo stamp keeps the distance, also when it closes full at once', async () => {
    h = await start({ batch: full, minIntervalMs: M, budgetWindowMs: 4 * M, maxWaitMs: 8000 });
    const x = sha256('solo-first');
    expect((await h.stamp(x, { key: KEY_B, body: solo(x) })).status).toBe(200);
    const riders = await Promise.all([
      h.stamp(sha256('r1'), { key: KEY_F }),
      h.stamp(sha256('r2'), { key: KEY_A }),
    ]);
    expect(riders.map((r) => r.status)).toEqual([200, 200]);
    const sizes = await Promise.all(
      riders.map(async (r) => ((await r.json()) as { batch: { size: number } }).batch.size),
    );
    expect(sizes).toEqual([2, 2]);
    expect(h.calls).toHaveLength(2);
    expectSpaced(h.calls);
  });

  it('a solo stamp that comes while a closed window still waits for the distance keeps it to the window, not only to the last call made', async () => {
    h = await start({ batch: full, minIntervalMs: M, budgetWindowMs: 4 * M, maxWaitMs: 8000 });
    const x = sha256('solo-first');
    expect((await h.stamp(x, { key: KEY_B, body: solo(x) })).status).toBe(200); // call 1 at about 0
    const r1 = h.stamp(sha256('r1'), { key: KEY_F }); // opens a window
    await sleep(40);
    const y = sha256('solo-second');
    const soloSecond = h.stamp(y, { key: KEY_C, body: solo(y) }); // waits for the distance to call 1 (until about M)
    await sleep(40);
    const r2 = h.stamp(sha256('r2'), { key: KEY_A }); // the window is full: its call waits for the distance to call 1 too
    const riders = [r1, r2];
    const second = await soloSecond; // free at M after call 1 without the window, but the window calls at M first
    expect(second.status).toBe(200);
    expect((await Promise.all(riders)).map((r) => r.status)).toEqual([200, 200]);
    expect(h.calls).toHaveLength(3);
    expect(same(h.calls[2]!.imprint, y)).toBe(true); // the solo stamp came after the window, not before it
    expectSpaced(h.calls);
  });

  it('a solo stamp at the door counts the window that waits for the distance: later than the waiting limit is 429', async () => {
    h = await start({ batch: full, minIntervalMs: M, budgetWindowMs: 4 * M, maxWaitMs: 1000 });
    const x = sha256('solo-first');
    expect((await h.stamp(x, { key: KEY_B, body: solo(x) })).status).toBe(200); // call 1 at about 0
    const riders = [h.stamp(sha256('r1'), { key: KEY_F }), h.stamp(sha256('r2'), { key: KEY_A })];
    await sleep(100); // the window is full and closed: its call is at about M, the next free time for a solo is 2 M
    const y = sha256('solo-behind-window');
    const t = await h.timed(y, { key: KEY_C, body: solo(y) }); // 2 M - 100 ms = 1100 ms away: more than 1000 ms
    expect(t.res.status).toBe(429);
    expect(t.at).toBeLessThan(400);
    expect((await Promise.all(riders)).map((r) => r.status)).toEqual([200, 200]);
    expect(h.calls).toHaveLength(2); // the refused solo stamp never reached the service
    expectSpaced(h.calls);
  });

  it('two solo stamps in a row keep the distance (the second waits)', async () => {
    h = await start({
      batch: { windowMs: M, max: 100 },
      minIntervalMs: M,
      budgetWindowMs: 4 * M,
      maxWaitMs: 8000,
    });
    const [a, b] = [sha256('s1'), sha256('s2')];
    const [ra, rb] = await Promise.all([
      h.stamp(a, { key: KEY_B, body: solo(a) }),
      h.stamp(b, { key: KEY_C, body: solo(b) }),
    ]);
    expect([ra.status, rb.status]).toEqual([200, 200]);
    expect(h.calls).toHaveLength(2);
    expectSpaced(h.calls);
  });

  it('two full windows in a row keep the distance', async () => {
    h = await start({ batch: full, minIntervalMs: M, budgetWindowMs: 4 * M, maxWaitMs: 8000 });
    const answers = await Promise.all(
      [0, 1, 2, 3].map((i) => h.stamp(sha256(`n${i}`), { key: i % 2 ? KEY_F : KEY_A })),
    );
    expect(answers.map((r) => r.status)).toEqual([200, 200, 200, 200]);
    expect(h.calls).toHaveLength(2);
    expectSpaced(h.calls);
  });

  it('a mixture of solo stamps and windows (full and timed) never gets closer than the distance', async () => {
    h = await start({ batch: full, minIntervalMs: M, budgetWindowMs: 4 * M, maxWaitMs: 10_000 });
    const s = [sha256('m1'), sha256('m2'), sha256('m3')];
    const sent = [
      h.stamp(s[0]!, { key: KEY_B, body: solo(s[0]!) }),
      h.stamp(sha256('n1'), { key: KEY_F }),
      h.stamp(sha256('n2'), { key: KEY_A }),
      h.stamp(s[1]!, { key: KEY_C, body: solo(s[1]!) }),
      h.stamp(sha256('n3'), { key: KEY_F }), // a window of one: closes with its timer
      h.stamp(s[2]!, { key: KEY_D, body: solo(s[2]!) }),
    ];
    await sleep(30);
    const answers = await Promise.all(sent);
    for (const a of answers) expect([200, 503]).toContain(a.status);
    expect(h.calls.length).toBeGreaterThanOrEqual(4);
    expectSpaced(h.calls);
  });

  it('the distance is not needed when it has passed: a solo stamp is served at once', async () => {
    h = await start({ batch: { windowMs: M, max: 100 }, minIntervalMs: M, maxWaitMs: 8000 });
    const a = sha256('first');
    expect((await h.stamp(a, { key: KEY_B, body: solo(a) })).status).toBe(200);
    await sleep(M + 100);
    const b = sha256('second');
    const t = await h.timed(b, { key: KEY_C, body: solo(b) });
    expect(t.res.status).toBe(200);
    expect(t.at).toBeLessThan(250);
  });

  it('the first stamp of a fresh relay is served at once', async () => {
    h = await start({ batch: { windowMs: M, max: 100 }, minIntervalMs: M });
    const a = sha256('fresh');
    const t = await h.timed(a, { key: KEY_B, body: solo(a) });
    expect(t.res.status).toBe(200);
    expect(t.at).toBeLessThan(250);
  });

  it('a distance that is longer than the waiting limit at once is 429 with Retry-After, like a slot that is too late', async () => {
    h = await start({ batch: { windowMs: 3000, max: 100 }, minIntervalMs: 3000, maxWaitMs: 1000 });
    const a = sha256('first');
    expect((await h.stamp(a, { key: KEY_B, body: solo(a) })).status).toBe(200);
    const b = sha256('second');
    const t = await h.timed(b, { key: KEY_C, body: solo(b) });
    expect(t.res.status).toBe(429);
    expect(Number(t.res.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    expect(t.at).toBeLessThan(400); // no waiting
    expect(h.calls).toHaveLength(1);
  });

  it('a solo stamp that waits for the distance longer than the waiting limit is 503 busy and is never stamped', async () => {
    h = await start({
      batch: { windowMs: M, max: 100 },
      minIntervalMs: M,
      budgetWindowMs: 8 * M,
      maxWaitMs: 1000,
    });
    const xs = [sha256('b1'), sha256('b2'), sha256('b3')];
    const keys = [KEY_B, KEY_C, KEY_D];
    const answers = await Promise.all(
      xs.map((x, i) => h.stamp(x, { key: keys[i]!, body: solo(x) })),
    );
    expect(answers.map((a) => a.status).sort()).toEqual([200, 200, 503]);
    await sleep(900);
    expect(h.calls).toHaveLength(2); // the third never reached the service
    expectSpaced(h.calls);
  });

  it('close() while a window waits for the distance: shutting-down for its requests, no call after the close', async () => {
    h = await start({ batch: full, minIntervalMs: 2000, budgetWindowMs: 8000, maxWaitMs: 8000 });
    const x = sha256('solo');
    expect((await h.stamp(x, { key: KEY_B, body: solo(x) })).status).toBe(200);
    const riders = [h.stamp(sha256('r1'), { key: KEY_F }), h.stamp(sha256('r2'), { key: KEY_A })];
    await sleep(150); // the window is full and closed, its stamp waits for the distance
    h.relay.close();
    const answers = await Promise.all(riders);
    expect(answers.map((a) => a.status)).toEqual([503, 503]);
    expect(await answers[0]!.json()).toEqual({ error: 'shutting-down' });
    await sleep(100);
    expect(h.calls).toHaveLength(1);
  });
});
