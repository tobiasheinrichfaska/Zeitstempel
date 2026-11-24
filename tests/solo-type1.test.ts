import { randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { toBase64Url } from '../src/index.ts';
import type { RelayKey } from '../relay/keys.ts';
import { loadServices } from '../relay/load.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import type { RelayOptions } from '../relay/relay.ts';
import { createRelayServer } from '../relay/server.ts';
import type { Upstream } from '../relay/upstream.ts';
import { makeTestKey, nodeAuthHeader, type TestKey } from './auth-helpers.ts';
import { sha256 } from './helpers.ts';
import { build, int, seq } from './token-builder.ts';
import { children, integerBytes, octets, parseDer } from '../src/lib/der.ts';

// Key type 1 asks for `mode: "solo"` (collecting operation): it takes no slot of its own. It waits the whole collecting
// time of a window; alone in the window at the close it is stamped directly, else `403 solo-not-allowed` (it stays out
// of the tree). Key type 2 is unchanged (at once, a slot of its own). Real clock, short windows.

const SERVICES = loadServices().filter((s) => s.id === 'freetsa');
const SIGNER = build();
const ORIGIN = 'https://app.example';
const KEY_A = makeTestKey('app-a'); // type 1
const KEY_B = makeTestKey('app-b'); // type 2
const KEY_F = makeTestKey('app-f'); // type 1
const asRelayKey = (k: TestKey, solo: boolean): RelayKey => ({
  id: k.id,
  publicKey: k.publicKey,
  ...(solo ? { solo: true } : {}),
});
const KEYS: RelayKey[] = [
  asRelayKey(KEY_A, false),
  asRelayKey(KEY_B, true),
  asRelayKey(KEY_F, false),
];
const KEY_C = makeTestKey('app-c'); // type 2
const KEY_D = makeTestKey('app-d'); // type 2
const KEY_G = makeTestKey('app-g'); // type 1

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
const W = 400; // the window

describe('key type 1 asks for solo: alone in the window it is stamped directly after the collecting time', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('alone: waits the full window, then a direct stamp of its own hash (no batch field), counted as solo', async () => {
    h = await start({ batch: { windowMs: W, max: 100 } });
    const x = sha256('alone');
    const t = await h.timed(x, { key: KEY_A, body: solo(x) });
    expect(t.res.status).toBe(200);
    expect(t.at).toBeGreaterThanOrEqual(W - 30);
    const body = (await t.res.json()) as Record<string, unknown>;
    expect(Object.keys(body)).not.toContain('batch');
    expect(h.calls).toHaveLength(1);
    expect(same(h.calls[0]!.imprint, x)).toBe(true); // the unchanged hash
    expect(h.calls[0]!.at).toBeGreaterThanOrEqual(W - 30); // not before the window closed
    expect(h.stats()).toEqual({ stamped: 1, refused: {}, batched: 0, solo: 1 });
  });

  it('with another hash in the window: 403 after the window, the other one gets its receipt, one stamp for the window', async () => {
    h = await start({ batch: { windowMs: W, max: 100 } });
    const x = sha256('solo-with-other');
    const y = sha256('the-other');
    const other = h.stamp(y, { key: KEY_F }); // opens the window
    await sleep(100);
    const t = await h.timed(x, { key: KEY_A, body: solo(x) });
    expect(t.res.status).toBe(403);
    expect(await t.res.json()).toEqual({ error: 'solo-not-allowed' });
    expect(t.at).toBeGreaterThanOrEqual(W - 100 - 40); // it waited for the close, not an answer at the door
    const got = await other;
    expect(got.status).toBe(200);
    const receipt = (await got.json()) as { batch: { size: number } };
    expect(receipt.batch.size).toBe(1); // the refused solo request is not in the tree
    expect(h.calls).toHaveLength(1);
    expect(same(h.calls[0]!.imprint, x)).toBe(false);
    expect(h.stats()).toMatchObject({
      soloDenied: 1,
      batched: 1,
      refused: { 'solo-not-allowed': 1 },
    });
    expect(h.stats().solo).toBeUndefined();
  });

  it('the solo request is the first in the window and another comes later: still 403 (not alone at the close)', async () => {
    h = await start({ batch: { windowMs: W, max: 100 } });
    const x = sha256('first-solo');
    const first = h.stamp(x, { key: KEY_A, body: solo(x) });
    await sleep(100);
    const later = h.stamp(sha256('later'), { key: KEY_F });
    expect((await first).status).toBe(403);
    expect((await later).status).toBe(200);
    expect(h.calls).toHaveLength(1);
    expect(same(h.calls[0]!.imprint, x)).toBe(false);
  });

  it('several type 1 solo requests in one window: all 403, none in the tree, the service sees no stamp at all', async () => {
    h = await start({ batch: { windowMs: W, max: 100 } });
    const xs = [sha256('s1'), sha256('s2'), sha256('s3')];
    const answers = await Promise.all(
      xs.map((x, i) => h.stamp(x, { key: i === 2 ? KEY_F : KEY_A, body: solo(x) })),
    );
    expect(answers.map((a) => a.status)).toEqual([403, 403, 403]);
    expect(h.calls).toHaveLength(0);
    expect(h.stats()).toMatchObject({ soloDenied: 3, refused: { 'solo-not-allowed': 3 } });
    expect(h.stats().stamped).toBe(0);
  });

  it('several solo requests and one normal one: the solo ones are 403, the normal one is a tree of one leaf', async () => {
    h = await start({ batch: { windowMs: W, max: 100 } });
    const [a, b, n] = [sha256('p1'), sha256('p2'), sha256('pn')];
    const answers = await Promise.all([
      h.stamp(a, { key: KEY_A, body: solo(a) }),
      h.stamp(b, { key: KEY_F, body: solo(b) }),
      h.stamp(n, { key: KEY_F }),
    ]);
    expect(answers.map((x) => x.status)).toEqual([403, 403, 200]);
    expect(((await answers[2]!.json()) as { batch: { size: number } }).batch.size).toBe(1);
    expect(h.calls).toHaveLength(1);
  });

  it('a window that held only refused solo requests books no slot: the next window opens at once', async () => {
    h = await start({
      batch: { windowMs: 150, max: 100 },
      minIntervalMs: 1000,
      budgetWindowMs: 1000,
      maxWaitMs: 4000,
    });
    const xs = [sha256('t1'), sha256('t2')];
    const refused = await Promise.all(xs.map((x) => h.stamp(x, { key: KEY_A, body: solo(x) })));
    expect(refused.map((r) => r.status)).toEqual([403, 403]);
    const t = await h.timed(sha256('after'), { key: KEY_F });
    expect(t.res.status).toBe(200);
    expect(t.at).toBeLessThan(150 + 400); // window only: it did not wait for a booked slot of a second
  });

  it('the 403 after the waiting has spent the budgets: the solo limit per key counts it', async () => {
    h = await start({ batch: { windowMs: 200, max: 100 }, minIntervalMs: 1000 });
    const limit = RELAY_LIMITS.soloPerMinutePerKey;
    const xs = Array.from({ length: limit }, (_, i) => sha256(`b${i}`));
    const answers = await Promise.all(xs.map((x) => h.stamp(x, { key: KEY_A, body: solo(x) })));
    expect(answers.map((a) => a.status)).toEqual(Array(limit).fill(403));
    const x = sha256('one-more');
    const over = await h.stamp(x, { key: KEY_A, body: solo(x) });
    expect(over.status).toBe(429);
    expect(over.headers.get('retry-after')).not.toBeNull();
  });

  it('a type 1 solo request joins a window that is open without a slot of its own', async () => {
    h = await start({
      batch: { windowMs: 300, max: 100 },
      minIntervalMs: 1000,
      budgetWindowMs: 1000,
    });
    const n = h.stamp(sha256('opens')); // the one slot of the second is the window's
    await sleep(50);
    const x = sha256('joins');
    const t = await h.timed(x, { key: KEY_A, body: solo(x) });
    expect(t.res.status).toBe(403); // not 429: it joined the open window
    expect((await n).status).toBe(200);
  });

  it('the queue limit of solo stamps is for type 2 only: a full queue does not turn type 1 solo requests away with 503 busy', async () => {
    const max = RELAY_LIMITS.soloQueueMax;
    h = await start({
      batch: { windowMs: 100, max: 100 },
      minIntervalMs: 200,
      budgetWindowMs: 200,
      maxWaitMs: 8000,
      keys: [...KEYS, asRelayKey(KEY_C, true), asRelayKey(KEY_D, true), asRelayKey(KEY_G, false)],
    });
    const type2 = [KEY_B, KEY_C, KEY_D];
    // one type 2 stamp takes the slot, `max` wait in the queue of the service: the queue is full
    const queued = Array.from({ length: max + 1 }, (_, i) => {
      const x = sha256(`full${i}`);
      return h.stamp(x, { key: type2[i % type2.length]!, body: solo(x) });
    });
    await sleep(60);
    // more type 1 solo requests than the queue holds (`max` + 2, from two keys, each within its own solo limit)
    const type1 = Array.from({ length: max + 2 }, (_, i) => {
      const x = sha256(`t1-${i}`);
      return h.stamp(x, { key: i % 2 === 0 ? KEY_A : KEY_G, body: solo(x) });
    });
    const statuses = (await Promise.all(type1)).map((r) => r.status);
    expect(statuses).not.toContain(503);
    expect(statuses.every((st) => st === 200 || st === 403)).toBe(true);
    expect(h.stats().refused['busy']).toBeUndefined();
    expect((await Promise.all(queued)).map((r) => r.status)).toEqual(Array(max + 1).fill(200));
  });

  it('type 2 is unchanged: at once, a direct stamp, also while a window is open', async () => {
    h = await start({ batch: { windowMs: 600, max: 100 } });
    const x = sha256('type2');
    const t = await h.timed(x, { key: KEY_B, body: solo(x) });
    expect(t.res.status).toBe(200);
    expect(t.at).toBeLessThan(300);
    expect(same(h.calls[0]!.imprint, x)).toBe(true);
    expect(h.calls[0]!.at).toBeLessThan(300);
  });

  it('a type 2 stamp does not make a type 1 solo request "not alone" (only entries of its own window count)', async () => {
    h = await start({ batch: { windowMs: W, max: 100 } });
    const x = sha256('a-alone');
    const a = h.stamp(x, { key: KEY_A, body: solo(x) });
    await sleep(50);
    const z = sha256('b-direct');
    expect((await h.stamp(z, { key: KEY_B, body: solo(z) })).status).toBe(200);
    expect((await a).status).toBe(200);
    expect(h.calls.map((c) => same(c.imprint, x) || same(c.imprint, z))).toEqual([true, true]);
  });

  it('flood: type 1 solo requests that arrive together leave the window to the normal request (E1)', async () => {
    // a 1.5 s service (4 slots per 6 s) as in the audit: four solo requests of one key at once
    h = await start({
      batch: { windowMs: 300, max: 100 },
      minIntervalMs: 1500,
      budgetWindowMs: 6000,
      maxWaitMs: 1000,
    });
    const xs = Array.from({ length: 4 }, (_, i) => sha256(`flood${i}`));
    const flood = xs.map((x) => h.stamp(x, { key: KEY_A, body: solo(x) }));
    await sleep(20);
    const n = await h.stamp(sha256('normal-b'), { key: KEY_F });
    expect(n.status).toBe(200);
    expect(((await n.json()) as { batch: { size: number } }).batch.size).toBe(1);
    expect((await Promise.all(flood)).map((r) => r.status)).toEqual([403, 403, 403, 403]);
    expect(h.calls).toHaveLength(1); // one stamp for the window; the solo requests took no slot
  });

  it('flood in a row: each solo request waits a window and takes at most the one slot of that window', async () => {
    h = await start({
      batch: { windowMs: 200, max: 100 },
      minIntervalMs: 1500,
      budgetWindowMs: 6000,
      maxWaitMs: 1000,
    });
    // the second one meets a normal request in its window: it takes no slot at all
    const x1 = sha256('row1');
    expect((await h.stamp(x1, { key: KEY_A, body: solo(x1) })).status).toBe(200);
    const x2 = sha256('row2');
    const second = h.stamp(x2, { key: KEY_A, body: solo(x2) });
    await sleep(40);
    const n = h.stamp(sha256('normal'), { key: KEY_F });
    expect((await second).status).toBe(403);
    expect((await n).status).toBe(200);
    expect(h.calls).toHaveLength(2); // two stamps, two slots (the first solo one and the shared window)
  });

  it('close() while a type 1 solo request waits in its window: 503 shutting-down, nothing stamped', async () => {
    h = await start({ batch: { windowMs: 2000, max: 100 } });
    const x = sha256('closing');
    const waiting = h.stamp(x, { key: KEY_A, body: solo(x) });
    await sleep(100);
    h.relay.close();
    const res = await waiting;
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: 'shutting-down' });
    expect(h.calls).toHaveLength(0);
  });

  it('without collecting operation `mode: "solo"` stays without effect: a direct stamp at once', async () => {
    h = await start({ batch: null });
    const x = sha256('no-batch');
    const t = await h.timed(x, { key: KEY_A, body: solo(x) });
    expect(t.res.status).toBe(200);
    expect(t.at).toBeLessThan(300);
  });
});
