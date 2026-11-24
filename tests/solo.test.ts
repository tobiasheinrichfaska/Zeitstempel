import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { toBase64Url } from '../src/index.ts';
import { readKeyFileFull, type KeyFile, type RelayKey } from '../relay/keys.ts';
import { createKeyWatcher } from '../relay/keywatch.ts';
import { loadServices } from '../relay/load.ts';
import { readSettings } from '../relay/main.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import type { RelayOptions } from '../relay/relay.ts';
import { createRelayServer } from '../relay/server.ts';
import type { Upstream } from '../relay/upstream.ts';
import { makeTestKey, nodeAuthHeader, type TestKey } from './auth-helpers.ts';
import { sha256 } from './helpers.ts';
import { build, int, seq } from './token-builder.ts';
import { children, integerBytes, octets, parseDer } from '../src/lib/der.ts';

// Key type 2 (solo), the planner of the collecting operation, the key file read again while running.
// Real clock and real timers: the budget window is made short (`budgetWindowMs`) so that a test need not wait a minute.

const SERVICES = loadServices().filter((s) => s.id === 'freetsa');
const SIGNER = build();
const ORIGIN = 'https://app.example';
const KEY_A = makeTestKey('app-a'); // type 1
const KEY_B = makeTestKey('app-b'); // type 2
const KEY_C = makeTestKey('app-c'); // type 2
const KEY_D = makeTestKey('app-d'); // type 2
const KEY_E = makeTestKey('app-e'); // type 2
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
  asRelayKey(KEY_E, true),
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

describe('key type 2: who may ask for a solo stamp (collecting operation)', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('type 2 gets a direct stamp of its hash (no tree, no batch field), counted as solo', async () => {
    h = await start();
    const x = sha256('solo-b');
    const res = await h.stamp(x, { key: KEY_B, body: solo(x) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual([
      'accuracyMs',
      'genTime',
      'serial',
      'service',
      'token',
    ]);
    expect(h.calls).toHaveLength(1);
    expect(same(h.calls[0]!.imprint, x)).toBe(true); // the service stamped the hash itself
    expect(h.stats()).toEqual({ stamped: 1, refused: {}, batched: 0, solo: 1 });
  });

  it('type 1 gets a direct stamp after the collecting time when it is alone in the window', async () => {
    h = await start();
    const x = sha256('solo-a');
    const res = await h.stamp(x, { key: KEY_A, body: solo(x) });
    expect(res.status).toBe(200);
    expect(Object.keys((await res.json()) as object)).not.toContain('batch');
    expect(same(h.calls[0]!.imprint, x)).toBe(true);
  });

  it('type 1 is refused with 403 solo-not-allowed (after the window) when another request is in its window', async () => {
    h = await start({ batch: { windowMs: 400, max: 100 } });
    const waiting = h.stamp(sha256('normal')); // opens the window
    await sleep(100);
    const x = sha256('solo-a2');
    const denied = await h.stamp(x, { key: KEY_A, body: solo(x) });
    expect(denied.status).toBe(403);
    expect(await denied.json()).toEqual({ error: 'solo-not-allowed' });
    expect((await waiting).status).toBe(200); // the window itself is not disturbed
    expect(h.calls).toHaveLength(1);
    expect(h.stats()).toMatchObject({ soloDenied: 1, refused: { 'solo-not-allowed': 1 } });
  });

  it('type 1 is also refused when it meets the request that waited in the queue of the service in one window', async () => {
    // one slot per second: the first stamp takes it, the next normal request waits for the next one
    h = await start({ minIntervalMs: 1000, budgetWindowMs: 1000, maxWaitMs: 4000 });
    const first = await h.stamp(sha256('first'), { key: KEY_B, body: solo(sha256('first')) });
    expect(first.status).toBe(200);
    const queued = h.stamp(sha256('queued')); // waits for the slot
    await sleep(150);
    const x = sha256('solo-a3');
    const denied = await h.stamp(x, { key: KEY_A, body: solo(x) });
    expect(denied.status).toBe(403);
    expect((await queued).status).toBe(200);
  });

  it('type 2 gets its solo stamp even while a window is open; the window finishes on its own', async () => {
    h = await start({ batch: { windowMs: 400, max: 100 } });
    const waiting = [h.stamp(sha256('n1')), h.stamp(sha256('n2'))];
    await sleep(100);
    const x = sha256('solo-b2');
    const direct = await h.stamp(x, { key: KEY_B, body: solo(x) });
    expect(direct.status).toBe(200);
    expect(Object.keys((await direct.json()) as object)).not.toContain('batch');
    const answers = await Promise.all(waiting);
    expect(answers.map((a) => a.status)).toEqual([200, 200]);
    expect(((await answers[0]!.json()) as { batch: { size: number } }).batch.size).toBe(2);
    expect(h.calls).toHaveLength(2);
  });

  it('without collecting operation `mode: "solo"` is a no-op: every request is direct, no key-type check', async () => {
    h = await start({ batch: null });
    const x = sha256('plain');
    const res = await h.stamp(x, { key: KEY_A, body: solo(x) }); // type 1, still served
    expect(res.status).toBe(200);
    expect(same(h.calls[0]!.imprint, x)).toBe(true);
    const y = sha256('plain2');
    expect((await h.stamp(y)).status).toBe(200); // no mode: as always
    expect(h.stats()).toEqual({ stamped: 2, refused: {} }); // no solo counters, nothing new in single operation
  });

  it('without collecting operation `mode: "solo"` is not limited like a solo stamp (no per-key solo limit)', async () => {
    h = await start({ batch: null, minIntervalMs: 1000 });
    const more = RELAY_LIMITS.soloPerMinutePerKey + 2;
    for (let i = 0; i < more; i += 1) {
      const x = sha256(`ns${i}`);
      expect((await h.stamp(x, { key: KEY_B, body: solo(x) })).status, `request ${i}`).toBe(200);
    }
    expect(h.stats()).toEqual({ stamped: more, refused: {} });
  });

  it('single operation keeps its old budget answer: 429 with Retry-After, no waiting', async () => {
    h = await start({ batch: null, minIntervalMs: 30_000 }); // two stamps per minute
    for (const t of ['a', 'b']) expect((await h.stamp(sha256(t))).status).toBe(200);
    const third = await h.timed(sha256('c'));
    expect(third.res.status).toBe(429);
    expect(Number(third.res.headers.get('retry-after'))).toBeGreaterThan(0);
    expect(third.at).toBeLessThan(1000);
  });
});

describe('the mode is part of the signed body', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('a body changed after signing (mode added or removed) is a 401', async () => {
    h = await start();
    const x = sha256('bound');
    const plain = JSON.stringify({ hash: toBase64Url(x) });
    const withMode = JSON.stringify(solo(x));
    // signed without the mode, sent with it: type 2 must not get a solo stamp by editing the body
    const added = await h.stamp(x, { key: KEY_B, raw: withMode, signedRaw: plain });
    expect(added.status).toBe(401);
    // signed with the mode, sent without it
    const removed = await h.stamp(x, { key: KEY_B, raw: plain, signedRaw: withMode });
    expect(removed.status).toBe(401);
    expect(h.calls).toHaveLength(0);
  });

  it('an unknown mode or a wrong type is 400, other fields stay 400 bad-hash', async () => {
    h = await start();
    const hash = toBase64Url(sha256('modes'));
    for (const mode of ['normal', 'SOLO', '', 'batch', 1, null, true, ['solo'], { a: 1 }]) {
      const res = await h.stamp(sha256('m'), { key: KEY_B, body: { hash, mode } });
      expect(res.status, JSON.stringify(mode)).toBe(400);
      expect(await res.json()).toEqual({ error: 'bad-mode' });
    }
    const extra = await h.stamp(sha256('m'), { key: KEY_B, body: { hash, mode: 'solo', x: 1 } });
    expect(extra.status).toBe(400);
    expect(await extra.json()).toEqual({ error: 'bad-hash' });
    const onlyMode = await h.stamp(sha256('m'), { key: KEY_B, body: { mode: 'solo' } });
    expect(await onlyMode.json()).toEqual({ error: 'bad-hash' });
    expect(h.calls).toHaveLength(0);
  });
});

describe('planner: a solo stamp takes a whole slot of the service, the rest waits', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('one slot per second: a solo stamp takes it, a waiting window is served after it', async () => {
    h = await start({ minIntervalMs: 1000, budgetWindowMs: 1000, maxWaitMs: 5000 });
    const x = sha256('s');
    const first = await h.timed(x, { key: KEY_B, body: solo(x) });
    expect(first.res.status).toBe(200);
    expect(first.at).toBeLessThan(700); // free service: served at once
    // three normal requests arrive while the slot is taken: they wait, then share one window
    const list = ['n1', 'n2', 'n3'].map((t) => sha256(t));
    const waiting = await Promise.all(list.map((hash) => h.timed(hash)));
    for (const w of waiting) expect(w.res.status).toBe(200);
    expect(Math.min(...waiting.map((w) => w.at))).toBeGreaterThan(700); // they had to wait for the slot
    const sizes = await Promise.all(
      waiting.map(async (w) => ((await w.res.json()) as { batch: { size: number } }).batch.size),
    );
    expect(sizes).toEqual([3, 3, 3]);
    expect(h.calls).toHaveLength(2); // the solo stamp and one window
  });

  it('solo and window alternate: a second solo request does not starve the waiting window', async () => {
    h = await start({ minIntervalMs: 1000, budgetWindowMs: 1000, maxWaitMs: 6000 });
    const x = sha256('first');
    expect((await h.stamp(x, { key: KEY_B, body: solo(x) })).status).toBe(200); // takes the slot
    const s1 = sha256('s1');
    const s2 = sha256('s2');
    const n = sha256('n');
    const order: string[] = [];
    const run = (name: string, p: Promise<Response>) =>
      p.then((r) => {
        order.push(name);
        return r;
      });
    const all = await Promise.all([
      run('s1', h.stamp(s1, { key: KEY_B, body: solo(s1) })),
      run('s2', h.stamp(s2, { key: KEY_C, body: solo(s2) })),
      run('n', h.stamp(n)),
    ]);
    expect(all.map((r) => r.status)).toEqual([200, 200, 200]);
    // slot 1: a solo, slot 2: the window (not the second solo), slot 3: the second solo
    expect(order.indexOf('n')).toBeLessThan(order.indexOf('s2'));
    expect(h.calls).toHaveLength(4);
  });

  it('a request that cannot get a slot within RELAY_MAX_WAIT_MS gets 503 busy with Retry-After', async () => {
    h = await start({ minIntervalMs: 1000, budgetWindowMs: 1000, maxWaitMs: 1500 });
    const x = sha256('t0');
    expect((await h.stamp(x, { key: KEY_B, body: solo(x) })).status).toBe(200); // slot used for 1 s
    const s1 = sha256('q1');
    const s2 = sha256('q2');
    const [r1, r2] = await Promise.all([
      h.timed(s1, { key: KEY_B, body: solo(s1) }), // gets the slot at 1 s
      h.timed(s2, { key: KEY_C, body: solo(s2) }), // would get it at 2 s: past its limit of 1.5 s
    ]);
    const done = [r1, r2];
    expect(done.map((d) => d.res.status).sort()).toEqual([200, 503]);
    const busy = done.find((d) => d.res.status === 503)!;
    expect(await busy.res.json()).toEqual({ error: 'busy' });
    expect(Number(busy.res.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    expect(busy.at).toBeGreaterThanOrEqual(1300);
    expect(busy.at).toBeLessThan(2500);
    expect(h.stats().refused['busy']).toBe(1);
  });

  it('a request answered with 503 busy leaves the queue: it is never stamped later, its slot is not used', async () => {
    h = await start({ minIntervalMs: 1000, budgetWindowMs: 1000, maxWaitMs: 1500 });
    const x = sha256('g0');
    expect((await h.stamp(x, { key: KEY_B, body: solo(x) })).status).toBe(200); // slot used for 1 s
    const s1 = sha256('g1');
    const s2 = sha256('g2');
    const [r1, r2] = await Promise.all([
      h.stamp(s1, { key: KEY_B, body: solo(s1) }), // gets the slot at 1 s
      h.stamp(s2, { key: KEY_C, body: solo(s2) }), // would get it at 2 s: past its limit of 1.5 s
    ]);
    expect([r1.status, r2.status].sort()).toEqual([200, 503]);
    const busyHash = r1.status === 503 ? s1 : s2;
    await sleep(2600); // long enough for the slot after the one of the other request
    expect(h.calls).toHaveLength(2); // the first stamp and the one that was served; the busy one never reached the service
    expect(h.calls.some((c) => same(c.imprint, busyHash))).toBe(false);
    expect(h.stats().stamped).toBe(2);
    // and the slot is free for a later request at once
    const y = sha256('g3');
    const later = await h.timed(y, { key: KEY_D, body: solo(y) });
    expect(later.res.status).toBe(200);
    expect(later.at).toBeLessThan(700);
  });

  it('a slot that is not free within the limit at all stays the old 429 (not a wait)', async () => {
    h = await start({ minIntervalMs: 30_000, maxWaitMs: 5000 }); // two stamps per minute
    for (const t of ['a', 'b']) expect((await h.stamp(sha256(t))).status).toBe(200);
    const late = await h.timed(sha256('c'));
    expect(late.res.status).toBe(429);
    expect(late.at).toBeLessThan(1000);
  });

  it('the queue of solo requests per service is limited: one more is 503 busy at once', async () => {
    const max = RELAY_LIMITS.soloQueueMax;
    h = await start({ minIntervalMs: 200, budgetWindowMs: 200, maxWaitMs: 8000 });
    const keys = [KEY_B, KEY_C, KEY_D, KEY_E];
    const total = max + 2; // one takes the slot, `max` wait, one is too many
    const answers = await Promise.all(
      Array.from({ length: total }, (_, i) => {
        const x = sha256(`q${i}`);
        return h.stamp(x, { key: keys[i % keys.length]!, body: solo(x) });
      }),
    );
    const statuses = answers.map((a) => a.status);
    expect(statuses.filter((s) => s === 503)).toHaveLength(1);
    expect(statuses.filter((s) => s === 200)).toHaveLength(total - 1);
    expect(h.stats().refused['busy']).toBe(1);
  });

  it('an own low solo limit per key: the fifth request in a minute is 429, another key still goes', async () => {
    const limit = RELAY_LIMITS.soloPerMinutePerKey;
    h = await start({ minIntervalMs: 1000 }); // slots are not the limit here (60 per minute)
    for (let i = 0; i < limit; i += 1) {
      const x = sha256(`k${i}`);
      expect((await h.stamp(x, { key: KEY_B, body: solo(x) })).status, `request ${i}`).toBe(200);
    }
    const x = sha256('one-too-many');
    const refused = await h.stamp(x, { key: KEY_B, body: solo(x) });
    expect(refused.status).toBe(429);
    expect(await refused.json()).toEqual({ error: 'rate-limited' });
    expect(Number(refused.headers.get('retry-after'))).toBeGreaterThan(0);
    // normal requests of the same key are not touched by the solo limit
    expect((await h.stamp(sha256('normal-b'), { key: KEY_B })).status).toBe(200);
    // another key has its own count
    const y = sha256('other-key');
    expect((await h.stamp(y, { key: KEY_C, body: solo(y) })).status).toBe(200);
    // the log carries no per-key number: the counters hold sums only
    expect(JSON.stringify(h.stats())).not.toContain('app-b');
  });

  it('closing answers the requests that wait for a slot with 503 shutting-down', async () => {
    h = await start({ minIntervalMs: 1000, budgetWindowMs: 1000, maxWaitMs: 8000 });
    const x = sha256('c0');
    expect((await h.stamp(x, { key: KEY_B, body: solo(x) })).status).toBe(200);
    const y = sha256('c1');
    const queued = h.stamp(y, { key: KEY_C, body: solo(y) });
    const normal = h.stamp(sha256('c2'));
    await sleep(150);
    h.relay.close();
    const answers = await Promise.all([queued, normal]);
    expect(answers.map((a) => a.status)).toEqual([503, 503]);
    for (const a of answers) expect(await a.json()).toEqual({ error: 'shutting-down' });
  });

  it('a solo request that waits is answered even if the service is slow (the stamp is awaited)', async () => {
    h = await start({ stampDelayMs: 300 });
    const x = sha256('slow');
    const res = await h.timed(x, { key: KEY_B, body: solo(x) });
    expect(res.res.status).toBe(200);
    expect(res.at).toBeGreaterThanOrEqual(280);
  });
});

describe('planner: the slot of a window is booked at the time of its stamp (never more calls than the budget)', () => {
  let h: Harness;
  afterEach(() => h.close());

  /** The most calls of the service in any interval of `ms` (the sliding window the service itself looks at). */
  const mostIn = (times: number[], ms: number): number =>
    Math.max(...times.map((a) => times.filter((t) => t >= a && t < a + ms).length));

  it('an open window, L-1 solo stamps, then one more: the service never sees more than L calls in a sliding window', async () => {
    // limit 4 per 2000 ms; the window opens at 0 and is stamped at 500 (the repro of the audit, scaled down)
    h = await start({
      batch: { windowMs: 500, max: 100 },
      minIntervalMs: 500,
      budgetWindowMs: 2000,
      maxWaitMs: 5000,
    });
    const answers: Promise<Response>[] = [h.stamp(sha256('w0'))]; // opens the window
    await sleep(40);
    for (const [i, key] of [KEY_B, KEY_C, KEY_D, KEY_E].entries()) {
      const x = sha256(`s${i}`);
      answers.push(h.stamp(x, { key, body: solo(x) })); // the fourth finds no slot until the first call is old
      await sleep(100);
    }
    const all = await Promise.all(answers);
    expect(all.map((r) => r.status)).toEqual([200, 200, 200, 200, 200]);
    expect(h.calls).toHaveLength(5);
    const times = h.calls.map((c) => c.at);
    // 5 ms of slack for the timers; the old behaviour put five calls into 1.6 s
    expect(mostIn(times, 2000 - 5)).toBeLessThanOrEqual(4);
  });

  it('while a window is open, a slot that is free only after the stamp of the window is the old 429, not a wait', async () => {
    // one call per 2000 ms; the window is stamped at 1500, so the slot is free at 3500 after it opened: more than the
    // longest wait (3000 ms) from the moment the solo request arrives
    h = await start({
      batch: { windowMs: 1500, max: 100 },
      minIntervalMs: 2000,
      budgetWindowMs: 2000,
      maxWaitMs: 3000,
    });
    const normal = h.stamp(sha256('r1'));
    await sleep(40);
    const x = sha256('r2');
    const refused = await h.timed(x, { key: KEY_B, body: solo(x) });
    expect(refused.res.status).toBe(429);
    expect(refused.at).toBeLessThan(500); // at once, not after the wait
    expect(Number(refused.res.headers.get('retry-after'))).toBeGreaterThanOrEqual(4);
    expect((await normal).status).toBe(200);
    expect(h.calls).toHaveLength(1);
  });

  it('a window that closes early (full) books the time of its real stamp, not the end of its window', async () => {
    // one call per 2000 ms: the window of 1500 ms is full with two requests and is stamped at once
    h = await start({
      batch: { windowMs: 1500, max: 2 },
      minIntervalMs: 2000,
      budgetWindowMs: 2000,
      maxWaitMs: 5000,
    });
    const first = h.stamp(sha256('f1'));
    await sleep(30);
    const second = h.stamp(sha256('f2')); // fills the window: stamped now
    await sleep(60);
    const x = sha256('after');
    const late = await h.timed(x, { key: KEY_B, body: solo(x) });
    expect((await Promise.all([first, second])).map((r) => r.status)).toEqual([200, 200]);
    expect(late.res.status).toBe(200);
    expect(h.calls).toHaveLength(2);
    const [windowCall, soloCall] = h.calls.map((c) => c.at) as [number, number];
    expect(windowCall).toBeLessThan(300); // stamped when it was full, not after 1500 ms
    // the slot of that stamp is free 2000 ms after it, not 2000 ms after the end of the window (3500)
    expect(soloCall - windowCall).toBeGreaterThanOrEqual(1995);
    expect(soloCall).toBeLessThan(2600);
  });

  it('while a window is open its slot counts as taken for the solo stamps that arrive', async () => {
    // one call per 2000 ms: the window (stamp at 600) holds the only slot, a solo stamp comes after it
    h = await start({
      batch: { windowMs: 600, max: 100 },
      minIntervalMs: 2000,
      budgetWindowMs: 2000,
      maxWaitMs: 5000,
    });
    const normal = h.stamp(sha256('o1'));
    await sleep(40);
    const x = sha256('o2');
    const soloAnswer = h.timed(x, { key: KEY_B, body: solo(x) });
    const [a, b] = await Promise.all([normal, soloAnswer]);
    expect(a.status).toBe(200);
    expect(b.res.status).toBe(200);
    const [windowCall, soloCall] = h.calls.map((c) => c.at) as [number, number];
    expect(windowCall).toBeGreaterThanOrEqual(580); // the window stamps when it closes ...
    expect(soloCall - windowCall).toBeGreaterThanOrEqual(1995); // ... and the solo stamp is a whole interval later
  });
});

describe('planner: a window that closes early, and a clock that is set back (audit 2: M04, M05, M08)', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('M04: a request that waits for a slot is served as soon as a window closes early, not at the time booked for the window', async () => {
    // one call per 2000 ms; the window (1500 ms, two requests) is booked for 1500, but a second request fills it and it
    // is stamped at once. The solo request that came in between waited for "1500 + 2000" and must look again.
    h = await start({
      batch: { windowMs: 1500, max: 2 },
      minIntervalMs: 2000,
      budgetWindowMs: 2000,
      maxWaitMs: 5000,
    });
    const first = h.stamp(sha256('e1'));
    await sleep(30);
    const x = sha256('e-solo');
    const soloAnswer = h.timed(x, { key: KEY_B, body: solo(x) }); // waits: the slot is booked until after the window
    await sleep(60);
    const second = h.stamp(sha256('e2')); // fills the window: stamped now
    const [a, b, c] = await Promise.all([first, second, soloAnswer]);
    expect([a.status, b.status, c.res.status]).toEqual([200, 200, 200]);
    expect(h.calls).toHaveLength(2);
    const [windowCall, soloCall] = h.calls.map((c2) => c2.at) as [number, number];
    expect(windowCall).toBeLessThan(400);
    expect(soloCall - windowCall).toBeGreaterThanOrEqual(1995); // never before the interval ...
    expect(soloCall - windowCall).toBeLessThan(2400); // ... but at that time, not at 1500 + 2000 after the opening (3500)
  });

  it('M05: a clock set back while a window is open does not push a waiting request past its limit (no lock)', async () => {
    // one call per 2000 ms; the window (600 ms) opens, then the clock goes back 5 s. The stamp of the window is still
    // at most one window length ahead, so the solo request waits about 2.6 s and is served; a stamp "booked" 5.6 s
    // ahead would make its slot later than the longest wait (5 s): a 429 for a clock that jumped.
    h = await start({
      batch: { windowMs: 600, max: 100 },
      minIntervalMs: 2000,
      budgetWindowMs: 2000,
      maxWaitMs: 5000,
    });
    const normal = h.stamp(sha256('c1'));
    await sleep(40);
    h.clock.offset = -5000;
    const x = sha256('c2');
    const soloAnswer = await h.timed(x, { key: KEY_B, body: solo(x) });
    expect(soloAnswer.res.status).toBe(200);
    expect((await normal).status).toBe(200);
    expect(h.calls).toHaveLength(2);
  }, 15_000);

  it('M08: a stamp "in the future" after a clock set back counts as now when a waiting request looks again (no lock)', async () => {
    // one call per 1000 ms. Solo A is stamped, solo B waits for the slot (900 ms), the clock goes back 5 s while it waits:
    // when B looks again A's stamp lies 5 s ahead. Counted as it is, B would wait 6 s and get 503 busy at 5 s; counted as
    // now, B waits one more interval and is served.
    h = await start({ minIntervalMs: 1000, budgetWindowMs: 1000, maxWaitMs: 5000 });
    const xa = sha256('m8-a');
    expect((await h.stamp(xa, { key: KEY_B, body: solo(xa) })).status).toBe(200);
    const xb = sha256('m8-b');
    const waiting = h.timed(xb, { key: KEY_C, body: solo(xb) });
    await sleep(100);
    h.clock.offset = -5000;
    const b = await waiting;
    expect(b.res.status).toBe(200);
    expect(b.at).toBeLessThan(3500);
    expect(h.calls).toHaveLength(2);
  }, 15_000);
});

describe('RELAY_MAX_WAIT_MS is read strictly', () => {
  const base = { RELAY_SERVICES: 'freetsa', RELAY_AUTH: 'off' };
  it('default 30000, 1000 and 60000 are valid', () => {
    expect(readSettings(base).maxWaitMs).toBeUndefined(); // the relay's own default applies
    expect(RELAY_LIMITS.maxWaitDefaultMs).toBe(30_000);
    expect(readSettings({ ...base, RELAY_MAX_WAIT_MS: '' }).maxWaitMs).toBeUndefined();
    expect(readSettings({ ...base, RELAY_MAX_WAIT_MS: '1000' }).maxWaitMs).toBe(1000);
    expect(readSettings({ ...base, RELAY_MAX_WAIT_MS: '60000' }).maxWaitMs).toBe(60_000);
  });
  it('anything else ends the start with a German line', () => {
    for (const v of ['999', '60001', '0', '1.5', 'abc', '1e4', ' 5000', '-1', '5000 ', '0x10']) {
      expect(() => readSettings({ ...base, RELAY_MAX_WAIT_MS: v }), v).toThrow(
        /RELAY_MAX_WAIT_MS: ungültig \(ganze Zahl von 1000 bis 60000 erwartet\)/,
      );
    }
  });
});

describe('key file read again: new keys count, removed keys stop, an invalid file keeps the old set', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('setKeys: a new key is valid at once, a removed one is invalid at once; counters and replay stay', async () => {
    h = await start({ keys: [asRelayKey(KEY_A, false)] });
    expect((await h.stamp(sha256('1'), { key: KEY_B })).status).toBe(401); // not known yet
    expect((await h.stamp(sha256('2'), { key: KEY_A })).status).toBe(200);
    h.relay.setKeys([asRelayKey(KEY_B, false)]); // A is gone, B is new
    expect((await h.stamp(sha256('3'), { key: KEY_B })).status).toBe(200);
    expect((await h.stamp(sha256('4'), { key: KEY_A })).status).toBe(401);
    expect(h.stats()).toMatchObject({ stamped: 2, batched: 2 }); // counters survive the swap
  });

  it('setKeys keeps the replay cache: an admitted request cannot be sent again after a reload', async () => {
    h = await start({ keys: [asRelayKey(KEY_A, false)], batch: null });
    const text = JSON.stringify({ hash: toBase64Url(sha256('r')) });
    const head = nodeAuthHeader(
      KEY_A,
      KEY_A.id,
      'POST',
      '/v1/stamp/freetsa',
      Math.floor(Date.now() / 1000),
      new TextEncoder().encode(text),
    );
    expect((await h.stamp(sha256('r'), { raw: text, head })).status).toBe(200);
    h.relay.setKeys([asRelayKey(KEY_A, false), asRelayKey(KEY_B, false)]);
    expect((await h.stamp(sha256('r'), { raw: text, head })).status).toBe(401); // the same head again
  });

  it('setKeys with a bad set throws and changes nothing', async () => {
    h = await start({ keys: [asRelayKey(KEY_A, false)] });
    const bad = { id: 'bad', publicKey: new Uint8Array(65) };
    expect(() => h.relay.setKeys([asRelayKey(KEY_B, false), bad])).toThrow();
    expect(() => h.relay.setKeys([asRelayKey(KEY_B, false), asRelayKey(KEY_B, false)])).toThrow();
    expect((await h.stamp(sha256('x'), { key: KEY_A })).status).toBe(200); // the old set is active
    expect((await h.stamp(sha256('y'), { key: KEY_B })).status).toBe(401);
  });

  it('a key that gets "solo" through a reload may ask for solo stamps from then on', async () => {
    h = await start({ keys: [asRelayKey(KEY_A, false)], batch: { windowMs: 400, max: 100 } });
    const open = h.stamp(sha256('window')); // a window with a waiting request
    await sleep(100);
    const x = sha256('upgrade');
    expect((await h.stamp(x, { key: KEY_A, body: solo(x) })).status).toBe(403);
    h.relay.setKeys([asRelayKey(KEY_A, true)]);
    const y = sha256('upgrade2');
    expect((await h.stamp(y, { key: KEY_A, body: solo(y) })).status).toBe(200);
    await open;
  });

  describe('the watcher with a real file', () => {
    let dir: string;
    let path: string;
    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), 'zeitstempel-keys-'));
      path = join(dir, 'relay-keys.json');
    });
    afterEach(() => rmSync(dir, { recursive: true, force: true }));
    const entry = (k: TestKey, solo = false) => ({
      id: k.id,
      publicKey: toBase64Url(k.publicKey),
      ...(solo ? { solo: true } : {}),
    });
    let bump = 0;
    const write = (text: string) => {
      writeFileSync(path, text);
      bump += 5; // a modification time that differs from every earlier one, whatever the file system
      const t = new Date(Date.now() + bump * 1000);
      utimesSync(path, t, t);
    };

    it('reloads on a change, keeps the old set for an invalid file (counted once), and takes the fixed file', async () => {
      write(JSON.stringify({ version: 2, keys: [entry(KEY_A)] }));
      h = await start({ keys: [asRelayKey(KEY_A, false)] });
      const reloaded: boolean[] = [];
      const watcher = createKeyWatcher({
        path,
        apply: (list) => h.relay.setKeys(list),
        now: () => Date.now(),
        startMs: Date.now(),
        onRestart: () => reloaded.push(false),
        onReloaded: () => h.relay.noteKeyReload(true),
        onFailed: () => h.relay.noteKeyReload(false),
      });
      watcher.check(); // the first look only confirms the start
      expect(h.stats().keyReloads).toBeUndefined();
      write(JSON.stringify({ version: 2, keys: [entry(KEY_A), entry(KEY_B)] }));
      watcher.check();
      expect((await h.stamp(sha256('b'), { key: KEY_B })).status).toBe(200);
      // an invalid file: the old set stays
      write('{ not json');
      watcher.check();
      watcher.check(); // the same state of the file is counted once
      watcher.check();
      expect((await h.stamp(sha256('a'), { key: KEY_A })).status).toBe(200);
      expect((await h.stamp(sha256('b2'), { key: KEY_B })).status).toBe(200);
      expect(h.stats()).toMatchObject({ keyReloads: 1, keyReloadFailed: 1 });
      // a structurally invalid file (duplicate id) is refused as well
      write(JSON.stringify({ version: 2, keys: [entry(KEY_A), entry(KEY_A)] }));
      watcher.check();
      expect(h.stats().keyReloadFailed).toBe(2);
      // fixed: B removed, C added; B stops at once
      write(JSON.stringify({ version: 2, keys: [entry(KEY_A), entry(KEY_C)] }));
      watcher.check();
      expect((await h.stamp(sha256('b3'), { key: KEY_B })).status).toBe(401);
      expect((await h.stamp(sha256('c'), { key: KEY_C })).status).toBe(200);
      expect(h.stats()).toMatchObject({ keyReloads: 2, keyReloadFailed: 2 });
      expect(reloaded).toEqual([]); // no restart asked for
      // a file that is gone: the old set stays, one failure counted
      rmSync(path);
      watcher.check();
      watcher.check();
      expect((await h.stamp(sha256('c2'), { key: KEY_C })).status).toBe(200);
      expect(h.stats().keyReloadFailed).toBe(3);
    });

    it('the log line of counters carries no key data', async () => {
      h = await start({ keys: [asRelayKey(KEY_A, false)] });
      h.relay.noteKeyReload(false);
      const line = JSON.stringify({ event: 'counts', ...h.stats() });
      expect(line).toBe(
        '{"event":"counts","stamped":0,"refused":{},"batched":0,"keyReloadFailed":1}',
      );
    });

    it('restartAfter ends the process once; the relay never writes the file; a restarted process does not repeat', () => {
      const startMs = Date.now() - 10_000;
      const restartAfter = Math.floor(Date.now() / 1000); // after the start, not later than now
      write(JSON.stringify({ version: 2, keys: [entry(KEY_A)], restartAfter }));
      const before = { text: readFileSync(path, 'utf8'), mtime: statSync(path).mtimeMs };
      const applied: number[] = [];
      let restarts = 0;
      const watcher = createKeyWatcher({
        path,
        apply: (list) => void applied.push(list.length),
        now: () => Date.now(),
        startMs,
        onRestart: () => void (restarts += 1),
      });
      watcher.check();
      watcher.check();
      watcher.check();
      expect(restarts).toBe(1); // once, not in a loop
      // the process that starts after `restartAfter` does not end again
      let again = 0;
      const second = createKeyWatcher({
        path,
        apply: () => undefined,
        now: () => Date.now() + 5000,
        startMs: Date.now() + 2000,
        onRestart: () => void (again += 1),
      });
      second.check();
      second.check();
      expect(again).toBe(0);
      // nothing was written
      expect(readFileSync(path, 'utf8')).toBe(before.text);
      expect(statSync(path).mtimeMs).toBe(before.mtime);
    });

    it('a new file without restartAfter takes the old one back: no restart later', () => {
      const now = 1_800_000_000_000;
      let clock = now;
      let current: KeyFile = { keys: KEYS, restartAfter: 1_800_000_100 };
      let signature = 'v1';
      let restarts = 0;
      const watcher = createKeyWatcher({
        path: 'unused',
        load: () => current,
        signature: () => signature,
        apply: () => undefined,
        now: () => clock,
        startMs: now,
        onRestart: () => void (restarts += 1),
      });
      watcher.check(); // restartAfter is 100 s ahead
      signature = 'v2';
      current = { keys: KEYS }; // the operator took the restart back
      watcher.check();
      clock = now + 500_000;
      watcher.check();
      expect(restarts).toBe(0);
    });

    it('restartAfter in the future waits; one before the start never fires', () => {
      const now = 1_800_000_000_000;
      const file = (restartAfter: number | undefined): KeyFile => ({
        keys: KEYS,
        ...(restartAfter === undefined ? {} : { restartAfter }),
      });
      let clock = now;
      let current = file(1_800_000_100); // 100 s after the start
      let signature = 'v1';
      let restarts = 0;
      const watcher = createKeyWatcher({
        path: 'unused',
        load: () => current,
        signature: () => signature,
        apply: () => undefined,
        now: () => clock,
        startMs: now,
        onRestart: () => void (restarts += 1),
      });
      watcher.check();
      expect(restarts).toBe(0);
      clock = now + 99_000;
      watcher.check();
      expect(restarts).toBe(0);
      clock = now + 100_000; // restartAfter <= now
      watcher.check();
      expect(restarts).toBe(1);
      clock = now + 500_000;
      watcher.check();
      expect(restarts).toBe(1);
      // equal to the start second and earlier: no restart (the start is the state the file asks for)
      for (const r of [1_800_000_000, 1_700_000_000]) {
        let n = 0;
        const w = createKeyWatcher({
          path: 'unused',
          load: () => file(r),
          signature: () => 'x',
          apply: () => undefined,
          now: () => now + 1_000_000,
          startMs: now,
          onRestart: () => void (n += 1),
        });
        w.check();
        expect(n, String(r)).toBe(0);
      }
      // a new restartAfter in a changed file, set after the first restart, does not restart this process again
      signature = 'v2';
      current = file(1_800_000_200);
      clock = now + 600_000;
      watcher.check();
      expect(restarts).toBe(1);
    });
  });
});

describe('key file reader: the key type and restartAfter', () => {
  const pub = () => toBase64Url(makeTestKey('x').publicKey);
  const entry = (extra: Record<string, unknown> = {}) => ({ id: 'a', publicKey: pub(), ...extra });
  const file = (keys: unknown[], extra: Record<string, unknown> = {}) => ({
    version: 2,
    keys,
    ...extra,
  });

  it('"solo": true is key type 2, false or missing is type 1', () => {
    const r = readKeyFileFull(
      file([
        entry({ solo: true }),
        { id: 'b', publicKey: pub(), solo: false },
        { id: 'c', publicKey: pub() },
      ]),
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.keys.map((k) => k.solo === true)).toEqual([true, false, false]);
  });

  it('solo must be a boolean: anything else names the entry, not the content', () => {
    for (const bad of ['yes', 'true', 1, 0, null, [], {}, undefined]) {
      const r = readKeyFileFull(file([entry(), { id: 'b', publicKey: pub(), solo: bad }]));
      expect(r, String(bad)).toMatchObject({ ok: false, reason: 'bad-key-file' });
      if (!r.ok) expect(String(r.detail)).toMatch(/^(solo|entry-fields) in keys\[1\]$/);
    }
    const r = readKeyFileFull(file([entry({ solo: 'yes' })]));
    expect(JSON.stringify(r)).not.toContain('yes');
  });

  it('restartAfter: an integer of Unix seconds, optional; every other form is refused', () => {
    const ok = readKeyFileFull(file([entry()], { restartAfter: 1_800_000_000 }));
    expect(ok.ok && ok.value.restartAfter).toBe(1_800_000_000);
    const none = readKeyFileFull(file([entry()]));
    expect(none.ok && none.value.restartAfter).toBeUndefined();
    for (const bad of [
      '1800000000',
      1.5,
      -1,
      0,
      999_999_999,
      100_000_000_000,
      null,
      NaN,
      Infinity,
      true,
      [],
    ]) {
      expect(readKeyFileFull(file([entry()], { restartAfter: bad })), String(bad)).toMatchObject({
        ok: false,
        reason: 'bad-key-file',
        detail: 'restart-after',
      });
    }
    // other top-level fields stay refused
    expect(readKeyFileFull(file([entry()], { restartAfterX: 1 }))).toMatchObject({ ok: false });
  });
});
