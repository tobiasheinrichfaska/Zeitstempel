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

// Solo stamps exist for key type 2 only. A key of type 1 that asks for `mode: "solo"` in collecting operation gets
// `403 solo-not-allowed` at once, before any work: it does not wait, takes no slot, does not enter a window or the tree,
// and costs no total or key budget (it is counted: `soloDenied`, `refused['solo-not-allowed']`). Key type 2 is unchanged.
// Real clock, short windows.

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

describe('key type 1 asks for solo: refused at once, before any work', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('403 solo-not-allowed at once (no waiting for the window), no call to the service', async () => {
    h = await start({ batch: { windowMs: 1500, max: 100 } });
    const x = sha256('alone');
    const t = await h.timed(x, { key: KEY_A, body: solo(x) });
    expect(t.res.status).toBe(403);
    expect(await t.res.json()).toEqual({ error: 'solo-not-allowed' });
    expect(t.at).toBeLessThan(400); // the window is 1.5 s: it was not waited for
    expect(h.calls).toHaveLength(0);
    expect(h.stats()).toEqual({
      stamped: 0,
      refused: { 'solo-not-allowed': 1 },
      batched: 0,
      soloDenied: 1,
    });
    expect(h.stats().solo).toBeUndefined();
  });

  it('it opens no window and books no slot: the next normal request is served at once', async () => {
    h = await start({
      batch: { windowMs: 150, max: 100 },
      minIntervalMs: 1000,
      budgetWindowMs: 1000, // one slot a second
      maxWaitMs: 4000,
    });
    const xs = [sha256('t1'), sha256('t2'), sha256('t3')];
    const refused = await Promise.all(xs.map((x) => h.stamp(x, { key: KEY_A, body: solo(x) })));
    expect(refused.map((r) => r.status)).toEqual([403, 403, 403]);
    const t = await h.timed(sha256('after'), { key: KEY_F });
    expect(t.res.status).toBe(200);
    expect(t.at).toBeLessThan(150 + 500); // the window only: no slot was booked for the refused requests
    // and a type 2 solo stamp is not held back either
    const s = sha256('type2-after');
    expect((await h.stamp(s, { key: KEY_B, body: solo(s) })).status).toBe(200);
  });

  it('a request in an open window is refused at once too; the rider and the tree are untouched', async () => {
    h = await start({ batch: { windowMs: 500, max: 100 } });
    const y = sha256('rider');
    const rider = h.stamp(y, { key: KEY_F }); // opens the window
    await sleep(80);
    const x = sha256('solo-in-open-window');
    const t = await h.timed(x, { key: KEY_A, body: solo(x) });
    expect(t.res.status).toBe(403);
    expect(t.at).toBeLessThan(250); // not after the close of the window (about 420 ms away)
    const got = await rider;
    expect(got.status).toBe(200);
    const receipt = (await got.json()) as { batch: { size: number } };
    expect(receipt.batch.size).toBe(1); // the refused request is not in the tree
    expect(h.calls).toHaveLength(1);
    expect(same(h.calls[0]!.imprint, x)).toBe(false);
    expect(h.stats()).toMatchObject({ stamped: 1, batched: 1, soloDenied: 1 });
  });

  it('the refused request costs no total, key or solo budget: far more than every limit, all 403, none 429', async () => {
    h = await start({ batch: { windowMs: 200, max: 100 }, minIntervalMs: 1000 });
    const n = RELAY_LIMITS.perMinutePerKey + RELAY_LIMITS.soloPerMinutePerKey + 5; // 29
    const answers: number[] = [];
    for (let i = 0; i < n; i += 1) {
      const x = sha256(`flood${i}`);
      answers.push((await h.stamp(x, { key: KEY_A, body: solo(x) })).status);
    }
    expect(answers).toEqual(Array(n).fill(403));
    expect(h.calls).toHaveLength(0);
    // the same key still has its whole budget for a normal request
    const ok = await h.stamp(sha256('normal-a'), { key: KEY_A });
    expect(ok.status).toBe(200);
    expect(h.stats()).toMatchObject({ soloDenied: n, refused: { 'solo-not-allowed': n } });
    expect(h.stats().stamped).toBe(1);
  });

  it('counters: each refusal counts once in `soloDenied` and in `refused`, a stamp does not', async () => {
    h = await start({ batch: { windowMs: 100, max: 100 } });
    for (const i of [1, 2, 3]) {
      const x = sha256(`c${i}`);
      expect((await h.stamp(x, { key: i === 2 ? KEY_F : KEY_A, body: solo(x) })).status).toBe(403);
    }
    expect(h.stats()).toMatchObject({ soloDenied: 3, refused: { 'solo-not-allowed': 3 } });
    expect(h.stats().stamped).toBe(0);
    const z = sha256('type2');
    expect((await h.stamp(z, { key: KEY_B, body: solo(z) })).status).toBe(200);
    expect(h.stats()).toMatchObject({ stamped: 1, solo: 1, soloDenied: 3 });
  });

  it('the refusal does not depend on the others: also with a free service, alone and with riders', async () => {
    h = await start({ batch: { windowMs: 300, max: 100 } });
    const riders = [h.stamp(sha256('r1')), h.stamp(sha256('r2'), { key: KEY_F })];
    const [a, b] = [sha256('sa'), sha256('sb')];
    const refused = await Promise.all([
      h.stamp(a, { key: KEY_A, body: solo(a) }),
      h.stamp(b, { key: KEY_F, body: solo(b) }),
    ]);
    expect(refused.map((r) => r.status)).toEqual([403, 403]);
    const sizes = await Promise.all(
      riders.map(
        async (r) => ((await r.then((x) => x.json())) as { batch: { size: number } }).batch.size,
      ),
    );
    expect(sizes).toEqual([2, 2]);
    expect(h.calls).toHaveLength(1);
  });

  it('a malformed mode keeps its own answer (400 bad-mode) and is not counted as a refused solo request', async () => {
    h = await start({ batch: { windowMs: 100, max: 100 } });
    const res = await h.stamp(sha256('m'), {
      key: KEY_A,
      body: { hash: toBase64Url(sha256('m')), mode: 'x' },
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: 'bad-mode' });
    expect(h.stats().soloDenied).toBeUndefined();
  });

  it('the queue limit of solo stamps is for type 2 only: type 1 solo requests are 403, never 503 busy', async () => {
    const max = RELAY_LIMITS.soloQueueMax;
    h = await start({
      batch: { windowMs: 100, max: 100 },
      minIntervalMs: 200,
      budgetWindowMs: 200,
      maxWaitMs: 8000,
      keys: [...KEYS, asRelayKey(KEY_C, true), asRelayKey(KEY_D, true), asRelayKey(KEY_G, false)],
    });
    const type2 = [KEY_B, KEY_C, KEY_D];
    const queued = Array.from({ length: max + 1 }, (_, i) => {
      const x = sha256(`full${i}`);
      return h.stamp(x, { key: type2[i % type2.length]!, body: solo(x) });
    });
    await sleep(60);
    const type1 = Array.from({ length: max + 2 }, (_, i) => {
      const x = sha256(`t1-${i}`);
      return h.stamp(x, { key: i % 2 === 0 ? KEY_A : KEY_G, body: solo(x) });
    });
    const statuses = (await Promise.all(type1)).map((r) => r.status);
    expect(statuses).toEqual(Array(max + 2).fill(403));
    expect(h.stats().refused['busy']).toBeUndefined();
    expect((await Promise.all(queued)).map((r) => r.status)).toEqual(Array(max + 1).fill(200));
  });

  it('type 2 is unchanged: at once, a direct stamp, also while a window is open', async () => {
    h = await start({ batch: { windowMs: 600, max: 100 }, minIntervalMs: 200 });
    const x = sha256('type2');
    const t = await h.timed(x, { key: KEY_B, body: solo(x) });
    expect(t.res.status).toBe(200);
    expect(t.at).toBeLessThan(300);
    expect(Object.keys((await t.res.json()) as object)).not.toContain('batch');
    expect(same(h.calls[0]!.imprint, x)).toBe(true);
    expect(h.calls[0]!.at).toBeLessThan(300);
    // while a window is open (its rider waits)
    const rider = h.stamp(sha256('rider2'), { key: KEY_F });
    await sleep(60);
    const z = sha256('type2-again');
    const again = await h.timed(z, { key: KEY_B, body: solo(z) });
    expect(again.res.status).toBe(200);
    expect(again.at).toBeLessThan(500 + 500);
    expect((await rider).status).toBe(200);
  });

  it('without collecting operation `mode: "solo"` stays without effect: a direct stamp at once, no key type check', async () => {
    h = await start({ batch: null });
    const x = sha256('no-batch');
    const t = await h.timed(x, { key: KEY_A, body: solo(x) }); // key type 1
    expect(t.res.status).toBe(200);
    expect(t.at).toBeLessThan(300);
    expect(h.stats()).toEqual({ stamped: 1, refused: {} });
  });

  it('after the relay is closed the answer is shutting-down, as for every request', async () => {
    h = await start({ batch: { windowMs: 2000, max: 100 } });
    h.relay.close();
    const x = sha256('closing');
    const res = await h.stamp(x, { key: KEY_A, body: solo(x) });
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: 'shutting-down' });
  });
});
