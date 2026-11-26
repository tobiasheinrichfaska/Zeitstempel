import { readFileSync } from 'node:fs';
import { toBase64Url } from '../src/index.ts';
import type { RelayKey } from '../relay/keys.ts';
import type { TestKey } from './auth-helpers.ts';
import {
  KEY_A,
  KEY_B,
  KEY_C,
  KEY_D,
  KEY_F,
  sha256,
  sleep,
  start,
  type Harness,
} from './spacing-harness.ts';

// Audit 9: empty share lists (N1), refunds counted exactly (M02, M05, M06, M07, M22, M25), a request that joined an open
// window is checked again (M32), `services` and the solo type are checked again for a waiting request (H2), the replay
// cache after a wall clock set back (N3), the comment of `maxClockOffsetMs` (N2).

const rk = (k: TestKey, extra: Partial<RelayKey> = {}): RelayKey => ({
  id: k.id,
  publicKey: k.publicKey,
  ...extra,
});
const ALL = (over: Record<string, Partial<RelayKey>> = {}): RelayKey[] =>
  [KEY_A, KEY_B, KEY_F].map((k) => rk(k, over[k.id] ?? {}));
const solo = (x: string) => ({ hash: toBase64Url(sha256(x)), mode: 'solo' });

describe('N1: the share lists of the relay do not pile up empty lists', () => {
  let h: Harness;
  afterEach(() => h.close());

  const body = (x: string, token: string) => ({
    hash: toBase64Url(sha256(x)),
    upstream: { token },
  });
  const round = async (i: number): Promise<void> => {
    const token = 'tok' + i; // a new identity (its own lane) per round
    const f = h.stamp(sha256('f' + i), { key: KEY_F, body: body('f' + i, token) });
    await sleep(5);
    const ac = new AbortController();
    const a = h.stamp(sha256('a' + i), {
      key: KEY_A,
      body: body('a' + i, token),
      signal: ac.signal,
    });
    a.catch(() => undefined);
    await sleep(30);
    ac.abort(); // A waits in the lane of F and gives up: its share comes back
    await f;
    await sleep(400); // A's booked time passes: noticed and refunded
  };

  it('a refund that empties the list of a key removes the list', async () => {
    h = await start({
      batch: null,
      bearer: true,
      minIntervalMs: 300,
      budgetWindowMs: 1200,
      keyShare: 50,
      maxWaitMs: 5000,
      upstreamIdentities: 64,
    });
    expect(h.relay.heldForTests().shares).toBe(0);
    await round(0);
    // only the list of F is left (A's was emptied by the refund)
    expect(h.relay.heldForTests().shares).toBe(1);
  }, 30_000);

  it('after many rounds, idle time and one more request the table is back to the lists in use', async () => {
    h = await start({
      batch: null,
      bearer: true,
      minIntervalMs: 300,
      budgetWindowMs: 1200,
      keyShare: 50,
      maxWaitMs: 5000,
      upstreamIdentities: 64,
    });
    for (let i = 0; i < 4; i += 1) await round(i);
    await sleep(1500);
    await h.stamp(sha256('last'), { key: KEY_F, body: body('last', 'tokLast') });
    expect(h.relay.heldForTests().shares).toBeLessThanOrEqual(1);
  }, 60_000);

  it('an expired identity leaves no share list behind', async () => {
    h = await start({
      batch: null,
      bearer: true,
      minIntervalMs: 300,
      budgetWindowMs: 1200,
      keyShare: 50,
      maxWaitMs: 5000,
      upstreamIdentities: 2,
    });
    expect((await h.stamp(sha256('1'), { key: KEY_F, body: body('1', 't1') })).status).toBe(200);
    expect((await h.stamp(sha256('2'), { key: KEY_A, body: body('2', 't2') })).status).toBe(200);
    expect(h.relay.heldForTests().shares).toBe(2);
    await sleep(1300);
    // the table of identities is full (2): the look for room drops the expired ones, shares included
    const r = await h.stamp(sha256('3'), { key: KEY_B, body: body('3', 't3') });
    expect(r.status).toBe(200);
    expect(h.relay.heldForTests().known).toBe(1);
    expect(h.relay.heldForTests().shares).toBeLessThanOrEqual(1);
  }, 30_000);
  it('an identity that expires leaves its share list behind only if nobody sweeps: `forget` drops it itself (the request that made room is refused after)', async () => {
    // the replay cache holds one entry (the head of the first request): the second request is a 429 after the look for room,
    // so it spends nothing and no sweep of `shareBudget` runs; only `forget` can remove the list of the expired identity
    h = await start({
      batch: null,
      bearer: true,
      minIntervalMs: 300,
      budgetWindowMs: 1200,
      keyShare: 50,
      maxWaitMs: 5000,
      upstreamIdentities: 1,
      authReplayEntries: 1,
    });
    expect((await h.stamp(sha256('1'), { key: KEY_F, body: body('1', 't1') })).status).toBe(200);
    expect(h.relay.heldForTests().shares).toBe(1);
    expect(h.relay.heldForTests().known).toBe(1);
    await sleep(1300);
    const r = await h.stamp(sha256('2'), { key: KEY_A, body: body('2', 't2') });
    expect(r.status).toBe(429); // the replay cache is full
    expect(h.relay.heldForTests().known).toBe(0); // the expired identity is gone ...
    expect(h.relay.heldForTests().shares).toBe(0); // ... and its share list with it
  }, 30_000);
});

describe('refunds count exactly', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('M02: a waiting request that lapses gives back the count of the service (4 per 2400 ms)', async () => {
    h = await start({ batch: null, minIntervalMs: 600, budgetWindowMs: 2400, maxWaitMs: 10_000 });
    expect((await h.stamp(sha256('1'), { key: KEY_A })).status).toBe(200);
    const waiting = h.stamp(sha256('2'), { key: KEY_F });
    await sleep(100);
    h.relay.setKeys(ALL({ [KEY_F.id]: { revoked: true } }));
    expect((await waiting).status).toBe(401);
    const statuses: number[] = [];
    for (let i = 0; i < 4; i += 1)
      statuses.push((await h.stamp(sha256('n' + i), { key: KEY_A })).status);
    expect(statuses).toEqual([200, 200, 200, 429]);
  });

  it('M22: the last of the chain gives its time back when it lapses (the next request does not wait for it)', async () => {
    h = await start({ batch: null, minIntervalMs: 600, maxWaitMs: 10_000 });
    expect((await h.stamp(sha256('1'), { key: KEY_A })).status).toBe(200);
    const waiting = h.stamp(sha256('2'), { key: KEY_F }); // booked for 600 ms after the first call
    await sleep(100);
    h.relay.setKeys(ALL({ [KEY_F.id]: { revoked: true } }));
    expect((await waiting).status).toBe(401);
    await sleep(60);
    expect((await h.stamp(sha256('3'), { key: KEY_A })).status).toBe(200);
    expect(h.calls).toHaveLength(2);
    // without the give back the third call would be booked behind the lapsed one: 1200 ms after the first
    expect(h.calls[1]!.at - h.calls[0]!.at).toBeLessThan(1000);
    expect(h.calls[1]!.at - h.calls[0]!.at).toBeGreaterThanOrEqual(550);
  });

  it('M05: a solo request that is 503 busy in the queue gives back key and solo budget (5 rounds, limit 4)', async () => {
    h = await start({ batch: { windowMs: 300, max: 100 }, minIntervalMs: 600, maxWaitMs: 1000 });
    const others = [KEY_C, KEY_D, KEY_C, KEY_D, KEY_C];
    for (let i = 0; i < 5; i += 1) {
      expect(
        (await h.stamp(sha256('o' + i), { key: others[i]!, body: solo('o' + i) })).status,
      ).toBe(200);
      const p = h.stamp(sha256('b' + i), { key: KEY_B, body: solo('b' + i) });
      await sleep(30);
      h.mono.offset += 5000;
      expect((await p).status).toBe(503);
      await sleep(650);
    }
  }, 60_000);

  it('M06, M25: a busy solo request of a key with perMinute 1 gets its only count back (list index 0)', async () => {
    const keys: RelayKey[] = [rk(KEY_B, { solo: true, perMinute: 1 }), rk(KEY_C, { solo: true })];
    h = await start({
      batch: { windowMs: 300, max: 100 },
      minIntervalMs: 600,
      maxWaitMs: 1000,
      keys,
    });
    expect((await h.stamp(sha256('c'), { key: KEY_C, body: solo('c') })).status).toBe(200);
    const p = h.stamp(sha256('b'), { key: KEY_B, body: solo('b') });
    await sleep(30);
    h.mono.offset += 5000;
    expect((await p).status).toBe(503);
    expect((await h.stamp(sha256('b2'), { key: KEY_B, body: solo('b2') })).status).toBe(200);
  });

  it('M07: a refund takes exactly one count (perMinute 3, refund in the middle of the list)', async () => {
    const keys: RelayKey[] = [rk(KEY_A, { perMinute: 3 }), rk(KEY_F)];
    h = await start({ batch: null, minIntervalMs: 300, maxWaitMs: 10_000, keys });
    expect((await h.stamp(sha256('a1'), { key: KEY_A })).status).toBe(200);
    const ac = new AbortController();
    const r = h.stamp(sha256('r'), { key: KEY_A, signal: ac.signal });
    r.catch(() => undefined);
    await sleep(5);
    const y = h.stamp(sha256('y'), { key: KEY_A });
    await sleep(30);
    ac.abort();
    await sleep(330); // R's booked time has passed: its count is back
    const a4 = h.stamp(sha256('a4'), { key: KEY_A });
    await sleep(10);
    expect((await h.stamp(sha256('a5'), { key: KEY_A })).status).toBe(429); // a1, y, a4: three
    expect((await y).status).toBe(200);
    expect((await a4).status).toBe(200);
  }, 30_000);
});

describe('M32: a request that joined an open window is checked again when the window is stamped', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('the joiner (not the opener) is revoked: 401, the opener is stamped', async () => {
    h = await start({ batch: { windowMs: 600, max: 100 }, minIntervalMs: 600, maxWaitMs: 10_000 });
    const opener = h.stamp(sha256('a'), { key: KEY_A });
    await sleep(100);
    const joiner = h.stamp(sha256('f'), { key: KEY_F }); // joins the open window
    await sleep(100);
    h.relay.setKeys(ALL({ [KEY_F.id]: { revoked: true } }));
    expect((await joiner).status).toBe(401);
    expect((await opener).status).toBe(200);
    expect(h.calls).toHaveLength(1);
  });
});

describe('H2: `services` and the solo type are looked at again for a request that waits', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('single operation: services narrowed to another service while the request waits: 401, no call', async () => {
    h = await start({ batch: null, minIntervalMs: 600, maxWaitMs: 10_000 });
    expect((await h.stamp(sha256('1'), { key: KEY_A })).status).toBe(200);
    const waiting = h.stamp(sha256('2'), { key: KEY_A });
    await sleep(100);
    h.relay.setKeys([rk(KEY_A, { services: ['digicert'] }), rk(KEY_B, { solo: true })]);
    expect((await waiting).status).toBe(401);
    expect(h.calls).toHaveLength(1);
    expect((await h.stamp(sha256('3'), { key: KEY_A })).status).toBe(403); // a new request: the door
    expect(h.stats().serviceDenied).toBeGreaterThanOrEqual(2);
  });

  it('collecting operation: a solo key demoted to type 1 while its solo stamp waits: 401, no call', async () => {
    h = await start({ batch: { windowMs: 300, max: 100 }, minIntervalMs: 600, maxWaitMs: 10_000 });
    expect((await h.stamp(sha256('1'), { key: KEY_C, body: solo('1') })).status).toBe(200);
    const waiting = h.stamp(sha256('2'), { key: KEY_B, body: solo('2') });
    await sleep(100);
    h.relay.setKeys([rk(KEY_B), rk(KEY_C, { solo: true })]);
    expect((await waiting).status).toBe(401);
    expect(h.calls).toHaveLength(1);
    expect((await h.stamp(sha256('3'), { key: KEY_B, body: solo('3') })).status).toBe(403);
  });

  it('a key that keeps its rights is stamped as before', async () => {
    h = await start({ batch: null, minIntervalMs: 600, maxWaitMs: 10_000 });
    expect((await h.stamp(sha256('1'), { key: KEY_A })).status).toBe(200);
    const waiting = h.stamp(sha256('2'), { key: KEY_A });
    await sleep(100);
    h.relay.setKeys([rk(KEY_A, { services: ['freetsa'] }), rk(KEY_B, { solo: true })]);
    expect((await waiting).status).toBe(200);
  });
});

describe('N3: replay cache after a wall clock set back', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('a full cache answers 429; the entries stay (the wall clock may let their heads in again), Retry-After is the bound of 125 s', async () => {
    h = await start({ batch: null, minIntervalMs: 50, authReplayEntries: 4 });
    for (const [i, k] of [KEY_A, KEY_A, KEY_F, KEY_F].entries()) {
      expect((await h.stamp(sha256('p' + i), { key: k })).status).toBe(200);
    }
    h.clock.offset = -3_600_000;
    h.mono.offset += 200_000;
    const r = await h.stamp(sha256('q'), { key: KEY_A });
    // The entries cannot be dropped: the wall clock may let their heads in again once it has caught up. The answer says so.
    expect(r.status).toBe(429);
    expect(Number(r.headers.get('Retry-After'))).toBe(125);
  });
});

describe('N2: the comment of maxClockOffsetMs', () => {
  it('names the real default (65000)', () => {
    const text = readFileSync(new URL('../src/client/client.ts', import.meta.url), 'utf8');
    expect(text).not.toContain('Default 120000');
    expect(text).toMatch(/maxClockOffsetMs\?: number;/);
    expect(text).toMatch(/Largest clock offset[^\n]*Default 65000/);
  });
});
