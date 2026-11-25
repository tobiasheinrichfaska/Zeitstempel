import { toBase64Url } from '../src/index.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import {
  KEY_A,
  KEY_B,
  KEY_F,
  M,
  TOL,
  expectSpaced,
  gaps,
  same,
  sha256,
  sleep,
  start,
  type Harness,
} from './spacing-harness.ts';

// Single operation (no `RELAY_BATCH_MS`): two calls of the relay to one service (and identity) are at least
// `minIntervalMs` apart, on top of the budget per minute. A request whose time is not yet there waits (at most
// `RELAY_MAX_WAIT_MS`); later than that at the door is `429`; a full queue or a wait that ran late is `503 busy`;
// `close()` answers the waiting ones. A stub service records the time of every call. Real clock; `minIntervalMs` 600 ms.

const hashes = (n: number, tag = 'h') => Array.from({ length: n }, (_, i) => sha256(`${tag}${i}`));
const withToken = (hash: Uint8Array, token: string) => ({
  hash: toBase64Url(hash),
  upstream: { token },
});

describe('single operation: the minimum distance between two calls to one service', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('13 requests at once reach the service at least one distance apart', async () => {
    h = await start({ batch: null, minIntervalMs: M, maxWaitMs: 10_000 });
    const xs = hashes(13);
    const answers = xs.map((x) => h.stamp(x, { key: KEY_A }));
    expect((await Promise.all(answers)).map((r) => r.status)).toEqual(Array(13).fill(200));
    expect(h.calls).toHaveLength(13);
    expectSpaced(h.calls);
    for (const g of gaps(h.calls)) expect(g).toBeGreaterThanOrEqual(M - TOL);
    for (const x of xs) expect(h.calls.filter((c) => same(c.imprint, x))).toHaveLength(1); // each hash once
    expect(h.stats()).toEqual({ stamped: 13, refused: {} });
  }, 30_000);

  it('the first request of a fresh relay and one after the distance has passed are served at once', async () => {
    h = await start({ batch: null, minIntervalMs: M });
    const t1 = await h.timed(sha256('fresh'), { key: KEY_A });
    expect(t1.res.status).toBe(200);
    expect(t1.at).toBeLessThan(250);
    await sleep(M + 50);
    const t2 = await h.timed(sha256('later'), { key: KEY_B });
    expect(t2.res.status).toBe(200);
    expect(t2.at).toBeLessThan(250);
    expectSpaced(h.calls);
  });

  it('a request whose time lies beyond the waiting limit is 429 with Retry-After at once and never reaches the service', async () => {
    h = await start({ batch: null, minIntervalMs: M, maxWaitMs: 1000 });
    const [a, b, c] = hashes(3);
    const first = h.stamp(a!, { key: KEY_A }); // now
    await sleep(20);
    const second = h.stamp(b!, { key: KEY_A }); // at M: within the limit, it waits
    await sleep(20);
    const t = await h.timed(c!, { key: KEY_A }); // at 2 M = 1200 ms: more than 1000 ms
    expect(t.res.status).toBe(429);
    expect(Number(t.res.headers.get('retry-after'))).toBe(2);
    expect(t.at).toBeLessThan(400); // no waiting
    expect(await t.res.json()).toEqual({ error: 'rate-limited' });
    expect((await first).status).toBe(200);
    expect((await second).status).toBe(200);
    expect(h.calls).toHaveLength(2);
    expectSpaced(h.calls);
    expect(h.stats()).toEqual({ stamped: 2, refused: { 'rate-limited': 1 } });
  });

  it('the budget per minute still counts on top: its 429 comes first when it is the longer wait', async () => {
    h = await start({
      batch: null,
      minIntervalMs: 20_000,
      budgetWindowMs: 60_000,
      maxWaitMs: 1000,
    });
    // three per minute at 20 s; the distance alone allows a second one only after 20 s: that is 429, too
    expect((await h.stamp(sha256('x'), { key: KEY_A })).status).toBe(200);
    const r = await h.stamp(sha256('y'), { key: KEY_A });
    expect(r.status).toBe(429);
    expect(Number(r.headers.get('retry-after'))).toBeGreaterThanOrEqual(19);
    expect(h.calls).toHaveLength(1);
  });

  it('a wait that ran late (the loop stood still) is 503 busy with Retry-After and the request is never stamped', async () => {
    h = await start({ batch: null, minIntervalMs: 300, maxWaitMs: 1000 });
    const [a, b, c] = hashes(3);
    const first = h.stamp(a!, { key: KEY_A }); // now
    await sleep(20);
    const second = h.stamp(b!, { key: KEY_A }); // at 300
    await sleep(20);
    const third = h.stamp(c!, { key: KEY_A }); // at 600: within the limit
    await sleep(50);
    h.mono.offset += 5000; // the process stood still: everything that was due is late now
    const [r1, r2, r3] = await Promise.all([first, second, third]);
    expect(r1.status).toBe(200);
    // both timers fire at 5000, far past the limit of 1000 (+ the slack): the time of the call counts, not only the booked time
    expect(r2.status).toBe(503);
    expect(r3.status).toBe(503);
    expect(await r3.json()).toEqual({ error: 'busy' });
    expect(Number(r3.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    expect(h.calls).toHaveLength(1);
    expect(h.stats().stamped).toBe(1);
    expect(h.stats().refused['busy']).toBe(2);
  });

  it('the waiting queue is limited per service: a further request is 503 busy at once, not stamped', async () => {
    const n = RELAY_LIMITS.singleQueueMax;
    h = await start({ batch: null, minIntervalMs: 100, maxWaitMs: 30_000 });
    const sent: Promise<Response>[] = [];
    for (const x of hashes(n + 1)) {
      sent.push(h.stamp(x, { key: KEY_A })); // the first is served at once, n wait
      await sleep(2);
    }
    const t = await h.timed(sha256('one-too-many'), { key: KEY_A });
    expect(t.res.status).toBe(503);
    expect(await t.res.json()).toEqual({ error: 'busy' });
    expect(Number(t.res.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    expect(t.at).toBeLessThan(400);
    expect((await Promise.all(sent)).map((r) => r.status)).toEqual(Array(n + 1).fill(200));
    expect(h.calls).toHaveLength(n + 1);
    expect(h.stats().refused['busy']).toBe(1);
  }, 20_000);

  it('close() answers the waiting requests with 503 shutting-down, nothing is stamped after it, new ones get the same', async () => {
    h = await start({ batch: null, minIntervalMs: 2000, maxWaitMs: 8000 });
    const [a, b, c] = hashes(3);
    expect((await h.stamp(a!, { key: KEY_A })).status).toBe(200);
    const waiting = [h.stamp(b!, { key: KEY_A }), h.stamp(c!, { key: KEY_F })];
    await sleep(100);
    h.relay.close();
    const answers = await Promise.all(waiting);
    expect(answers.map((r) => r.status)).toEqual([503, 503]);
    expect(await answers[0]!.json()).toEqual({ error: 'shutting-down' });
    expect((await h.stamp(sha256('after'), { key: KEY_A })).status).toBe(503);
    await sleep(100);
    expect(h.calls).toHaveLength(1);
    expect(h.stats().stamped).toBe(1);
  });

  it('a wait does not break the windows of the authentication and of the token time (the head is checked at the door)', async () => {
    // The limit of the wait is at most the window of the authentication and the slack of `genTime`, so a head that was
    // fresh at the door never expires while it waits, and the token is stamped around the moment of the call.
    expect(RELAY_LIMITS.maxWaitMaxMs).toBeLessThanOrEqual(RELAY_LIMITS.authWindowSeconds * 1000);
    expect(RELAY_LIMITS.maxWaitMaxMs).toBeLessThanOrEqual(RELAY_LIMITS.genTimeSlackMs);
    h = await start({ batch: null, minIntervalMs: M, maxWaitMs: 8000 });
    expect((await h.stamp(sha256('first'), { key: KEY_A })).status).toBe(200);
    // the second waits; while it waits the wall clock of the relay runs 59 s ahead (head 59 s old: inside the window)
    const secondHash = sha256('second');
    const head = (await import('./auth-helpers.ts')).nodeAuthHeaderMs(
      KEY_B,
      KEY_B.id,
      'POST',
      '/v1/stamp/freetsa',
      Date.now(),
      new TextEncoder().encode(JSON.stringify({ hash: toBase64Url(secondHash) })),
    );
    const second = h.stamp(secondHash, { key: KEY_B, head });
    await sleep(100);
    h.clock.offset += 59_000;
    const r = await second;
    expect(r.status).toBe(200); // not refused for the age of its head, token time within the slack
    // the same head again, after the wait and still inside the window: a replay
    const again = await h.stamp(secondHash, { key: KEY_B, head });
    expect(again.status).toBe(401);
    expect(h.calls).toHaveLength(2);
  });
});

describe('single operation: credentials of the app are an identity of their own', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('different tokens are different lanes (no distance between them); the same token from two keys is one lane', async () => {
    h = await start({ batch: null, bearer: true, minIntervalMs: M, maxWaitMs: 8000 });
    const t0 = Date.now();
    const sent = [
      h.stamp(sha256('a1'), { key: KEY_A, body: withToken(sha256('a1'), 'token-one') }),
      h.stamp(sha256('b1'), { key: KEY_A, body: withToken(sha256('b1'), 'token-two') }),
      h.stamp(sha256('a2'), { key: KEY_B, body: withToken(sha256('a2'), 'token-one') }), // same identity, other key
      h.stamp(sha256('b2'), { key: KEY_B, body: withToken(sha256('b2'), 'token-two') }),
    ];
    expect((await Promise.all(sent)).map((r) => r.status)).toEqual([200, 200, 200, 200]);
    expect(h.calls).toHaveLength(4);
    for (const token of ['token-one', 'token-two']) {
      const own = h.calls.filter((c) => c.token === token);
      expect(own).toHaveLength(2);
      expectSpaced(own);
    }
    // the two identities did not wait for each other: both first calls are early, both second calls are about one distance away
    const early = h.calls.filter((c) => c.at < 250);
    expect(early).toHaveLength(2);
    expect(new Set(early.map((c) => c.token)).size).toBe(2);
    expect(Date.now() - t0).toBeLessThan(2 * M + 400); // not four distances
  });

  it('two lanes of one service (own credentials) both keep the distance on their own', async () => {
    h = await start({ batch: null, minIntervalMs: M, maxWaitMs: 8000 });
    const answers = await Promise.all([
      h.stamp(sha256('p'), { key: KEY_A }),
      h.stamp(sha256('q'), { key: KEY_B }),
    ]);
    expect(answers.map((r) => r.status)).toEqual([200, 200]);
    expectSpaced(h.calls); // the lane is the service (the relay's own credentials): one distance for all keys
  });
});

describe('single operation: collecting operation is not changed by the distance of single operation', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('requests of one window need no distance among themselves: one call for all, answered with the window', async () => {
    h = await start({ batch: { windowMs: M, max: 100 }, minIntervalMs: M, maxWaitMs: 8000 });
    const t0 = Date.now();
    const answers = await Promise.all(hashes(5).map((x) => h.stamp(x, { key: KEY_A })));
    expect(answers.map((r) => r.status)).toEqual(Array(5).fill(200));
    expect(h.calls).toHaveLength(1);
    expect(Date.now() - t0).toBeLessThan(M + 400);
  });
});
