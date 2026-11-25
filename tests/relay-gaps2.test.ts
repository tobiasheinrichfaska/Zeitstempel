import { toBase64Url } from '../src/index.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import {
  KEY_A,
  KEY_B,
  KEY_C,
  KEY_D,
  KEY_F,
  sha256,
  sleep,
  solo,
  start,
  type Harness,
} from './spacing-harness.ts';

// Gaps that the mutation runs of the audits left open (all against the relay with stubs, nothing leaves the process):
// - the minimum distance to the millisecond: the monotonic clock of the relay is virtual (`virtualMono`, it moves only
//   when the test moves it), so there is no timer jitter and no tolerance: one millisecond too short is a call too early;
// - the tables per identity are emptied when an identity expires (`heldForTests`);
// - the look at the door reads the gate of the identity, not the gate of the service.

const MIN = 100; // minIntervalMs of the virtual-clock tests (the real timers of the relay run MIN ms at a time)

const until = async (check: () => boolean, ms = 3000): Promise<void> => {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) throw new Error('condition not reached');
    await sleep(5);
  }
};

/**
 * The second call may not come before the distance has passed: at `MIN - 1` ms after the first it must not be made,
 * at `MIN` it is made, and the two calls are exactly `MIN` apart on the monotonic clock of the relay (0 ms tolerance).
 */
async function exactDistance(
  h: Harness,
  first: () => Promise<Response>,
  second: () => Promise<Response>,
): Promise<void> {
  const p1 = first();
  await until(() => h.calls.length === 1);
  const p2 = second();
  await sleep(450); // the window closes (100 ms) and the timers of the relay look several times: virtual time stands still
  expect(h.calls).toHaveLength(1);
  h.advance(MIN - 1);
  await sleep(450);
  expect(h.calls).toHaveLength(1); // one millisecond before the distance: still not called
  h.advance(1);
  await until(() => h.calls.length === 2);
  expect(h.calls[1]!.mono - h.calls[0]!.mono).toBe(MIN);
  expect((await p1).status).toBe(200);
  expect((await p2).status).toBe(200);
}

describe('the minimum distance is exact to the millisecond (virtual monotonic clock, no tolerance)', () => {
  let h: Harness;
  afterEach(() => h.close());
  const collecting = (over: { minIntervalMs?: number } = {}) =>
    start({
      batch: { windowMs: 100, max: 100 },
      minIntervalMs: MIN,
      maxWaitMs: 60_000,
      virtualMono: true,
      ...over,
    });

  it('single operation after single operation, a request that arrives while the distance runs', async () => {
    h = await start({ batch: null, minIntervalMs: MIN, maxWaitMs: 10_000, virtualMono: true });
    await exactDistance(
      h,
      () => h.stamp(sha256('s1'), { key: KEY_A }),
      () => h.stamp(sha256('s2'), { key: KEY_A }),
    );
  });

  it('single operation: a request that arrives one millisecond too early waits, one at the exact time is served at once', async () => {
    h = await start({ batch: null, minIntervalMs: MIN, maxWaitMs: 10_000, virtualMono: true });
    const p1 = h.stamp(sha256('e1'), { key: KEY_A });
    await until(() => h.calls.length === 1);
    h.advance(MIN - 1);
    const p2 = h.stamp(sha256('e2'), { key: KEY_A }); // arrives at MIN - 1: its time is one millisecond away
    await sleep(450);
    expect(h.calls).toHaveLength(1);
    h.advance(1);
    await until(() => h.calls.length === 2);
    expect(h.calls[1]!.mono - h.calls[0]!.mono).toBe(MIN);
    h.advance(MIN); // exactly the distance after the second call: served at once, no wait
    const p3 = h.stamp(sha256('e3'), { key: KEY_A });
    await until(() => h.calls.length === 3);
    expect(h.calls[2]!.mono - h.calls[1]!.mono).toBe(MIN);
    expect((await Promise.all([p1, p2, p3])).map((r) => r.status)).toEqual([200, 200, 200]);
  });

  it('single operation: a call that is made late pushes the next one, counted from the call as it really was', async () => {
    h = await start({ batch: null, minIntervalMs: MIN, maxWaitMs: 10_000, virtualMono: true });
    const p1 = h.stamp(sha256('l1'), { key: KEY_A });
    await until(() => h.calls.length === 1);
    const p2 = h.stamp(sha256('l2'), { key: KEY_A }); // due at MIN
    const p3 = h.stamp(sha256('l3'), { key: KEY_A }); // booked for 2 MIN
    await sleep(100);
    h.advance(MIN + 50); // the process was late: the second call is made 50 ms after its time
    await until(() => h.calls.length === 2);
    expect(h.calls[1]!.mono - h.calls[0]!.mono).toBe(MIN + 50);
    h.advance(MIN - 1); // booked time of the third has passed, but the distance to the call that was really made is not over
    await sleep(450);
    expect(h.calls).toHaveLength(2);
    h.advance(1);
    await until(() => h.calls.length === 3);
    expect(h.calls[2]!.mono - h.calls[1]!.mono).toBe(MIN);
    expect((await Promise.all([p1, p2, p3])).map((r) => r.status)).toEqual([200, 200, 200]);
  });

  it('solo after solo', async () => {
    h = await collecting();
    await exactDistance(
      h,
      () => h.stamp(sha256('a'), { key: KEY_B, body: solo(sha256('a')) }),
      () => h.stamp(sha256('b'), { key: KEY_C, body: solo(sha256('b')) }),
    );
  });

  it('window after window', async () => {
    h = await collecting();
    await exactDistance(
      h,
      () => h.stamp(sha256('w1'), { key: KEY_A }),
      () => h.stamp(sha256('w2'), { key: KEY_F }),
    );
  });

  it('window after solo', async () => {
    h = await collecting();
    await exactDistance(
      h,
      () => h.stamp(sha256('x'), { key: KEY_B, body: solo(sha256('x')) }),
      () => h.stamp(sha256('w'), { key: KEY_A }),
    );
  });

  it('solo after window', async () => {
    h = await collecting();
    await exactDistance(
      h,
      () => h.stamp(sha256('w'), { key: KEY_A }),
      () => h.stamp(sha256('y'), { key: KEY_D, body: solo(sha256('y')) }),
    );
  });
});

describe('an expired identity leaves nothing behind in the tables of the relay', () => {
  let h: Harness;
  afterEach(() => h.close());
  const token = (n: number) => `token-${n}`;
  const withToken = (hash: Uint8Array, t: string) => ({
    hash: toBase64Url(hash),
    upstream: { token: t },
  });

  it('single operation: the gates and the budget times of expired identities are dropped when a new identity comes', async () => {
    h = await start({ batch: null, bearer: true, minIntervalMs: 50, budgetWindowMs: 400 });
    for (let i = 0; i < 6; i += 1) {
      const x = sha256(`g${i}`);
      expect((await h.stamp(x, { key: KEY_A, body: withToken(x, token(i)) })).status).toBe(200);
    }
    expect(h.relay.heldForTests()).toMatchObject({ known: 6, gates: 6, windows: 6 });
    await sleep(500); // a whole window of the budget (400 ms) after the last answer: all six are expired
    const x = sha256('g-new');
    expect((await h.stamp(x, { key: KEY_A, body: withToken(x, 'token-new') })).status).toBe(200);
    expect(h.relay.heldForTests()).toEqual({
      known: 1,
      windows: 1,
      lastCall: 0,
      lanes: 0,
      gates: 1,
      shares: 0,
    });
  });

  it('collecting operation: the last calls, lanes and budget times of expired identities are dropped too', async () => {
    h = await start({
      batch: { windowMs: 50, max: 100 },
      bearer: true,
      minIntervalMs: 50,
      budgetWindowMs: 400,
    });
    for (let i = 0; i < 6; i += 1) {
      const x = sha256(`c${i}`);
      expect((await h.stamp(x, { key: KEY_A, body: withToken(x, token(i)) })).status).toBe(200);
    }
    expect(h.relay.heldForTests()).toMatchObject({ known: 6, lastCall: 6, windows: 6 });
    await sleep(500);
    const x = sha256('c-new');
    expect((await h.stamp(x, { key: KEY_A, body: withToken(x, 'token-new') })).status).toBe(200);
    expect(h.relay.heldForTests()).toEqual({
      known: 1,
      windows: 1,
      lastCall: 1,
      lanes: 1,
      gates: 0,
      shares: 0,
    });
  });
});

describe('the look at the door reads the gate of the identity, not the one of the service', () => {
  let h: Harness;
  afterEach(() => h.close());
  const M = 600;
  const withToken = (hash: Uint8Array, t: string) => ({
    hash: toBase64Url(hash),
    upstream: { token: t },
  });

  it('a lane that is booked beyond the waiting limit is 429; another identity of the same service is served at once', async () => {
    h = await start({ batch: null, bearer: true, minIntervalMs: M, maxWaitMs: 1000 });
    const one = (name: string) => {
      const x = sha256(name);
      return h.stamp(x, { key: KEY_A, body: withToken(x, 'token-one') });
    };
    const first = one('o1'); // now
    await sleep(20);
    const second = one('o2'); // at M: within the limit, it waits
    await sleep(20);
    const x = sha256('o3');
    const busy = await h.timed(x, { key: KEY_A, body: withToken(x, 'token-one') }); // at 2 M: more than 1000 ms
    expect(busy.res.status).toBe(429);
    expect(Number(busy.res.headers.get('retry-after'))).toBe(2);
    const y = sha256('t1');
    const free = await h.timed(y, { key: KEY_A, body: withToken(y, 'token-two') }); // its own lane: nothing booked
    expect(free.res.status).toBe(200);
    expect(free.at).toBeLessThan(250); // and no wait for the lane of the other identity
    expect((await first).status).toBe(200);
    expect((await second).status).toBe(200);
    expect(h.calls.filter((c) => c.token === 'token-one')).toHaveLength(2);
    expect(h.calls.filter((c) => c.token === 'token-two')).toHaveLength(1);
    expect(h.stats().refused).toEqual({ 'rate-limited': 1 });
  });
  it('the waiting queue is counted per identity: a full queue of one identity is 503 busy, another identity is served', async () => {
    const n = RELAY_LIMITS.singleQueueMax;
    h = await start({ batch: null, bearer: true, minIntervalMs: 100, maxWaitMs: 30_000 });
    const as = (name: string, t: string) => {
      const x = sha256(name);
      return h.stamp(x, { key: KEY_A, body: withToken(x, t) });
    };
    const sent: Promise<Response>[] = [];
    for (let i = 0; i <= n; i += 1) {
      sent.push(as(`q${i}`, 'token-one')); // the first is served at once, n wait
      await sleep(2);
    }
    const full = await as('q-extra', 'token-one');
    expect(full.status).toBe(503);
    expect(await full.json()).toEqual({ error: 'busy' });
    expect((await as('other', 'token-two')).status).toBe(200); // its own lane, its own queue
    expect((await Promise.all(sent)).map((r) => r.status)).toEqual(Array(n + 1).fill(200));
    expect(h.stats().refused['busy']).toBe(1);
  }, 20_000);
});
