import { toBase64Url } from '../src/index.ts';
import { RELAY_LIMITS, WAIT_TOLERANCE_MS } from '../relay/limits.ts';
import { KEY_A, KEY_B, sha256, sleep, solo, start, type Harness } from './spacing-harness.ts';

// Single operation, the findings of the sixth audit (stubs only, nothing leaves the process). Most tests use the virtual
// monotonic clock of the harness (`virtualMono`): it moves only when the test moves it, so a stalled loop, a late timer
// and the distance to the millisecond are exact; the real timers of the relay still run (a few hundred ms per test).
// - F1 the last request the door lets through must not be refused after the whole wait because the calls before it were late;
// - F5 a booking that is not used (busy, client gone) is given back when it is the last of the chain;
// - F3 a request whose client is gone is not stamped (no call, `client-aborted`);
// - F2 an identity is dropped on the monotonic clock and not before its distance is over;
// - the gaps of the mutation runs: the distance after a late call (M03, M05) and the `Retry-After` of the full queue (M27).

const MIN = 200; // minIntervalMs
const until = async (check: () => boolean, ms = 4000): Promise<void> => {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) throw new Error('condition not reached');
    await sleep(5);
  }
};
const withToken = (hash: Uint8Array, token: string) => ({
  hash: toBase64Url(hash),
  upstream: { token },
});

describe('F1: the last request that the door lets through is stamped, whatever the timers before it did', () => {
  let h: Harness;
  afterEach(() => h.close());
  const N = 6; // maxWait / MIN + 1: the last one is booked at exactly the limit

  /** N requests at once; every call is `late` ms after its time (the loop stood still a bit each time). */
  async function burst(late: number): Promise<number[]> {
    h = await start({ batch: null, minIntervalMs: MIN, maxWaitMs: 1000, virtualMono: true });
    const sent = Array.from({ length: N }, (_, i) => h.stamp(sha256(`f1-${i}`), { key: KEY_A }));
    await until(() => h.calls.length === 1);
    await sleep(150); // all have arrived (the clock stood still, so all are booked from the same moment)
    for (let i = 1; i < N; i += 1) {
      h.advance(MIN + late);
      await until(() => h.calls.length === i + 1 || h.stats().refused['busy'] !== undefined);
      if (h.stats().refused['busy'] !== undefined) break;
    }
    return (await Promise.all(sent)).map((r) => r.status);
  }

  it('calls that are late by 10 ms each (40 ms in all, within the slack): all six are stamped, none is busy', async () => {
    expect(WAIT_TOLERANCE_MS).toBe(50);
    const statuses = await burst(10);
    expect(statuses).toEqual(Array(N).fill(200));
    expect(h.calls).toHaveLength(N);
    for (let i = 1; i < N; i += 1) {
      expect(h.calls[i]!.mono - h.calls[i - 1]!.mono).toBe(MIN + 10); // never closer than the distance
    }
    expect(h.stats()).toEqual({ stamped: N, refused: {} });
  }, 15_000);

  it('calls that are late by more than the slack in all (15 ms each, 60 ms): the last one is 503 busy, not stamped', async () => {
    const statuses = await burst(15);
    expect(statuses.filter((s) => s === 200)).toHaveLength(N - 1);
    expect(statuses.filter((s) => s === 503)).toHaveLength(1);
    expect(h.calls).toHaveLength(N - 1);
    expect(h.stats().refused['busy']).toBe(1);
  }, 15_000);

  it('with real timers: a burst of maxWait / distance + 1 requests is stamped completely, at least one distance apart', async () => {
    h = await start({ batch: null, minIntervalMs: MIN, maxWaitMs: 1000 });
    const sent = Array.from({ length: N }, (_, i) => h.stamp(sha256(`f1r-${i}`), { key: KEY_A }));
    expect((await Promise.all(sent)).map((r) => r.status)).toEqual(Array(N).fill(200));
    expect(h.calls).toHaveLength(N);
    const times = h.calls.map((c) => c.mono).sort((a, b) => a - b);
    for (let i = 1; i < N; i += 1)
      expect(times[i]! - times[i - 1]!).toBeGreaterThanOrEqual(MIN - 5);
    expect(h.stats()).toEqual({ stamped: N, refused: {} });
  }, 15_000);
});

describe('F5: a booking that nobody uses is given back when it is the last of the chain', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('a request that ends busy does not leave its time booked: the next request is called as soon as the distance allows', async () => {
    h = await start({ batch: null, minIntervalMs: MIN, maxWaitMs: 500, virtualMono: true });
    const a = h.stamp(sha256('p-a'), { key: KEY_A }); // now (T0)
    await until(() => h.calls.length === 1);
    const b = h.stamp(sha256('p-b'), { key: KEY_A }); // booked for T0 + 200
    await sleep(20);
    const c = h.stamp(sha256('p-c'), { key: KEY_A }); // booked for T0 + 400, within the limit of 500
    await sleep(20);
    h.advance(380); // the loop stood still: b is called at T0 + 380, so c would be called at 580: beyond 500 + the slack
    await until(() => h.calls.length === 2);
    const rc = await c;
    expect(rc.status).toBe(503);
    expect(await rc.json()).toEqual({ error: 'busy' });
    h.advance(200); // 580: the distance to the call of b has passed; c's booking (till 600) must not hold it back
    const d = h.stamp(sha256('p-d'), { key: KEY_A });
    await until(() => h.calls.length === 3, 1500); // at once, not at 600
    expect(h.calls[2]!.mono - h.calls[1]!.mono).toBe(MIN);
    expect((await Promise.all([a, b, d])).map((r) => r.status)).toEqual([200, 200, 200]);
    expect(h.calls).toHaveLength(3);
  });
});

describe('F3: a request whose client is gone while it waits is not stamped', () => {
  let h: Harness;
  afterEach(() => h.close());
  const gone = (p: Promise<Response>) =>
    p.then(
      () => 'answered',
      () => 'aborted',
    );

  it('last of the chain: no call, counted as client-aborted, its time is free for the next request, the distance holds', async () => {
    h = await start({ batch: null, minIntervalMs: MIN, maxWaitMs: 10_000, virtualMono: true });
    const a = h.stamp(sha256('g-a'), { key: KEY_A });
    await until(() => h.calls.length === 1);
    const ctl = new AbortController();
    const b = gone(h.stamp(sha256('g-b'), { key: KEY_A, signal: ctl.signal })); // booked for T0 + 200
    await sleep(50);
    ctl.abort(); // the client (or its proxy) gives up while b waits
    expect(await b).toBe('aborted');
    await until(() => h.stats().refused['client-aborted'] === 1); // seen when its time is looked at (real timer, 200 ms)
    expect(h.calls).toHaveLength(1); // the service was not called for it
    expect(h.stats().stamped).toBe(1);
    const c = h.stamp(sha256('g-c'), { key: KEY_A }); // takes the free time, T0 + 200, not T0 + 400
    await sleep(100);
    expect(h.calls).toHaveLength(1);
    h.advance(MIN - 1);
    await sleep(300);
    expect(h.calls).toHaveLength(1); // one millisecond before the distance
    h.advance(1);
    await until(() => h.calls.length === 2);
    expect(h.calls[1]!.mono - h.calls[0]!.mono).toBe(MIN);
    expect((await Promise.all([a, c])).map((r) => r.status)).toEqual([200, 200]);
    expect(h.stats()).toEqual({ stamped: 2, refused: { 'client-aborted': 1 } });
  });

  it('in the middle of the chain: no call either, the later request keeps its own time (the gap is not filled, order stays)', async () => {
    h = await start({ batch: null, minIntervalMs: MIN, maxWaitMs: 10_000, virtualMono: true });
    const a = h.stamp(sha256('m-a'), { key: KEY_A });
    await until(() => h.calls.length === 1);
    const ctl = new AbortController();
    const b = gone(h.stamp(sha256('m-b'), { key: KEY_A, signal: ctl.signal })); // T0 + 200
    await sleep(20);
    const c = h.stamp(sha256('m-c'), { key: KEY_A }); // T0 + 400
    await sleep(20);
    ctl.abort();
    expect(await b).toBe('aborted');
    await sleep(500); // b's time is looked at: nobody calls, its booking is not given back (c is behind it)
    const d = h.stamp(sha256('m-d'), { key: KEY_A }); // behind c: T0 + 600, not in front of it
    await sleep(50);
    h.advance(MIN); // the time of b has come
    await sleep(450);
    expect(h.calls).toHaveLength(1);
    expect(h.stats().refused['client-aborted']).toBe(1);
    h.advance(MIN); // T0 + 400: c
    await until(() => h.calls.length === 2);
    expect(h.calls[1]!.mono - h.calls[0]!.mono).toBe(2 * MIN);
    await sleep(300);
    expect(h.calls).toHaveLength(2);
    h.advance(MIN); // T0 + 600: d
    await until(() => h.calls.length === 3);
    expect(h.calls[2]!.mono - h.calls[1]!.mono).toBe(MIN);
    expect((await Promise.all([a, c, d])).map((r) => r.status)).toEqual([200, 200, 200]);
    expect(h.stats()).toEqual({ stamped: 3, refused: { 'client-aborted': 1 } });
  });
});

describe('the distance after a call that was late (gaps M03, M05 of the mutation runs)', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('a request that arrives shortly after a late call, but before the booked time, waits for the distance to that call', async () => {
    h = await start({ batch: null, minIntervalMs: MIN, maxWaitMs: 10_000, virtualMono: true });
    const a = h.stamp(sha256('t-a'), { key: KEY_A });
    await until(() => h.calls.length === 1);
    const b = h.stamp(sha256('t-b'), { key: KEY_A }); // booked for T0 + 200
    await sleep(20);
    h.advance(250); // the process was late: b is called at T0 + 250 (booking of the next: 400, distance to b: 450)
    await until(() => h.calls.length === 2);
    h.advance(160); // T0 + 410: past the booking (400), but only 160 ms after the call of b
    const c = h.stamp(sha256('t-c'), { key: KEY_A });
    await sleep(450);
    expect(h.calls).toHaveLength(2); // not called at once
    h.advance(MIN - 160 - 1);
    await sleep(300);
    expect(h.calls).toHaveLength(2);
    h.advance(1);
    await until(() => h.calls.length === 3);
    expect(h.calls[2]!.mono - h.calls[1]!.mono).toBe(MIN);
    expect((await Promise.all([a, b, c])).map((r) => r.status)).toEqual([200, 200, 200]);
  });

  it('a request that is called at once (nothing booked) counts as a call: a late waiter behind it keeps the distance to it', async () => {
    h = await start({ batch: null, minIntervalMs: MIN, maxWaitMs: 10_000, virtualMono: true });
    const a = h.stamp(sha256('u-a'), { key: KEY_A });
    await until(() => h.calls.length === 1);
    const b = h.stamp(sha256('u-b'), { key: KEY_A }); // booked for T0 + 200, its timer has not fired yet
    await sleep(20);
    h.advance(1000); // the loop stood still: the time of b is long past, its timer fires only later
    const c = h.stamp(sha256('u-c'), { key: KEY_A }); // arrives first: nothing in its way, called at once (T0 + 1000)
    await until(() => h.calls.length === 2);
    expect(h.calls[1]!.mono - h.calls[0]!.mono).toBe(1000);
    await sleep(450); // now the timer of b looks: it is due, but only 0 ms after the call of c
    expect(h.calls).toHaveLength(2);
    h.advance(MIN - 1);
    await sleep(300);
    expect(h.calls).toHaveLength(2);
    h.advance(1);
    await until(() => h.calls.length === 3);
    expect(h.calls[2]!.mono - h.calls[1]!.mono).toBe(MIN);
    expect((await Promise.all([a, b, c])).map((r) => r.status)).toEqual([200, 200, 200]);
  });
});

describe('M27: the full waiting queue is 503 busy with Retry-After from the time still booked', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('Retry-After is the booked time in seconds, rounded up (not a fixed value)', async () => {
    const n = RELAY_LIMITS.singleQueueMax;
    const m = 300;
    h = await start({ batch: null, minIntervalMs: m, maxWaitMs: 30_000, virtualMono: true });
    for (let i = 0; i <= n; i += 1) {
      void h.stamp(sha256(`r-${i}`), { key: KEY_A }).catch(() => undefined); // the first is called at once, n wait
      await sleep(3);
    }
    const r = await h.stamp(sha256('r-extra'), { key: KEY_A });
    expect(r.status).toBe(503);
    expect(await r.json()).toEqual({ error: 'busy' });
    // the next free time is (n + 1) distances away: 17 * 300 ms = 5100 ms
    expect(Number(r.headers.get('retry-after'))).toBe(Math.ceil(((n + 1) * m) / 1000));
    h.advance(1000); // one second later the same wait is shorter by that
    const r2 = await h.stamp(sha256('r-extra2'), { key: KEY_A });
    expect(r2.status).toBe(503);
    expect(Number(r2.headers.get('retry-after'))).toBe(Math.ceil(((n + 1) * m - 1000) / 1000));
  }, 20_000);
});

describe('M28: the late 503 busy carries Retry-After from the time still booked (virtual monotonic clock)', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('Retry-After is the end of the booked chain in seconds, rounded up (not a fixed value)', async () => {
    h = await start({ batch: null, minIntervalMs: 1000, maxWaitMs: 1000, virtualMono: true });
    const a = h.stamp(sha256('m28-a'), { key: KEY_A }); // called at once: T0
    await until(() => h.calls.length === 1);
    const b = h.stamp(sha256('m28-b'), { key: KEY_A }); // booked for T0 + 1000, within the limit
    await sleep(20);
    h.advance(1000);
    const c = h.stamp(sha256('m28-c'), { key: KEY_A }); // booked for T0 + 2000 (1000 + 1000 limit); the chain ends at T0 + 3000
    await sleep(20);
    h.advance(100); // the loop stood still: b's timer fires at T0 + 1100, past its limit (T0 + 1000 + slack)
    const rb = await b;
    expect(rb.status).toBe(503);
    expect(await rb.json()).toEqual({ error: 'busy' });
    // b is not the last of the chain (no time is given back): 3000 - 1100 = 1900 ms, rounded up to 2 s
    expect(rb.headers.get('retry-after')).toBe('2');
    expect((await a).status).toBe(200);
    h.advance(5000); // let c finish (it is late too)
    await c;
  }, 20_000);
});

describe('F2: an identity is dropped on the monotonic clock, and not before its distance is over', () => {
  let h: Harness;
  afterEach(() => h.close());
  /** Time passes for the monotonic clock and for the wall clock alike. */
  const pass = (ms: number): void => {
    h.advance(ms);
    h.clock.offset += ms;
  };

  it('single operation: a jump of the wall clock does not drop the gate of an identity (another identity arrives after it)', async () => {
    h = await start({
      batch: null,
      bearer: true,
      minIntervalMs: MIN,
      maxWaitMs: 10_000,
      virtualMono: true,
    });
    const x1 = sha256('x1');
    const p1 = h.stamp(x1, { key: KEY_A, body: withToken(x1, 'tok-x') });
    await until(() => h.calls.length === 1);
    expect((await p1).status).toBe(200); // x is idle now
    h.clock.offset += 120_000; // only the wall clock jumps (NTP step, resume); the monotonic one stands still
    const y = sha256('y1');
    expect((await h.stamp(y, { key: KEY_A, body: withToken(y, 'tok-y') })).status).toBe(200); // a new identity: the sweep
    const x2 = sha256('x2');
    const p2 = h.stamp(x2, { key: KEY_A, body: withToken(x2, 'tok-x') });
    await sleep(450);
    expect(h.calls.filter((c) => c.token === 'tok-x')).toHaveLength(1); // x waits for its distance
    h.advance(MIN);
    await until(() => h.calls.filter((c) => c.token === 'tok-x').length === 2);
    const xs = h.calls.filter((c) => c.token === 'tok-x');
    expect(xs[1]!.mono - xs[0]!.mono).toBe(MIN);
    expect((await p2).status).toBe(200);
  });

  const LONG = 120_000; // a service whose distance is longer than the window of the budget (60 s)

  it('single operation: a distance longer than the budget window is kept for an identity that is idle for the window', async () => {
    h = await start({
      batch: null,
      bearer: true,
      minIntervalMs: LONG,
      maxWaitMs: 30_000,
      virtualMono: true,
    });
    const send = (name: string, token: string) => {
      const x = sha256(name);
      return h.stamp(x, { key: KEY_A, body: withToken(x, token) });
    };
    expect((await send('l1', 'tok-x')).status).toBe(200);
    pass(61_000); // idle for the window, the distance (120 s) is not over
    expect((await send('l-y', 'tok-y')).status).toBe(200); // a new identity: the sweep must not drop the one of x
    const early = await send('l2', 'tok-x'); // 59 s to wait: beyond the limit of 30 s
    expect(early.status).toBe(429);
    expect(Number(early.headers.get('retry-after'))).toBe(59);
    expect(h.calls.filter((c) => c.token === 'tok-x')).toHaveLength(1);
    pass(LONG - 61_000); // the distance is over
    expect((await send('l3', 'tok-x')).status).toBe(200);
    const xs = h.calls.filter((c) => c.token === 'tok-x');
    expect(xs).toHaveLength(2);
    expect(xs[1]!.mono - xs[0]!.mono).toBe(LONG);
    pass(LONG + 1000); // idle for the distance: both are gone when the next new identity comes, memory stays bounded
    expect((await send('l-z', 'tok-z')).status).toBe(200);
    expect(h.relay.heldForTests()).toMatchObject({ known: 1, gates: 1 });
  });

  it('collecting operation: the same (a distance of 120 s, an identity that was idle for 61 s)', async () => {
    h = await start({
      batch: { windowMs: LONG, max: 100 },
      bearer: true,
      minIntervalMs: LONG,
      maxWaitMs: 30_000,
      virtualMono: true,
    });
    const send = (name: string, token: string) => {
      const x = sha256(name);
      return h.stamp(x, { key: KEY_B, body: { ...withToken(x, token), ...solo(x) } });
    };
    expect((await send('c1', 'tok-x')).status).toBe(200);
    pass(61_000);
    expect((await send('c-y', 'tok-y')).status).toBe(200);
    const early = await send('c2', 'tok-x');
    expect(early.status).toBe(429);
    expect(h.calls.filter((c) => c.token === 'tok-x')).toHaveLength(1);
    pass(LONG - 61_000);
    expect((await send('c3', 'tok-x')).status).toBe(200);
    const xs = h.calls.filter((c) => c.token === 'tok-x');
    expect(xs).toHaveLength(2);
    expect(xs[1]!.mono - xs[0]!.mono).toBe(LONG);
  });
});

describe('Q4 F1: a loop that stood still does not stamp past the limit (the time of the call counts, not only the booked time)', () => {
  let h: Harness;
  afterEach(() => h.close());

  /** a is called at once, b is booked one distance later; the monotonic clock jumps by `stall` before b's timer fires. */
  async function stalled(stall: number): Promise<Response> {
    h = await start({ batch: null, minIntervalMs: MIN, maxWaitMs: 1000, virtualMono: true });
    const a = h.stamp(sha256('q-a'), { key: KEY_A });
    await until(() => h.calls.length === 1);
    const b = h.stamp(sha256('q-b'), { key: KEY_A }); // booked for T0 + 200, within the limit
    await sleep(40); // b waits for its real timer (200 ms)
    h.advance(stall); // the loop stood still: b's timer fires when the clock is already here
    const rb = await b;
    expect((await a).status).toBe(200);
    return rb;
  }

  it('a stall past the limit and the slack: 503 busy with Retry-After, no call to the service', async () => {
    const rb = await stalled(1000 + WAIT_TOLERANCE_MS + 1);
    expect(rb.status).toBe(503);
    expect(await rb.json()).toEqual({ error: 'busy' });
    expect(Number(rb.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    expect(h.calls).toHaveLength(1);
    expect(h.stats()).toEqual({ stamped: 1, refused: { busy: 1 } });
  });

  it('a stall just within the limit and the slack: stamped, at least one distance after the call before', async () => {
    const rb = await stalled(1000 + WAIT_TOLERANCE_MS);
    expect(rb.status).toBe(200);
    expect(h.calls).toHaveLength(2);
    expect(h.calls[1]!.mono - h.calls[0]!.mono).toBe(1000 + WAIT_TOLERANCE_MS);
    expect(h.stats()).toEqual({ stamped: 2, refused: {} });
  });
});

describe('Q4 F1: collecting operation, a solo request that waits in the queue while the loop stood still', () => {
  let h: Harness;
  afterEach(() => h.close());

  async function stalledSolo(stall: number): Promise<Response> {
    h = await start({
      batch: { windowMs: 300, max: 100 },
      minIntervalMs: MIN,
      maxWaitMs: 1000,
      virtualMono: true,
    });
    const send = (name: string) => {
      const x = sha256(name);
      return h.stamp(x, { key: KEY_B, body: solo(x) });
    };
    const a = send('qs-a'); // a slot at once
    await until(() => h.calls.length === 1);
    const b = send('qs-b'); // waits for the distance (200 ms, a real timer)
    await sleep(40);
    h.advance(stall);
    const rb = await b;
    expect((await a).status).toBe(200);
    return rb;
  }

  it('a stall past the limit and the slack: 503 busy, no call', async () => {
    const rb = await stalledSolo(1000 + WAIT_TOLERANCE_MS + 1);
    expect(rb.status).toBe(503);
    expect(await rb.json()).toEqual({ error: 'busy' });
    expect(h.calls).toHaveLength(1);
  });

  it('a stall just within the limit and the slack: stamped', async () => {
    const rb = await stalledSolo(1000 + WAIT_TOLERANCE_MS);
    expect(rb.status).toBe(200);
    expect(h.calls).toHaveLength(2);
    expect(h.calls[1]!.mono - h.calls[0]!.mono).toBe(1000 + WAIT_TOLERANCE_MS);
  });
});

describe('Q4 F2: Retry-After of the full identity table follows the distance when it is longer than the budget window', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('minIntervalMs 120 s: the table of 3 is full, the fourth identity waits for the first to expire (110 s at 10 s, not 50 s)', async () => {
    const LONG = 120_000;
    h = await start({
      batch: null,
      bearer: true,
      minIntervalMs: LONG,
      maxWaitMs: 30_000,
      virtualMono: true,
      upstreamIdentities: 3,
    });
    const send = (name: string, token: string) => {
      const x = sha256(name);
      return h.stamp(x, { key: KEY_A, body: withToken(x, token) });
    };
    for (const [i, t] of ['tok-a', 'tok-b', 'tok-c'].entries()) {
      expect((await send(`id-${i}`, t)).status).toBe(200);
      h.advance(i === 2 ? 8000 : 1000); // a at 0, b at 1 s, c at 2 s, now 10 s
    }
    const full = await send('id-d', 'tok-d');
    expect(full.status).toBe(503);
    expect(await full.json()).toEqual({ error: 'busy' });
    expect(Number(full.headers.get('retry-after'))).toBe(110); // 120 s kept - 10 s idle; the budget window (60 s) would say 50
    h.advance(100_000); // 110 s: a is still within its 120 s
    expect(Number((await send('id-d2', 'tok-d')).headers.get('retry-after'))).toBe(10);
    h.advance(10_000); // 120 s: a has expired
    expect((await send('id-d3', 'tok-d')).status).toBe(200);
  });
});
