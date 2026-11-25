import {
  KEY_A,
  KEY_B,
  KEY_C,
  KEY_D,
  KEY_F,
  M,
  TOL,
  expectSpaced,
  gaps,
  same,
  sha256,
  sleep,
  solo,
  start,
  type Harness,
} from './spacing-harness.ts';
import { toBase64Url } from '../src/index.ts';

// Chains of windows that wait for the minimum distance (`RELAY_BATCH_MAX` 2: every pair of requests closes a window at
// once, so the second, third, ... window all wait behind the one before): the service never sees two calls closer
// than `minIntervalMs`, however long the chain is, also when the event loop stands still or the clock jumps. A stub
// service records the time of every call. Real clock; `minIntervalMs` 600 ms.

describe('chains of windows that wait for the minimum distance', () => {
  let h: Harness;
  afterEach(() => h.close());
  const pair = { windowMs: M, max: 2 };
  const keyOf = (i: number) => (i % 2 ? KEY_F : KEY_A);

  for (const windows of [4, 5, 9]) {
    it(`${windows} windows in a row (${windows - 1} of them delayed) are one distance apart each, no closer`, async () => {
      h = await start({
        batch: pair,
        minIntervalMs: M,
        budgetWindowMs: (windows + 4) * M,
        maxWaitMs: 30_000,
      });
      const t0 = Date.now();
      const answers = await Promise.all(
        Array.from({ length: windows * 2 }, (_, i) =>
          h
            .stamp(sha256(`chain-${i}`), { key: keyOf(i) })
            .then((r) => ({ s: r.status, at: Date.now() - t0 })),
        ),
      );
      expect(answers.every((a) => a.s === 200)).toBe(true);
      expect(h.calls).toHaveLength(windows);
      expectSpaced(h.calls);
      // laid one behind the other: the k-th delayed window calls k distances after the first, not later
      const last = Math.max(...h.calls.map((c) => c.at));
      expect(last).toBeLessThan((windows - 1) * M + 6 * TOL);
      expect(last).toBeGreaterThanOrEqual((windows - 1) * M - 2 * TOL);
    }, 30_000);
  }

  it('a mixture of delayed windows and solo stamps of key type 2 keeps the distance', async () => {
    h = await start({ batch: pair, minIntervalMs: M, budgetWindowMs: 14 * M, maxWaitMs: 30_000 });
    const s = [sha256('x1'), sha256('x2'), sha256('x3')];
    const sent = [
      ...[0, 1, 2, 3, 4, 5].map((i) => h.stamp(sha256(`mix-${i}`), { key: keyOf(i) })),
      h.stamp(s[0]!, { key: KEY_B, body: solo(s[0]!) }),
      h.stamp(s[1]!, { key: KEY_C, body: solo(s[1]!) }),
      h.stamp(s[2]!, { key: KEY_D, body: solo(s[2]!) }),
    ];
    const answers = await Promise.all(sent);
    expect(answers.map((a) => a.status)).toEqual(Array(9).fill(200));
    expect(h.calls).toHaveLength(6); // three windows and three solo stamps
    expectSpaced(h.calls);
  }, 30_000);

  it('a solo stamp that comes behind a chain of delayed windows is served after the last of them', async () => {
    h = await start({ batch: pair, minIntervalMs: M, budgetWindowMs: 14 * M, maxWaitMs: 30_000 });
    const sent = Array.from({ length: 8 }, (_, i) =>
      h.stamp(sha256(`beh-${i}`), { key: keyOf(i) }).then((r) => r.status),
    ); // four windows: at once, then M, 2 M, 3 M
    await sleep(50);
    const x = sha256('behind-chain');
    const t = await h.timed(x, { key: KEY_B, body: solo(x) });
    expect(t.res.status).toBe(200);
    expect(await Promise.all(sent)).toEqual(Array(8).fill(200));
    expect(h.calls).toHaveLength(5);
    expect(same(h.calls[4]!.imprint, x)).toBe(true); // the last call of all
    expect(h.calls[4]!.at).toBeGreaterThanOrEqual(4 * M - 2 * TOL);
    expectSpaced(h.calls);
  }, 30_000);

  it('every identity has its own chain: one identity does not hold the other, each keeps its own distance', async () => {
    h = await start({
      batch: pair,
      minIntervalMs: M,
      budgetWindowMs: 14 * M,
      maxWaitMs: 30_000,
      bearer: true,
    });
    const as = (token: string, tag: string, key: typeof KEY_A) =>
      h.stamp(sha256(tag), {
        key,
        body: { hash: toBase64Url(sha256(tag)), upstream: { token } },
      });
    const sent = [
      ...[0, 1, 2, 3, 4, 5].map((i) => as('tok-x', `ix-${i}`, keyOf(i))),
      ...[0, 1].map((i) => as('tok-y', `iy-${i}`, KEY_C)),
    ];
    const answers = await Promise.all(sent);
    expect(answers.map((a) => a.status)).toEqual(Array(8).fill(200));
    const x = h.calls.filter((c) => c.token === 'tok-x');
    const y = h.calls.filter((c) => c.token === 'tok-y');
    expect(x).toHaveLength(3);
    expect(y).toHaveLength(1);
    expectSpaced(x);
    expect(y[0]!.at).toBeLessThan(M / 2); // not behind the chain of the other identity
  }, 30_000);

  it('the event loop stands still while two delayed windows are due: they still call one distance apart', async () => {
    h = await start({ batch: pair, minIntervalMs: M, budgetWindowMs: 8 * M, maxWaitMs: 30_000 });
    const sent = Array.from({ length: 6 }, (_, i) =>
      h.stamp(sha256(`stall-${i}`), { key: keyOf(i) }).then((r) => r.status),
    );
    await sleep(M * 0.9); // the first window called at once; the second waits until M, the third until 2 M
    const end = Date.now() + M * 1.4; // block the loop until about 2.3 M: both timers are due
    while (Date.now() < end) {
      /* a synchronous wait: no timer, no I/O */
    }
    expect(await Promise.all(sent)).toEqual(Array(6).fill(200));
    expect(h.calls).toHaveLength(3);
    expectSpaced(h.calls);
  }, 30_000);

  it('the event loop stands still while a delayed window and a solo stamp are due: the distance holds', async () => {
    h = await start({ batch: pair, minIntervalMs: M, budgetWindowMs: 8 * M, maxWaitMs: 30_000 });
    const x = sha256('stall-solo-first');
    expect((await h.stamp(x, { key: KEY_B, body: solo(x) })).status).toBe(200);
    const sent = [
      h.stamp(sha256('sw1'), { key: KEY_F }).then((r) => r.status),
      h.stamp(sha256('sw2'), { key: KEY_A }).then((r) => r.status),
    ];
    await sleep(60);
    const y = sha256('stall-solo-second');
    sent.push(h.stamp(y, { key: KEY_C, body: solo(y) }).then((r) => r.status));
    await sleep(M * 0.5);
    const end = Date.now() + M * 1.8;
    while (Date.now() < end) {
      /* blocked */
    }
    expect(await Promise.all(sent)).toEqual([200, 200, 200]);
    expect(h.calls).toHaveLength(3);
    expectSpaced(h.calls);
  }, 30_000);

  it('a clock set back while windows wait does not hold them: they still call one distance apart, in the order they closed', async () => {
    h = await start({ batch: pair, minIntervalMs: M, budgetWindowMs: 8 * M, maxWaitMs: 30_000 });
    const t0 = Date.now();
    const when: number[] = [];
    const sent: Promise<number>[] = [];
    for (let i = 0; i < 8; i += 1) {
      sent.push(
        h.stamp(sha256(`cb-${i}`), { key: keyOf(i) }).then((r) => {
          when[i] = Date.now() - t0;
          return r.status;
        }),
      );
      await sleep(10);
      if (i === 3) h.clock.offset -= 3_600_000; // after two windows, the clock goes back
    }
    expect(await Promise.all(sent)).toEqual(Array(8).fill(200));
    expect(h.calls).toHaveLength(4);
    expectSpaced(h.calls);
    // the pairs (0,1) (2,3) (4,5) (6,7) are answered in the order they closed
    const pairTimes = [0, 2, 4, 6].map((i) => Math.max(when[i]!, when[i + 1]!));
    expect(pairTimes).toEqual([...pairTimes].sort((a, b) => a - b));
    expect(Math.max(...h.calls.map((c) => c.at))).toBeLessThan(3 * M + 6 * TOL); // not held by the clock
  }, 30_000);

  it('delayed windows count against the budget of the service: a request that comes after them waits for its slot', async () => {
    const bw = Math.round(3.5 * M); // three calls in any 3.5 M
    h = await start({ batch: pair, minIntervalMs: M, budgetWindowMs: bw, maxWaitMs: 30_000 });
    const sent = Array.from({ length: 6 }, (_, i) =>
      h.stamp(sha256(`bud-${i}`), { key: keyOf(i) }).then((r) => r.status),
    ); // the 1st window calls at once, the 2nd and 3rd wait: three slots are booked
    await sleep(50);
    sent.push(h.stamp(sha256('bud-late'), { key: KEY_A }).then((r) => r.status));
    expect(await Promise.all(sent)).toEqual(Array(7).fill(200));
    const times = h.calls.map((c) => c.at).sort((a, b) => a - b);
    expect(times).toHaveLength(4);
    for (let i = 3; i < times.length; i += 1) {
      expect(times[i]! - times[i - 3]!).toBeGreaterThanOrEqual(bw - TOL); // never four calls within the budget window
    }
    expectSpaced(h.calls);
  }, 30_000);
});

describe('503 busy of a solo stamp that waited for the distance', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('Retry-After counts the distance, not only the slots', async () => {
    h = await start({
      batch: { windowMs: 3000, max: 100 },
      minIntervalMs: 3000,
      budgetWindowMs: 30_000,
      maxWaitMs: 4000,
    });
    const [a, b, c] = [sha256('r1'), sha256('r2'), sha256('r3')];
    const first = await h.stamp(a, { key: KEY_B, body: solo(a) }); // called at once
    expect(first.status).toBe(200);
    const second = h.stamp(b, { key: KEY_C, body: solo(b) }); // waits 3 s for the distance: fits the limit of 4 s
    const third = h.stamp(c, { key: KEY_D, body: solo(c) }); // queued as well: behind the second, it waits 3 s more
    expect((await second).status).toBe(200);
    const late = await third; // at 4 s the distance is 2 s away: 503 busy
    expect(late.status).toBe(503);
    expect(await late.json()).toEqual({ error: 'busy' });
    expect(Number(late.headers.get('retry-after'))).toBeGreaterThanOrEqual(2);
    expect(gaps(h.calls)).toHaveLength(1);
  }, 30_000);
});

describe('order of the refusals of a solo request of key type 1', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('the form of the body (bad-mode, bad-hash, bad-upstream) is judged before the key type: 400 before 403', async () => {
    h = await start({ batch: { windowMs: M, max: 100 }, minIntervalMs: M, bearer: true });
    const hash = toBase64Url(sha256('order'));
    const ask = async (body: unknown, key = KEY_A) => {
      const r = await h.stamp(sha256('order'), { key, body });
      return [r.status, ((await r.json()) as { error: string }).error];
    };
    expect(await ask({ hash, mode: 'solo', upstream: { token: 'tok' } })).toEqual([
      403,
      'solo-not-allowed',
    ]);
    expect(await ask({ hash, mode: 'solo', upstream: { token: 'a b' } })).toEqual([
      400,
      'bad-upstream',
    ]);
    expect(await ask({ hash, mode: 'solo' })).toEqual([400, 'bad-upstream']); // the service needs the client's token
    expect(await ask({ hash, mode: 'other', upstream: { token: 'tok' } })).toEqual([
      400,
      'bad-mode',
    ]);
    expect(await ask({ hash: 'x', mode: 'solo', upstream: { token: 'tok' } })).toEqual([
      400,
      'bad-hash',
    ]);
    expect(h.calls).toHaveLength(0);
    expect(h.stats().refused['solo-not-allowed']).toBe(1);
  });

  it('without authentication (RELAY_AUTH=off) every solo request is 403 in collecting operation', async () => {
    h = await start({ batch: { windowMs: M, max: 100 }, minIntervalMs: M, keys: 'off' });
    const x = sha256('open-solo');
    const r = await h.stamp(x, { body: solo(x), head: '' });
    expect(r.status).toBe(403);
    expect(await r.json()).toEqual({ error: 'solo-not-allowed' });
    expect(h.calls).toHaveLength(0);
  });
});
