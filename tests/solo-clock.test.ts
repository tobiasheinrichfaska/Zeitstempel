import {
  KEY_A,
  KEY_B,
  KEY_C,
  KEY_D,
  KEY_F,
  M,
  TOL,
  expectSpaced,
  sha256,
  sleep,
  solo,
  start,
  type Harness,
} from './spacing-harness.ts';

// The planner of collecting operation (minimum distance, sliding budget of the service, waits) runs on the monotonic
// clock only. A jump of the wall clock forward (an NTP step, 30 s or 59 s: more is refused by the authentication, which
// reads the wall clock) gives back no distance and no slot; a jump back holds nothing. The stub service records the real
// time of every call; the wall clock (`clock`) and the monotonic clock (`mono`) of the relay are steered apart.

describe('a jump of the wall clock does not touch the distance or the budget of the service', () => {
  let h: Harness;
  afterEach(() => h.close());
  const full = { windowMs: M, max: 2 };
  const soloKeys = [KEY_B, KEY_C, KEY_D];

  for (const jump of [30_000, 59_000]) {
    it(`solo stamps: ${jump / 1000} s forward between two stamps, the second still waits for the distance`, async () => {
      h = await start({ batch: full, minIntervalMs: M, budgetWindowMs: 20 * M, maxWaitMs: 8000 });
      const x = sha256('s1');
      expect((await h.stamp(x, { key: KEY_B, body: solo(x) })).status).toBe(200);
      h.clock.offset += jump;
      const y = sha256('s2');
      expect((await h.stamp(y, { key: KEY_C, body: solo(y) })).status).toBe(200);
      expect(h.calls).toHaveLength(2);
      expectSpaced(h.calls);
    });

    it(`solo stamps: ${jump / 1000} s forward gives no slot back (never more calls than the budget in a sliding window)`, async () => {
      const bw = Math.round(3.5 * M); // three calls in any 3.5 M (the distance alone would allow four)
      h = await start({ batch: full, minIntervalMs: M, budgetWindowMs: bw, maxWaitMs: 8000 });
      for (let i = 0; i < 3; i += 1) {
        const x = sha256(`b${i}`);
        expect((await h.stamp(x, { key: soloKeys[i]!, body: solo(x) })).status).toBe(200);
      }
      h.clock.offset += jump;
      const y = sha256('b-late');
      expect((await h.stamp(y, { key: KEY_B, body: solo(y) })).status).toBe(200);
      const times = h.calls.map((c) => c.at).sort((a, b) => a - b);
      expect(times).toHaveLength(4);
      expect(times[3]! - times[0]!).toBeGreaterThanOrEqual(bw - TOL);
      expectSpaced(h.calls);
    });

    it(`windows: ${jump / 1000} s forward between two full windows, the second still waits for the distance`, async () => {
      h = await start({ batch: full, minIntervalMs: M, budgetWindowMs: 20 * M, maxWaitMs: 8000 });
      const first = await Promise.all([
        h.stamp(sha256('w1'), { key: KEY_A }),
        h.stamp(sha256('w2'), { key: KEY_F }),
      ]);
      expect(first.map((r) => r.status)).toEqual([200, 200]);
      h.clock.offset += jump;
      const second = await Promise.all([
        h.stamp(sha256('w3'), { key: KEY_A }),
        h.stamp(sha256('w4'), { key: KEY_F }),
      ]);
      expect(second.map((r) => r.status)).toEqual([200, 200]);
      expect(h.calls).toHaveLength(2);
      expectSpaced(h.calls);
    });

    it(`windows: ${jump / 1000} s forward gives no slot back (a window after the budget is used up waits for it)`, async () => {
      const bw = Math.round(3.5 * M);
      h = await start({ batch: full, minIntervalMs: M, budgetWindowMs: bw, maxWaitMs: 8000 });
      const three = await Promise.all(
        Array.from({ length: 6 }, (_, i) =>
          h.stamp(sha256(`wb${i}`), { key: i % 2 ? KEY_F : KEY_A }).then((r) => r.status),
        ),
      );
      expect(three).toEqual(Array(6).fill(200)); // three windows: calls at 0, M, 2M
      h.clock.offset += jump;
      const late = await Promise.all([
        h.stamp(sha256('wb-x'), { key: KEY_A }).then((r) => r.status),
        h.stamp(sha256('wb-y'), { key: KEY_F }).then((r) => r.status),
      ]);
      expect(late).toEqual([200, 200]);
      const times = h.calls.map((c) => c.at).sort((a, b) => a - b);
      expect(times).toHaveLength(4);
      expect(times[3]! - times[0]!).toBeGreaterThanOrEqual(bw - TOL);
      expectSpaced(h.calls);
    }, 20_000);
  }

  it('a jump forward and back again (59 s) changes nothing: the distance holds and nothing is locked', async () => {
    h = await start({ batch: full, minIntervalMs: M, budgetWindowMs: 20 * M, maxWaitMs: 8000 });
    const x = sha256('fb1');
    expect((await h.stamp(x, { key: KEY_B, body: solo(x) })).status).toBe(200);
    h.clock.offset += 59_000;
    const y = sha256('fb2');
    expect((await h.stamp(y, { key: KEY_C, body: solo(y) })).status).toBe(200);
    h.clock.offset -= 59_000;
    const z = sha256('fb3');
    const t = await h.timed(z, { key: KEY_D, body: solo(z) });
    expect(t.res.status).toBe(200);
    expect(h.calls).toHaveLength(3);
    expectSpaced(h.calls);
    expect(t.at).toBeLessThan(2 * M + 4 * TOL); // not held: one distance after the one before
  });

  it('the monotonic clock decides, the wall clock does not: when it has run on, a solo stamp is served at once', async () => {
    h = await start({ batch: full, minIntervalMs: M, budgetWindowMs: 20 * M, maxWaitMs: 8000 });
    const x = sha256('eq1');
    expect((await h.stamp(x, { key: KEY_B, body: solo(x) })).status).toBe(200);
    h.mono.offset += 2 * M; // the monotonic clock has gone on (a stalled loop): the distance is over
    const y = sha256('eq2');
    const t = await h.timed(y, { key: KEY_C, body: solo(y) });
    expect(t.res.status).toBe(200);
    expect(t.at).toBeLessThan(M / 2);
    // the other way round: the wall clock alone, whatever its jump, does not shorten the wait
    h.clock.offset += 59_000;
    const z = sha256('eq3');
    const u = await h.timed(z, { key: KEY_D, body: solo(z) });
    expect(u.res.status).toBe(200);
    expect(u.at).toBeGreaterThanOrEqual(M - 2 * TOL);
  });

  it('the wall clock set back for good locks nothing (the planner never reads it)', async () => {
    h = await start({ batch: full, minIntervalMs: M, budgetWindowMs: 20 * M, maxWaitMs: 8000 });
    for (let i = 0; i < 3; i += 1) {
      h.clock.offset -= 50_000;
      const x = sha256(`back${i}`);
      const r = await h.stamp(x, { key: soloKeys[i]!, body: solo(x) });
      expect(r.status).toBe(200);
    }
    expect(h.calls).toHaveLength(3);
    expectSpaced(h.calls);
  });
});

describe('delayed windows wait on a timer for their time, they do not poll', () => {
  let h: Harness;
  afterEach(() => {
    vi.restoreAllMocks();
    return h.close();
  });

  it('a window behind a delayed window sets no timer of a millisecond again and again while the one in front waits', async () => {
    const pair = { windowMs: M, max: 2 };
    h = await start({ batch: pair, minIntervalMs: M, budgetWindowMs: 20 * M, maxWaitMs: 60_000 });
    // the monotonic clock of the process runs at a quarter of the speed: the first delayed window needs four times as
    // long as its timer says, and the one behind it is due (by its timer) long before it
    const realNow = performance.now.bind(performance);
    const t0 = realNow();
    vi.spyOn(performance, 'now').mockImplementation(() => t0 + (realNow() - t0) * 0.25);
    const real = globalThis.setTimeout;
    let short = 0;
    vi.spyOn(globalThis, 'setTimeout').mockImplementation(((
      fn: () => void,
      ms?: number,
      ...rest: unknown[]
    ) => {
      if (ms === undefined || ms <= 2) short += 1;
      return real(fn, ms, ...rest);
    }) as typeof setTimeout);
    const sent = await Promise.all(
      Array.from({ length: 6 }, (_, i) =>
        h.stamp(sha256(`poll-${i}`), { key: i % 2 ? KEY_F : KEY_A }).then((r) => r.status),
      ),
    );
    expect(sent).toEqual(Array(6).fill(200));
    expect(h.calls).toHaveLength(3);
    await sleep(50);
    expect(short).toBeLessThan(60); // a poll every millisecond would be about a thousand
  }, 30_000);
});
