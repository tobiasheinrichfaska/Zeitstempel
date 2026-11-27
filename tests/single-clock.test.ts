import { KEY_A, KEY_F, M, sha256, start, type Harness } from './spacing-harness.ts';

// Single operation: the counters per minute (service budget, total, per key, share of a key) run on the monotonic
// clock (`mono`), like the minimum distance. A jump of the wall clock forward (30 s or 59 s: more is refused by the
// authentication) gives no budget back; a jump back locks nothing. The wall clock (`clock`) and the monotonic clock
// of the relay are steered apart.

describe('single operation: a jump of the wall clock does not touch the counters per minute', () => {
  let h: Harness;
  afterEach(() => h.close());

  for (const jump of [30_000, 59_000]) {
    it(`service budget: ${jump / 1000} s forward gives no place back (429 while the minute is used up)`, async () => {
      const bw = Math.round(3.5 * M); // three admissions in any 3.5 M
      h = await start({ batch: null, minIntervalMs: M, budgetWindowMs: bw, maxWaitMs: 8000 });
      const three = await Promise.all(
        [0, 1, 2].map((i) => h.stamp(sha256(`sb${i}`), { key: i % 2 ? KEY_F : KEY_A })),
      );
      expect(three.map((r) => r.status)).toEqual([200, 200, 200]);
      h.clock.offset += jump;
      const late = await h.stamp(sha256('sb-late'), { key: KEY_A });
      expect(late.status).toBe(429);
      expect(h.calls).toHaveLength(3);
    }, 20_000);

    it(`share of a key: ${jump / 1000} s forward gives no place back (key-share)`, async () => {
      // lane limit 3, share 50 percent: one admission per key in the window
      h = await start({
        batch: null,
        minIntervalMs: M,
        budgetWindowMs: Math.round(3.5 * M),
        keyShare: 50,
        maxWaitMs: 8000,
      });
      expect((await h.stamp(sha256('sh1'), { key: KEY_A })).status).toBe(200);
      h.clock.offset += jump;
      const second = await h.stamp(sha256('sh2'), { key: KEY_A });
      expect(second.status).toBe(429);
      expect((await second.json()).error).toBe('key-share');
      expect(h.calls).toHaveLength(1);
    });
  }

  it('the monotonic clock decides: when it has run on past the minute, the budget is free again', async () => {
    const bw = Math.round(3.5 * M);
    h = await start({ batch: null, minIntervalMs: M, budgetWindowMs: bw, maxWaitMs: 8000 });
    await Promise.all([0, 1, 2].map((i) => h.stamp(sha256(`mo${i}`), { key: KEY_A })));
    expect((await h.stamp(sha256('mo-x'), { key: KEY_A })).status).toBe(429);
    h.mono.offset += 2 * bw;
    expect((await h.stamp(sha256('mo-y'), { key: KEY_A })).status).toBe(200);
  }, 20_000);

  it('the wall clock set back for good locks nothing', async () => {
    h = await start({ batch: null, minIntervalMs: M, budgetWindowMs: 20 * M, maxWaitMs: 8000 });
    for (let i = 0; i < 3; i += 1) {
      h.clock.offset -= 50_000;
      const r = await h.stamp(sha256(`back${i}`), { key: KEY_A });
      expect(r.status).toBe(200);
    }
    expect(h.calls).toHaveLength(3);
  }, 20_000);
});
