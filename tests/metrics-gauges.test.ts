import { afterEach, describe, expect, it } from 'vitest';
import { toBase64Url } from '../src/index.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import { createMetrics } from '../relay/metrics.ts';
import type { RelayGauges } from '../relay/relay.ts';
import {
  KEY_A,
  KEY_B,
  KEY_C,
  KEY_F,
  sha256,
  sleep,
  solo,
  start,
  type Harness,
} from './spacing-harness.ts';

// `relay.gauges()` and the series `/metrics` writes from it: open identities, replay cache, waiting requests per service,
// the difference of the last `genTime` to the relay's clock, the age of the last call. Numbers only; against stubs.

const MIN = 100; // minIntervalMs of the virtual-clock tests

const until = async (check: () => boolean, ms = 3000): Promise<void> => {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) throw new Error('condition not reached');
    await sleep(5);
  }
};

const single = () =>
  start({ batch: null, minIntervalMs: MIN, maxWaitMs: 10_000, virtualMono: true });
const collecting = (windowMs = 100) =>
  start({
    batch: { windowMs, max: 100 },
    minIntervalMs: MIN,
    maxWaitMs: 60_000,
    virtualMono: true,
  });

describe('relay.gauges(): single operation', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('starts empty: known services at 0, nothing known about a call or a token', async () => {
    h = await single();
    expect(h.relay.gauges()).toEqual({
      identities: 0,
      replayEntries: 0,
      queued: { freetsa: 0 },
      lastGenTimeDeltaMs: {},
      lastServiceCallAgeSeconds: {},
    });
  });

  it('after a stamp: one replay entry, the call age counts on the monotonic clock', async () => {
    h = await single();
    expect((await h.stamp(sha256('g1'), { key: KEY_A })).status).toBe(200);
    const g = h.relay.gauges();
    expect(g.replayEntries).toBe(1);
    expect(g.identities).toBe(0); // no credentials of the client: no identity
    expect(g.lastServiceCallAgeSeconds).toEqual({ freetsa: 0 });
    expect(Object.keys(g.lastGenTimeDeltaMs)).toEqual(['freetsa']);
    // the stub stamps the relay's own second (cut to whole seconds): a difference of under a second, plus the work
    expect(g.lastGenTimeDeltaMs.freetsa).toBeGreaterThanOrEqual(0);
    expect(g.lastGenTimeDeltaMs.freetsa).toBeLessThan(3000);
    h.advance(5500);
    expect(h.relay.gauges().lastServiceCallAgeSeconds).toEqual({ freetsa: 5 });
    h.advance(500);
    expect(h.relay.gauges().lastServiceCallAgeSeconds).toEqual({ freetsa: 6 });
  });

  it('the difference of the genTime is the absolute value, for a token behind and for one ahead of the relay clock', async () => {
    h = await single();
    h.gen.offset = -20_000;
    expect((await h.stamp(sha256('d1'), { key: KEY_A })).status).toBe(200);
    const behind = h.relay.gauges().lastGenTimeDeltaMs.freetsa!;
    expect(behind).toBeGreaterThanOrEqual(20_000);
    expect(behind).toBeLessThan(23_000);
    h.advance(MIN);
    h.gen.offset = 25_000;
    expect((await h.stamp(sha256('d2'), { key: KEY_F })).status).toBe(200);
    const ahead = h.relay.gauges().lastGenTimeDeltaMs.freetsa!;
    expect(ahead).toBeGreaterThanOrEqual(23_000);
    expect(ahead).toBeLessThan(26_000);
  });

  it('a token that is refused (more than 60 s back) does not move the value', async () => {
    h = await single();
    expect((await h.stamp(sha256('r1'), { key: KEY_A })).status).toBe(200);
    const before = h.relay.gauges().lastGenTimeDeltaMs.freetsa;
    h.advance(MIN);
    h.gen.offset = -90_000;
    expect((await h.stamp(sha256('r2'), { key: KEY_F })).status).toBe(502);
    const g = h.relay.gauges();
    expect(g.lastGenTimeDeltaMs.freetsa).toBe(before);
    expect(h.stats().refused['upstream-too-old']).toBe(1);
    expect(g.lastServiceCallAgeSeconds).toEqual({ freetsa: 0 }); // the call was made all the same
  });

  it('the waiting for the minimum distance is counted, not the call at the service', async () => {
    h = await single();
    const p1 = h.stamp(sha256('q1'), { key: KEY_A });
    await until(() => h.calls.length === 1);
    expect(h.relay.gauges().queued).toEqual({ freetsa: 0 }); // answered or at the service: not waiting
    const p2 = h.stamp(sha256('q2'), { key: KEY_F });
    const p3 = h.stamp(sha256('q3'), { key: KEY_A });
    await until(() => h.relay.gauges().queued.freetsa === 2);
    h.advance(MIN);
    await until(() => h.calls.length === 2);
    expect(h.relay.gauges().queued).toEqual({ freetsa: 1 });
    h.advance(MIN);
    await until(() => h.calls.length === 3);
    expect(h.relay.gauges().queued).toEqual({ freetsa: 0 });
    expect((await Promise.all([p1, p2, p3])).map((r) => r.status)).toEqual([200, 200, 200]);
  });

  it('a replay entry that cannot matter any more is not counted (both clocks past it), and nothing is dropped by looking', async () => {
    h = await single();
    expect((await h.stamp(sha256('p1'), { key: KEY_A })).status).toBe(200);
    h.advance(MIN);
    expect((await h.stamp(sha256('p2'), { key: KEY_F })).status).toBe(200);
    expect(h.relay.gauges().replayEntries).toBe(2);
    h.clock.offset += 200_000; // the wall clock alone is not enough ...
    expect(h.relay.gauges().replayEntries).toBe(2);
    h.advance(200_000); // ... and neither is the monotonic clock alone
    expect(h.relay.gauges().replayEntries).toBe(0);
    h.clock.offset -= 200_000; // back: the entries were not dropped by the look
    h.vmono.now -= 200_000;
    expect(h.relay.gauges().replayEntries).toBe(2);
  });

  it('looking changes nothing: `heldForTests` keeps its fields and values', async () => {
    h = await single();
    expect((await h.stamp(sha256('h1'), { key: KEY_A })).status).toBe(200);
    const before = h.relay.heldForTests();
    expect(Object.keys(before)).toEqual([
      'known',
      'windows',
      'lastCall',
      'lanes',
      'gates',
      'shares',
    ]);
    for (let i = 0; i < 5; i += 1) h.relay.gauges();
    expect(h.relay.heldForTests()).toEqual(before);
  });

  it('a made-up service name in the path creates nothing (404, tables and gauges unchanged)', async () => {
    h = await single();
    expect((await h.stamp(sha256('m1'), { key: KEY_A })).status).toBe(200);
    const held = h.relay.heldForTests();
    const gauges = JSON.stringify(h.relay.gauges());
    for (let i = 0; i < 40; i += 1) {
      const r = await fetch(`${h.base}/v1/stamp/invented-${i}`, { method: 'POST', body: '{}' });
      expect(r.status).toBe(404);
    }
    const r = await fetch(`${h.base}/v1/stamp/__proto__`, { method: 'POST', body: '{}' });
    expect(r.status).toBe(404);
    expect(h.relay.heldForTests()).toEqual(held);
    expect(JSON.stringify(h.relay.gauges())).toBe(gauges);
    for (const part of ['queued', 'lastGenTimeDeltaMs', 'lastServiceCallAgeSeconds'] as const)
      expect(Object.keys(h.relay.gauges()[part])).toEqual(['freetsa']);
  });
});

describe('relay.gauges(): identities (credentials of the client)', () => {
  let h: Harness;
  afterEach(() => h.close());
  const withToken = (hash: Uint8Array, t: string) => ({
    hash: toBase64Url(hash),
    upstream: { token: t },
  });

  it('counts the open ones over all services; an expired one is not counted although the table still holds it', async () => {
    h = await start({ batch: null, bearer: true, minIntervalMs: 50, budgetWindowMs: 400 });
    for (let i = 0; i < 3; i += 1) {
      const x = sha256(`i${i}`);
      expect((await h.stamp(x, { key: KEY_A, body: withToken(x, `token-${i}`) })).status).toBe(200);
    }
    expect(h.relay.gauges().identities).toBe(3);
    expect(h.relay.heldForTests().known).toBe(3);
    await sleep(500); // a whole budget window after the last answer
    expect(h.relay.gauges().identities).toBe(0);
    expect(h.relay.heldForTests().known).toBe(3); // looking drops nothing
    const x = sha256('i-new');
    expect((await h.stamp(x, { key: KEY_A, body: withToken(x, 'token-new') })).status).toBe(200);
    expect(h.relay.gauges().identities).toBe(1);
    expect(h.relay.heldForTests().known).toBe(1);
  });

  it('the waiting of an identity counts for its service (lane key `<id>#<digest>`)', async () => {
    h = await start({
      batch: null,
      bearer: true,
      minIntervalMs: MIN,
      maxWaitMs: 10_000,
      virtualMono: true,
    });
    const a = sha256('w1');
    const b = sha256('w2');
    const p1 = h.stamp(a, { key: KEY_A, body: withToken(a, 'same-token') });
    await until(() => h.calls.length === 1);
    const p2 = h.stamp(b, { key: KEY_F, body: withToken(b, 'same-token') });
    await until(() => h.relay.gauges().queued.freetsa === 1);
    h.advance(MIN);
    expect((await Promise.all([p1, p2])).map((r) => r.status)).toEqual([200, 200]);
    expect(h.relay.gauges().queued).toEqual({ freetsa: 0 });
  });
});

describe('relay.gauges(): collecting operation', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('the members of an open window are counted, until the window is stamped', async () => {
    h = await collecting(1500);
    const p1 = h.stamp(sha256('c1'), { key: KEY_A });
    const p2 = h.stamp(sha256('c2'), { key: KEY_F });
    await until(() => h.relay.gauges().queued.freetsa === 2);
    expect(h.calls).toHaveLength(0);
    expect((await Promise.all([p1, p2])).map((r) => r.status)).toEqual([200, 200]);
    expect(h.calls).toHaveLength(1); // one stamp for the window
    const g = h.relay.gauges();
    expect(g.queued).toEqual({ freetsa: 0 });
    expect(g.replayEntries).toBe(2);
    expect(g.lastServiceCallAgeSeconds).toEqual({ freetsa: 0 });
    expect(g.lastGenTimeDeltaMs.freetsa).toBeLessThan(3000);
  });

  it('a closed window that waits for the minimum distance is counted', async () => {
    h = await collecting();
    const p1 = h.stamp(sha256('d1'), { key: KEY_A });
    await until(() => h.calls.length === 1);
    const p2 = h.stamp(sha256('d2'), { key: KEY_F });
    const p3 = h.stamp(sha256('d3'), { key: KEY_A });
    await sleep(450); // its window closes (100 ms) and waits: the virtual clock stands still
    expect(h.calls).toHaveLength(1);
    expect(h.relay.gauges().queued).toEqual({ freetsa: 2 });
    h.advance(MIN);
    await until(() => h.calls.length === 2);
    expect(h.relay.gauges().queued).toEqual({ freetsa: 0 });
    expect((await Promise.all([p1, p2, p3])).map((r) => r.status)).toEqual([200, 200, 200]);
  });

  it('a solo stamp that waits in the queue of its service is counted', async () => {
    h = await collecting();
    const p1 = h.stamp(sha256('s1'), { key: KEY_B, body: solo(sha256('s1')) });
    await until(() => h.calls.length === 1);
    const p2 = h.stamp(sha256('s2'), { key: KEY_C, body: solo(sha256('s2')) });
    await until(() => h.relay.gauges().queued.freetsa === 1);
    h.advance(MIN);
    await until(() => h.calls.length === 2);
    expect(h.relay.gauges().queued).toEqual({ freetsa: 0 });
    expect((await Promise.all([p1, p2])).map((r) => r.status)).toEqual([200, 200]);
  });

  it('a request that waits in the queue of its lane for a free slot (no window yet) is counted, and not any more once it is answered', async () => {
    // budget window 300 ms, distance 100 ms: three slots; three solo stamps take them, the fourth request has to queue
    h = await start({
      batch: { windowMs: 100, max: 100 },
      minIntervalMs: MIN,
      budgetWindowMs: 3 * MIN,
      maxWaitMs: 60_000,
      virtualMono: true,
    });
    const soloKeys = [KEY_B, KEY_C, KEY_B];
    const done: Promise<{ status: number }>[] = [];
    for (let i = 0; i < 3; i += 1) {
      done.push(h.stamp(sha256(`n${i}`), { key: soloKeys[i]!, body: solo(sha256(`n${i}`)) }));
      await until(() => h.calls.length === i + 1);
      if (i < 2) h.advance(MIN); // the distance to the next solo stamp; after the third the slots stay taken
    }
    done.push(h.stamp(sha256('n-normal'), { key: KEY_A }));
    await until(() => h.relay.gauges().queued.freetsa === 1);
    expect(h.calls).toHaveLength(3);
    h.advance(3 * MIN); // the slots of the minute are free again
    await until(() => h.calls.length === 4);
    expect(h.relay.gauges().queued).toEqual({ freetsa: 0 });
    expect((await Promise.all(done)).map((r) => r.status)).toEqual([200, 200, 200, 200]);
    expect(h.relay.gauges().queued).toEqual({ freetsa: 0 });
  });

  it('a request that leaves (the relay closes) is no longer counted', async () => {
    h = await collecting(1500);
    const p = h.stamp(sha256('x1'), { key: KEY_A });
    await until(() => h.relay.gauges().queued.freetsa === 1);
    h.relay.close();
    expect((await p).status).toBe(503);
    expect(h.relay.gauges().queued).toEqual({ freetsa: 0 });
  });
});

describe('/metrics writes the gauges', () => {
  let h: Harness;
  afterEach(() => h.close());
  const scrape = async (): Promise<string> => {
    const r = await fetch(`${h.base}/metrics`);
    expect(r.status).toBe(200);
    return r.text();
  };
  const value = (text: string, series: string): number | undefined => {
    const line = text.split('\n').find((l) => l.startsWith(series + ' '));
    return line === undefined ? undefined : Number(line.slice(series.length + 1));
  };
  const LINE =
    /^(?:# HELP [a-z_]+ [ -~]+|# TYPE [a-z_]+ (?:counter|gauge)|[a-z_]+(?:\{[a-z_]+="[a-z0-9-]+"(?:,[a-z_]+="[a-z0-9-]+")*\})? \d+)$/;

  it('before any stamp: the always-present series are 0, the ones that need a call or a token are absent', async () => {
    h = await start({ metrics: true, batch: null, minIntervalMs: MIN, virtualMono: true });
    const text = await scrape();
    expect(value(text, 'zeitstempel_identities_open')).toBe(0);
    expect(value(text, 'zeitstempel_replay_entries')).toBe(0);
    expect(value(text, 'zeitstempel_stamp_queued{service="freetsa"}')).toBe(0);
    expect(text).toContain('# TYPE zeitstempel_last_gentime_delta_seconds gauge');
    expect(text).toContain('# TYPE zeitstempel_service_last_call_age_seconds gauge');
    expect(text).not.toMatch(/^zeitstempel_last_gentime_delta_seconds\{/m);
    expect(text).not.toMatch(/^zeitstempel_service_last_call_age_seconds\{/m);
  });

  it('after stamps: the values of `relay.gauges()`, every line in the closed form, no trace of a key, hash or token', async () => {
    h = await start({
      metrics: true,
      bearer: true,
      batch: null,
      minIntervalMs: MIN,
      virtualMono: true,
    });
    const secrets: string[] = [KEY_A.id, KEY_F.id, 'token-secret-1', 'token-secret-2'];
    for (const [i, key] of [KEY_A, KEY_F].entries()) {
      const x = sha256(`mx${i}`);
      secrets.push(toBase64Url(x), Buffer.from(x).toString('hex'));
      const r = await h.stamp(x, {
        key,
        body: { hash: toBase64Url(x), upstream: { token: `token-secret-${i + 1}` } },
      });
      expect(r.status).toBe(200);
      h.advance(MIN);
    }
    h.gen.offset = 0;
    h.advance(3200);
    const text = await scrape();
    expect(value(text, 'zeitstempel_identities_open')).toBe(2);
    expect(value(text, 'zeitstempel_replay_entries')).toBe(2);
    expect(value(text, 'zeitstempel_stamp_queued{service="freetsa"}')).toBe(0);
    expect(value(text, 'zeitstempel_service_last_call_age_seconds{service="freetsa"}')).toBe(3);
    const delta = value(text, 'zeitstempel_last_gentime_delta_seconds{service="freetsa"}');
    expect(delta).toBeGreaterThanOrEqual(0);
    expect(delta).toBeLessThan(3);
    for (const line of text.split('\n').filter((l) => l !== '')) expect(line, line).toMatch(LINE);
    for (const s of secrets) expect(text, s).not.toContain(s);
    expect(text).not.toMatch(/[0-9a-f]{32,}/);
  });

  it('the difference of the genTime is written in whole seconds (the value behind the alarm at 30 s)', async () => {
    h = await start({ metrics: true, batch: null, minIntervalMs: MIN, virtualMono: true });
    h.gen.offset = -35_000;
    expect((await h.stamp(sha256('al1'), { key: KEY_A })).status).toBe(200);
    const delta = value(
      await scrape(),
      'zeitstempel_last_gentime_delta_seconds{service="freetsa"}',
    )!;
    expect(delta).toBeGreaterThan(30);
    expect(delta).toBeLessThan(40);
  });

  it('a request to a made-up service adds no series', async () => {
    h = await start({ metrics: true, batch: null, minIntervalMs: MIN, virtualMono: true });
    const before = (await scrape()).split('\n').filter((l) => l.includes('service='));
    for (let i = 0; i < 30; i += 1)
      await fetch(`${h.base}/v1/stamp/invented-${i}`, { method: 'POST', body: '{}' });
    const after = (await scrape()).split('\n').filter((l) => l.includes('service='));
    expect(after.map((l) => l.replace(/ \d+$/, ''))).toEqual(
      before.map((l) => l.replace(/ \d+$/, '')),
    );
    expect(after.join('\n')).not.toContain('invented');
  });
});

describe('createMetrics: a hostile or wrong `gauges` writes no new label and no wrong number', () => {
  const stats = { stamped: 0, refused: {} };
  const make = (ids: string[], gauges: () => RelayGauges) =>
    createMetrics({ serviceIds: ids, stats: () => stats, gauges, mono: () => 0 });

  it('only the offered services are written; other names, inherited and odd values are not', () => {
    const own = JSON.parse(
      '{"__proto__": 7, "freetsa": 3, "evil": 9, "a\\"b": 1, "x\\ny": 2}',
    ) as Record<string, number>;
    const hostile: RelayGauges = {
      identities: -1,
      replayEntries: Number.NaN,
      queued: own,
      lastGenTimeDeltaMs: { freetsa: Number.POSITIVE_INFINITY, other: 4999, evil: 1 },
      lastServiceCallAgeSeconds: Object.assign(Object.create({ freetsa: 5 }) as object, {
        other: -3,
      }) as Record<string, number>,
    };
    const m = make(['freetsa', 'other'], () => hostile);
    const text = m.render(stats, hostile);
    expect(text).toContain('zeitstempel_stamp_queued{service="freetsa"} 3');
    expect(text).toContain('zeitstempel_stamp_queued{service="other"} 0'); // an own value that is not there: 0
    expect(text).toContain('zeitstempel_identities_open 0');
    expect(text).toContain('zeitstempel_replay_entries 0');
    expect(text).not.toContain('evil');
    expect(text).not.toContain('__proto__');
    expect(text).not.toMatch(/last_gentime_delta_seconds\{service="freetsa"\}/); // Infinity: left out
    expect(text).toContain('zeitstempel_last_gentime_delta_seconds{service="other"} 4');
    expect(text).not.toMatch(/last_call_age_seconds\{/); // inherited and negative: left out
    expect(m.trackedSeries()).toBe(0);
  });

  it('no gauges given (an old caller): the same series as zeros or absent, no throw', () => {
    const m = createMetrics({ serviceIds: ['freetsa'], stats: () => stats, mono: () => 0 });
    const text = m.render(stats);
    expect(text).toContain('zeitstempel_stamp_queued{service="freetsa"} 0');
    expect(text).toContain('zeitstempel_identities_open 0');
  });

  it('many services and full gauges stay within the size bound, with no series beyond the list', () => {
    const ids = Array.from({ length: 120 }, (_, i) => `svc-${i}`);
    const full: RelayGauges = {
      identities: 64,
      replayEntries: 180,
      queued: Object.fromEntries(ids.map((id) => [id, 16])),
      lastGenTimeDeltaMs: Object.fromEntries(ids.map((id) => [id, 1234])),
      lastServiceCallAgeSeconds: Object.fromEntries(ids.map((id) => [id, 99])),
    };
    const text = make(ids, () => full).render(stats, full);
    expect(Buffer.byteLength(text)).toBeLessThanOrEqual(RELAY_LIMITS.metricsMaxBytes);
  });
});
