import { toBase64Url } from '../src/index.ts';
import type { RelayKey } from '../relay/keys.ts';
import { nodeAuthHeaderMs, type TestKey } from './auth-helpers.ts';
import { KEY_A, KEY_B, KEY_F, sha256, sleep, start, type Harness } from './spacing-harness.ts';

// Audit 8 findings B4 (a waiting request looks at its key again when it is stamped), B2 (a request that waits and then
// is not sent to the service gives its share and budget back) and B1 (a replay entry survives a wall clock that ran
// ahead and was set back). Real clock, a stub service, `minIntervalMs` 600 ms.

const rk = (k: TestKey, extra: Partial<RelayKey> = {}): RelayKey => ({
  id: k.id,
  publicKey: k.publicKey,
  ...extra,
});
const ALL = (over: Record<string, Partial<RelayKey>> = {}): RelayKey[] =>
  [KEY_A, KEY_B, KEY_F].map((k) => rk(k, over[k.id] ?? {}));

describe('B4: a waiting request is checked against its key again when it is stamped', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('single operation: a key revoked while the request waits gets 401 and no call to the service', async () => {
    h = await start({ batch: null, minIntervalMs: 600, maxWaitMs: 10_000 });
    expect((await h.stamp(sha256('1'), { key: KEY_A })).status).toBe(200);
    const waiting = h.stamp(sha256('2'), { key: KEY_A });
    await sleep(100);
    h.relay.setKeys(ALL({ [KEY_A.id]: { revoked: true } }));
    const r = await waiting;
    expect(r.status).toBe(401);
    expect(await r.json()).toEqual({ error: 'unauthorized' });
    expect(h.calls).toHaveLength(1);
    expect((await h.stamp(sha256('3'), { key: KEY_A })).status).toBe(401);
  });

  it('single operation: a key removed from the file while the request waits gets 401', async () => {
    h = await start({ batch: null, minIntervalMs: 600, maxWaitMs: 10_000 });
    expect((await h.stamp(sha256('1'), { key: KEY_A })).status).toBe(200);
    const waiting = h.stamp(sha256('2'), { key: KEY_A });
    await sleep(100);
    h.relay.setKeys([rk(KEY_F)]);
    expect((await waiting).status).toBe(401);
    expect(h.calls).toHaveLength(1);
  });

  it('single operation: a key whose notAfter passes while the request waits gets 401; other keys are not touched', async () => {
    h = await start({ batch: null, minIntervalMs: 600, maxWaitMs: 10_000 });
    expect((await h.stamp(sha256('1'), { key: KEY_A })).status).toBe(200);
    const waiting = h.stamp(sha256('2'), { key: KEY_A });
    const other = h.stamp(sha256('3'), { key: KEY_F });
    await sleep(100);
    h.relay.setKeys(ALL({ [KEY_A.id]: { notAfter: Math.floor(Date.now() / 1000) - 1 } }));
    expect((await waiting).status).toBe(401);
    expect((await other).status).toBe(200);
    expect(h.calls).toHaveLength(2);
  });

  it('collecting operation: a revoked key leaves the window (401), the others are stamped; an empty window makes no call', async () => {
    h = await start({ batch: { windowMs: 500, max: 100 }, minIntervalMs: 600, maxWaitMs: 10_000 });
    const a = h.stamp(sha256('a'), { key: KEY_A });
    const f = h.stamp(sha256('f'), { key: KEY_F });
    await sleep(100);
    h.relay.setKeys(ALL({ [KEY_A.id]: { revoked: true } }));
    expect((await a).status).toBe(401);
    expect((await f).status).toBe(200);
    expect(h.calls).toHaveLength(1);
    // a window that holds only the revoked key's request
    await sleep(700);
    const lone = h.stamp(sha256('lone'), { key: KEY_B });
    await sleep(100);
    h.relay.setKeys(ALL({ [KEY_B.id]: { revoked: true } }));
    expect((await lone).status).toBe(401);
    expect(h.calls).toHaveLength(1);
  });

  it('collecting operation: a waiting solo stamp of a revoked key gets 401 and no call', async () => {
    h = await start({ batch: { windowMs: 500, max: 100 }, minIntervalMs: 600, maxWaitMs: 10_000 });
    const body = (x: string) => ({ hash: toBase64Url(sha256(x)), mode: 'solo' });
    expect((await h.stamp(sha256('1'), { key: KEY_B, body: body('1') })).status).toBe(200);
    const waiting = h.stamp(sha256('2'), { key: KEY_B, body: body('2') });
    await sleep(100);
    h.relay.setKeys(ALL({ [KEY_B.id]: { revoked: true } }));
    expect((await waiting).status).toBe(401);
    expect(h.calls).toHaveLength(1);
  });
});

describe('B2: what a request spent comes back when it was not sent to the service', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('a request that gives up while it waits gives its share back (and the key budget)', async () => {
    // 4 per window of 2400 ms; a share of 50 percent is 2
    h = await start({ batch: null, minIntervalMs: 600, budgetWindowMs: 2400, keyShare: 50 });
    expect((await h.stamp(sha256('1'), { key: KEY_A })).status).toBe(200);
    const stop = new AbortController();
    const gone = h.stamp(sha256('2'), { key: KEY_A, signal: stop.signal });
    gone.catch(() => undefined);
    await sleep(100);
    stop.abort();
    await sleep(650); // the request notices at its time, when it would have been stamped
    const third = await h.stamp(sha256('3'), { key: KEY_A });
    expect(third.status).toBe(200); // not 429 key-share: only one stamp was made
    expect(h.calls).toHaveLength(2);
  });

  it('the budget of the key comes back too (perMinute 2)', async () => {
    h = await start({
      batch: null,
      minIntervalMs: 600,
      maxWaitMs: 10_000,
      keys: [rk(KEY_A, {}), rk(KEY_F, {})].map((k, i) => (i === 0 ? { ...k, perMinute: 2 } : k)),
    });
    expect((await h.stamp(sha256('1'), { key: KEY_A })).status).toBe(200);
    const stop = new AbortController();
    const gone = h.stamp(sha256('2'), { key: KEY_A, signal: stop.signal });
    gone.catch(() => undefined);
    await sleep(100);
    stop.abort();
    await sleep(650); // the request notices at its time, when it would have been stamped
    expect((await h.stamp(sha256('3'), { key: KEY_A })).status).toBe(200);
    expect(h.calls).toHaveLength(2);
  });

  it('a request ended with 503 busy (the loop stood still) gives its share back, too', async () => {
    // share 50 percent of 4 = 2 per key
    h = await start({
      batch: null,
      minIntervalMs: 600,
      budgetWindowMs: 2400,
      keyShare: 50,
      maxWaitMs: 1000,
    });
    expect((await h.stamp(sha256('1'), { key: KEY_A })).status).toBe(200);
    const second = h.stamp(sha256('2'), { key: KEY_A });
    await sleep(20);
    h.mono.offset += 5000; // its timer fires far past the limit: busy, no call
    expect((await second).status).toBe(503);
    expect((await h.stamp(sha256('3'), { key: KEY_A })).status).toBe(200); // not 429 key-share
    expect(h.calls).toHaveLength(2);
  });

  it('a request answered with shutting-down is not counted; the replay entry stays (the head was seen)', async () => {
    h = await start({ batch: null, minIntervalMs: 2000, maxWaitMs: 8000 });
    expect((await h.stamp(sha256('1'), { key: KEY_A })).status).toBe(200);
    const text = JSON.stringify({ hash: toBase64Url(sha256('2')) });
    const head = nodeAuthHeaderMs(
      KEY_A,
      KEY_A.id,
      'POST',
      '/v1/stamp/freetsa',
      Date.now(),
      new TextEncoder().encode(text),
    );
    const waiting = h.stamp(sha256('2'), { key: KEY_A, raw: text, head });
    await sleep(100);
    h.relay.close();
    expect((await waiting).status).toBe(503);
    expect((await h.stamp(sha256('2'), { key: KEY_A, raw: text, head })).status).toBe(401);
  });
});

describe('B1: a replay entry is not forgotten when the wall clock ran ahead and was set back', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('the same head is refused after the clock went 66 s ahead, another request passed, and the clock came back', async () => {
    h = await start({ batch: null, minIntervalMs: 50 });
    const path = '/v1/stamp/freetsa';
    const text = JSON.stringify({ hash: toBase64Url(sha256('replayed')) });
    const head = nodeAuthHeaderMs(
      KEY_A,
      KEY_A.id,
      'POST',
      path,
      Date.now(),
      new TextEncoder().encode(text),
    );
    expect((await h.stamp(sha256('replayed'), { key: KEY_A, raw: text, head })).status).toBe(200);
    h.clock.offset = 66_000; // the relay's wall clock runs ahead (the entry is "expired" by it)
    expect((await h.stamp(sha256('other'), { key: KEY_A })).status).toBe(200);
    h.clock.offset = 0; // corrected: the first head lies in its window again
    expect((await h.stamp(sha256('replayed'), { key: KEY_A, raw: text, head })).status).toBe(401);
    expect(h.calls).toHaveLength(2);
  });
});
