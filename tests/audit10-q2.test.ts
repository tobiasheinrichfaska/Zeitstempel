import { toBase64Url } from '../src/index.ts';
import type { RelayKey } from '../relay/keys.ts';
import { makeTestKey, type TestKey } from './auth-helpers.ts';
import { KEY_A, KEY_B, KEY_F, sha256, sleep, start, type Harness } from './spacing-harness.ts';

// Audit 10, question 2: the same key id is entered again with ANOTHER public key while a request signed with the old one waits.
const rk = (k: TestKey, extra: Partial<RelayKey> = {}): RelayKey => ({
  id: k.id,
  publicKey: new Uint8Array(k.publicKey),
  ...extra,
});
const solo = (x: string) => ({ hash: toBase64Url(sha256(x)), mode: 'solo' });
const NEW_A = makeTestKey(KEY_A.id); // same id, other pair
const NEW_B = makeTestKey(KEY_B.id);

describe('Q2: key id re-entered with another public key', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('door: a new request with the old key is refused after the swap (control)', async () => {
    h = await start({ batch: null, minIntervalMs: 600, maxWaitMs: 10_000 });
    h.relay.setKeys([rk(NEW_A), rk(KEY_B, { solo: true }), rk(KEY_F)]);
    expect((await h.stamp(sha256('x'), { key: KEY_A })).status).toBe(401);
    expect((await h.stamp(sha256('y'), { key: NEW_A })).status).toBe(200);
  });
  it('single operation: waiting request with the old signature', async () => {
    h = await start({ batch: null, minIntervalMs: 600, maxWaitMs: 10_000 });
    expect((await h.stamp(sha256('1'), { key: KEY_F })).status).toBe(200);
    const w = h.stamp(sha256('2'), { key: KEY_A });
    await sleep(100);
    h.relay.setKeys([rk(NEW_A), rk(KEY_B, { solo: true }), rk(KEY_F)]);
    const r = await w;
    console.log('Q2 single: status', r.status, 'calls', h.calls.length);
    expect(r.status).toBe(401);
    expect(h.calls).toHaveLength(1);
  });
  it('collecting: item in a window and a waiting solo stamp', async () => {
    h = await start({ batch: { windowMs: 400, max: 100 }, minIntervalMs: 600, maxWaitMs: 10_000 });
    expect((await h.stamp(sha256('1'), { key: KEY_B, body: solo('1') })).status).toBe(200);
    const s = h.stamp(sha256('2'), { key: KEY_B, body: solo('2') });
    const w = h.stamp(sha256('3'), { key: KEY_A });
    await sleep(100);
    h.relay.setKeys([rk(NEW_A), rk(NEW_B, { solo: true }), rk(KEY_F)]);
    const [rs, rw] = [await s, await w];
    console.log('Q2 collecting: solo', rs.status, 'window', rw.status, 'calls', h.calls.length);
    expect(rs.status).toBe(401);
    expect(rw.status).toBe(401);
    expect(h.calls).toHaveLength(1);
  });
});
