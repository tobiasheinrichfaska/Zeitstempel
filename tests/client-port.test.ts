import { createRelayClient } from '../src/client/index.ts';
import type { ClientFailure, RelayClientOptions } from '../src/client/index.ts';
import { sha256 } from './helpers.ts';
import {
  KEY_1,
  TEST_AUDIENCE,
  TRUST,
  hashOf,
  okBody,
  startFake,
  type FakeRelay,
} from './client-harness.ts';

// What the removed client of the main entry did and `zeitstempel/client` took over (2026-11-25): the pause after a
// 429 across calls on a monotonic clock, `Retry-After` as an HTTP date, a deadline per send with failover, and the
// relay's `serial` claim checked against the verified token.

const options = (origin: string, over: Partial<RelayClientOptions> = {}): RelayClientOptions => ({
  relayUrl: origin,
  audience: TEST_AUDIENCE,
  keyId: KEY_1.id,
  privateKey: KEY_1.privateKey,
  trust: TRUST,
  services: ['freetsa'],
  ...over,
});
function make(o: RelayClientOptions) {
  const r = createRelayClient(o);
  if (!r.ok) throw new Error(`client: ${r.reason} ${r.detail ?? ''}`);
  return r.value;
}
const failure = (r: { ok: boolean }): ClientFailure => {
  expect(r.ok).toBe(false);
  return r as ClientFailure;
};
const hash = sha256('port');

describe('ported from the old client', () => {
  let fake: FakeRelay | null = null;
  afterEach(async () => {
    await fake?.close();
    fake = null;
  });

  it('a 429 that ends a call pauses later calls on the monotonic clock: nothing is sent', async () => {
    fake = await startFake((s, n) =>
      n === 0
        ? { status: 429, headers: { 'Retry-After': '120' }, json: { error: 'rate-limited' } }
        : { status: 200, json: okBody('freetsa', hashOf(s), Date.now()) },
    );
    let mono = 1000;
    let wall = Date.now();
    const client = make(
      options(fake.origin, { timeoutMs: 5000, monoNow: () => mono, now: () => wall }),
    );
    expect(failure(await client.stamp(hash))).toMatchObject({ reason: 'relay-error', status: 429 });
    expect(client.pausedForMs()).toBe(120_000);
    // the device clock set back by an hour stretches nothing: the pause runs on the monotonic clock
    wall -= 3_600_000;
    mono += 60_000;
    const paused = failure(await client.stamp(hash));
    expect(paused).toMatchObject({ reason: 'paused', detail: 'retry in 60 s' });
    expect(fake.seen).toHaveLength(1);
    mono += 60_000;
    wall = Date.now();
    expect(client.pausedForMs()).toBe(0);
    expect((await client.stamp(hash)).ok).toBe(true);
    expect(fake.seen).toHaveLength(2);
  });

  it('a monotonic clock that jumps back past the longest pause forgets the pause', async () => {
    fake = await startFake(() => ({
      status: 429,
      headers: { 'Retry-After': '3600' },
      json: { error: 'rate-limited' },
    }));
    let mono = 10_000_000;
    const client = make(options(fake.origin, { timeoutMs: 5000, monoNow: () => mono }));
    failure(await client.stamp(hash));
    expect(client.pausedForMs()).toBe(3_600_000);
    mono -= 1_000_000;
    expect(client.pausedForMs()).toBe(0);
  });

  it('Retry-After as an HTTP date is measured against the answer Date', async () => {
    fake = await startFake((s, n) => {
      if (n > 0) return { status: 200, json: okBody('freetsa', hashOf(s), Date.now()) };
      const base = Date.now() - 600_000; // the relay's Date says 10 minutes ago; the date is 1 s after it
      return {
        status: 429,
        headers: {
          Date: new Date(base).toUTCString(),
          'Retry-After': new Date(base + 1000).toUTCString(),
        },
        json: { error: 'rate-limited' },
      };
    });
    const client = make(options(fake.origin));
    const t0 = Date.now();
    expect((await client.stamp(hash)).ok).toBe(true);
    const took = Date.now() - t0;
    expect(took).toBeGreaterThanOrEqual(900);
    expect(took).toBeLessThan(5000);
  });

  it('an HTTP date beyond the deadline ends the call at once and sets the pause', async () => {
    fake = await startFake(() => ({
      status: 429,
      headers: { 'Retry-After': new Date(Date.now() + 300_000).toUTCString() },
      json: { error: 'rate-limited' },
    }));
    const client = make(options(fake.origin, { timeoutMs: 5000 }));
    failure(await client.stamp(hash));
    expect(client.pausedForMs()).toBeGreaterThan(290_000);
    expect(client.pausedForMs()).toBeLessThanOrEqual(301_000);
  });

  it('attemptTimeoutMs: a service that does not answer in time gives way to the next one', async () => {
    fake = await startFake((s) =>
      s.path === '/v1/stamp/freetsa'
        ? { status: 200, json: okBody('freetsa', hashOf(s), Date.now()), delayMs: 3000 }
        : { status: 200, json: okBody('sectigo', hashOf(s), Date.now()) },
    );
    const client = make(
      options(fake.origin, { services: ['freetsa', 'sectigo'], attemptTimeoutMs: 1000 }),
    );
    const t0 = Date.now();
    const r = await client.stamp(hash);
    expect(r.ok).toBe(true);
    expect(Date.now() - t0).toBeLessThan(2500);
    expect(fake.seen.map((s) => s.path)).toEqual(['/v1/stamp/freetsa', '/v1/stamp/sectigo']);
  });

  it('attemptTimeoutMs on every service: timeout', async () => {
    fake = await startFake((s) => ({
      status: 200,
      json: okBody('freetsa', hashOf(s), Date.now()),
      delayMs: 3000,
    }));
    const client = make(options(fake.origin, { attemptTimeoutMs: 1000 }));
    expect(failure(await client.stamp(hash))).toMatchObject({
      reason: 'timeout',
      detail: 'freetsa',
    });
  });

  it("the relay's serial must be the verified token's", async () => {
    fake = await startFake((s) => ({
      status: 200,
      json: { ...okBody('freetsa', hashOf(s), Date.now()), serial: 'ff' },
    }));
    const client = make(options(fake.origin));
    expect(failure(await client.stamp(hash))).toMatchObject({
      reason: 'bad-response',
      detail: 'serial',
    });
  });

  it('an unknown field in the answer is refused', async () => {
    fake = await startFake((s) => ({
      status: 200,
      json: { ...okBody('freetsa', hashOf(s), Date.now()), extra: 1 },
    }));
    const client = make(options(fake.origin));
    expect(failure(await client.stamp(hash))).toMatchObject({ reason: 'bad-response' });
  });

  it('checks the new options', () => {
    for (const over of [
      { monoNow: 1 },
      { attemptTimeoutMs: 999 },
      { attemptTimeoutMs: 600_001 },
      { attemptTimeoutMs: Number.NaN },
    ]) {
      const r = createRelayClient(options('https://relay.example', over as never));
      expect(r, JSON.stringify(over)).toMatchObject({ ok: false, reason: 'bad-options' });
    }
    expect(
      createRelayClient(
        options('https://relay.example', { monoNow: () => 1, attemptTimeoutMs: 1000 }),
      ).ok,
    ).toBe(true);
  });

  it('a monotonic clock that answers no number is bad-options, nothing is sent', async () => {
    fake = await startFake(() => ({ status: 500 }));
    const client = make(options(fake.origin, { monoNow: () => Number.NaN }));
    expect(failure(await client.stamp(hash))).toMatchObject({
      reason: 'bad-options',
      detail: 'monoNow',
    });
    expect(fake.seen).toHaveLength(0);
  });
});
