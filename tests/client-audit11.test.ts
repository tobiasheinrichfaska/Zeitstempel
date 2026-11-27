import { createRelayClient } from '../src/client/index.ts';
import type {
  ClientFailure,
  FetchInit,
  RelayClientOptions,
  ResponseLike,
} from '../src/client/index.ts';
import { sha256 } from './helpers.ts';
import { KEY_1, TEST_AUDIENCE, TRUST, okBody, sleep } from './client-harness.ts';

// Low findings of the audit of 2026-11-25 that still held: listener and timer leaks on early ends, the learned clock
// offset for a `Retry-After` date, and a 429 whose body was cut by `attemptTimeoutMs`.

const hash = sha256('audit11');
const ORIGIN = 'http://localhost:9';

function respond(status: number, headers: Record<string, string>, body: string): ResponseLike {
  const h = new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return {
    status,
    headers: { get: (n) => h.get(n.toLowerCase()) ?? null },
    text: async () => body,
  };
}
function make(
  fetch: (url: string, init: FetchInit) => Promise<ResponseLike>,
  over: Partial<RelayClientOptions> = {},
) {
  const r = createRelayClient({
    relayUrl: ORIGIN,
    audience: TEST_AUDIENCE,
    keyId: KEY_1.id,
    privateKey: KEY_1.privateKey,
    trust: TRUST,
    services: ['freetsa'],
    fetch,
    ...over,
  });
  if (!r.ok) throw new Error(`client: ${r.reason}`);
  return r.value;
}
const failure = (r: { ok: boolean }): ClientFailure => {
  expect(r.ok).toBe(false);
  return r as ClientFailure;
};
/** A signal that counts its abort listeners. */
function countingSignal() {
  const signal = new AbortController().signal;
  let live = 0;
  const add = signal.addEventListener.bind(signal);
  const remove = signal.removeEventListener.bind(signal);
  signal.addEventListener = ((type: string, fn: EventListener, o?: AddEventListenerOptions) => {
    if (type === 'abort') live += 1;
    add(type, fn, o);
  }) as typeof signal.addEventListener;
  signal.removeEventListener = ((type: string, fn: EventListener, o?: EventListenerOptions) => {
    if (type === 'abort') live -= 1;
    remove(type, fn, o);
  }) as typeof signal.removeEventListener;
  return { signal, live: () => live };
}

describe('audit 2026-11-25, low findings', () => {
  it('a call refused as paused leaves no listener on the caller signal', async () => {
    const client = make(
      async () => respond(429, { 'Retry-After': '120' }, '{"error":"rate-limited"}'),
      { maxAttempts: 1 },
    );
    failure(await client.stamp(hash));
    expect(client.pausedForMs()).toBeGreaterThan(0);
    const s = countingSignal();
    expect(failure(await client.stamp(hash, { signal: s.signal })).reason).toBe('paused');
    expect(s.live()).toBe(0);
  });

  it('a bad monoNow leaves no listener on the caller signal', async () => {
    const client = make(async () => respond(500, {}, '{}'), { monoNow: () => NaN });
    const s = countingSignal();
    expect(failure(await client.stamp(hash, { signal: s.signal }))).toMatchObject({
      reason: 'bad-options',
      detail: 'monoNow',
    });
    expect(s.live()).toBe(0);
  });

  it('a clock that turns bad while the answer is checked ends the attempt deadline too', async () => {
    let calls = 0;
    let attemptSignal: AbortSignal | undefined;
    const client = make(
      async (_url, init) => {
        attemptSignal = init.signal;
        return respond(200, {}, JSON.stringify(okBody('freetsa', hash, Date.now())));
      },
      { attemptTimeoutMs: 1000, now: () => (++calls === 1 ? Date.now() : NaN) },
    );
    expect(failure(await client.stamp(hash))).toMatchObject({
      reason: 'bad-options',
      detail: 'now',
    });
    await sleep(1200);
    expect(attemptSignal?.aborted).toBe(false); // the timer of the attempt was cleared
  });

  it('a Retry-After date without a Date header is measured with the learned clock offset', async () => {
    const behind = 50_000; // the device clock is 50 s behind the relay
    let n = 0;
    const client = make(
      async () => {
        n += 1;
        if (n === 1)
          return respond(401, { Date: new Date().toUTCString() }, '{"error":"unauthorized"}');
        const at = new Date(Date.now() + 10_000).toUTCString();
        return respond(429, { 'Retry-After': at }, '{"error":"rate-limited"}');
      },
      { maxAttempts: 1, now: () => Date.now() - behind },
    );
    expect(failure(await client.stamp(hash))).toMatchObject({ status: 429 });
    expect(client.pausedForMs()).toBeLessThanOrEqual(11_000); // not 60 s
    expect(client.pausedForMs()).toBeGreaterThanOrEqual(9_000);
  });

  it('a 429 whose body is cut by attemptTimeoutMs still keeps the relay pause', async () => {
    let sent = 0;
    const client = make(
      async (_url, init) => {
        sent += 1;
        return {
          status: 429,
          headers: { get: (name) => (name.toLowerCase() === 'retry-after' ? '120' : null) },
          text: () =>
            new Promise<string>((_resolve, reject) => {
              init.signal.addEventListener('abort', () => reject(new Error('aborted')));
            }),
        };
      },
      { maxAttempts: 1, attemptTimeoutMs: 1000, timeoutMs: 5000 },
    );
    expect(failure(await client.stamp(hash))).toMatchObject({ reason: 'relay-error', status: 429 });
    expect(client.pausedForMs()).toBeGreaterThan(100_000);
    expect(sent).toBe(1);
  });

  it('the total deadline firing while a 200 body is read ends with timeout, not bad-response', async () => {
    const client = make(
      async (_url, init) => ({
        status: 200,
        headers: { get: () => null },
        text: () =>
          new Promise<string>((_resolve, reject) => {
            init.signal.addEventListener('abort', () => reject(new Error('aborted')));
          }),
      }),
      { maxAttempts: 1, attemptTimeoutMs: 5000, timeoutMs: 1000 },
    );
    expect(failure(await client.stamp(hash))).toMatchObject({ reason: 'timeout' });
  });
});
