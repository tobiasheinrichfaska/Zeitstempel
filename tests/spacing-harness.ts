import { randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { toBase64Url } from '../src/index.ts';
import type { RelayKey } from '../relay/keys.ts';
import { loadServices } from '../relay/load.ts';
import type { RelayOptions } from '../relay/relay.ts';
import { createRelayServer } from '../relay/server.ts';
import type { Upstream } from '../relay/upstream.ts';
import { TEST_AUDIENCE, makeTestKey, nodeAuthHeaderMs, type TestKey } from './auth-helpers.ts';
import { sha256 } from './helpers.ts';
export { sha256 };
import { build, int, seq } from './token-builder.ts';
import { children, integerBytes, octets, parseDer } from '../src/lib/der.ts';

// Harness of the spacing tests (`solo-spacing.test.ts`, `solo-chain.test.ts`). The minimum spacing: two calls of the relay to one service (one identity) are at least `minIntervalMs` apart,
// whether the one before was a window or a solo stamp of key type 2 (on top of the sliding budget). A stub service
// records the time of every call. Real clock; `minIntervalMs` 600 ms, so a test takes a few seconds at most.

export const SERVICES = loadServices().filter((s) => s.id === 'freetsa');
export const SIGNER = build();
export const ORIGIN = 'https://app.example';
export const KEY_A = makeTestKey('app-a'); // type 1
export const KEY_B = makeTestKey('app-b'); // type 2
export const KEY_F = makeTestKey('app-f'); // type 1
export const KEY_C = makeTestKey('app-c'); // type 2
export const KEY_D = makeTestKey('app-d'); // type 2
const asRelayKey = (k: TestKey, solo: boolean): RelayKey => ({
  id: k.id,
  publicKey: k.publicKey,
  ...(solo ? { solo: true } : {}),
});
const KEYS: RelayKey[] = [
  asRelayKey(KEY_A, false),
  asRelayKey(KEY_B, true),
  asRelayKey(KEY_C, true),
  asRelayKey(KEY_D, true),
  asRelayKey(KEY_F, false),
];

const genTimeText = (ms: number) =>
  new Date(ms)
    .toISOString()
    .replace(/[-:T]/g, '')
    .replace(/\.\d+Z$/, 'Z');

/** The imprint a request to a service carries (what the service is asked to stamp). */
function imprintOf(request: Uint8Array): Uint8Array {
  return octets(children(children(parseDer(request))[1]!)[1]!);
}

function replyFor(request: Uint8Array, nowMs: number): Uint8Array {
  const parts = children(parseDer(request));
  const made = build({
    keys: SIGNER.keys,
    hash: imprintOf(request),
    nonceBytes: integerBytes(parts[2]!),
    genTime: genTimeText(nowMs),
  });
  return seq(seq(int(0)), made.token);
}

export interface Harness {
  calls: { imprint: Uint8Array; at: number; mono: number; token?: string }[];
  /** The relay's clock is the real one plus `offset` ms (the tests set it back); requests are signed with it. */
  clock: { offset: number };
  /**
   * The relay's monotonic clock is `performance.now()` plus `offset` ms (a test lets it jump to stand in for a stalled
   * loop). The wall clock (`clock`) and this one are steered apart.
   */
  mono: { offset: number };
  /**
   * With `virtualMono: true` the relay's monotonic clock is this value (ms) and stands still until `advance` moves it:
   * no timer jitter, so a test can test the distance to the millisecond. Without it the value is unused.
   */
  vmono: { now: number };
  advance: (ms: number) => void;
  relay: ReturnType<typeof createRelayServer>['relay'];
  stats: ReturnType<typeof createRelayServer>['relay']['stats'];
  stamp: (
    hash: Uint8Array,
    over?: {
      key?: TestKey;
      body?: unknown;
      raw?: string;
      signedRaw?: string;
      type?: string;
      head?: string;
      /** Aborting it closes the connection (a client or a proxy that gives up). */
      signal?: AbortSignal;
    },
  ) => Promise<Response>;
  /** Like `stamp`, plus the time until the answer. */
  timed: (hash: Uint8Array, over?: { key?: TestKey; body?: unknown }) => Promise<Timed>;
  close: () => Promise<void>;
}
interface Timed {
  res: Response;
  at: number;
}

export async function start(
  over: {
    batch?: { windowMs: number; max: number } | null;
    minIntervalMs?: number;
    budgetWindowMs?: number;
    maxWaitMs?: number;
    stampDelayMs?: number;
    keys?: RelayKey[] | 'off';
    /** The service takes a bearer token from the client: each token is an identity (its own lane). */
    bearer?: boolean;
    upstreamIdentities?: number;
    /** The monotonic clock of the relay is virtual (`vmono`, moved by `advance` only); the real timers still run. */
    virtualMono?: boolean;
  } = {},
): Promise<Harness> {
  const calls: Harness['calls'] = [];
  const clock = { offset: 0 };
  const mono = { offset: 0 };
  const vmono = { now: 1_000_000 };
  const monoNow = (): number => (over.virtualMono ? vmono.now : performance.now() + mono.offset);
  const t0 = Date.now();
  const stub: Upstream = async (_t, body, creds) => {
    calls.push({
      imprint: imprintOf(body),
      at: Date.now() - t0,
      mono: monoNow(),
      ...(creds?.kind === 'bearer' ? { token: creds.token } : {}),
    });
    if (over.stampDelayMs) await new Promise((r) => setTimeout(r, over.stampDelayMs));
    return {
      status: 200,
      contentType: 'application/timestamp-reply',
      body: replyFor(body, Date.now() + clock.offset),
    };
  };
  const batch = over.batch === undefined ? { windowMs: 100, max: 100 } : over.batch;
  const options: RelayOptions = {
    services: SERVICES.map((s) => ({
      ...s,
      minIntervalMs: over.minIntervalMs ?? 1000,
      ...(over.bearer ? { auth: { kind: 'bearer' as const, source: 'client' as const } } : {}),
      anchorPems: [...s.anchorPems, SIGNER.caPem],
    })),
    origins: [ORIGIN],
    allowPlainHttp: false,
    upstream: stub,
    random: (n) => new Uint8Array(randomBytes(n)),
    now: () => Date.now() + clock.offset,
    monotonicNow: monoNow,
    keys: over.keys ?? KEYS,
    audience: TEST_AUDIENCE,
    ...(batch === null ? {} : { batch }),
    ...(over.upstreamIdentities === undefined
      ? {}
      : { upstreamIdentities: over.upstreamIdentities }),
    ...(over.maxWaitMs === undefined ? {} : { maxWaitMs: over.maxWaitMs }),
    ...(over.budgetWindowMs === undefined ? {} : { budgetWindowMs: over.budgetWindowMs }),
  };
  const { server, relay } = createRelayServer(options);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const stamp: Harness['stamp'] = (hash, o = {}) => {
    const path = '/v1/stamp/freetsa';
    const key = o.key ?? KEY_A;
    const text = o.raw ?? JSON.stringify(o.body ?? { hash: toBase64Url(hash) });
    const head =
      o.head ??
      nodeAuthHeaderMs(
        key,
        key.id,
        'POST',
        path,
        Date.now() + clock.offset,
        new TextEncoder().encode(o.signedRaw ?? text),
      );
    return fetch(base + path, {
      method: 'POST',
      body: text,
      headers: { 'Content-Type': o.type ?? 'application/json', 'X-Zeitstempel-Auth': head },
      ...(o.signal === undefined ? {} : { signal: o.signal }),
    });
  };
  return {
    calls,
    clock,
    mono,
    vmono,
    advance: (ms) => {
      vmono.now += ms;
    },
    relay,
    stats: relay.stats,
    stamp,
    timed: async (hash, o = {}) => {
      const started = Date.now();
      const res = await stamp(hash, o);
      return { res, at: Date.now() - started };
    },
    close: () =>
      new Promise((r) => {
        relay.close();
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}

export const solo = (hash: Uint8Array) => ({ hash: toBase64Url(hash), mode: 'solo' });
export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
export const same = (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));

export const M = 600; // minIntervalMs
export const TOL = 40; // timers and the clock of the test process are not exact

/** The gaps between the calls the service saw, in the order of the calls. */
export function gaps(calls: { at: number }[]): number[] {
  const times = calls.map((c) => c.at).sort((a, b) => a - b);
  return times.slice(1).map((t, i) => t - times[i]!);
}
export const expectSpaced = (calls: { at: number }[]) => {
  for (const g of gaps(calls)) expect(g).toBeGreaterThanOrEqual(M - TOL);
};
