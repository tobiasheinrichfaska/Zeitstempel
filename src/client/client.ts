import { copyBytes, fromBase64Url, toBase64Url } from '../lib/bytes.ts';
import { signRelayRequest } from '../lib/auth.ts';
import { verifyBatchedTimestamp, type BatchProof } from '../lib/batch.ts';
import { fail, ok, type Reason, type Result } from '../lib/result.ts';
import { verifyTimestampToken, type TrustAnchors } from '../lib/verify.ts';
import { parsePemCertificates } from '../lib/x509.ts';
import { readEvidence, type Evidence } from './evidence.ts';
import { listItems, plainFields } from './plain.ts';

/**
 * The client of a relay (docs/client.md): signs, sends, reads the answer, checks the token against the caller's
 * trust anchors with a mandatory `minGenTime`, and gives evidence only when that check passed. The only
 * network call is the one to the relay, through `fetch` (the environment's or the one passed in).
 */

/** What the client needs of a `Response` (a real one fits). */
export interface ResponseLike {
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}

export interface FetchInit {
  method: 'POST';
  headers: Record<string, string>;
  body: Uint8Array;
  signal: AbortSignal;
  redirect: 'error';
  credentials: 'omit';
  cache: 'no-store';
}

export type FetchLike = (url: string, init: FetchInit) => Promise<ResponseLike>;

export interface RelayClientOptions {
  /** Origin of the relay: `https://relay.example` (plain `http` only for localhost); no path, query or credentials. */
  relayUrl: string;
  /** The relay's `RELAY_AUDIENCE`, exactly. */
  audience: string;
  /** Key id as the relay's key file names it. */
  keyId: string;
  /** ECDSA P-256 private key: PKCS#8 bytes or a `CryptoKey` (it may be non-extractable). */
  privateKey: Uint8Array | CryptoKey;
  /**
   * Trust anchors as PEM texts: the caller's decision. A list (1 to 64) trusts all anchors equally for every
   * service. A map `{ [serviceId]: string[] }` (one entry per id of `services`, each 1 to 64) verifies a token
   * against the anchors of the service that was asked only.
   */
  trust: TrustAnchors | Readonly<Record<string, readonly string[]>>;
  /** Policy OID(s) the token must carry (passed to `verifyTimestampToken`); default: any. */
  expectedPolicy?: string | readonly string[];
  /** Service ids in order of preference (1 to 16, from `services.json`). */
  services: readonly string[];
  /** Default: the environment's `fetch`. */
  fetch?: FetchLike;
  /** The clock in Unix milliseconds. Default `Date.now`. */
  now?: () => number;
  /** Total time for one `stamp` call (all attempts), 1000 to 600000 ms. Default 130000 (docs/client.md). */
  timeoutMs?: number;
  /** Most sends per service for `429` and `503 busy`, 1 to 10. Default 3. */
  maxAttempts?: number;
  /** Tolerance below the send time for the token's `genTime`, 0 to 3600000 ms. Default 60000. */
  minGenTimeSlackMs?: number;
  /** Largest clock offset a `Date` header may correct, 0 to 86400000 ms. Default 65000. */
  maxClockOffsetMs?: number;
  /** Random bytes for the `jti` of each head: `(length) => Uint8Array`. Default `crypto.getRandomValues`. */
  random?: (length: number) => Uint8Array;
  /**
   * A **monotonic** clock in milliseconds (default `performance.now`): measures the deadline and the pause after a
   * `429`, so that a device clock set back or forward stretches neither.
   */
  monoNow?: () => number;
  /**
   * Deadline of ONE send (answer included), 1000 to 600000 ms; when it runs out the next service is tried (failover,
   * like a network error). Default: none (only `timeoutMs`).
   */
  attemptTimeoutMs?: number;
}

export interface StampOptions {
  /** `solo`: a direct stamp without a tree (key type 2 only). Default `normal` (no `mode` is sent). */
  mode?: 'normal' | 'solo';
  /** Aborts the call (`aborted`). */
  signal?: AbortSignal;
  /** Only this service, no failover. Must be one of `services`. */
  service?: string;
}

export type ClientReason =
  | Reason
  /** `fetch` failed on every service tried (no answer). */
  | 'network-error'
  /** `timeoutMs` ran out. */
  | 'timeout'
  /** The caller's `signal` aborted. */
  | 'aborted'
  /** A pause after a `429` (or `503 busy`) of an earlier call is still running: nothing was sent. */
  | 'paused'
  /** The relay answered with an error: `status` and `code` (its `error` text) say which. */
  | 'relay-error'
  /** A 200 whose body is no relay answer. */
  | 'bad-response';

export interface ClientFailure {
  ok: false;
  reason: ClientReason;
  detail?: string;
  /** HTTP status of the last relay answer, for `relay-error`. */
  status?: number;
  /** The relay's `error` code, for `relay-error`. */
  code?: string;
}
export type ClientResult<T> = { ok: true; value: T } | ClientFailure;

export interface RelayClient {
  stamp(hash: Uint8Array, options?: StampOptions): Promise<ClientResult<Evidence>>;
  /** Milliseconds left of the pause after a `429`/`503 busy` that ended an earlier call (0 when none). */
  pausedForMs(): number;
}

const KEY_ID = /^[a-z][a-z0-9-]{0,31}$/;
const SERVICE_ID = /^[a-z][a-z0-9-]{0,31}$/;
const AUDIENCE = /^[\x21-\x7e]{1,128}$/;
const CODE = /^[a-z][a-z0-9-]{0,47}$/;
const LOCAL_HOST = /^(localhost|127(\.\d{1,3}){3}|\[::1\])$/;
const MAX_ANSWER_CHARS = 1_000_000;
const MAX_ERROR_CHARS = 8_192;
const MAX_PEM_CHARS = 20_000;
/** What `signRelayRequest` and the relay's key file allow. */
const MAX_KEY_BYTES = 256;

export const CLIENT_LIMITS = {
  /** Default of `timeoutMs`: see docs/client.md for the formula. */
  DEFAULT_TIMEOUT_MS: 130_000,
  DEFAULT_MAX_ATTEMPTS: 3,
  DEFAULT_SLACK_MS: 60_000,
  DEFAULT_MAX_CLOCK_OFFSET_MS: 65_000,
  MAX_SERVICES: 16,
  MAX_TRUST: 64,
  /** Longest pause the client takes at the relay's word (`Retry-After`) across calls. */
  MAX_PAUSE_MS: 3_600_000,
} as const;

const OPTION_FIELDS = [
  'relayUrl',
  'audience',
  'keyId',
  'privateKey',
  'trust',
  'expectedPolicy',
  'services',
  'fetch',
  'now',
  'timeoutMs',
  'maxAttempts',
  'minGenTimeSlackMs',
  'maxClockOffsetMs',
  'random',
  'monoNow',
  'attemptTimeoutMs',
] as const;
const REQUIRED_FIELDS = ['relayUrl', 'audience', 'keyId', 'privateKey', 'trust', 'services'];

const inRange = (v: unknown, min: number, max: number, integer: boolean): v is number =>
  typeof v === 'number' &&
  Number.isFinite(v) &&
  v >= min &&
  v <= max &&
  (!integer || Number.isInteger(v));

function readOrigin(value: unknown): string | null {
  try {
    if (typeof value !== 'string' || value.length > 512) return null;
    const url = new URL(value);
    if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '')
      return null;
    if (url.pathname !== '/' || /[?#]/.test(value)) return null;
    if (url.protocol === 'http:' && !LOCAL_HOST.test(url.hostname)) return null;
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    return url.origin;
  } catch {
    return null;
  }
}

/**
 * Makes a client. Every option is checked once and copied; a wrong one is `bad-options` (or `bad-key`,
 * `bad-key-id`, `bad-pem`), never a throw. Does no network call and signs nothing yet.
 */
export function createRelayClient(options: RelayClientOptions): Result<RelayClient> {
  try {
    const o = plainFields(options, OPTION_FIELDS, REQUIRED_FIELDS);
    if (o === null) return fail('bad-options', 'options');
    const origin = readOrigin(o.relayUrl);
    if (origin === null) return fail('bad-options', 'relayUrl');
    if (typeof o.audience !== 'string' || !AUDIENCE.test(o.audience)) {
      return fail('bad-options', 'audience');
    }
    if (typeof o.keyId !== 'string' || !KEY_ID.test(o.keyId)) return fail('bad-key-id');
    let privateKey: Uint8Array | CryptoKey;
    if (o.privateKey instanceof Uint8Array) {
      const copy = copyBytes(o.privateKey, 1, MAX_KEY_BYTES);
      if (copy === null) return fail('bad-key');
      privateKey = copy;
    } else if (typeof CryptoKey === 'function' && o.privateKey instanceof CryptoKey) {
      privateKey = o.privateKey;
    } else {
      return fail('bad-key');
    }
    const serviceItems = listItems(o.services, CLIENT_LIMITS.MAX_SERVICES);
    if (serviceItems === null || serviceItems.length === 0) return fail('bad-options', 'services');
    const services: string[] = [];
    for (const id of serviceItems) {
      if (typeof id !== 'string' || !SERVICE_ID.test(id) || services.includes(id)) {
        return fail('bad-options', 'services');
      }
      services.push(id);
    }
    const readPems = (value: unknown): string[] | Result<never> => {
      const items = listItems(value, CLIENT_LIMITS.MAX_TRUST);
      if (items === null || items.length === 0) return fail('bad-options', 'trust');
      const pems: string[] = [];
      for (const pem of items) {
        if (typeof pem !== 'string' || pem.length === 0 || pem.length > MAX_PEM_CHARS) {
          return fail('bad-options', 'trust');
        }
        try {
          parsePemCertificates(pem);
        } catch {
          return fail('bad-pem');
        }
        pems.push(pem);
      }
      return pems;
    };
    let trust: readonly string[] | Readonly<Record<string, readonly string[]>>;
    if (Array.isArray(o.trust)) {
      const list = readPems(o.trust);
      if (!Array.isArray(list)) return list;
      trust = list;
    } else {
      const map = plainFields(o.trust, services, services);
      if (map === null) return fail('bad-options', 'trust');
      const copy: Record<string, readonly string[]> = Object.create(null) as Record<
        string,
        readonly string[]
      >;
      for (const id of services) {
        const list = readPems(map[id]);
        if (!Array.isArray(list)) return list;
        copy[id] = list;
      }
      trust = copy;
    }
    for (const name of ['fetch', 'now', 'random', 'monoNow'] as const) {
      if (name in o && typeof o[name] !== 'function') return fail('bad-options', name);
    }
    const timeoutMs = 'timeoutMs' in o ? o.timeoutMs : CLIENT_LIMITS.DEFAULT_TIMEOUT_MS;
    if (!inRange(timeoutMs, 1000, 600_000, false)) return fail('bad-options', 'timeoutMs');
    const maxAttempts = 'maxAttempts' in o ? o.maxAttempts : CLIENT_LIMITS.DEFAULT_MAX_ATTEMPTS;
    if (!inRange(maxAttempts, 1, 10, true)) return fail('bad-options', 'maxAttempts');
    const slack = 'minGenTimeSlackMs' in o ? o.minGenTimeSlackMs : CLIENT_LIMITS.DEFAULT_SLACK_MS;
    if (!inRange(slack, 0, 3_600_000, false)) return fail('bad-options', 'minGenTimeSlackMs');
    const maxOffset =
      'maxClockOffsetMs' in o ? o.maxClockOffsetMs : CLIENT_LIMITS.DEFAULT_MAX_CLOCK_OFFSET_MS;
    if (!inRange(maxOffset, 0, 86_400_000, false)) return fail('bad-options', 'maxClockOffsetMs');
    const attemptTimeoutMs = 'attemptTimeoutMs' in o ? o.attemptTimeoutMs : null;
    if (attemptTimeoutMs !== null && !inRange(attemptTimeoutMs, 1000, 600_000, false)) {
      return fail('bad-options', 'attemptTimeoutMs');
    }
    const fetchFn: FetchLike =
      'fetch' in o
        ? (o.fetch as FetchLike)
        : (url, init) =>
            globalThis.fetch(url, {
              ...init,
              body: init.body as BodyInit,
            }) as Promise<ResponseLike>;
    const clock = 'now' in o ? (o.now as () => number) : () => Date.now();
    const random =
      'random' in o
        ? (o.random as (length: number) => Uint8Array)
        : (n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n));
    const mono = 'monoNow' in o ? (o.monoNow as () => number) : () => performance.now();
    const expectedPolicy =
      'expectedPolicy' in o ? (o.expectedPolicy as string | readonly string[]) : undefined;
    const state = new Session({
      origin,
      audience: o.audience,
      keyId: o.keyId,
      privateKey,
      trust,
      expectedPolicy,
      services,
      fetchFn,
      clock,
      random,
      mono,
      attemptTimeoutMs,
      timeoutMs,
      maxAttempts,
      slack,
      maxOffset,
    });
    return ok({
      stamp: (hash, stampOptions) => state.stamp(hash, stampOptions),
      pausedForMs: () => state.pausedForMs(),
    });
  } catch {
    return fail('bad-options'); // not reachable by design
  }
}

interface Config {
  origin: string;
  audience: string;
  keyId: string;
  privateKey: Uint8Array | CryptoKey;
  trust: readonly string[] | Readonly<Record<string, readonly string[]>>;
  expectedPolicy: string | readonly string[] | undefined;
  services: readonly string[];
  fetchFn: FetchLike;
  clock: () => number;
  random: (length: number) => Uint8Array;
  mono: () => number;
  attemptTimeoutMs: number | null;
  timeoutMs: number;
  maxAttempts: number;
  slack: number;
  maxOffset: number;
}

const failure = (
  reason: ClientReason,
  extra: { detail?: string; status?: number; code?: string } = {},
): ClientFailure => ({ ok: false, reason, ...extra });

class BadClock extends Error {}

/** Waits `ms` or until the signal aborts, whichever is first. */
function pause(ms: number, signal: AbortSignal): Promise<void> {
  // aborted already (while the body of the answer was read): no wait at all
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => {
      clearTimeout(timer);
      signal.removeEventListener('abort', done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal.addEventListener('abort', done, { once: true });
  });
}

class Session {
  /** What the relay's `Date` taught about the client's clock; kept for later calls. */
  private offsetMs = 0;
  /** End of the pause after a `429`/`503 busy` that ended a call, on the monotonic clock. */
  private blockedUntil = -Infinity;

  private readonly c: Config;

  constructor(config: Config) {
    this.c = config;
  }

  private now(offset: number): number {
    const t = this.c.clock();
    if (typeof t !== 'number' || !Number.isFinite(t)) throw new BadClock();
    return Math.floor(t) + offset;
  }

  private mono(): number {
    const t = this.c.mono();
    if (typeof t !== 'number' || !Number.isFinite(t)) throw new BadClock('monoNow');
    return t;
  }

  pausedForMs(): number {
    try {
      const left = this.blockedUntil - this.mono();
      // longer than the longest pause ever set: the monotonic clock went back (a wrong injected one): forget it
      if (left > CLIENT_LIMITS.MAX_PAUSE_MS) {
        this.blockedUntil = -Infinity;
        return 0;
      }
      return Math.max(0, Math.ceil(left));
    } catch {
      return 0;
    }
  }

  async stamp(hashInput: Uint8Array, stampOptions?: StampOptions): Promise<ClientResult<Evidence>> {
    const hash = copyBytes(hashInput, 32, 32);
    if (hash === null) return failure('bad-hash');
    let mode: 'normal' | 'solo' = 'normal';
    let userSignal: AbortSignal | undefined;
    let order: readonly string[] = this.c.services;
    if (stampOptions !== undefined) {
      const f = plainFields(stampOptions, ['mode', 'signal', 'service'], []);
      if (f === null) return failure('bad-options', { detail: 'options' });
      if (f.mode !== undefined && f.mode !== 'normal' && f.mode !== 'solo') {
        return failure('bad-options', { detail: 'mode' });
      }
      if (f.mode === 'solo') mode = 'solo';
      if ('signal' in f && f.signal !== undefined) {
        // `instanceof` runs the code of a proxy (`getPrototypeOf`): a hostile value must give a code, never a throw
        let isSignal: boolean;
        try {
          isSignal = typeof AbortSignal === 'function' && f.signal instanceof AbortSignal;
        } catch {
          isSignal = false;
        }
        if (!isSignal) return failure('bad-options', { detail: 'signal' });
        userSignal = f.signal as AbortSignal;
      }
      if ('service' in f && f.service !== undefined) {
        if (typeof f.service !== 'string' || !this.c.services.includes(f.service)) {
          return failure('bad-options', { detail: 'service' });
        }
        order = [f.service];
      }
    }
    const control = new AbortController();
    let cause: 'aborted' | 'timeout' = 'timeout';
    const onAbort = () => {
      if (!control.signal.aborted) cause = 'aborted'; // a deadline that fired first stays the cause
      control.abort();
    };
    let startedAt: number;
    try {
      if (userSignal?.aborted) return failure('aborted');
    } catch {
      return failure('bad-options', { detail: 'signal' }); // a signal of this realm that misbehaves
    }
    try {
      startedAt = this.mono();
      const paused = this.pausedForMs();
      if (paused > 0) {
        return failure('paused', { detail: `retry in ${Math.ceil(paused / 1000)} s` });
      }
    } catch {
      return failure('bad-options', { detail: 'monoNow' });
    }
    // added only now: every early end above leaves no listener on the caller's signal
    try {
      userSignal?.addEventListener('abort', onAbort, { once: true });
    } catch {
      return failure('bad-options', { detail: 'signal' });
    }
    const timer = setTimeout(() => control.abort(), this.c.timeoutMs);
    try {
      const run = await this.run(hash, mode, order, control.signal, startedAt);
      if (
        !run.ok &&
        control.signal.aborted &&
        (run.reason === 'network-error' || (run.reason === 'bad-response' && run.detail === 'json'))
      ) {
        return failure(cause);
      }
      return run;
    } catch (e) {
      if (e instanceof BadClock) {
        return failure('bad-options', { detail: e.message === 'monoNow' ? 'monoNow' : 'now' });
      }
      return failure(control.signal.aborted ? cause : 'network-error', { detail: 'unexpected' });
    } finally {
      clearTimeout(timer);
      try {
        userSignal?.removeEventListener('abort', onAbort);
      } catch {
        // a hostile signal must not turn the result into a rejection
      }
    }
  }

  private async run(
    hash: Uint8Array,
    mode: 'normal' | 'solo',
    order: readonly string[],
    signal: AbortSignal,
    startedAt: number,
  ): Promise<ClientResult<Evidence>> {
    const c = this.c;
    const text = JSON.stringify(
      mode === 'solo' ? { hash: toBase64Url(hash), mode } : { hash: toBase64Url(hash) },
    );
    const body = new TextEncoder().encode(text);
    let offset = this.offsetMs;
    let clockFixed = false; // the one correction by the relay's `Date` of this call
    let fixPending = false; // the corrected clock is kept only when the relay then accepted a head
    let last: ClientFailure | null = null;
    for (const service of order) {
      const path = '/v1/stamp/' + service;
      let attempts = 0;
      for (;;) {
        if (signal.aborted) return failure('network-error');
        attempts += 1;
        const sentMs = this.now(offset);
        let jti: Uint8Array | null;
        try {
          jti = copyBytes(c.random(16), 16, 16);
        } catch {
          jti = null;
        }
        if (jti === null) return failure('bad-options', { detail: 'random' });
        const signed = await signRelayRequest({
          privateKey: c.privateKey,
          keyId: c.keyId,
          method: 'POST',
          path,
          body,
          nowMs: sentMs,
          audience: c.audience,
          jti,
        });
        if (!signed.ok)
          return failure(
            signed.reason,
            signed.detail === undefined ? {} : { detail: signed.detail },
          );
        // the deadline of this one send (`attemptTimeoutMs`): its end is a failover like a network error
        const attempt = new AbortController();
        let attemptTimedOut = false;
        const onOuter = () => attempt.abort();
        signal.addEventListener('abort', onOuter, { once: true });
        const attemptTimer =
          c.attemptTimeoutMs === null
            ? undefined
            : setTimeout(() => {
                attemptTimedOut = true;
                attempt.abort();
              }, c.attemptTimeoutMs);
        const endAttempt = () => {
          clearTimeout(attemptTimer);
          signal.removeEventListener('abort', onOuter);
        };
        const timedOutHere = () => attemptTimedOut && !signal.aborted;
        let res: ResponseLike;
        let status: number;
        try {
          res = await c.fetchFn(c.origin + path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': signed.value },
            body,
            signal: attempt.signal,
            redirect: 'error',
            credentials: 'omit',
            cache: 'no-store',
          });
          status = res.status;
          if (typeof status !== 'number') throw new TypeError('status');
        } catch {
          endAttempt();
          if (signal.aborted) return failure('network-error');
          last = timedOutHere()
            ? failure('timeout', { detail: service })
            : failure('network-error', { detail: service });
          break; // the next service
        }
        if (fixPending && status !== 401) this.offsetMs = offset;
        if (status === 200) {
          let verified: ClientResult<Evidence>;
          try {
            verified = await this.finish(res, hash, service, sentMs, offset, mode);
          } finally {
            endAttempt(); // also when `finish` throws `BadClock`
          }
          if (!verified.ok && timedOutHere()) {
            last = failure('timeout', { detail: service });
            break; // the body did not come in time: the next service
          }
          return verified;
        }
        const error = await readError(res);
        endAttempt();
        // a 429 says what it means by its status and `Retry-After`: a body cut by the deadline still pauses
        if (timedOutHere() && status !== 429) {
          last = failure('timeout', { detail: service });
          break;
        }
        const refused = failure('relay-error', {
          status,
          ...(error.code === undefined ? {} : { code: error.code }),
          detail: error.reason ?? service,
        });
        if (status === 401) {
          const candidate = clockFixed
            ? null
            : relayClockOffset(res, () => this.now(0), c.maxOffset);
          if (candidate === null) return refused;
          clockFixed = true;
          fixPending = true;
          offset = candidate;
          attempts -= 1; // the correction is not an attempt
          continue;
        }
        if (status === 429 || (status === 503 && error.code === 'busy')) {
          const asked = retryAfterMs(res, () => this.now(offset)); // the learned offset: relay time
          const wait = Math.min(asked, c.timeoutMs);
          const left = c.timeoutMs - (this.mono() - startedAt);
          if (attempts >= c.maxAttempts || wait >= left) {
            // the call ends on the relay's word: no later call sends before the pause is over
            // extend, never shorten: a pause still running (set by a call in parallel) keeps its later end
            const until = this.mono() + Math.min(asked, CLIENT_LIMITS.MAX_PAUSE_MS);
            this.blockedUntil = Math.max(this.blockedUntil, until);
            return refused;
          }
          await pause(wait, signal);
          continue;
        }
        if (status === 500 || status === 502 || status === 503 || status === 504) {
          last = refused;
          break; // the next service
        }
        return refused; // 400, 403, 404, 405, 413, 415 and anything unknown: no other service helps
      }
    }
    return last ?? failure('network-error');
  }

  private async finish(
    res: ResponseLike,
    hash: Uint8Array,
    service: string,
    sentMs: number,
    offset: number,
    mode: 'normal' | 'solo',
  ): Promise<ClientResult<Evidence>> {
    const c = this.c;
    let answer: unknown;
    try {
      const text = await res.text();
      if (typeof text !== 'string' || text.length > MAX_ANSWER_CHARS) {
        return failure('bad-response', { detail: 'size' });
      }
      answer = JSON.parse(text);
    } catch {
      return failure('bad-response', { detail: 'json' });
    }
    const f = plainFields(
      answer,
      ['service', 'genTime', 'accuracyMs', 'serial', 'token', 'batch'],
      ['service', 'token'],
    );
    if (f === null || f.service !== service || typeof f.token !== 'string') {
      return failure('bad-response', { detail: 'shape' });
    }
    // a direct stamp was asked for (`solo`): a collected receipt is another statement, whatever it proves
    if (mode === 'solo' && 'batch' in f) return failure('bad-response', { detail: 'mode' });
    const token = f.token.length > 400_000 ? null : fromBase64Url(f.token);
    if (token === null) return failure('bad-response', { detail: 'token' });
    // minGenTime is mandatory: without it a back-dated token from a stolen or expired service key passes
    const receivedMs = this.now(offset);
    // The corrected clock comes from the relay's `Date`: it may only make the check stricter, never looser. The
    // floor is the later of the corrected and the uncorrected (device) send time.
    const floorMs = Math.max(sentMs, sentMs - offset);
    const options = {
      now: new Date(receivedMs),
      minGenTime: new Date(floorMs - c.slack),
      ...(c.expectedPolicy === undefined ? {} : { expectedPolicy: c.expectedPolicy }),
    };
    const trust: readonly string[] = Array.isArray(c.trust)
      ? (c.trust as readonly string[])
      : (c.trust as Readonly<Record<string, readonly string[]>>)[service]!;
    const kind = 'batch' in f ? 'batch' : 'single';
    const verified =
      kind === 'single'
        ? await verifyTimestampToken(token, hash, trust, options)
        : await verifyBatchedTimestamp(
            { token, hash, batch: f.batch as BatchProof },
            trust,
            options,
          );
    if (!verified.ok) return verified;
    // the relay's own claim of the serial must name this token (a mixed-up answer is not taken)
    if ('serial' in f && f.serial !== verified.value.serial) {
      return failure('bad-response', { detail: 'serial' });
    }
    const evidence = readEvidence({
      v: 1,
      kind,
      service,
      hash: toBase64Url(hash),
      hashAlg: 'sha256',
      receivedAtMs: receivedMs,
      token: toBase64Url(token),
      ...(kind === 'batch' ? { batch: f.batch } : {}),
      policy: verified.value.policy,
      genTime: verified.value.genTime,
      signerNotAfter: verified.value.signerNotAfter,
    });
    return evidence.ok ? evidence : failure('bad-response', { detail: 'evidence' });
  }
}

/** `{ error, reason }` of a relay error answer; nothing that does not look like a code is kept. */
async function readError(res: ResponseLike): Promise<{ code?: string; reason?: string }> {
  try {
    const text = await res.text();
    if (typeof text !== 'string' || text.length > MAX_ERROR_CHARS) return {};
    const f = plainFields(JSON.parse(text), ['error', 'reason'], []);
    if (f === null) return {};
    return {
      ...(typeof f.error === 'string' && CODE.test(f.error) ? { code: f.error } : {}),
      ...(typeof f.reason === 'string' && CODE.test(f.reason) ? { reason: f.reason } : {}),
    };
  } catch {
    return {};
  }
}

/**
 * `Retry-After` as milliseconds: whole seconds, or an HTTP date (RFC 9110) measured against the answer's own `Date`
 * (else the client's clock), rounded up to whole seconds. Missing, unreadable or a date in the past: one second.
 */
function retryAfterMs(res: ResponseLike, clockNow: () => number): number {
  try {
    const raw = res.headers.get('Retry-After');
    const value = typeof raw === 'string' && raw.length <= 64 ? raw.trim() : '';
    if (/^\d{1,6}$/.test(value)) return Number(value) * 1000;
    if (value !== '' && /[a-z]/i.test(value)) {
      const at = Date.parse(value);
      const dateHeader = res.headers.get('Date');
      const relayNow =
        typeof dateHeader === 'string' && dateHeader.length <= 64 ? Date.parse(dateHeader) : NaN;
      const base = Number.isFinite(relayNow) ? relayNow : clockNow();
      if (Number.isFinite(at) && at > base) return Math.ceil((at - base) / 1000) * 1000;
    }
  } catch {
    /* unreadable */
  }
  return 1000;
}

/** The offset (relay time minus the client's clock) from the `Date` header of a 401, or null when it is no help. */
function relayClockOffset(
  res: ResponseLike,
  clockNow: () => number,
  maxOffsetMs: number,
): number | null {
  try {
    const header = res.headers.get('Date');
    if (typeof header !== 'string' || header.length > 64) return null;
    const relayMs = Date.parse(header);
    if (!Number.isFinite(relayMs)) return null;
    const offset = relayMs - clockNow();
    return Math.abs(offset) <= maxOffsetMs ? offset : null;
  } catch {
    return null;
  }
}
