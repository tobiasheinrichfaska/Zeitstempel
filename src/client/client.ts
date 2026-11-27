import { copyBytes, fromBase64Url, toBase64Url } from '../lib/bytes.ts';
import { signRelayRequest } from '../lib/auth.ts';
import { verifyBatchedTimestamp, type BatchProof } from '../lib/batch.ts';
import { fail, ok, type Reason, type Result } from '../lib/result.ts';
import { verifyTimestampToken, type TrustAnchors } from '../lib/verify.ts';
import { parsePemCertificates } from '../lib/x509.ts';
import { renewalImprint, type RenewalLink } from '../lib/renewal.ts';
import { readEvidence, verifyEvidence, type Evidence, type RenewalEvidence } from './evidence.ts';
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
  /** Trust anchors as PEM texts (1 to 64): the caller's decision. */
  trust: TrustAnchors;
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
  /**
   * Renews evidence before its signer certificate expires: stamps the `renewalImprint` of the whole evidence (the hash and
   * every token so far) through the relay, with the rules of `stamp`, and returns the evidence with the new link appended.
   * The evidence must verify against `trust` now (else its failure code, nothing is sent), and so must the result.
   * Same options as `stamp`. Never rejects.
   */
  renew(evidence: unknown, options?: StampOptions): Promise<ClientResult<Evidence>>;
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
} as const;

const OPTION_FIELDS = [
  'relayUrl',
  'audience',
  'keyId',
  'privateKey',
  'trust',
  'services',
  'fetch',
  'now',
  'timeoutMs',
  'maxAttempts',
  'minGenTimeSlackMs',
  'maxClockOffsetMs',
  'random',
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
    const trustItems = listItems(o.trust, CLIENT_LIMITS.MAX_TRUST);
    if (trustItems === null || trustItems.length === 0) return fail('bad-options', 'trust');
    const trust: string[] = [];
    for (const pem of trustItems) {
      if (typeof pem !== 'string' || pem.length === 0 || pem.length > MAX_PEM_CHARS) {
        return fail('bad-options', 'trust');
      }
      try {
        parsePemCertificates(pem);
      } catch {
        return fail('bad-pem');
      }
      trust.push(pem);
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
    for (const name of ['fetch', 'now', 'random'] as const) {
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
    const state = new Session({
      origin,
      audience: o.audience,
      keyId: o.keyId,
      privateKey,
      trust,
      services,
      fetchFn,
      clock,
      random,
      timeoutMs,
      maxAttempts,
      slack,
      maxOffset,
    });
    return ok({
      stamp: (hash, stampOptions) => state.stamp(hash, stampOptions),
      renew: (evidence, stampOptions) => state.renew(evidence, stampOptions),
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
  trust: readonly string[];
  services: readonly string[];
  fetchFn: FetchLike;
  clock: () => number;
  random: (length: number) => Uint8Array;
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

  private readonly c: Config;

  constructor(config: Config) {
    this.c = config;
  }

  private now(offset: number): number {
    const t = this.c.clock();
    if (typeof t !== 'number' || !Number.isFinite(t)) throw new BadClock();
    return Math.floor(t) + offset;
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
      cause = 'aborted';
      control.abort();
    };
    try {
      if (userSignal?.aborted) return failure('aborted');
      userSignal?.addEventListener('abort', onAbort, { once: true });
    } catch {
      return failure('bad-options', { detail: 'signal' }); // a signal of this realm that misbehaves
    }
    const startedAt = performance.now();
    const timer = setTimeout(() => control.abort(), this.c.timeoutMs);
    try {
      const run = await this.run(hash, mode, order, control.signal, startedAt);
      if (!run.ok && control.signal.aborted && run.reason === 'network-error') {
        return failure(cause);
      }
      return run;
    } catch (e) {
      if (e instanceof BadClock) return failure('bad-options', { detail: 'now' });
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

  /** The clock for a chain check: `now` (no token from the future) and `at` (the last signer must be valid now). */
  private checkTime(): { now: Date; at: Date } {
    const t = new Date(this.now(this.offsetMs));
    return { now: t, at: t };
  }

  async renew(
    evidenceInput: unknown,
    stampOptions?: StampOptions,
  ): Promise<ClientResult<Evidence>> {
    try {
      const read = readEvidence(evidenceInput);
      if (!read.ok)
        return failure(read.reason, read.detail === undefined ? {} : { detail: read.detail });
      const evidence = read.value;
      const hash = fromBase64Url(evidence.hash)!;
      const chain: RenewalLink[] = [
        {
          token: fromBase64Url(evidence.token)!,
          ...(evidence.batch ? { batch: evidence.batch } : {}),
        },
        ...(evidence.renewals ?? []).map((r) => ({
          token: fromBase64Url(r.token)!,
          ...(r.batch ? { batch: r.batch } : {}),
        })),
      ];
      // a chain that is already broken or expired is not worth another stamp
      const before = await verifyEvidence(evidence, hash, {
        trust: this.c.trust,
        ...this.checkTime(),
      });
      if (!before.ok)
        return failure(before.reason, before.detail === undefined ? {} : { detail: before.detail });
      const imprint = await renewalImprint({ hash, links: chain });
      if (!imprint.ok)
        return failure(
          imprint.reason,
          imprint.detail === undefined ? {} : { detail: imprint.detail },
        );
      const stamped = await this.stamp(imprint.value, stampOptions);
      if (!stamped.ok) return stamped;
      const s = stamped.value;
      const link: RenewalEvidence = {
        kind: s.kind,
        service: s.service,
        receivedAtMs: s.receivedAtMs,
        token: s.token,
        ...(s.batch === undefined ? {} : { batch: s.batch }),
        ...(s.policy === undefined ? {} : { policy: s.policy }),
        genTime: s.genTime,
        ...(s.signerNotAfter === undefined ? {} : { signerNotAfter: s.signerNotAfter }),
      };
      const renewed = readEvidence({ ...evidence, renewals: [...(evidence.renewals ?? []), link] });
      if (!renewed.ok) return failure('bad-renewal', { detail: renewed.detail ?? 'renewals' });
      // the whole chain once more: the previous signer must have been valid when the new link was made
      const after = await verifyEvidence(renewed.value, hash, {
        trust: this.c.trust,
        ...this.checkTime(),
      });
      if (!after.ok)
        return failure(after.reason, after.detail === undefined ? {} : { detail: after.detail });
      return renewed;
    } catch (e) {
      return failure('bad-options', { detail: e instanceof BadClock ? 'now' : 'unexpected' });
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
        let res: ResponseLike;
        let status: number;
        try {
          res = await c.fetchFn(c.origin + path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': signed.value },
            body,
            signal,
            redirect: 'error',
            credentials: 'omit',
            cache: 'no-store',
          });
          status = res.status;
          if (typeof status !== 'number') throw new TypeError('status');
        } catch {
          if (signal.aborted) return failure('network-error');
          last = failure('network-error', { detail: service });
          break; // the next service
        }
        if (fixPending && status !== 401) this.offsetMs = offset;
        if (status === 200) {
          const verified = await this.finish(res, hash, service, sentMs, offset, mode);
          return verified;
        }
        const error = await readError(res);
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
          if (attempts >= c.maxAttempts) return refused;
          const wait = retryAfterMs(res, c.timeoutMs);
          const left = c.timeoutMs - (performance.now() - startedAt);
          if (wait >= left) return refused; // would not be answered in time anyway
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
    const options = { now: new Date(receivedMs), minGenTime: new Date(sentMs - c.slack) };
    const kind = 'batch' in f ? 'batch' : 'single';
    const verified =
      kind === 'single'
        ? await verifyTimestampToken(token, hash, c.trust, options)
        : await verifyBatchedTimestamp(
            { token, hash, batch: f.batch as BatchProof },
            c.trust,
            options,
          );
    if (!verified.ok) return verified;
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

/** `Retry-After` in seconds as milliseconds, at most `capMs`; missing or unreadable: one second. */
function retryAfterMs(res: ResponseLike, capMs: number): number {
  try {
    const value = res.headers.get('Retry-After');
    if (value !== null && /^\d{1,6}$/.test(value.trim())) {
      return Math.min(Number(value.trim()) * 1000, capMs);
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
