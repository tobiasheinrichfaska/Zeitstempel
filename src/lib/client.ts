import { fromBase64Url, toBase64Url } from './bytes.ts';
import { fail, ok, type Failure, type Result } from './result.ts';
import { verifyTimestampToken, type TrustAnchors, type VerifiedTimestamp } from './verify.ts';

/**
 * Client for the library's own relay (`docs/relay.md`): `GET <relay>/v1/services` and
 * `POST <relay>/v1/stamp/<id>`. Like the rest of the core it uses no global: `fetch` and the monotonic
 * clock are parameters, nothing throws, errors are codes (`Reason`) with an English detail.
 */

/** Limits of the client, in one place. */
export const CLIENT_LIMITS = {
  /** Deadline of one call (the relay itself waits up to 10 s for the service: stay well above). */
  timeoutMs: 20_000,
  /** The pause after a 429 without a usable `Retry-After`. */
  defaultRetrySeconds: 60,
  /** The longest pause the client takes at the relay's word. */
  maxRetrySeconds: 3600,
  /** How many of the relay's services are tried one after another when one cannot be reached. */
  maxServicesTried: 3,
  /** Longest list of services the client reads. */
  maxServices: 32,
  /** Longest serial (lower-case hex digits) of an answer. */
  maxSerialChars: 64,
  /** Longest token of an answer (Base64url characters, about 12 KiB of DER). */
  maxTokenChars: 12_288,
} as const;

/** What the client needs from `fetch`; the real `fetch` fits. */
export interface FetchInit {
  method: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  credentials: 'omit';
  referrerPolicy: 'no-referrer';
  cache: 'no-store';
  redirect: 'error';
  signal: AbortSignal;
}
export interface FetchResponse {
  status: number;
  headers: { get(name: string): string | null };
  json(): Promise<unknown>;
}
export type FetchLike = (url: string, init: FetchInit) => Promise<FetchResponse>;

export interface RelayClientOptions {
  /** Base address of the relay, e.g. `https://relay.example` (a trailing slash is ignored). */
  relay: string;
  fetch: FetchLike;
  /** Milliseconds on a **monotonic** clock (e.g. `performance.now()`); a changed device clock must not move it. */
  now: () => number;
  /** The services the caller trusts: service id → PEM text of its trust anchors. */
  trusted: ReadonlyMap<string, TrustAnchors>;
  /**
   * Wall clock in milliseconds since the epoch. Used only to turn a `Retry-After` given as an HTTP date into
   * a pause; without it such a header counts as unusable (60 s). Never used for the pause itself.
   */
  wallNow?: () => number;
  /** Deadline of one call; default `CLIENT_LIMITS.timeoutMs`. */
  timeoutMs?: number;
  /** Replaceable in tests; default `verifyTimestampToken` (without a nonce: the relay chooses it). */
  verify?: (
    token: Uint8Array,
    hash: Uint8Array,
    anchors: TrustAnchors,
  ) => Promise<Result<VerifiedTimestamp>>;
}

/** A stamp the client has checked itself. */
export interface RelayStamp {
  serviceId: string;
  /** The DER token. */
  token: Uint8Array;
  /** Time and serial of the **verified** token (not the relay's claims). */
  genTime: string;
  serial: string;
  verified: VerifiedTimestamp;
}

/** The relay's answer to `POST /v1/stamp/<id>`, read strictly and **not yet verified**. */
export interface RelayAnswer {
  service: string;
  genTime: string;
  accuracyMs: number | null;
  serial: string;
  token: Uint8Array;
}

export interface RelayClient {
  /** The ids the relay offers, in its order. */
  services(): Promise<Result<string[]>>;
  /** Asks for a time stamp of a SHA-256 (32 bytes) and verifies the token before returning it. */
  stamp(sha256: Uint8Array): Promise<Result<RelayStamp>>;
  /** Milliseconds left of a pause after a 429 (0 when none). */
  pausedForMs(): number;
}

const SERVICE_ID = /^[a-z][a-z0-9-]{0,31}$/;
const SERIAL = /^[0-9a-f]+$/;

/** Reads `GET /v1/services` strictly: the ids in the relay's order, or `relay-bad-response`. */
export function parseServiceList(value: unknown): Result<string[]> {
  const bad = (detail: string) => fail('relay-bad-response', detail);
  if (typeof value !== 'object' || value === null) return bad('service list is not an object');
  const list = (value as Record<string, unknown>).services;
  if (!Array.isArray(list) || list.length > CLIENT_LIMITS.maxServices) {
    return bad('services missing or too long');
  }
  const ids: string[] = [];
  for (const entry of list) {
    const id = (entry as { id?: unknown } | null)?.id;
    if (typeof id !== 'string' || !SERVICE_ID.test(id)) return bad('service id');
    ids.push(id);
  }
  return ok(ids);
}

/**
 * Reads the answer to `POST /v1/stamp/<id>` strictly: exactly `service`, `genTime`, `accuracyMs` (whole
 * number or null), `serial` (lower-case hex) and `token` (Base64url of the DER token, within the limit).
 * Anything else is `relay-bad-response`, never a guess.
 */
export function parseRelayAnswer(value: unknown): Result<RelayAnswer> {
  const bad = (detail: string) => fail('relay-bad-response', detail);
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return bad('answer is not an object');
  }
  const o = value as Record<string, unknown>;
  if (Object.keys(o).sort().join(',') !== 'accuracyMs,genTime,serial,service,token') {
    return bad('unexpected fields');
  }
  if (typeof o.service !== 'string' || !SERVICE_ID.test(o.service)) return bad('service');
  if (typeof o.genTime !== 'string' || Number.isNaN(Date.parse(o.genTime))) return bad('genTime');
  if (o.accuracyMs !== null && !(Number.isInteger(o.accuracyMs) && (o.accuracyMs as number) >= 0)) {
    return bad('accuracyMs');
  }
  if (
    typeof o.serial !== 'string' ||
    !SERIAL.test(o.serial) ||
    o.serial.length > CLIENT_LIMITS.maxSerialChars
  ) {
    return bad('serial');
  }
  if (typeof o.token !== 'string' || o.token.length > CLIENT_LIMITS.maxTokenChars) {
    return bad('token');
  }
  const token = o.token.length === 0 ? null : fromBase64Url(o.token);
  if (!token) return bad('token');
  return ok({
    service: o.service,
    genTime: o.genTime,
    accuracyMs: o.accuracyMs as number | null,
    serial: o.serial,
    token,
  });
}

type Reply =
  | { kind: 'reply'; status: number; headers: FetchResponse['headers']; body: unknown }
  | { kind: 'failed'; timedOut: boolean; detail: string };

/** Creates a client for one relay. See `docs/relay.md` ("Der Client der Bibliothek"). */
export function createRelayClient(options: RelayClientOptions): RelayClient {
  const send = options.fetch;
  const now = options.now;
  const timeoutMs = options.timeoutMs ?? CLIENT_LIMITS.timeoutMs;
  const verify =
    options.verify ?? ((token, hash, anchors) => verifyTimestampToken(token, hash, anchors));
  const root = options.relay.replace(/\/+$/, '');
  let blockedUntil = -Infinity;

  async function call(
    path: string,
    init: Pick<FetchInit, 'method' | 'headers' | 'body'>,
  ): Promise<Reply> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await send(`${root}${path}`, {
        ...init,
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        cache: 'no-store',
        redirect: 'error',
        signal: controller.signal,
      });
      let body: unknown = null;
      try {
        body = await response.json();
      } catch {
        // an error answer need not be JSON; a good one is checked below
      }
      return { kind: 'reply', status: response.status, headers: response.headers, body };
    } catch (error) {
      const timedOut = controller.signal.aborted;
      return {
        kind: 'failed',
        timedOut,
        detail: timedOut ? 'timeout' : error instanceof Error ? error.message : String(error),
      };
    } finally {
      clearTimeout(timer);
    }
  }

  const errorCode = (body: unknown): string => {
    const code = (body as { error?: unknown } | null)?.error;
    return typeof code === 'string' && /^[a-z-]{1,40}$/.test(code) ? `, ${code}` : '';
  };
  const unreachable = (r: Extract<Reply, { kind: 'failed' }>): Failure =>
    fail(r.timedOut ? 'relay-timeout' : 'relay-unreachable', r.detail);

  /** Seconds of a `Retry-After` header: whole seconds or (with `wallNow`) an HTTP date; else the default. */
  function retrySeconds(header: string | null): number {
    const max = CLIENT_LIMITS.maxRetrySeconds;
    const text = (header ?? '').trim();
    if (/^[0-9]+$/.test(text)) {
      const asked = Number(text);
      if (Number.isSafeInteger(asked) && asked > 0) return Math.min(asked, max);
    } else if (options.wallNow && text !== '' && !/^-?[0-9.]+$/.test(text)) {
      const at = Date.parse(text);
      if (!Number.isNaN(at)) {
        const seconds = Math.ceil((at - options.wallNow()) / 1000);
        if (seconds > 0) return Math.min(seconds, max);
      }
    }
    return CLIENT_LIMITS.defaultRetrySeconds;
  }

  /** A 429: set the pause and answer `relay-rate-limited` (one place for both calls). */
  function rateLimited(headers: FetchResponse['headers']): Failure {
    const seconds = retrySeconds(headers.get('Retry-After'));
    blockedUntil = now() + seconds * 1000;
    return fail('relay-rate-limited', `retry in ${seconds} s`);
  }

  function pausedForMs(): number {
    // a pause longer than the longest one ever set means the clock went back: forget it
    if (blockedUntil - now() > CLIENT_LIMITS.maxRetrySeconds * 1000) blockedUntil = -Infinity;
    return Math.max(0, blockedUntil - now());
  }

  async function services(): Promise<Result<string[]>> {
    const r = await call('/v1/services', { method: 'GET' });
    if (r.kind === 'failed') return unreachable(r);
    if (r.status === 429) return rateLimited(r.headers);
    if (r.status !== 200) return fail('relay-refused', `status ${r.status}${errorCode(r.body)}`);
    return parseServiceList(r.body);
  }

  async function stamp(sha256: Uint8Array): Promise<Result<RelayStamp>> {
    if (!(sha256 instanceof Uint8Array) || sha256.length !== 32) {
      return fail('bad-hash', 'a SHA-256 has 32 bytes');
    }
    const wait = pausedForMs();
    if (wait > 0) {
      return fail('relay-rate-limited', `retry in ${Math.ceil(wait / 1000)} s`);
    }
    const listed = await services();
    if (!listed.ok) return listed;
    const known = listed.value.filter((id) => options.trusted.has(id));
    if (known.length === 0) {
      return fail('no-trusted-service', "none of the relay's services is trusted by the caller");
    }
    let last: Failure = fail('relay-unreachable', 'no service');
    for (const id of known.slice(0, CLIENT_LIMITS.maxServicesTried)) {
      const r = await call(`/v1/stamp/${id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash: toBase64Url(sha256) }),
      });
      if (r.kind === 'failed') {
        last = unreachable(r);
        continue; // this service could not be reached: the next one may
      }
      if (r.status === 429) return rateLimited(r.headers);
      if (r.status === 502 || r.status === 504) {
        last = fail('relay-unreachable', `status ${r.status}${errorCode(r.body)}`);
        continue; // this service did not answer: the next one may
      }
      if (r.status !== 200) return fail('relay-refused', `status ${r.status}${errorCode(r.body)}`);
      const answer = parseRelayAnswer(r.body);
      if (!answer.ok) return answer;
      if (answer.value.service !== id) {
        return fail('relay-bad-response', 'another service id than asked for');
      }
      let verified: Result<VerifiedTimestamp>;
      try {
        verified = await verify(answer.value.token, sha256, options.trusted.get(id) ?? []);
      } catch (error) {
        return fail('malformed', error instanceof Error ? error.message : String(error));
      }
      if (!verified.ok) return verified;
      if (verified.value.serial !== answer.value.serial) {
        return fail('relay-bad-response', 'serial differs from the token');
      }
      return ok({
        serviceId: id,
        token: answer.value.token,
        genTime: verified.value.genTime,
        serial: verified.value.serial,
        verified: verified.value,
      });
    }
    return last;
  }

  return { services, stamp, pausedForMs };
}
