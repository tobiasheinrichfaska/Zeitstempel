import {
  createHash,
  generateKeyPairSync,
  verify as verifySignatureNode,
  type KeyObject,
} from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import {
  buildTimestampRequest,
  fromBase64Url,
  readTimestampResponse,
  toBase64Url,
  verifyTimestampToken,
  type Service,
  type VerifiedTimestamp,
} from '../src/index.ts';
import { buildBatch } from './batch.ts';
import { publicKeyObject, type RelayKey } from './keys.ts';
import { RELAY_LIMITS } from './limits.ts';
import { UpstreamError, type Upstream } from './upstream.ts';

/** A service together with its trust anchors (PEM text), as the relay needs it. */
export interface RelayService extends Service {
  anchorPems: string[];
}

export interface RelayOptions {
  services: readonly RelayService[];
  /** Origins that may call from a browser, exactly as sent (`https://app.example`). */
  origins: readonly string[];
  /** Services whose address is plain http are refused unless this is true. */
  allowPlainHttp: boolean;
  upstream: Upstream;
  /** Random bytes (nonce); a parameter so tests are deterministic. */
  random: (n: number) => Uint8Array;
  /** Milliseconds since the epoch. */
  now: () => number;
  /**
   * Who may stamp: the accepted keys (id and public key), or `'off'` to accept unsigned requests
   * (local development only; there is no default, so it cannot be forgotten).
   */
  keys: readonly RelayKey[] | 'off';
  /** Size of the replay cache (default `RELAY_LIMITS.authReplayEntries`); a parameter for tests. */
  authReplayEntries?: number;
  /** The ECDSA check (default `node:crypto` verify); a parameter so a test can count the verifications. */
  verifySignature?: typeof verifySignatureNode;
  /**
   * Collecting operation (docs/relay.md, "Sammelbetrieb"): requests for one service are collected for
   * `windowMs` (or until `max` are waiting), their hashes become the leaves of a Merkle tree and the service
   * stamps the one value that covers the tree. Absent: every request gets a stamp of its own (the default).
   */
  batch?: { windowMs: number; max: number };
}

/** A parsed `X-Zeitstempel-Auth` header whose form and time are fine; the signature is not yet checked. */
interface Auth {
  kid: string;
  ts: number;
  signature: Uint8Array;
}

/** Counters only: no address, no hash, no token ever leaves a request. */
export interface RelayStats {
  /** Stamps obtained from a service (in collecting operation: one per window). */
  stamped: number;
  refused: Record<string, number>;
  /** Only in collecting operation: requests answered with a receipt (a sum, nothing about who or what). */
  batched?: number;
}

const JSON_TYPE = 'application/json';
/** Response headers a browser page may read: Retry-After (429) and Date (the relay's clock, for a 401 from clock skew). */
const EXPOSED_HEADERS = 'Retry-After, Date';
const AUTH_FORM = /^v2\.([a-z][a-z0-9-]{0,31})\.(0|[1-9][0-9]{0,11})\.([A-Za-z0-9_-]{86})$/;
const AUTH_PREFIX = 'zeitstempel-auth-v2';
const STAMP_PATH = /^\/v1\/stamp\/([a-z][a-z0-9-]{0,31})$/;

export interface Relay {
  handle: (req: IncomingMessage, res: ServerResponse) => void;
  /**
   * The server ended this connection because the request did not arrive in time (Node's 408): counted as
   * `request-timeout`, and the request in flight on it is then not counted as `client-aborted`.
   */
  requestTimedOut: (socket: Duplex) => void;
  stats: () => RelayStats;
  /**
   * Ends collecting operation: the requests that wait in an open window are answered with `503
   * shutting-down`, no timer is left, and new requests get the same answer. A window whose call to the
   * service is already running finishes normally (bounded by `upstreamTimeoutMs`). Does nothing for single stamps.
   */
  close: () => void;
}

export function createRelay(options: RelayOptions): Relay {
  const usable = options.services.filter(
    (s) => options.allowPlainHttp || new URL(s.url).protocol === 'https:',
  );
  const byId = new Map(usable.map((s) => [s.id, s]));
  const batch = options.batch;
  if (
    batch !== undefined &&
    !(
      Number.isInteger(batch.windowMs) &&
      batch.windowMs >= 1 &&
      Number.isInteger(batch.max) &&
      batch.max >= 2 &&
      batch.max <= RELAY_LIMITS.batchMaxMax
    )
  ) {
    throw new Error('relay batch settings are invalid'); // at start, no content
  }
  const stats: RelayStats = { stamped: 0, refused: {}, ...(batch ? { batched: 0 } : {}) };
  const timedOut = new WeakSet<Duplex>(); // connections the server itself ended for being too slow
  const windows = new Map<string, number[]>(); // service id → request times in the window
  const keyWindows = new Map<string, number[]>(); // key id → request times in the window (memory only)
  let total: number[] = [];
  const keyById = new Map<string, KeyObject>();
  if (options.keys !== 'off') {
    for (const k of options.keys) {
      const key = publicKeyObject(k.publicKey);
      if (key === null) throw new Error('relay key is not a valid P-256 public key'); // at start, no content
      if (keyById.has(k.id)) throw new Error('relay key ids must be unique'); // at start, no content
      keyById.set(k.id, key);
    }
  }
  const authRequired = options.keys !== 'off';
  const doVerify = options.verifySignature ?? verifySignatureNode;
  // Heads signed before this process started are refused (the replay cache is empty after a restart,
  // so an old head could otherwise be replayed once more within its window).
  // Only ever lowered (on every request, see parseAuth), never recomputed upwards: a start clock that ran
  // ahead and is corrected later drops it once to the first corrected time.
  let startMs = options.now();
  if (!Number.isFinite(startMs)) throw new Error('relay clock is not finite at start'); // at start, no content
  // A key nobody holds: an unknown id still gets the same verification (against this random key made
  // for the process, whose private half is dropped at once), so the answer tells nothing. `verified`
  // also insists on a known id.
  const dummyKey: KeyObject | null = authRequired
    ? generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey
    : null;
  // A signed request is remembered by the digest of its signed message (with the key id), NOT by the
  // signature: ECDSA is malleable (for a valid (r, s) the pair (r, n - s) is valid for the same message),
  // so a cache on signatures would let the twin pass as new. Value: the time (ms) until which a replay
  // could still pass the window, and the key id it belongs to.
  const replay = new Map<string, { until: number; kid: string }>();
  const replayMax = options.authReplayEntries ?? RELAY_LIMITS.authReplayEntries;
  const replayMaxPerKey = Math.max(1, Math.ceil(replayMax * RELAY_LIMITS.authReplayKeyShare));
  const windowMs = RELAY_LIMITS.authWindowSeconds * 1000;
  // A replay can arrive with its head at the edge of the window and its body up to the request
  // timeout later: an entry must outlive `ts + window` by that much.
  const keepMs = windowMs + RELAY_LIMITS.requestTimeoutMs;
  const inWindow = (ts: number): boolean => Math.abs(options.now() - ts * 1000) <= windowMs;

  function countOnce(kind: string): void {
    stats.refused[kind] = (stats.refused[kind] ?? 0) + 1;
  }

  function send(
    res: ServerResponse,
    status: number,
    body: unknown,
    origin: string | null,
    extra: Record<string, string> = {},
  ): void {
    const text = JSON.stringify(body);
    if (status >= 400) {
      const kind = (body as { error?: string }).error ?? 'error';
      stats.refused[kind] = (stats.refused[kind] ?? 0) + 1;
    }
    res.writeHead(status, {
      'Content-Type': `${JSON_TYPE}; charset=utf-8`,
      'Content-Length': String(Buffer.byteLength(text)),
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...(origin
        ? {
            'Access-Control-Allow-Origin': origin,
            // Without this a browser hides Retry-After and Date (the relay's clock, which the app reads to
            // correct its own after a 401) from the page's script.
            'Access-Control-Expose-Headers': EXPOSED_HEADERS,
            Vary: 'Origin',
          }
        : { Vary: 'Origin' }),
      ...extra,
    });
    res.end(text);
  }

  /**
   * Looks at the budget (total, per service, and per key when there is one) WITHOUT spending it: the
   * seconds to wait when any limit is reached (the longest of all that apply, so a client that waits
   * that long is not refused by another limit), and `spend` to count the request once it is served.
   */
  function budget(
    serviceId: string,
    minIntervalMs: number,
    kid: string | null,
    /** false: the request joins a window that is open already, the service's own budget is not touched */
    forService = true,
  ): { wait: number | null; spend: () => void } {
    const now = options.now();
    // Times in the future (the clock was set back) count as `now`: a jump back must not lock the budget
    // for the length of the jump, and the wait stays within one window.
    const fresh = (times: number[]): number[] =>
      times.filter((t) => now - t < RELAY_LIMITS.windowMs).map((t) => Math.min(t, now));
    total = fresh(total);
    const own = fresh(windows.get(serviceId) ?? []);
    const mine = kid === null ? [] : fresh(keyWindows.get(kid) ?? []);
    windows.set(serviceId, own);
    if (kid !== null) keyWindows.set(kid, mine);
    const ownLimit = Math.max(1, Math.floor(RELAY_LIMITS.windowMs / minIntervalMs));
    // the slot that frees first is the (length - limit + 1)-th oldest entry
    const until = (times: number[], limit: number): number =>
      Math.max(1, Math.ceil((RELAY_LIMITS.windowMs - (now - times[times.length - limit]!)) / 1000));
    const waits: number[] = [];
    if (total.length >= RELAY_LIMITS.perMinuteTotal) {
      waits.push(until(total, RELAY_LIMITS.perMinuteTotal));
    }
    if (forService && own.length >= ownLimit) waits.push(until(own, ownLimit));
    if (kid !== null && mine.length >= RELAY_LIMITS.perMinutePerKey) {
      waits.push(until(mine, RELAY_LIMITS.perMinutePerKey));
    }
    return {
      wait: waits.length === 0 ? null : Math.max(...waits),
      spend: () => {
        total.push(now);
        if (forService) own.push(now);
        if (kid !== null) mine.push(now);
      },
    };
  }

  /** Form and time of the auth header, before the body is read; null for anything wrong. */
  function parseAuth(req: IncomingMessage): Auth | null {
    const seenMs = options.now();
    // never up: a clock jump back lowers it for good; a reading that is not finite (NaN, -Infinity) is
    // no time and must not poison it
    if (Number.isFinite(seenMs)) startMs = Math.min(startMs, seenMs);
    const value = req.headers['x-zeitstempel-auth'];
    if (typeof value !== 'string') return null;
    const m = AUTH_FORM.exec(value);
    if (!m) return null;
    const signature = fromBase64Url(m[3]!);
    if (!signature || signature.length !== 64) return null;
    const ts = Number(m[2]);
    if (!inWindow(ts)) return null;
    // Signed before this process started (`startMs` is the lowest clock value seen so far).
    if (ts * 1000 < startMs - 1000) return null;
    return { kid: m[1]!, ts, signature };
  }

  /**
   * Checks the ECDSA signature over method, path, time and body (same work for an unknown id: it is
   * checked against the dummy key). Returns the cache id of the signed message, or null when refused.
   */
  function checkSignature(
    auth: Auth,
    method: string,
    path: string,
    body: Uint8Array,
  ): string | null {
    const key = keyById.get(auth.kid);
    const message = `${AUTH_PREFIX}\n${method}\n${path}\n${auth.ts}\n${createHash('sha256').update(body).digest('hex')}`;
    let valid: boolean;
    try {
      valid = doVerify(
        'sha256',
        Buffer.from(message),
        { key: key ?? dummyKey!, dsaEncoding: 'ieee-p1363' },
        auth.signature,
      );
    } catch {
      valid = false;
    }
    // Always exactly one verification, known id or not; the id decides only afterwards.
    if (!(valid && key !== undefined)) return null;
    return `${auth.kid}:${createHash('sha256').update(message).digest('hex')}`;
  }

  /** Read only: has a request with this signed message been admitted before (and not yet expired)? */
  function seen(id: string): boolean {
    const entry = replay.get(id);
    return entry !== undefined && entry.until >= options.now();
  }

  /**
   * Read only: the seconds to wait when the cache cannot take another entry of this key (it is full, or
   * the key holds its share already: one key cannot lock out the others), else null. The longest of the
   * two applies. Nothing is written, so a refusal here costs nothing; `remember` cannot fail afterwards.
   */
  function cacheWait(kid: string): number | null {
    const now = options.now();
    let soonest = Infinity;
    let soonestOwn = Infinity;
    let own = 0;
    for (const [id, entry] of replay) {
      if (entry.until < now) {
        replay.delete(id);
        continue;
      }
      // An entry never lives longer than `keepMs` past the newest head the window lets in; a longer
      // remainder means the clock was set back, and the wait stays within that bound.
      const until = Math.min(entry.until, now + windowMs + keepMs);
      soonest = Math.min(soonest, until);
      if (entry.kid === kid) {
        own += 1;
        soonestOwn = Math.min(soonestOwn, until);
      }
    }
    const waits: number[] = [];
    if (own >= replayMaxPerKey) waits.push(Math.max(1, Math.ceil((soonestOwn - now) / 1000)));
    if (replay.size >= replayMax) waits.push(Math.max(1, Math.ceil((soonest - now) / 1000)));
    return waits.length === 0 ? null : Math.max(...waits);
  }

  /** Writes a request down; only after `seen` said no and `cacheWait` said null, in the same step. */
  function remember(id: string, auth: Auth): void {
    replay.set(id, { until: auth.ts * 1000 + keepMs, kid: auth.kid });
  }

  /** The client went away while its body was coming: nobody is left to answer. */
  class ClientAborted extends Error {}

  async function readBody(req: IncomingMessage): Promise<Uint8Array | null> {
    const declared = req.headers['content-length'];
    if (declared !== undefined && Number(declared) > RELAY_LIMITS.bodyBytes) return null;
    const chunks: Buffer[] = [];
    let size = 0;
    try {
      for await (const chunk of req) {
        size += (chunk as Buffer).length;
        if (size > RELAY_LIMITS.bodyBytes) return null;
        chunks.push(chunk as Buffer);
      }
    } catch (e) {
      // the connection broke or the client aborted (ECONNRESET, 'aborted'): not an error of the relay
      if (req.destroyed || req.socket.destroyed) throw new ClientAborted();
      throw e;
    }
    return new Uint8Array(Buffer.concat(chunks));
  }

  /** The hash from the body: 32 raw bytes, or JSON `{"hash": "<base64url>"}`. */
  function hashFrom(type: string, body: Uint8Array): Uint8Array | 'unsupported' | 'bad' {
    if (type === 'application/octet-stream') return body.length === 32 ? body : 'bad';
    if (type !== JSON_TYPE) return 'unsupported';
    try {
      const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)) as unknown;
      if (typeof data !== 'object' || data === null || Array.isArray(data)) return 'bad';
      const keys = Object.keys(data);
      const hash = (data as { hash?: unknown }).hash;
      if (keys.length !== 1 || typeof hash !== 'string') return 'bad';
      const bytes = fromBase64Url(hash);
      return bytes && bytes.length === 32 ? bytes : 'bad';
    } catch {
      return 'bad';
    }
  }

  async function stamp(
    req: IncomingMessage,
    res: ServerResponse,
    service: RelayService,
    origin: string | null,
    auth: Auth | null,
    path: string,
  ): Promise<void> {
    const type = String(req.headers['content-type'] ?? '')
      .split(';')[0]!
      .trim()
      .toLowerCase();
    // No header, no stamp: decided here, in the one place that stamps, whatever the route did before.
    if (authRequired && !auth) return unauthorized(res, origin);
    const body = await readBody(req);
    if (!body) return send(res, 413, { error: 'too-large' }, origin, { Connection: 'close' });
    let signedId: string | null = null;
    if (auth) {
      // The window again: a slow body must not carry a head that was fresh when it arrived.
      if (!inWindow(auth.ts)) return unauthorized(res, origin);
      signedId = checkSignature(auth, req.method ?? '', path, body);
      if (signedId === null) return unauthorized(res, origin);
      // A replay dies here: before the Content-Type and the hash are looked at, and before the budget.
      if (seen(signedId)) return unauthorized(res, origin);
    }
    // The Content-Type is deliberately not part of the signature (the body is): it only selects how the
    // already authenticated bytes are read.
    const hash = hashFrom(type, body);
    if (hash === 'unsupported') return send(res, 415, { error: 'unsupported-media-type' }, origin);
    if (hash === 'bad') return send(res, 400, { error: 'bad-hash' }, origin);

    // Collecting operation: a window that is open already takes this request without touching the service's
    // budget (one stamp per window); the budget of a key and the total still count every request.
    if (batch && closed) return send(res, 503, { error: 'shutting-down' }, origin);
    const open = batch ? openWindows.get(service.id) : undefined;
    // Look at the budget and at the replay cache first, spend and write only if both let the request
    // pass: a 429 never costs budget and never leaves an entry. (No await between look and write.)
    const budgetNow = budget(
      service.id,
      service.minIntervalMs,
      auth?.kid ?? null,
      open === undefined,
    );
    const cache = auth ? cacheWait(auth.kid) : null;
    const waits = [budgetNow.wait, cache].filter((w): w is number => w !== null);
    if (waits.length > 0) {
      return send(res, 429, { error: 'rate-limited' }, origin, {
        'Retry-After': String(Math.max(...waits)),
      });
    }
    budgetNow.spend();
    if (auth && signedId !== null) remember(signedId, auth);

    if (batch) {
      // The answer comes when the window is closed and the service has answered (the 5 s request deadline
      // is over by now: it only governs the reading of the request).
      const reply = await join(service, hash, open);
      if (res.destroyed) return countAborted(req, res);
      return send(res, reply.status, reply.body, origin);
    }
    const got = await obtain(service, hash);
    if (!got.ok) return send(res, got.status, got.body, origin);
    stats.stamped += 1;
    return send(res, 200, stampBody(service, got), origin);
  }

  /** What a stamp obtained from a service tells the caller (the fields of the 200 answer, without `batch`). */
  function stampBody(service: RelayService, got: Obtained & { ok: true }) {
    return {
      service: service.id,
      genTime: got.verified.genTime,
      accuracyMs: got.verified.accuracyMs,
      serial: got.verified.serial,
      token: toBase64Url(got.token),
    };
  }

  type Obtained =
    | { ok: true; token: Uint8Array; verified: VerifiedTimestamp }
    | { ok: false; status: number; body: { error: string; reason?: string } };

  /**
   * One stamp from a service for `hash`: builds the request with a nonce of the relay, calls the one address of
   * the service, reads and checks the answer (hash, nonce, signature, chain, and a time around the moment of
   * the request). The same for a single request and for the imprint of a batch.
   */
  async function obtain(service: RelayService, hash: Uint8Array): Promise<Obtained> {
    const nonce = options.random(8);
    const request = buildTimestampRequest(hash, nonce);
    if (!request.ok) return { ok: false, status: 500, body: { error: 'internal' } };
    const sentMs = options.now(); // the moment the request goes to the service: the token must not be older
    let answer;
    try {
      answer = await options.upstream(service, request.value);
    } catch (e) {
      const kind = e instanceof UpstreamError ? e.kind : 'failed';
      return {
        ok: false,
        status: kind === 'timeout' ? 504 : 502,
        body: { error: `upstream-${kind}` },
      };
    }
    if (answer.status !== 200 || answer.contentType !== 'application/timestamp-reply') {
      return { ok: false, status: 502, body: { error: 'upstream-refused' } };
    }
    const response = readTimestampResponse(answer.body);
    if (!response.ok) {
      return {
        ok: false,
        status: 502,
        body: { error: 'upstream-invalid', reason: response.reason },
      };
    }
    // The time of the token must lie around the moment of the request: not ahead of the relay's clock and not
    // older than the request (both within `genTimeSlackMs`). Without the lower bound a service key that has
    // expired or leaked could hand out back-dated tokens that still verify.
    const verified = await verifyTimestampToken(response.value.token, hash, service.anchorPems, {
      expectedNonce: nonce,
      now: new Date(options.now()),
      maxSkewMs: RELAY_LIMITS.genTimeSlackMs,
      minGenTime: new Date(sentMs - RELAY_LIMITS.genTimeSlackMs),
    });
    if (!verified.ok) {
      // a cause of its own in the counters (a service that back-dates is an alarm, not a client error)
      if (verified.reason === 'time-too-old') countOnce('upstream-too-old');
      return {
        ok: false,
        status: 502,
        body: { error: 'upstream-invalid', reason: verified.reason },
      };
    }
    return { ok: true, token: response.value.token, verified: verified.value };
  }

  // ---- Collecting operation ----

  interface Reply {
    status: number;
    body: unknown;
  }
  interface Waiting {
    hash: Uint8Array;
    resolve: (reply: Reply) => void;
  }
  interface Window {
    service: RelayService;
    waiting: Waiting[];
    timer: ReturnType<typeof setTimeout> | null;
  }
  const openWindows = new Map<string, Window>(); // service id -> the window that takes requests
  let closed = false;

  /** Puts a request into the open window of its service, or opens one (the timer starts with the first). */
  function join(
    service: RelayService,
    hash: Uint8Array,
    existing: Window | undefined,
  ): Promise<Reply> {
    return new Promise((resolve) => {
      let w = existing;
      if (w === undefined) {
        const created: Window = { service, waiting: [], timer: null };
        created.timer = setTimeout(() => closeWindow(created), batch!.windowMs);
        openWindows.set(service.id, created);
        w = created;
      }
      w.waiting.push({ hash, resolve });
      if (w.waiting.length >= batch!.max) closeWindow(w); // full: the next request opens a new window
    });
  }

  const answerAll = (waiting: readonly Waiting[], reply: Reply): void => {
    for (const w of waiting) w.resolve(reply);
  };

  function closeWindow(w: Window): void {
    if (openWindows.get(w.service.id) !== w) return; // closed already (timer and full window meet)
    openWindows.delete(w.service.id);
    if (w.timer !== null) clearTimeout(w.timer);
    flush(w).catch(() => answerAll(w.waiting, { status: 500, body: { error: 'internal' } }));
  }

  /** An integer 0 <= x < m from the relay's random source, without bias (rejection sampling). */
  function randomBelow(m: number): number {
    const limit = Math.floor(0x1_0000_0000 / m) * m;
    for (let attempt = 0; attempt < 64; attempt += 1) {
      const b = options.random(4);
      if (b.length !== 4) throw new Error('random source gave the wrong length');
      const v = ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
      if (v < limit) return v % m;
    }
    throw new Error('random source does not spread');
  }

  /** The tree order: a Fisher-Yates shuffle, so the order of the leaves tells nothing about the order of arrival. */
  function shuffled(n: number): number[] {
    const order = Array.from({ length: n }, (_, i) => i);
    for (let i = n - 1; i > 0; i -= 1) {
      const j = randomBelow(i + 1);
      [order[i], order[j]] = [order[j]!, order[i]!];
    }
    return order;
  }

  /** One window: salts, tree, one stamp for the imprint, and a receipt for each waiting request. */
  async function flush(w: Window): Promise<void> {
    const waiting = w.waiting;
    const entries = waiting.map((x) => {
      const salt = options.random(32);
      if (salt.length !== 32) throw new Error('random source gave the wrong length');
      return { hash: x.hash, salt: new Uint8Array(salt) };
    });
    const built = buildBatch(entries, shuffled(waiting.length));
    const got = await obtain(w.service, new Uint8Array(built.imprint));
    if (!got.ok) return answerAll(waiting, { status: got.status, body: got.body });
    stats.stamped += 1;
    stats.batched = (stats.batched ?? 0) + waiting.length;
    const base = stampBody(w.service, got);
    waiting.forEach((x, i) => {
      const proof = built.proofs[i]!;
      x.resolve({
        status: 200,
        body: {
          ...base,
          batch: {
            v: 1,
            size: proof.size,
            index: proof.index,
            salt: toBase64Url(entries[i]!.salt),
            path: proof.path.map((node) => toBase64Url(new Uint8Array(node))),
          },
        },
      });
    });
  }

  function close(): void {
    closed = true;
    for (const w of [...openWindows.values()]) {
      openWindows.delete(w.service.id);
      if (w.timer !== null) clearTimeout(w.timer);
      answerAll(w.waiting, { status: 503, body: { error: 'shutting-down' } });
    }
  }

  /** One answer for every authentication failure: nothing says whether id, time or signature was wrong. */
  function unauthorized(res: ServerResponse, origin: string | null): void {
    send(res, 401, { error: 'unauthorized' }, origin);
  }

  /** The connection is gone: counted, not answered (there is nobody to answer), and not an `internal`. */
  function countAborted(req: IncomingMessage, res: ServerResponse): void {
    // the server ended it for being too slow: already counted as `request-timeout`, not a client's doing
    if (!timedOut.has(req.socket)) {
      stats.refused['client-aborted'] = (stats.refused['client-aborted'] ?? 0) + 1;
    }
    try {
      res.destroy();
    } catch {
      // nothing left to close
    }
  }

  /** Last resort: a 500 with a code and no details. Never throws, so it cannot end the process. */
  function answerInternal(res: ServerResponse, echo: string | null): void {
    try {
      if (!res.headersSent) send(res, 500, { error: 'internal' }, echo);
      else res.end();
    } catch {
      res.destroy();
    }
  }

  function handle(req: IncomingMessage, res: ServerResponse): void {
    const sent = req.headers.origin;
    const origin = typeof sent === 'string' ? sent : null;
    const echo = origin !== null && options.origins.includes(origin) ? origin : null;
    try {
      route(req, res, origin, echo);
    } catch {
      answerInternal(res, echo);
    }
  }

  function route(
    req: IncomingMessage,
    res: ServerResponse,
    origin: string | null,
    echo: string | null,
  ): void {
    if (origin !== null && echo === null) {
      return send(res, 403, { error: 'origin-not-allowed' }, null);
    }
    let url: URL;
    try {
      url = new URL(req.url ?? '/', 'http://relay.invalid');
    } catch {
      // e.g. `//`, `//[`: a target that is no address at all
      return send(res, 400, { error: 'bad-request' }, echo);
    }
    if (url.search !== '') return send(res, 400, { error: 'no-query' }, echo);
    // The signature binds the path literally: the raw target must be the canonical path (no `./`, `..`,
    // backslash, absolute form, empty query `?`), so what is signed is what is routed.
    if (req.url !== url.pathname) return send(res, 400, { error: 'bad-request' }, echo);

    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Methods': 'GET, POST',
        'Access-Control-Allow-Headers': 'Content-Type, X-Zeitstempel-Auth',
        'Access-Control-Max-Age': '600',
        ...(echo
          ? {
              'Access-Control-Allow-Origin': echo,
              'Access-Control-Expose-Headers': EXPOSED_HEADERS,
            }
          : {}),
        Vary: 'Origin',
      });
      return void res.end();
    }
    if (url.pathname === '/health' && req.method === 'GET') {
      return send(res, 200, { ok: true, services: [...byId.keys()] }, echo);
    }
    if (url.pathname === '/v1/services' && req.method === 'GET') {
      return send(
        res,
        200,
        {
          services: usable.map((s) => ({
            id: s.id,
            name: s.name,
            qualified: s.qualified,
            intendedUse: s.intendedUse,
          })),
        },
        echo,
      );
    }
    const m = STAMP_PATH.exec(url.pathname);
    if (m) {
      if (req.method !== 'POST')
        return send(res, 405, { error: 'method-not-allowed' }, echo, { Allow: 'POST' });
      // 404 and 405 can come before the signature check; they tell only public things (which services exist).
      const service = byId.get(m[1]!);
      if (!service) return send(res, 404, { error: 'unknown-service' }, echo);
      const auth = authRequired ? parseAuth(req) : null;
      stamp(req, res, service, echo, auth, url.pathname).catch((e: unknown) => {
        if (e instanceof ClientAborted) return countAborted(req, res);
        answerInternal(res, echo);
      });
      return;
    }
    return send(res, 404, { error: 'not-found' }, echo);
  }

  function requestTimedOut(socket: Duplex): void {
    timedOut.add(socket);
    stats.refused['request-timeout'] = (stats.refused['request-timeout'] ?? 0) + 1;
  }

  return {
    handle,
    requestTimedOut,
    stats: () => ({
      stamped: stats.stamped,
      refused: { ...stats.refused },
      ...(batch ? { batched: stats.batched ?? 0 } : {}),
    }),
    close,
  };
}
