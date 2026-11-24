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
import {
  credentialIdentity,
  credentialsFromClient,
  validCredentials,
  type UpstreamCredentials,
} from './credentials.ts';
import { isAuthHeaderName } from '../src/lib/services.ts';
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
  /**
   * Collecting operation only: the longest a request waits for a free slot of its service before it gets `503
   * busy` (default `RELAY_LIMITS.maxWaitDefaultMs`). A slot that is not free within this time is a `429` at once.
   */
  maxWaitMs?: number;
  /** Window of the budget counters in ms (default `RELAY_LIMITS.windowMs`); a parameter so a test need not wait a minute. */
  budgetWindowMs?: number;
  /**
   * Credentials the relay holds itself, by service id (read from its environment by `main.ts`; memory only). Allowed
   * only for a service whose `auth.source` is `relay` or `either`; a service with `source: 'relay'` must have them.
   */
  upstreamAuth?: ReadonlyMap<string, UpstreamCredentials>;
  /** Identities (credentials of the app) known at once per service (default `RELAY_LIMITS.upstreamIdentitiesMax`); a parameter for tests. */
  upstreamIdentities?: number;
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
  /** Solo stamps obtained (collecting operation); present once the first one was counted. */
  solo?: number;
  /** Solo requests of a key of type 1 refused with `403 solo-not-allowed`; present once counted. */
  soloDenied?: number;
  /** Key file reloads applied / refused (invalid file, old set kept); present once counted. */
  keyReloads?: number;
  keyReloadFailed?: number;
}

const JSON_TYPE = 'application/json';
/** Response headers a browser page may read: Retry-After (429) and Date (the relay's clock, for a 401 from clock skew). */
const EXPOSED_HEADERS = 'Retry-After, Date';
const AUTH_FORM = /^v2\.([a-z][a-z0-9-]{0,31})\.(0|[1-9][0-9]{0,11})\.([A-Za-z0-9_-]{86})$/;
const AUTH_PREFIX = 'zeitstempel-auth-v2';
/** The member sets of a JSON body (sorted, joined by a comma): `hash`, plus `mode` and `upstream` when given. */
const BODY_KEYS = ['hash', 'hash,mode', 'hash,upstream', 'hash,mode,upstream'];
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
  /**
   * Replaces the accepted keys at once (the key file was reloaded): keys that are gone are invalid from now on,
   * counters and the replay cache stay. Throws, and changes nothing, when a key is invalid or an id is
   * used twice, or when the relay runs without authentication.
   */
  setKeys: (keys: readonly RelayKey[]) => void;
  /** Counts a reload of the key file: applied (`true`) or refused (`false`). */
  noteKeyReload: (applied: boolean) => void;
}

export function createRelay(options: RelayOptions): Relay {
  const usable = options.services.filter(
    (s) => options.allowPlainHttp || new URL(s.url).protocol === 'https:',
  );
  const byId = new Map(usable.map((s) => [s.id, s]));
  // Paid services: checked again here (the file reader checked them once): https only, a sound header name, and the
  // credentials of the relay present exactly where the service says the relay holds them. Throws at start, no content.
  const relayCredentials = new Map<string, UpstreamCredentials>();
  for (const s of usable) {
    const a = s.auth ?? { kind: 'none' as const };
    const given = options.upstreamAuth?.get(s.id);
    if (a.kind === 'none') {
      if (given !== undefined) throw new Error(`relay: ${s.id} takes no credentials`);
      continue;
    }
    if (new URL(s.url).protocol !== 'https:')
      throw new Error(`relay: ${s.id} wants credentials but is not https`);
    if (a.kind === 'header' && !isAuthHeaderName(a.header))
      throw new Error(`relay: ${s.id} has a bad header name`);
    if (a.source === 'client' && given !== undefined) {
      throw new Error(`relay: ${s.id} takes its credentials from the client only`);
    }
    if (given === undefined) {
      if (a.source === 'relay') throw new Error(`relay: ${s.id} has no credentials of the relay`);
      continue;
    }
    if (
      given.kind !== a.kind ||
      (given.kind === 'header' && a.kind === 'header' && given.header !== a.header) ||
      !validCredentials(given)
    ) {
      throw new Error(`relay: the credentials of ${s.id} do not fit its auth`);
    }
    relayCredentials.set(s.id, { ...given });
  }
  for (const id of options.upstreamAuth?.keys() ?? []) {
    if (!byId.has(id))
      throw new Error(`relay: credentials for a service that is not offered: ${id}`);
  }
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
  // lane key (the service id; for credentials of the client `<id>#<digest>`) → times of the service's requests/slots in the window
  const windows = new Map<string, number[]>();
  const keyWindows = new Map<string, number[]>(); // key id → request times in the window (memory only)
  let total: number[] = [];
  const buildKeys = (keys: readonly RelayKey[]) => {
    const byId = new Map<string, KeyObject>();
    const solo = new Set<string>();
    for (const k of keys) {
      const key = publicKeyObject(k.publicKey);
      if (key === null) throw new Error('relay key is not a valid P-256 public key'); // no content
      if (byId.has(k.id)) throw new Error('relay key ids must be unique'); // no content
      byId.set(k.id, key);
      if (k.solo === true) solo.add(k.id);
    }
    return { byId, solo };
  };
  const initial = options.keys === 'off' ? buildKeys([]) : buildKeys(options.keys);
  let keyById = initial.byId; // replaced as a whole when the key file is reloaded
  let soloKids = initial.solo; // key type 2: may ask for a solo stamp
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
  const bw = options.budgetWindowMs ?? RELAY_LIMITS.windowMs;
  const maxWaitMs = options.maxWaitMs ?? RELAY_LIMITS.maxWaitDefaultMs;
  const soloWindows = new Map<string, number[]>(); // key id -> solo request times (memory only, never logged)
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
    laneKey: string,
    minIntervalMs: number,
    kid: string | null,
    /**
     * true: the service's own budget counts and is spent with the rest; false: the request joins a window that
     * is open already, the service's budget is not touched; 'defer': only the total and the key count here, the
     * slot of the service is taken later by the planner (`slotMs` says how long until one is free).
     */
    forService: boolean | 'defer' = true,
  ): { wait: number | null; slotMs: number; spend: () => void } {
    const now = options.now();
    // Times in the future (the clock was set back) count as `now`: a jump back must not lock the budget
    // for the length of the jump, and the wait stays within one window.
    const fresh = (times: number[]): number[] =>
      times.filter((t) => now - t < bw).map((t) => Math.min(t, now));
    total = fresh(total);
    const own = fresh(windows.get(laneKey) ?? []);
    const mine = kid === null ? [] : fresh(keyWindows.get(kid) ?? []);
    // an identity not known yet leaves nothing behind when the request is refused (written by `spend`)
    if (windows.has(laneKey)) windows.set(laneKey, own);
    if (kid !== null) keyWindows.set(kid, mine);
    const ownLimit = Math.max(1, Math.floor(bw / minIntervalMs));
    // the slot that frees first is the (length - limit + 1)-th oldest entry
    const until = (times: number[], limit: number): number =>
      Math.max(1, Math.ceil((bw - (now - times[times.length - limit]!)) / 1000));
    const waits: number[] = [];
    if (total.length >= RELAY_LIMITS.perMinuteTotal) {
      waits.push(until(total, RELAY_LIMITS.perMinuteTotal));
    }
    const slotMs =
      own.length >= ownLimit ? Math.max(1, bw - (now - own[own.length - ownLimit]!)) : 0;
    if (forService === true && own.length >= ownLimit) waits.push(until(own, ownLimit));
    if (kid !== null && mine.length >= RELAY_LIMITS.perMinutePerKey) {
      waits.push(until(mine, RELAY_LIMITS.perMinutePerKey));
    }
    return {
      wait: waits.length === 0 ? null : Math.max(...waits),
      slotMs,
      spend: () => {
        total.push(now);
        if (forService === true) {
          own.push(now);
          windows.set(laneKey, own);
        }
        if (kid !== null) mine.push(now);
      },
    };
  }

  /** The solo requests of one key in the last window: the seconds to wait when the limit is reached, and `spend`. Memory only. */
  function soloBudget(kid: string): { wait: number | null; spend: () => void } {
    const now = options.now();
    const times = (soloWindows.get(kid) ?? [])
      .filter((t) => now - t < bw)
      .map((t) => Math.min(t, now));
    soloWindows.set(kid, times);
    const limit = RELAY_LIMITS.soloPerMinutePerKey;
    return {
      wait:
        times.length >= limit
          ? Math.max(1, Math.ceil((bw - (now - times[times.length - limit]!)) / 1000))
          : null,
      spend: () => void times.push(now),
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

  /**
   * The hash from the body: 32 raw bytes, or JSON `{"hash": "<base64url>"}` with the optional field `"mode"`
   * (only `"solo"` is known; anything else is `bad-mode`). The mode is part of the body, so the signature binds it.
   */
  function hashFrom(
    type: string,
    body: Uint8Array,
  ):
    | { hash: Uint8Array; solo: boolean; upstream: unknown; hasUpstream: boolean }
    | 'unsupported'
    | 'bad'
    | 'bad-mode' {
    if (type === 'application/octet-stream') {
      return body.length === 32
        ? { hash: body, solo: false, upstream: undefined, hasUpstream: false }
        : 'bad';
    }
    if (type !== JSON_TYPE) return 'unsupported';
    try {
      const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)) as unknown;
      if (typeof data !== 'object' || data === null || Array.isArray(data)) return 'bad';
      const keys = Object.keys(data).sort().join();
      const hash = (data as { hash?: unknown }).hash;
      if (!BODY_KEYS.includes(keys) || typeof hash !== 'string') return 'bad';
      const bytes = fromBase64Url(hash);
      if (!bytes || bytes.length !== 32) return 'bad';
      const hasUpstream = keys.endsWith('upstream');
      const upstream = hasUpstream ? (data as { upstream?: unknown }).upstream : undefined;
      if (!keys.includes('mode')) return { hash: bytes, solo: false, upstream, hasUpstream };
      return (data as { mode?: unknown }).mode === 'solo'
        ? { hash: bytes, solo: true, upstream, hasUpstream }
        : 'bad-mode';
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
    const parsed = hashFrom(type, body);
    if (parsed === 'unsupported')
      return send(res, 415, { error: 'unsupported-media-type' }, origin);
    if (parsed === 'bad') return send(res, 400, { error: 'bad-hash' }, origin);
    if (parsed === 'bad-mode') return send(res, 400, { error: 'bad-mode' }, origin);
    const hash = parsed.hash;
    // The credentials of a paid service: from the client, from the relay, or `bad-upstream`. The identity (a digest,
    // memory only) keeps the windows, slots and budgets of different credentials apart.
    const wanted = credentialsFor(service, parsed.hasUpstream, parsed.upstream);
    if (wanted === 'bad-upstream') return send(res, 400, { error: 'bad-upstream' }, origin);
    const creds = wanted.creds;
    const tracked = wanted.identity !== null; // credentials of the client: each its own lane, limited in number
    const lk = tracked ? `${service.id}#${wanted.identity}` : service.id;

    // Without collecting operation every request is a direct stamp already: `mode: "solo"` changes nothing
    // and the key type is not looked at.
    const wantsSolo = batch !== undefined && parsed.solo;
    if (batch && closed) return send(res, 503, { error: 'shutting-down' }, origin);
    if (wantsSolo && !(auth !== null && soloKids.has(auth.kid)) && laneBusy(lk)) {
      // key type 1: a solo stamp only for a service nobody else waits for (a solo stamp takes a whole slot)
      stats.soloDenied = (stats.soloDenied ?? 0) + 1;
      return send(res, 403, { error: 'solo-not-allowed' }, origin);
    }
    // Collecting operation: a window that is open already takes this request without touching the service's
    // budget (one stamp per window); the budget of a key and the total still count every request.
    const open = batch ? openWindows.get(lk) : undefined;
    const joinsOpen = open !== undefined && !wantsSolo;
    // A new identity needs a place in the table of this service (dropped identities make room; else `503 busy`).
    if (tracked && !known.has(lk)) {
      const full = identitiesFullWait(service.id);
      if (full !== null)
        return send(res, 503, { error: 'busy' }, origin, { 'Retry-After': String(full) });
    }
    // Look at the budget and at the replay cache first, spend and write only if both let the request
    // pass: a 429 never costs budget and never leaves an entry. (No await between look and write.)
    const budgetNow = budget(
      lk,
      service.minIntervalMs,
      auth?.kid ?? null,
      batch ? (joinsOpen ? false : 'defer') : true,
    );
    const cache = auth ? cacheWait(auth.kid) : null;
    const soloNow = wantsSolo && auth ? soloBudget(auth.kid) : null;
    const waits = [budgetNow.wait, cache, soloNow?.wait ?? null].filter(
      (w): w is number => w !== null,
    );
    // The slot of the service is not free within the longest wait: the old 429 (waiting is for a short squeeze only)
    if (batch && !joinsOpen && budgetNow.slotMs > maxWaitMs) {
      waits.push(Math.max(1, Math.ceil(budgetNow.slotMs / 1000)));
    }
    if (waits.length > 0) {
      return send(res, 429, { error: 'rate-limited' }, origin, {
        'Retry-After': String(Math.max(...waits)),
      });
    }
    if (wantsSolo && (lanes.get(lk)?.solo.length ?? 0) >= RELAY_LIMITS.soloQueueMax) {
      return send(res, 503, { error: 'busy' }, origin, {
        'Retry-After': String(Math.max(1, Math.ceil(budgetNow.slotMs / 1000))),
      });
    }
    budgetNow.spend();
    soloNow?.spend();
    if (auth && signedId !== null) remember(signedId, auth);
    const entry = tracked ? touchIdentity(lk, service.id) : null;
    if (entry) entry.pending += 1;
    try {
      if (batch) {
        // The answer comes when the window is closed and the service has answered (the 5 s request deadline
        // is over by now: it only governs the reading of the request).
        const reply = joinsOpen
          ? await joinOpen(open, hash)
          : await enqueue(service, lk, creds, hash, wantsSolo);
        if (res.destroyed) return countAborted(req, res);
        return send(res, reply.status, reply.body, origin, reply.headers);
      }
      const got = await obtain(service, hash, creds);
      if (!got.ok) return send(res, got.status, got.body, origin);
      stats.stamped += 1;
      return send(res, 200, stampBody(service, got), origin);
    } finally {
      if (entry) {
        entry.pending -= 1;
        entry.lastMs = options.now(); // the identity lives a whole window after its last answer
      }
    }
  }

  // ---- Credentials of paid services ----

  /** The identities of the app known now: lane key -> service, last activity, requests in flight. Memory only, never output. */
  const identitiesMax = options.upstreamIdentities ?? RELAY_LIMITS.upstreamIdentitiesMax;
  const known = new Map<string, { serviceId: string; lastMs: number; pending: number }>();

  /**
   * What the request must send to the service: the credentials (or none) and the identity (null: the relay's own or
   * none, the lane of the service itself). `bad-upstream` for any mismatch with the service's `auth`: a value where none
   * is taken, none where the client must give one, a value that is not well formed.
   */
  function credentialsFor(
    service: RelayService,
    given: boolean,
    value: unknown,
  ): 'bad-upstream' | { creds: UpstreamCredentials | undefined; identity: string | null } {
    const a = service.auth ?? { kind: 'none' as const };
    if (a.kind === 'none' || a.source === 'relay') {
      return given ? 'bad-upstream' : { creds: relayCredentials.get(service.id), identity: null };
    }
    if (!given) {
      const own = relayCredentials.get(service.id);
      return a.source === 'either' && own !== undefined
        ? { creds: own, identity: null }
        : 'bad-upstream';
    }
    const mine = credentialsFromClient(a, value);
    return mine === null ? 'bad-upstream' : { creds: mine, identity: credentialIdentity(mine) };
  }

  /** Is an identity gone for good: idle for a whole window and nothing in flight? */
  const expired = (e: { lastMs: number; pending: number }, now: number): boolean =>
    e.pending === 0 && now - Math.min(e.lastMs, now) >= bw;

  /**
   * Drops the identities of a service that are expired, then: null when there is room for one more, else the seconds
   * until the first one expires (at least 1).
   */
  function identitiesFullWait(serviceId: string): number | null {
    const now = options.now();
    let count = 0;
    let soonest = Infinity;
    for (const [key, e] of known) {
      if (e.serviceId !== serviceId) continue;
      if (expired(e, now)) {
        known.delete(key);
        windows.delete(key);
        lanes.delete(key);
        continue;
      }
      count += 1;
      soonest = Math.min(
        soonest,
        e.pending > 0 ? 1 : Math.max(1, Math.ceil((bw - (now - Math.min(e.lastMs, now))) / 1000)),
      );
    }
    return count >= identitiesMax ? soonest : null;
  }

  function touchIdentity(key: string, serviceId: string) {
    let e = known.get(key);
    if (e === undefined) {
      e = { serviceId, lastMs: options.now(), pending: 0 };
      known.set(key, e);
    }
    e.lastMs = options.now();
    return e;
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
  async function obtain(
    service: RelayService,
    hash: Uint8Array,
    creds?: UpstreamCredentials,
  ): Promise<Obtained> {
    const nonce = options.random(8);
    const request = buildTimestampRequest(hash, nonce);
    if (!request.ok) return { ok: false, status: 500, body: { error: 'internal' } };
    const sentMs = options.now(); // the moment the request goes to the service: the token must not be older
    let answer;
    try {
      answer =
        creds === undefined
          ? await options.upstream(service, request.value)
          : await options.upstream(service, request.value, creds);
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
    headers?: Record<string, string>;
  }
  interface Waiting {
    hash: Uint8Array;
    resolve: (reply: Reply) => void;
  }
  interface Window {
    service: RelayService;
    /** The lane (service and identity) this window belongs to; windows of different credentials are never merged. */
    key: string;
    creds: UpstreamCredentials | undefined;
    waiting: Waiting[];
    timer: ReturnType<typeof setTimeout> | null;
  }
  const openWindows = new Map<string, Window>(); // lane key -> the window that takes requests
  let closed = false;

  /** A request that waits for a slot of its service (not yet in a window, not yet stamped). */
  interface Queued extends Waiting {
    timer: ReturnType<typeof setTimeout> | null;
  }
  /**
   * The planner of one service: requests that wait for a slot. A slot is one stamp of the service (the budget
   * `60000 / minIntervalMs` per minute): a window takes one, a solo stamp takes one. They alternate when both wait.
   */
  interface Lane {
    service: RelayService;
    key: string;
    creds: UpstreamCredentials | undefined;
    solo: Queued[];
    normal: Queued[];
    lastWasSolo: boolean;
    timer: ReturnType<typeof setTimeout> | null;
  }
  const lanes = new Map<string, Lane>();
  const laneOf = (
    key: string,
    service: RelayService,
    creds: UpstreamCredentials | undefined,
  ): Lane => {
    let lane = lanes.get(key);
    if (lane === undefined) {
      lane = { service, key, creds, solo: [], normal: [], lastWasSolo: false, timer: null };
      lanes.set(key, lane);
    }
    return lane;
  };

  /** Does anybody wait for this service: in an open window or in the queue? */
  function laneBusy(key: string): boolean {
    const lane = lanes.get(key);
    return (
      (lane !== undefined && lane.solo.length + lane.normal.length > 0) ||
      (openWindows.get(key)?.waiting.length ?? 0) > 0
    );
  }

  /** Milliseconds until the service has a free slot (0: now). */
  function slotWaitMs(key: string, service: RelayService): number {
    const now = options.now();
    const own = (windows.get(key) ?? []).filter((t) => now - t < bw);
    windows.set(key, own);
    const limit = Math.max(1, Math.floor(bw / service.minIntervalMs));
    return own.length >= limit
      ? Math.max(1, bw - (now - Math.min(own[own.length - limit]!, now)))
      : 0;
  }

  /** Takes a slot of the service now. */
  function takeSlot(key: string): void {
    const own = windows.get(key) ?? [];
    own.push(options.now());
    windows.set(key, own);
  }

  /** A request joins a window that is open (it takes no slot: the window has one). */
  function joinOpen(w: Window, hash: Uint8Array): Promise<Reply> {
    return new Promise((resolve) => {
      w.waiting.push({ hash, resolve });
      if (w.waiting.length >= batch!.max) closeWindow(w); // full: the next request waits for a slot
    });
  }

  /** Opens the window of a service with the requests that wait for it (the timer starts now). */
  function openWindowWith(lane: Lane, items: Waiting[]): void {
    const created: Window = {
      service: lane.service,
      key: lane.key,
      creds: lane.creds,
      waiting: items,
      timer: null,
    };
    created.timer = setTimeout(() => closeWindow(created), batch!.windowMs);
    openWindows.set(lane.key, created);
    if (items.length >= batch!.max) closeWindow(created);
  }

  /**
   * A request that needs a slot: it waits in the queue of its service (for the longest `maxWaitMs`, then
   * `503 busy`); `dispatch` serves it at once when a slot is free.
   */
  function enqueue(
    service: RelayService,
    key: string,
    creds: UpstreamCredentials | undefined,
    hash: Uint8Array,
    solo: boolean,
  ): Promise<Reply> {
    return new Promise((resolve) => {
      const lane = laneOf(key, service, creds);
      const item: Queued = { hash, resolve, timer: null };
      item.timer = setTimeout(() => {
        const list = solo ? lane.solo : lane.normal;
        const at = list.indexOf(item);
        if (at < 0) return;
        list.splice(at, 1);
        resolve({
          status: 503,
          body: { error: 'busy' },
          headers: {
            'Retry-After': String(Math.max(1, Math.ceil(slotWaitMs(key, service) / 1000))),
          },
        });
      }, maxWaitMs);
      (solo ? lane.solo : lane.normal).push(item);
      dispatch(lane);
    });
  }

  /** Gives free slots to the waiting requests: a solo request and a window alternate, so nothing starves. */
  function dispatch(lane: Lane): void {
    const service = lane.service;
    if (lane.timer !== null) clearTimeout(lane.timer);
    lane.timer = null;
    while (!closed && lane.solo.length + lane.normal.length > 0) {
      const wait = slotWaitMs(lane.key, service);
      if (wait > 0) {
        lane.timer = setTimeout(() => dispatch(lane), wait);
        return;
      }
      const solo = lane.solo.length > 0 && (lane.normal.length === 0 || !lane.lastWasSolo);
      takeSlot(lane.key);
      lane.lastWasSolo = solo;
      if (solo) {
        const item = lane.solo.shift()!;
        if (item.timer !== null) clearTimeout(item.timer);
        runSolo(lane, item);
      } else {
        // the window takes the requests that wait, up to its size; the others wait for the next slot
        const items = lane.normal.splice(0, batch!.max);
        for (const i of items) if (i.timer !== null) clearTimeout(i.timer);
        openWindowWith(lane, items);
      }
    }
  }

  /** A direct stamp of one hash (no tree, no `batch` in the answer). */
  function runSolo(lane: Lane, item: Waiting): void {
    const service = lane.service;
    const done = async (): Promise<void> => {
      const got = await obtain(service, item.hash, lane.creds);
      if (!got.ok) return item.resolve({ status: got.status, body: got.body });
      stats.stamped += 1;
      stats.solo = (stats.solo ?? 0) + 1;
      item.resolve({ status: 200, body: stampBody(service, got) });
    };
    done().catch(() => item.resolve({ status: 500, body: { error: 'internal' } }));
  }

  const answerAll = (waiting: readonly Waiting[], reply: Reply): void => {
    for (const w of waiting) w.resolve(reply);
  };

  function closeWindow(w: Window): void {
    if (openWindows.get(w.key) !== w) return; // closed already (timer and full window meet)
    openWindows.delete(w.key);
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
    const got = await obtain(w.service, new Uint8Array(built.imprint), w.creds);
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
      openWindows.delete(w.key);
      if (w.timer !== null) clearTimeout(w.timer);
      answerAll(w.waiting, { status: 503, body: { error: 'shutting-down' } });
    }
    for (const lane of lanes.values()) {
      if (lane.timer !== null) clearTimeout(lane.timer);
      lane.timer = null;
      const queued = [...lane.solo.splice(0), ...lane.normal.splice(0)];
      for (const q of queued) {
        if (q.timer !== null) clearTimeout(q.timer);
        q.resolve({ status: 503, body: { error: 'shutting-down' } });
      }
    }
  }

  function setKeys(keys: readonly RelayKey[]): void {
    if (!authRequired) throw new Error('relay runs without authentication'); // no content
    const next = buildKeys(keys); // throws before anything changes
    keyById = next.byId;
    soloKids = next.solo;
  }

  function noteKeyReload(applied: boolean): void {
    if (applied) stats.keyReloads = (stats.keyReloads ?? 0) + 1;
    else stats.keyReloadFailed = (stats.keyReloadFailed ?? 0) + 1;
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
            // only the paid ones: what the app has to send (never a value, never whether the relay holds credentials)
            ...(s.auth === undefined || s.auth.kind === 'none' ? {} : { auth: s.auth }),
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
      ...(stats.solo === undefined ? {} : { solo: stats.solo }),
      ...(stats.soloDenied === undefined ? {} : { soloDenied: stats.soloDenied }),
      ...(stats.keyReloads === undefined ? {} : { keyReloads: stats.keyReloads }),
      ...(stats.keyReloadFailed === undefined ? {} : { keyReloadFailed: stats.keyReloadFailed }),
    }),
    close,
    setKeys,
    noteKeyReload,
  };
}
