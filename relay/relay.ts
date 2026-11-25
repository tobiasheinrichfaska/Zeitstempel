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
import { AUTH_START_SLACK_MS, RELAY_LIMITS, WAIT_TOLERANCE_MS } from './limits.ts';
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
  /**
   * The name of this relay as the signed head must carry it (`RELAY_AUDIENCE`): printable ASCII without a space, 1 to 128
   * characters. Required when `keys` is a list (a relay with keys and no audience does not start); not used with `'off'`.
   */
  audience?: string;
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
   * The longest a request waits for a free slot of its service (collecting operation) or for the minimum distance to
   * the last call of its service (single operation) before it gets `503 busy` (default `RELAY_LIMITS.maxWaitDefaultMs`).
   * A slot that is not free within this time is a `429` at once.
   */
  maxWaitMs?: number;
  /**
   * The monotonic clock in ms (default `performance.now()`): every wait of single operation (the minimum distance between
   * two calls to a service) and, in collecting operation, the whole planner (distance, sliding budget of the service,
   * counters per minute, windows, waits) is measured on it, never on the wall clock (`now`). A parameter so a test can
   * let it jump.
   */
  monotonicNow?: () => number;
  /** Window of the budget counters in ms (default `RELAY_LIMITS.windowMs`); a parameter so a test need not wait a minute. */
  budgetWindowMs?: number;
  /**
   * Credentials the relay holds itself, by service id (read from its environment by `main.ts`; memory only). Allowed
   * only for a service whose `auth.source` is `relay` or `either`; a service with `source: 'relay'` must have them.
   */
  upstreamAuth?: ReadonlyMap<string, UpstreamCredentials>;
  /** Identities (credentials of the app) known at once per service (default `RELAY_LIMITS.upstreamIdentitiesMax`); a parameter for tests. */
  upstreamIdentities?: number;
  /**
   * `RELAY_KEY_SHARE`: the share of a service's budget per minute (whole percent, 10 to 100, default 100 = off) that ONE key
   * may use at one lane (service and identity): at most `max(1, floor(budget * share / 100))` admitted requests per
   * sliding minute, then `429 key-share`. Single operation: every request; collecting operation: the solo stamps (a window
   * is one slot for all its hashes). Only with authentication (a request without a key id has no share).
   */
  keyShare?: number;
}

/** A parsed `X-Zeitstempel-Auth` header whose form and time are fine; the signature is not yet checked. */
interface Auth {
  kid: string;
  /** Unix milliseconds, as signed. */
  ts: number;
  /** The head's own identifier as written (22 characters, canonical base64url of 16 bytes). */
  jti: string;
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
  keyFileWritable?: number;
  /** Requests signed (validly) with a revoked key (`"revoked": true`), answered 401 like an unknown key; present once counted; global, never per key. */
  keyRevoked?: number;
  /** Requests signed (validly) with a key past its `notAfter`, answered 401 like an unknown key; present once counted; global, never per key. */
  keyExpired?: number;
  /** Requests of a key whose `services` does not name the service: `403 service-not-allowed`; present once counted. */
  serviceDenied?: number;
  /** Requests refused with `429 key-share` (only the share of the key at a service was reached); present once counted; global, never per key. */
  shareDenied?: number;
}

const JSON_TYPE = 'application/json';
/** Response headers a browser page may read: Retry-After (429) and Date (the relay's clock, for a 401 from clock skew). */
const EXPOSED_HEADERS = 'Retry-After, Date';
const AUTH_FORM =
  /^v3\.([a-z][a-z0-9-]{0,31})\.([1-9][0-9]{11,14})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{86})$/;
const AUTH_PREFIX = 'zeitstempel-auth-v3';
const AUDIENCE_FORM = /^[\x21-\x7e]{1,128}$/;
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
   * Ends the relay's waiting: the requests that wait in an open window, for a slot or (single operation) for the
   * minimum distance to the last call are answered with `503 shutting-down`, no timer is left, and new requests get the
   * same answer. A call to the service that is already running finishes normally (bounded by `upstreamTimeoutMs`).
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
  /** Counts the key file turning writable for group or others (once per change of state). */
  noteKeyFileWritable: () => void;
  /**
   * FOR TESTS ONLY (changes no behaviour, never output by the server): how many entries the tables per identity hold
   * (identities, budget times, last calls, lanes of the planner, gates of single operation). Their number must stay
   * limited: an expired identity leaves none behind.
   */
  heldForTests: () => Record<
    'known' | 'windows' | 'lastCall' | 'lanes' | 'gates' | 'shares',
    number
  >;
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
  // `RELAY_KEY_SHARE`: per (key id, lane) the times of the admitted requests in the window (memory only, never output).
  // Entries whose times are all expired are dropped at every admission: the table holds the keys and lanes active in the last window.
  const keyShare = options.keyShare ?? 100;
  if (!(Number.isInteger(keyShare) && keyShare >= 10 && keyShare <= 100)) {
    throw new Error('relay keyShare is invalid'); // at start, no content
  }
  const shares = new Map<string, number[]>();
  let total: number[] = [];
  const buildKeys = (keys: readonly RelayKey[]) => {
    const byId = new Map<string, KeyObject>();
    const solo = new Set<string>();
    const revoked = new Set<string>();
    const notAfter = new Map<string, number>(); // key id -> Unix seconds
    const services = new Map<string, ReadonlySet<string>>(); // key id -> the only services it may use
    const perMinute = new Map<string, number>(); // key id -> own limit per minute
    for (const k of keys) {
      const key = publicKeyObject(k.publicKey);
      if (key === null) throw new Error('relay key is not a valid P-256 public key'); // no content
      if (byId.has(k.id)) throw new Error('relay key ids must be unique'); // no content
      byId.set(k.id, key);
      if (k.solo === true) solo.add(k.id);
      if (k.revoked === true) revoked.add(k.id);
      if (k.notAfter !== undefined) {
        if (!Number.isInteger(k.notAfter)) throw new Error('relay key notAfter is invalid');
        notAfter.set(k.id, k.notAfter);
      }
      if (k.services !== undefined) services.set(k.id, new Set(k.services));
      if (k.perMinute !== undefined) {
        if (
          !Number.isInteger(k.perMinute) ||
          k.perMinute < 1 ||
          k.perMinute > RELAY_LIMITS.perMinutePerKey
        ) {
          throw new Error('relay key perMinute is invalid'); // no content
        }
        perMinute.set(k.id, k.perMinute);
      }
    }
    return { byId, solo, revoked, notAfter, services, perMinute };
  };
  const initial = options.keys === 'off' ? buildKeys([]) : buildKeys(options.keys);
  let keyById = initial.byId; // replaced as a whole when the key file is reloaded
  let soloKids = initial.solo; // key type 2: may ask for a solo stamp
  let revokedKids = initial.revoked; // refused like an unknown key (401)
  let notAfterKids = initial.notAfter; // key id -> Unix seconds: from then on refused like a revoked key
  let servicesOfKid = initial.services; // key id -> the only services it may use (absent: all)
  let perMinuteOfKid = initial.perMinute; // key id -> own limit per minute (absent: `perMinutePerKey`)
  const authRequired = options.keys !== 'off';
  const audience = options.audience ?? '';
  if (authRequired && !AUDIENCE_FORM.test(audience)) {
    throw new Error('relay: audience missing or invalid'); // no content
  }
  const doVerify = options.verifySignature ?? verifySignatureNode;
  // Heads signed (their `ts`, milliseconds) before this process started are refused (the replay cache is empty after a restart,
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
  // A signed request is remembered by its key id and its `jti` (16 random bytes the app makes per request, signed with
  // the rest), NOT by the signature: ECDSA is malleable (for a valid (r, s) the pair (r, n - s) is valid for the same
  // message), so a cache on signatures would let the twin pass as new; the twin carries the same `jti`. Value: the time (ms) until which a replay
  // could still pass the window, the same moment on the monotonic clock (`monoUntil`: a wall clock that ran ahead and is set
  // back must not make an entry forget a head whose window comes back; an entry goes only when BOTH clocks say it is over),
  // and the key id it belongs to.
  const replay = new Map<string, { until: number; monoUntil: number; kid: string }>();
  const replayMax = options.authReplayEntries ?? RELAY_LIMITS.authReplayEntries;
  const replayMaxPerKey = Math.max(1, Math.ceil(replayMax * RELAY_LIMITS.authReplayKeyShare));
  const windowMs = RELAY_LIMITS.authWindowSeconds * 1000;
  const bw = options.budgetWindowMs ?? RELAY_LIMITS.windowMs;
  const maxWaitMs = options.maxWaitMs ?? RELAY_LIMITS.maxWaitDefaultMs;
  // The one place single operation reads the time of its waits (the monotonic clock of the process).
  const mono = options.monotonicNow ?? (() => performance.now());
  // The time of the planner and of the counters per minute: the monotonic clock in collecting operation (a jump of the
  // wall clock must not give back a distance or a budget), the wall clock in single operation (its sliding budget and
  // counters stay as they were; its minimum distance runs on `mono`). The wall clock stays for the authentication (`ts`,
  // replay cache), `genTime` and the start time.
  const tick = (): number => (options.batch === undefined ? options.now() : mono());
  const soloWindows = new Map<string, number[]>(); // key id -> solo request times (memory only, never logged)
  // A replay can arrive with its head at the edge of the window and its body up to the request
  // timeout later: an entry must outlive `ts + window` by that much.
  const keepMs = windowMs + RELAY_LIMITS.requestTimeoutMs;
  const inWindow = (ts: number): boolean => Math.abs(options.now() - ts) <= windowMs;

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
    /** A solo stamp: it also has to keep the minimum distance to the last call of the service (`slotMs` counts it). */
    forSolo = false,
  ): { wait: number | null; slotMs: number; spend: () => void; unspend: () => void } {
    const now = tick();
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
    // In collecting operation the slot of an open window counts too: its stamp is still to come (`stampAt`).
    const booked = batch ? [...own, ...reservedStamp(laneKey, now)] : own;
    const countMs =
      booked.length >= ownLimit ? Math.max(1, bw - (now - booked[booked.length - ownLimit]!)) : 0;
    const slotMs = forSolo ? Math.max(countMs, spacingMs(laneKey, minIntervalMs, now)) : countMs;
    if (forService === true && own.length >= ownLimit) waits.push(until(own, ownLimit));
    const keyLimit = kid === null ? 0 : (perMinuteOfKid.get(kid) ?? RELAY_LIMITS.perMinutePerKey);
    if (kid !== null && mine.length >= keyLimit) {
      waits.push(until(mine, keyLimit));
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
      // nothing was sent to the service after all: the count comes back
      unspend: () => {
        removeOne(total, now);
        if (forService === true) removeOne(windows.get(laneKey), now);
        if (kid !== null) removeOne(keyWindows.get(kid), now);
      },
    };
  }

  /** Takes one entry with this value (the newest) out of a list of times; nothing when it is gone already. */
  function removeOne(list: number[] | undefined, value: number): void {
    const at = list?.lastIndexOf(value) ?? -1;
    if (at >= 0) list!.splice(at, 1);
  }

  /**
   * The share of one key at one lane (`RELAY_KEY_SHARE`): the seconds to wait when the key has used its part of the lane's
   * budget in the last window, and `spend`. A look writes nothing. Null at 100 (off).
   */
  function shareBudget(
    laneKey: string,
    kid: string,
    minIntervalMs: number,
  ): { wait: number | null; spend: () => void; unspend: () => void } | null {
    if (keyShare >= 100) return null;
    const now = tick();
    const id = `${kid}|${laneKey}`;
    const times = (shares.get(id) ?? []).filter((t) => now - t < bw).map((t) => Math.min(t, now));
    const laneLimit = Math.max(1, Math.floor(bw / minIntervalMs));
    const limit = Math.max(1, Math.floor((laneLimit * keyShare) / 100));
    return {
      wait:
        times.length >= limit
          ? Math.max(1, Math.ceil((bw - (now - times[times.length - limit]!)) / 1000))
          : null,
      spend: () => {
        times.push(now);
        shares.set(id, times);
        for (const [other, list] of shares) {
          if (
            other !== id &&
            (list.length === 0 || now - Math.min(list[list.length - 1]!, now) >= bw)
          ) {
            shares.delete(other);
          }
        }
      },
      unspend: () => {
        removeOne(shares.get(id), now);
        // an empty list is no list (nothing would ever age it out)
        if (shares.get(id)?.length === 0) shares.delete(id);
      },
    };
  }

  /** The solo requests of one key in the last window: the seconds to wait when the limit is reached, and `spend`. Memory only. */
  function soloBudget(kid: string): {
    wait: number | null;
    spend: () => void;
    unspend: () => void;
  } {
    const now = tick();
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
      unspend: () => removeOne(soloWindows.get(kid), now),
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
    const signature = fromBase64Url(m[4]!);
    if (!signature || signature.length !== 64) return null;
    // The `jti` is the cache key: only the one canonical spelling of 16 bytes counts (22 characters leave 4 spare bits).
    const jtiBytes = fromBase64Url(m[3]!);
    if (!jtiBytes || jtiBytes.length !== 16 || toBase64Url(jtiBytes) !== m[3]) return null;
    const ts = Number(m[2]);
    if (!inWindow(ts)) return null;
    // Signed before this process started (`startMs` is the lowest clock value seen so far).
    if (ts < startMs - AUTH_START_SLACK_MS) return null;
    return { kid: m[1]!, ts, jti: m[3]!, signature };
  }

  /**
   * Checks the ECDSA signature over method, path, time and body (same work for an unknown id: it is
   * checked against the dummy key). Returns the cache id (key id and `jti`), or null when refused.
   */
  function checkSignature(
    auth: Auth,
    method: string,
    path: string,
    body: Uint8Array,
  ): string | null {
    const key = keyById.get(auth.kid);
    const message = `${AUTH_PREFIX}\n${method}\n${path}\n${audience}\n${auth.ts}\n${auth.jti}\n${createHash('sha256').update(body).digest('hex')}`;
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
    // Always exactly one verification, known id or not, revoked or not, expired or not; the id decides only afterwards.
    if (!(valid && key !== undefined)) return null;
    // A revoked or expired key is refused with the same 401 and after the same work as an unknown one; only the
    // global counters know (a valid signature of that key: not a guess at an id), never a number per key.
    if (revokedKids.has(auth.kid)) {
      stats.keyRevoked = (stats.keyRevoked ?? 0) + 1;
      return null;
    }
    const until = notAfterKids.get(auth.kid);
    if (until !== undefined && options.now() >= until * 1000) {
      stats.keyExpired = (stats.keyExpired ?? 0) + 1;
      return null;
    }
    return `${auth.kid}:${auth.jti}`;
  }

  /**
   * Is the key of a request that waited no longer valid (removed from the file, revoked, past `notAfter`)? Looked at when the
   * request is stamped, so a change of the file reaches the requests that were admitted before it. Counted like at the door.
   */
  function lapsed(kid: string, atDoor: KeyObject | undefined): boolean {
    const now = keyById.get(kid);
    if (now === undefined) return true;
    // the id was entered again with another public key: the signature of the waiting request was made with the old one
    if (atDoor !== undefined && !now.equals(atDoor)) return true;
    if (revokedKids.has(kid)) {
      stats.keyRevoked = (stats.keyRevoked ?? 0) + 1;
      return true;
    }
    const until = notAfterKids.get(kid);
    if (until !== undefined && options.now() >= until * 1000) {
      stats.keyExpired = (stats.keyExpired ?? 0) + 1;
      return true;
    }
    return false;
  }

  /** Read only: has a request with this signed message been admitted before (and not yet expired)? */
  function seen(id: string): boolean {
    const entry = replay.get(id);
    return entry !== undefined && (entry.until >= options.now() || entry.monoUntil >= mono());
  }

  /**
   * Read only: the seconds to wait when the cache cannot take another entry of this key (it is full, or
   * the key holds its share already: one key cannot lock out the others), else null. The longest of the
   * two applies. Nothing is written, so a refusal here costs nothing; `remember` cannot fail afterwards.
   */
  function cacheWait(kid: string): number | null {
    const now = options.now();
    const monoNow = mono();
    let soonest = Infinity; // milliseconds until the first entry goes
    let soonestOwn = Infinity;
    let own = 0;
    for (const [id, entry] of replay) {
      if (entry.until < now && entry.monoUntil < monoNow) {
        replay.delete(id);
        continue;
      }
      // An entry never lives longer than `keepMs` past the newest head the window lets in; a longer
      // remainder means the clock was set back, and the wait stays within that bound. It lives as long as the later
      // of the two clocks says.
      const left = Math.min(
        Math.max(entry.until - now, entry.monoUntil - monoNow),
        windowMs + keepMs,
      );
      soonest = Math.min(soonest, left);
      if (entry.kid === kid) {
        own += 1;
        soonestOwn = Math.min(soonestOwn, left);
      }
    }
    const waits: number[] = [];
    if (own >= replayMaxPerKey) waits.push(Math.max(1, Math.ceil(soonestOwn / 1000)));
    if (replay.size >= replayMax) waits.push(Math.max(1, Math.ceil(soonest / 1000)));
    return waits.length === 0 ? null : Math.max(...waits);
  }

  /** Writes a request down; only after `seen` said no and `cacheWait` said null, in the same step. */
  function remember(id: string, auth: Auth): void {
    const until = auth.ts + keepMs;
    replay.set(id, {
      until,
      monoUntil: mono() + Math.max(0, until - options.now()),
      kid: auth.kid,
    });
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
    if (closed) return send(res, 503, { error: 'shutting-down' }, origin);
    // Solo stamps exist for key type 2 only (a direct stamp at once, with a slot of its own). A key of type 1 (or no key)
    // that asks for one is refused here, before any work: no window, no slot, no wait, no entry in the tree, no
    // identity, and no total or key budget spent (like `bad-mode`); only the counters know it.
    // A key that names its services (`services` in the key file) may use only those: refused before any work, like
    // the solo case: no window, no slot, no budget and no replay entry spent; only the counters know it.
    const allowed = auth === null ? undefined : servicesOfKid.get(auth.kid);
    if (allowed !== undefined && !allowed.has(service.id)) {
      stats.serviceDenied = (stats.serviceDenied ?? 0) + 1;
      return send(res, 403, { error: 'service-not-allowed' }, origin);
    }
    const direct = wantsSolo && auth !== null && soloKids.has(auth.kid);
    if (wantsSolo && !direct) {
      stats.soloDenied = (stats.soloDenied ?? 0) + 1;
      return send(res, 403, { error: 'solo-not-allowed' }, origin);
    }
    // Collecting operation: a window that is open already takes this request without touching the service's
    // budget (one stamp per window); the budget of a key and the total still count every request.
    const open = batch ? openWindows.get(lk) : undefined;
    const joinsOpen = open !== undefined && !direct;
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
      direct,
    );
    const cache = auth ? cacheWait(auth.kid) : null;
    const soloNow = wantsSolo && auth ? soloBudget(auth.kid) : null;
    // The share of the key at this lane (off at 100): every request in single operation, only the solo stamps in collecting
    // operation (a window is one slot for all its hashes: joining it takes none).
    const shareNow =
      auth !== null && (!batch || direct) ? shareBudget(lk, auth.kid, service.minIntervalMs) : null;
    const waits = [budgetNow.wait, cache, soloNow?.wait ?? null, shareNow?.wait ?? null].filter(
      (w): w is number => w !== null,
    );
    // The slot of the service is not free within the longest wait: the old 429 (waiting is for a short squeeze only)
    if (batch && !joinsOpen && budgetNow.slotMs > maxWaitMs) {
      waits.push(Math.max(1, Math.ceil(budgetNow.slotMs / 1000)));
    }
    // Single operation: the minimum distance to the last call of the service (and identity), looked at without
    // reserving. Later than the longest wait: 429 at once, like a slot that is too late.
    const gateMs = batch ? 0 : gateWaitMs(lk, service.minIntervalMs);
    if (gateMs > maxWaitMs) waits.push(Math.max(1, Math.ceil(gateMs / 1000)));
    if (waits.length > 0) {
      // only the share says no: its own code (the same 429 with Retry-After; nothing is spent either way)
      if (shareNow?.wait != null && waits.length === 1) {
        stats.shareDenied = (stats.shareDenied ?? 0) + 1;
        return send(res, 429, { error: 'key-share' }, origin, { 'Retry-After': String(waits[0]) });
      }
      return send(res, 429, { error: 'rate-limited' }, origin, {
        'Retry-After': String(Math.max(...waits)),
      });
    }
    if (gateMs > 0 && (gates.get(lk)?.waiting.size ?? 0) >= RELAY_LIMITS.singleQueueMax) {
      return send(res, 503, { error: 'busy' }, origin, {
        'Retry-After': String(Math.max(1, Math.ceil(gateMs / 1000))),
      });
    }
    if (direct && (lanes.get(lk)?.solo.length ?? 0) >= RELAY_LIMITS.soloQueueMax) {
      return send(res, 503, { error: 'busy' }, origin, {
        'Retry-After': String(Math.max(1, Math.ceil(budgetNow.slotMs / 1000))),
      });
    }
    budgetNow.spend();
    soloNow?.spend();
    shareNow?.spend();
    // a request that is not sent to the service after all (it gave up, was busy, the relay ended, its key lapsed while it
    // waited) gives the count back; the replay entry stays (the head was seen)
    const refund = (): void => {
      budgetNow.unspend();
      soloNow?.unspend();
      shareNow?.unspend();
    };
    // Still allowed: the key itself (`lapsed`), and what the door looked at: its `services` and, for a solo stamp, its type.
    // A change of the file reaches a waiting request as a 401 (like a removed key).
    const keyAtDoor = auth === null ? undefined : keyById.get(auth.kid); // no await since `checkSignature`: the key that verified
    const valid = (): boolean => {
      if (auth === null) return true;
      if (lapsed(auth.kid, keyAtDoor)) return false;
      const only = servicesOfKid.get(auth.kid);
      if (only !== undefined && !only.has(service.id)) {
        stats.serviceDenied = (stats.serviceDenied ?? 0) + 1;
        return false;
      }
      if (direct && !soloKids.has(auth.kid)) {
        stats.soloDenied = (stats.soloDenied ?? 0) + 1;
        return false;
      }
      return true;
    };
    if (auth && signedId !== null) remember(signedId, auth);
    const entry = tracked ? touchIdentity(lk, service) : null;
    if (entry) entry.pending += 1;
    try {
      if (batch) {
        // The answer comes when the window is closed and the service has answered (the 5 s request deadline
        // is over by now: it only governs the reading of the request).
        const reply = joinsOpen
          ? await joinOpen(open, hash, valid)
          : await enqueue(service, lk, creds, hash, direct, valid);
        if (reply.unsent) refund();
        if (res.destroyed) return countAborted(req, res);
        return send(res, reply.status, reply.body, origin, reply.headers);
      }
      const got = await spaced(service, lk, hash, creds, () => res.destroyed, valid);
      // the client gave up while the request waited for its time: the service was not called for it
      if (got === 'gone') {
        refund();
        return countAborted(req, res);
      }
      if (!got.ok) {
        if (got.unsent) refund();
        return send(res, got.status, got.body, origin, got.headers);
      }
      stats.stamped += 1;
      return send(res, 200, stampBody(service, got), origin);
    } finally {
      if (entry) {
        entry.pending -= 1;
        entry.lastMs = mono(); // the identity lives a whole window (at least one distance) after its last answer
      }
    }
  }

  // ---- Credentials of paid services ----

  /** The identities of the app known now: lane key -> service, last activity, requests in flight. Memory only, never output. */
  const identitiesMax = options.upstreamIdentities ?? RELAY_LIMITS.upstreamIdentitiesMax;
  const known = new Map<
    string,
    { serviceId: string; lastMs: number; pending: number; keepMs: number }
  >();

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

  /**
   * Is an identity gone for good: idle for `keepMs` and nothing in flight? `now` and `lastMs` are on the monotonic clock
   * (in single operation, too: a jump of the wall clock must not drop a gate and give back a distance).
   */
  const expired = (e: { lastMs: number; pending: number; keepMs: number }, now: number): boolean =>
    e.pending === 0 && now - Math.min(e.lastMs, now) >= e.keepMs;

  /**
   * Drops the identities of a service that are expired, then: null when there is room for one more, else the seconds
   * until the first one expires (at least 1).
   */
  function identitiesFullWait(serviceId: string): number | null {
    const now = mono();
    let count = 0;
    let soonest = Infinity;
    for (const [key, e] of known) {
      if (e.serviceId !== serviceId) continue;
      if (expired(e, now)) {
        known.delete(key);
        windows.delete(key);
        lastCall.delete(key);
        lanes.delete(key);
        gates.delete(key);
        for (const id of shares.keys()) if (id.endsWith(`|${key}`)) shares.delete(id);
        continue;
      }
      count += 1;
      soonest = Math.min(
        soonest,
        e.pending > 0
          ? 1
          : Math.max(1, Math.ceil((e.keepMs - (now - Math.min(e.lastMs, now))) / 1000)),
      );
    }
    return count >= identitiesMax ? soonest : null;
  }

  function touchIdentity(key: string, service: RelayService) {
    let e = known.get(key);
    if (e === undefined) {
      // kept for a whole budget window, and at least for the minimum distance of the service: the gate and the last call
      // of the identity are what holds that distance, they must not be dropped before it is over
      const keepMs = Math.max(bw, service.minIntervalMs);
      e = { serviceId: service.id, lastMs: mono(), pending: 0, keepMs };
      known.set(key, e);
    }
    e.lastMs = mono();
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
    | {
        ok: false;
        status: number;
        body: { error: string; reason?: string };
        headers?: Record<string, string>;
        /** Nothing was sent to the service for this request (busy, shutting down, key lapsed): what it spent comes back. */
        unsent?: true;
      };

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

  // ---- Single operation: the minimum distance ----

  /**
   * The gate of one lane (service and identity) in single operation: the monotonic time of the last call made, the
   * earliest time the next reservation may call (each reservation books `minIntervalMs` after the one before), and the
   * requests that wait for their time. Memory only, never output.
   */
  interface Gate {
    last: number;
    next: number;
    waiting: Set<GateWait>;
  }
  interface GateWait {
    timer: ReturnType<typeof setTimeout> | null;
    resolve: (how: 'go' | 'busy' | 'closing' | 'gone' | 'lapsed') => void;
  }
  const gates = new Map<string, Gate>();

  /** Milliseconds until a call of this lane may be made without coming closer than `minIntervalMs` to the one before (0: now). */
  function gateWaitMs(key: string, minIntervalMs: number): number {
    const g = gates.get(key);
    if (g === undefined) return 0;
    return Math.max(0, g.next - mono(), g.last + minIntervalMs - mono());
  }

  /**
   * One stamp in single operation, at least `minIntervalMs` after the call before it (on the monotonic clock, whatever
   * the wall clock does): it takes the next free time of its lane at once (so the order is the order of arrival) and
   * waits for it. The door has refused a time later than `maxWaitMs`; when the call is late because the ones before it
   * were (a loop that stood still), it is `503 busy` rather than later than the limit. `close()` ends the wait.
   */
  async function spaced(
    service: RelayService,
    key: string,
    hash: Uint8Array,
    creds: UpstreamCredentials | undefined,
    aborted: () => boolean,
    valid: () => boolean,
  ): Promise<Obtained | 'gone'> {
    const m = service.minIntervalMs;
    let g = gates.get(key);
    if (g === undefined) {
      g = { last: -Infinity, next: -Infinity, waiting: new Set() };
      gates.set(key, g);
    }
    const gate = g;
    const start = mono();
    const at = Math.max(start, gate.next, gate.last + m);
    gate.next = at + m;
    if (at <= start) {
      gate.last = start;
      return obtain(service, hash, creds);
    }
    const deadline = start + maxWaitMs;
    // The time this request booked is given back when it will not call after all (busy, client gone) and it is the last
    // of the chain: a gap in the middle is not filled (the order of arrival stays), but the end of the chain must not
    // wait for a call nobody makes. The distance to the call really made (`gate.last`) is checked at every call anyway.
    const giveBack = (): void => {
      if (gate.next === at + m) gate.next = at;
    };
    const how = await new Promise<'go' | 'busy' | 'closing' | 'gone' | 'lapsed'>((resolve) => {
      const entry: GateWait = { timer: null, resolve };
      gate.waiting.add(entry);
      const finish = (h: 'go' | 'busy' | 'closing' | 'gone' | 'lapsed'): void => {
        gate.waiting.delete(entry);
        entry.timer = null;
        resolve(h);
      };
      const look = (): void => {
        const t = mono();
        if (aborted()) {
          giveBack();
          return finish('gone');
        }
        // the key may have been revoked or removed while the request waited: no call for it
        if (!valid()) {
          giveBack();
          return finish('lapsed');
        }
        // the distance to the call that was made last, as it really was (a timer may fire late or a bit early)
        const due = Math.max(at, gate.last + m);
        // the door lets the last one through at the very limit, and every call before it may be a few ms late
        // (timers): the sum of those delays must not cost the request the slot the door promised
        // `t` counts too: a loop that stood still fires the timer long after `due`, and the call would then lie far
        // past the limit although the time it booked was within it
        if (Math.max(due, t) > deadline + WAIT_TOLERANCE_MS) {
          giveBack();
          return finish('busy');
        }
        if (due > t) {
          entry.timer = setTimeout(look, Math.ceil(due - t));
          return;
        }
        gate.last = t; // the call is made now: the next one counts from here
        finish('go');
      };
      entry.timer = setTimeout(look, Math.ceil(at - start));
    });
    if (how === 'closing') {
      return { ok: false, status: 503, body: { error: 'shutting-down' }, unsent: true };
    }
    if (how === 'gone') return 'gone';
    if (how === 'lapsed')
      return { ok: false, status: 401, body: { error: 'unauthorized' }, unsent: true };
    if (how === 'busy') {
      return {
        ok: false,
        status: 503,
        unsent: true,
        body: { error: 'busy' },
        headers: { 'Retry-After': String(Math.max(1, Math.ceil((gate.next - mono()) / 1000))) },
      };
    }
    return obtain(service, hash, creds);
  }

  // ---- Collecting operation ----

  interface Reply {
    status: number;
    body: unknown;
    headers?: Record<string, string>;
    /** Nothing was sent to the service for this request: what it spent comes back. */
    unsent?: true;
  }
  interface Waiting {
    hash: Uint8Array;
    resolve: (reply: Reply) => void;
    /** Is its key still valid? Looked at again when it is stamped. */
    valid: () => boolean;
  }
  const LAPSED: Reply = { status: 401, body: { error: 'unauthorized' }, unsent: true };
  interface Window {
    service: RelayService;
    /** The lane (service and identity) this window belongs to; windows of different credentials are never merged. */
    key: string;
    creds: UpstreamCredentials | undefined;
    waiting: Waiting[];
    timer: ReturnType<typeof setTimeout> | null;
    /** When it will be stamped at the latest (opening + window length): the time its slot is booked for. */
    stampAt: number;
  }
  const openWindows = new Map<string, Window>(); // lane key -> the window that takes requests
  let closed = false;

  /** A request that waits for a slot of its service (not yet in a window, not yet stamped). */
  interface Queued extends Waiting {
    timer: ReturnType<typeof setTimeout> | null;
    /** The monotonic time its wait ends (arrival + `maxWaitMs`); the timer of the wait is real and a loop that stood still fires it late. */
    deadline: number;
    solo: boolean;
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

  /** The time (`tick`: the monotonic clock) of the last call to a service per lane (service and identity); memory only, never output. */
  const lastCall = new Map<string, number>();
  /**
   * A window that is closed but must wait for the minimum distance to the last call of its service before it is
   * stamped; in the order of their stamps.
   */
  interface Delayed {
    at: number;
    w: Window;
    timer: ReturnType<typeof setTimeout> | null;
  }
  const delayedWindows = new Map<string, Delayed[]>(); // lane key -> its delayed windows

  /**
   * The times the windows of a lane will stamp, still to come, in ascending order: the windows that wait for the
   * distance (at that time) and the open one (opening + window length, at most one window length ahead even if the
   * clock was set back).
   */
  function reservedStamp(key: string, now: number): number[] {
    const times = (delayedWindows.get(key) ?? []).map((d, i) =>
      Math.min(d.at, now + (i + 1) * d.w.service.minIntervalMs),
    );
    const open = openWindows.get(key);
    if (open !== undefined) times.push(Math.min(open.stampAt, now + batch!.windowMs));
    return times.sort((a, b) => a - b);
  }

  /**
   * Milliseconds until a call to the service of this lane may be made without coming closer than `minIntervalMs` to
   * the one before (0: now): the last call made, and the windows that are delayed and will call before it (all of them,
   * or only those before `before`). A time in the future (the clock was set back) counts as `now`; the k-th delayed
   * window counts at most k times `minIntervalMs` ahead (the chain of delayed windows lies one distance apart each, so
   * the k-th is that far ahead at the most; a clock that was set back cannot hold it longer).
   */
  function spacingMs(key: string, minIntervalMs: number, now: number, before?: Delayed): number {
    let last = -Infinity;
    const made = lastCall.get(key);
    if (made !== undefined) {
      // stored as `now` from here on (the same rule as for the budget): a clock that stays behind cannot hold it ahead
      if (made > now) lastCall.set(key, now);
      last = Math.min(made, now);
    }
    let position = 0;
    for (const d of delayedWindows.get(key) ?? []) {
      if (d === before) break;
      position += 1;
      last = Math.max(last, Math.min(d.at, now + position * minIntervalMs));
    }
    return last === -Infinity ? 0 : Math.max(0, last + minIntervalMs - now);
  }

  /**
   * Milliseconds until the service has a free slot (0: now). A slot is counted at the time of the STAMP, the
   * moment the service sees the call: the times of the stamps made, and for an open window the time it will be
   * stamped (`open + windowMs`, at the latest), for a window that waits for the distance the time it will call. So a
   * window holds its slot from its opening on, and the stamps that come before it count it already: in any minute
   * the service sees at most `bw / minIntervalMs` calls. The minimum distance to the last call is a second rule
   * (`spacingMs`) that the solo stamps and the stamps of the windows keep on top of this one.
   */
  function slotWaitMs(key: string, service: RelayService): number {
    const now = tick();
    // times in the future (the clock was set back) count as `now` and are stored so: a request that waits and looks again
    // (no new request passes `budget`) would else see the same future time every time and wait for the length of the jump
    const own = (windows.get(key) ?? []).filter((t) => now - t < bw).map((t) => Math.min(t, now));
    windows.set(key, own);
    // except the stamps that are still to come (windows, at most one window length ahead)
    const booked = [...own, ...reservedStamp(key, now)];
    const limit = Math.max(1, Math.floor(bw / service.minIntervalMs));
    return booked.length >= limit ? Math.max(1, bw - (now - booked[booked.length - limit]!)) : 0;
  }

  /** Books a call to the service at this moment: the budget and the last call (the distance counts from here). */
  function takeSlot(key: string): void {
    const now = tick();
    const own = windows.get(key) ?? [];
    own.push(now);
    windows.set(key, own);
    lastCall.set(key, now);
  }

  /** A request joins a window that is open (it takes no slot: the window has one). */
  function joinOpen(w: Window, hash: Uint8Array, valid: () => boolean): Promise<Reply> {
    return new Promise((resolve) => {
      w.waiting.push({ hash, resolve, valid });
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
      stampAt: tick() + batch!.windowMs,
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
    valid: () => boolean,
  ): Promise<Reply> {
    return new Promise((resolve) => {
      const lane = laneOf(key, service, creds);
      const item: Queued = {
        hash,
        resolve,
        valid,
        timer: null,
        deadline: tick() + maxWaitMs,
        solo,
      };
      item.timer = setTimeout(() => dropBusy(lane, item), maxWaitMs);
      (solo ? lane.solo : lane.normal).push(item);
      dispatch(lane);
    });
  }

  /** A request leaves the queue of its lane with `503 busy` (its wait is over); false when it is not in the queue any more. */
  function dropBusy(lane: Lane, item: Queued): boolean {
    const list = item.solo ? lane.solo : lane.normal;
    const at = list.indexOf(item);
    if (at < 0) return false;
    list.splice(at, 1);
    if (item.timer !== null) clearTimeout(item.timer);
    const waitMs = Math.max(
      slotWaitMs(lane.key, lane.service),
      item.solo ? spacingMs(lane.key, lane.service.minIntervalMs, tick()) : 0,
    );
    item.resolve({
      status: 503,
      body: { error: 'busy' },
      headers: { 'Retry-After': String(Math.max(1, Math.ceil(waitMs / 1000))) },
      unsent: true,
    });
    return true;
  }

  /**
   * Gives free slots to the waiting requests: a solo request and a window alternate, so nothing starves. A window
   * needs a slot of the budget; a solo stamp needs one too and, on top, the minimum distance to the last call of the
   * service (a window keeps the distance when it stamps, see `stampWindow`).
   */
  function dispatch(lane: Lane): void {
    const service = lane.service;
    if (lane.timer !== null) clearTimeout(lane.timer);
    lane.timer = null;
    // a request whose wait is over (by the monotonic clock) gets no slot: after a stall the timer of this lane may fire
    // before the timer of the wait, and the stamp would lie past the limit
    const late = tick() - WAIT_TOLERANCE_MS;
    for (const item of [...lane.solo, ...lane.normal])
      if (item.deadline < late) dropBusy(lane, item);
    while (!closed && lane.solo.length + lane.normal.length > 0) {
      const countWait = slotWaitMs(lane.key, service);
      const soloWait = Math.max(countWait, spacingMs(lane.key, service.minIntervalMs, tick()));
      const canSolo = lane.solo.length > 0 && soloWait === 0;
      const canNormal = lane.normal.length > 0 && countWait === 0;
      if (!canSolo && !canNormal) {
        const wait = Math.min(
          lane.solo.length > 0 ? soloWait : Infinity,
          lane.normal.length > 0 ? countWait : Infinity,
        );
        lane.timer = setTimeout(() => dispatch(lane), wait);
        return;
      }
      const solo = canSolo && (!canNormal || !lane.lastWasSolo);
      lane.lastWasSolo = solo;
      if (solo) {
        takeSlot(lane.key); // the stamp is made now
        const item = lane.solo.shift()!;
        if (item.timer !== null) clearTimeout(item.timer);
        stampSolo(lane, item);
      } else {
        // the window takes the requests that wait, up to its size; the others wait for the next slot
        // (its slot is booked by the window itself: `stampAt` while it is open, the real stamp time at its close)
        const items = lane.normal.splice(0, batch!.max);
        for (const i of items) if (i.timer !== null) clearTimeout(i.timer);
        openWindowWith(lane, items);
      }
    }
  }

  /** A direct stamp of one hash (key type 2, no tree, no `batch` in the answer). */
  function stampSolo(lane: Lane, item: Waiting): void {
    const done = async (): Promise<void> => {
      if (!item.valid()) return item.resolve(LAPSED); // its key lapsed while it waited: no call
      const got = await obtain(lane.service, item.hash, lane.creds);
      if (!got.ok) return item.resolve({ status: got.status, body: got.body });
      stats.stamped += 1;
      stats.solo = (stats.solo ?? 0) + 1;
      item.resolve({ status: 200, body: stampBody(lane.service, got) });
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
    stampWindow(w);
    // a lane that waits for a slot looks again: a window that closed early frees its slot earlier than booked
    const waiting = lanes.get(w.key);
    if (waiting !== undefined && waiting.timer !== null) dispatch(waiting);
  }

  /**
   * The closed window calls the service: at once, or when the minimum distance to the last call is kept (a window that
   * closes full right after a solo stamp or another window would else come closer). Until then it holds its place
   * (`delayedWindows`: counted by the budget, the distance counts from it).
   */
  function stampWindow(w: Window): void {
    const now = tick();
    const wait = spacingMs(w.key, w.service.minIntervalMs, now);
    if (wait <= 0) return callService(w);
    const d: Delayed = { at: now + wait, w, timer: null };
    delayedWindows.set(w.key, [...(delayedWindows.get(w.key) ?? []), d]);
    armDelayed(d, wait);
  }

  function armDelayed(d: Delayed, ms: number): void {
    if (d.timer !== null) clearTimeout(d.timer);
    d.timer = setTimeout(() => fireDelayed(d), Math.ceil(ms));
  }

  /**
   * The wait is over (a timer of the length of the distance, on the monotonic clock like the distance itself). Windows
   * call in the order they closed: one that is not the first does not look again on its own (no polling): the one in
   * front arms it when that has called (or has to wait longer than it thought: a loop that stood still, a timer
   * that fired early).
   */
  function fireDelayed(d: Delayed): void {
    d.timer = null;
    const list = delayedWindows.get(d.w.key) ?? [];
    const index = list.indexOf(d);
    if (index < 0 || index > 0) return;
    const mi = d.w.service.minIntervalMs;
    // the distance again: the loop may have stood still while this and the one before were due
    const now = tick();
    const wait = spacingMs(d.w.key, mi, now, d);
    if (wait > 0) {
      d.at = now + wait;
      let before = d.at;
      for (const e of list.slice(1)) {
        // the windows behind it keep their distance to it
        before += mi;
        e.at = Math.max(e.at, before);
        before = e.at;
      }
      return armDelayed(d, wait);
    }
    list.splice(index, 1);
    if (list.length === 0) delayedWindows.delete(d.w.key);
    callService(d.w);
    // the next one calls one distance after this call (a timer of that length, once)
    const next = list[0];
    if (next !== undefined) armDelayed(next, Math.max(1, spacingMs(d.w.key, mi, tick(), next)));
  }

  /** The window is stamped now: the slot is booked at this time, then the tree is built and the service is called. */
  function callService(w: Window): void {
    takeSlot(w.key);
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
    // a request whose key lapsed while the window was open is out of the tree (and answered 401); nothing left, no call
    const waiting = w.waiting.filter((x) => {
      if (x.valid()) return true;
      x.resolve(LAPSED);
      return false;
    });
    if (waiting.length === 0) return;
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
    for (const g of gates.values()) {
      for (const w of [...g.waiting]) {
        if (w.timer !== null) clearTimeout(w.timer);
        g.waiting.delete(w);
        w.resolve('closing');
      }
    }
    for (const w of [...openWindows.values()]) {
      openWindows.delete(w.key);
      if (w.timer !== null) clearTimeout(w.timer);
      answerAll(w.waiting, { status: 503, body: { error: 'shutting-down' }, unsent: true });
    }
    for (const list of [...delayedWindows.values()]) {
      for (const d of list) {
        if (d.timer !== null) clearTimeout(d.timer);
        answerAll(d.w.waiting, { status: 503, body: { error: 'shutting-down' }, unsent: true });
      }
    }
    delayedWindows.clear();
    for (const lane of lanes.values()) {
      if (lane.timer !== null) clearTimeout(lane.timer);
      lane.timer = null;
      const queued = [...lane.solo.splice(0), ...lane.normal.splice(0)];
      for (const q of queued) {
        if (q.timer !== null) clearTimeout(q.timer);
        q.resolve({ status: 503, body: { error: 'shutting-down' }, unsent: true });
      }
    }
  }

  function setKeys(keys: readonly RelayKey[]): void {
    if (!authRequired) throw new Error('relay runs without authentication'); // no content
    const next = buildKeys(keys); // throws before anything changes
    keyById = next.byId;
    soloKids = next.solo;
    revokedKids = next.revoked;
    notAfterKids = next.notAfter;
    servicesOfKid = next.services;
    perMinuteOfKid = next.perMinute;
  }

  function noteKeyReload(applied: boolean): void {
    if (applied) stats.keyReloads = (stats.keyReloads ?? 0) + 1;
    else stats.keyReloadFailed = (stats.keyReloadFailed ?? 0) + 1;
  }

  function noteKeyFileWritable(): void {
    stats.keyFileWritable = (stats.keyFileWritable ?? 0) + 1;
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
      ...(stats.keyFileWritable === undefined ? {} : { keyFileWritable: stats.keyFileWritable }),
      ...(stats.keyRevoked === undefined ? {} : { keyRevoked: stats.keyRevoked }),
      ...(stats.keyExpired === undefined ? {} : { keyExpired: stats.keyExpired }),
      ...(stats.serviceDenied === undefined ? {} : { serviceDenied: stats.serviceDenied }),
      ...(stats.shareDenied === undefined ? {} : { shareDenied: stats.shareDenied }),
    }),
    close,
    setKeys,
    noteKeyReload,
    noteKeyFileWritable,
    heldForTests: () => ({
      known: known.size,
      windows: windows.size,
      lastCall: lastCall.size,
      lanes: lanes.size,
      gates: gates.size,
      shares: shares.size,
    }),
  };
}
