import {
  createHash,
  generateKeyPairSync,
  verify as verifySignatureNode,
  type KeyObject,
} from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { fromBase64Url, toBase64Url } from '../src/index.ts';
import { publicKeyObject, type RelayKey } from './keys.ts';
import { AUTH_START_SLACK_MS, RELAY_LIMITS } from './limits.ts';
import type { RelayContext } from './types.ts';

const AUTH_FORM =
  /^v3\.([a-z][a-z0-9-]{0,31})\.([1-9][0-9]{11,14})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{86})$/;
const AUTH_PREFIX = 'zeitstempel-auth-v3';
const AUDIENCE_FORM = /^[\x21-\x7e]{1,128}$/;

/** A parsed `X-Zeitstempel-Auth` header whose form and time are fine; the signature is not yet checked. */
export interface Auth {
  kid: string;
  /** Unix milliseconds, as signed. */
  ts: number;
  /** The head's own identifier as written (22 characters, canonical base64url of 16 bytes). */
  jti: string;
  signature: Uint8Array;
}

/**
 * The accepted keys and what the key file says about them; replaced as a whole when the key file is read again (`setKeys`).
 * One object shared by the parts of the relay, so every look sees the set of the moment.
 */
export interface KeyState {
  keyById: Map<string, KeyObject>; // replaced as a whole when the key file is reloaded
  soloKids: Set<string>; // key type 2: may ask for a solo stamp
  revokedKids: Set<string>; // refused like an unknown key (401)
  notAfterKids: Map<string, number>; // key id -> Unix seconds: from then on refused like a revoked key
  servicesOfKid: Map<string, ReadonlySet<string>>; // key id -> the only services it may use (absent: all)
  perMinuteOfKid: Map<string, number>; // key id -> own limit per minute (absent: `perMinutePerKey`)
}

export const emptyKeyState = (): KeyState => ({
  keyById: new Map(),
  soloKids: new Set(),
  revokedKids: new Set(),
  notAfterKids: new Map(),
  servicesOfKid: new Map(),
  perMinuteOfKid: new Map(),
});

/** The head of a request (`X-Zeitstempel-Auth`): its form, its signature, the replay cache and the key set. */
export function createAuthHead(ctx: RelayContext, ks: KeyState) {
  const { options, stats, mono, authRequired } = ctx;
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
  ks.keyById = initial.byId; // replaced as a whole when the key file is reloaded
  ks.soloKids = initial.solo; // key type 2: may ask for a solo stamp
  ks.revokedKids = initial.revoked; // refused like an unknown key (401)
  ks.notAfterKids = initial.notAfter; // key id -> Unix seconds: from then on refused like a revoked key
  ks.servicesOfKid = initial.services; // key id -> the only services it may use (absent: all)
  ks.perMinuteOfKid = initial.perMinute; // key id -> own limit per minute (absent: `perMinutePerKey`)

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

  // A replay can arrive with its head at the edge of the window and its body up to the request
  // timeout later: an entry must outlive `ts + window` by that much.
  const keepMs = windowMs + RELAY_LIMITS.requestTimeoutMs;
  const inWindow = (ts: number): boolean => Math.abs(options.now() - ts) <= windowMs;

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
    const key = ks.keyById.get(auth.kid);
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
    if (ks.revokedKids.has(auth.kid)) {
      stats.keyRevoked = (stats.keyRevoked ?? 0) + 1;
      return null;
    }
    const until = ks.notAfterKids.get(auth.kid);
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
    const now = ks.keyById.get(kid);
    if (now === undefined) return true;
    // the id was entered again with another public key: the signature of the waiting request was made with the old one
    if (atDoor !== undefined && !now.equals(atDoor)) return true;
    if (ks.revokedKids.has(kid)) {
      stats.keyRevoked = (stats.keyRevoked ?? 0) + 1;
      return true;
    }
    const until = ks.notAfterKids.get(kid);
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

  function setKeys(keys: readonly RelayKey[]): void {
    if (!authRequired) throw new Error('relay runs without authentication'); // no content
    const next = buildKeys(keys); // throws before anything changes
    ks.keyById = next.byId;
    ks.soloKids = next.solo;
    ks.revokedKids = next.revoked;
    ks.notAfterKids = next.notAfter;
    ks.servicesOfKid = next.services;
    ks.perMinuteOfKid = next.perMinute;
  }

  return {
    parseAuth,
    checkSignature,
    lapsed,
    seen,
    cacheWait,
    remember,
    inWindow,
    setKeys,
    replay,
  };
}
