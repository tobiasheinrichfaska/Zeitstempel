import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import { createAuthHead, emptyKeyState, type Auth } from './auth-head.ts';
import { ClientAborted, hashFrom, JSON_TYPE, readBody } from './body.ts';
import { createBudgets } from './budgets.ts';
import { createIdentities } from './identities.ts';
import { RELAY_LIMITS } from './limits.ts';
import { createObtain } from './obtain.ts';
import { createPlanner } from './planner.ts';
import type {
  Relay,
  RelayContext,
  RelayGauges,
  RelayOptions,
  RelayService,
  RelayStats,
} from './types.ts';

export type { Relay, RelayGauges, RelayOptions, RelayService, RelayStats } from './types.ts';

/** Response headers a browser page may read: Retry-After (429) and Date (the relay's clock, for a 401 from clock skew). */
const EXPOSED_HEADERS = 'Retry-After, Date';
const STAMP_PATH = /^\/v1\/stamp\/([a-z][a-z0-9-]{0,31})$/;

export function createRelay(options: RelayOptions): Relay {
  const usable = options.services.filter(
    (s) => options.allowPlainHttp || new URL(s.url).protocol === 'https:',
  );
  const byId = new Map(usable.map((s) => [s.id, s]));
  const authRequired = options.keys !== 'off';
  const batch = options.batch;
  const bw = options.budgetWindowMs ?? RELAY_LIMITS.windowMs;
  const maxWaitMs = options.maxWaitMs ?? RELAY_LIMITS.maxWaitDefaultMs;
  // The one place single operation reads the time of its waits (the monotonic clock of the process).
  const mono = options.monotonicNow ?? (() => performance.now());
  // The time of the planner and of the counters per minute: the monotonic clock in collecting operation (a jump of the
  // wall clock must not give back a distance or a budget), the wall clock in single operation (its sliding budget and
  // counters stay as they were; its minimum distance runs on `mono`). The wall clock stays for the authentication (`ts`,
  // replay cache), `genTime` and the start time.
  const tick = (): number => (options.batch === undefined ? options.now() : mono());
  const stats: RelayStats = { stamped: 0, refused: {}, ...(batch ? { batched: 0 } : {}) };
  const timedOut = new WeakSet<Duplex>(); // connections the server itself ended for being too slow
  const life = { closed: false };
  const ctx: RelayContext = {
    options,
    stats,
    batch,
    bw,
    maxWaitMs,
    mono,
    tick,
    authRequired,
    life,
    countOnce,
  };
  // The parts, made in the order the checks at start always ran: the credentials of paid services, the settings of the
  // collecting operation, the share of a key, the keys and the audience.
  const identities = createIdentities(ctx, usable, byId, forget);
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
  const ks = emptyKeyState();
  const budgets = createBudgets(ctx, ks, {
    reservedStamp: (key, now) => planner.reservedStamp(key, now),
    spacingMs: (key, minIntervalMs, now) => planner.spacingMs(key, minIntervalMs, now),
  });
  const heads = createAuthHead(ctx, ks);
  const obtainer = createObtain(ctx);
  const planner = createPlanner(ctx, budgets.windows, obtainer);
  const { windows, shares, budget, shareBudget, soloBudget } = budgets;
  const {
    parseAuth,
    checkSignature,
    lapsed,
    seen,
    cacheWait,
    remember,
    inWindow,
    setKeys,
    replay,
  } = heads;
  const { known, expired, credentialsFor, identitiesFullWait, touchIdentity } = identities;
  const { stampBody, serviceCalledAt, lastGenDelta } = obtainer;
  const {
    gates,
    openWindows,
    lanes,
    delayedWindows,
    lastCall,
    gateWaitMs,
    spaced,
    joinOpen,
    enqueue,
    close,
  } = planner;

  /** An identity of the app is gone: what the other parts hold for its lane goes with it. */
  function forget(key: string): void {
    windows.delete(key);
    lastCall.delete(key);
    lanes.delete(key);
    gates.delete(key);
    for (const id of shares.keys()) if (id.endsWith(`|${key}`)) shares.delete(id);
  }

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
    if (life.closed) return send(res, 503, { error: 'shutting-down' }, origin);
    // Solo stamps exist for key type 2 only (a direct stamp at once, with a slot of its own). A key of type 1 (or no key)
    // that asks for one is refused here, before any work: no window, no slot, no wait, no entry in the tree, no
    // identity, and no total or key budget spent (like `bad-mode`); only the counters know it.
    // A key that names its services (`services` in the key file) may use only those: refused before any work, like
    // the solo case: no window, no slot, no budget and no replay entry spent; only the counters know it.
    const allowed = auth === null ? undefined : ks.servicesOfKid.get(auth.kid);
    if (allowed !== undefined && !allowed.has(service.id)) {
      stats.serviceDenied = (stats.serviceDenied ?? 0) + 1;
      return send(res, 403, { error: 'service-not-allowed' }, origin);
    }
    const direct = wantsSolo && auth !== null && ks.soloKids.has(auth.kid);
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
    const keyAtDoor = auth === null ? undefined : ks.keyById.get(auth.kid); // no await since `checkSignature`: the key that verified
    const valid = (): boolean => {
      if (auth === null) return true;
      if (lapsed(auth.kid, keyAtDoor)) return false;
      const only = ks.servicesOfKid.get(auth.kid);
      if (only !== undefined && !only.has(service.id)) {
        stats.serviceDenied = (stats.serviceDenied ?? 0) + 1;
        return false;
      }
      if (direct && !ks.soloKids.has(auth.kid)) {
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

  function gauges(): RelayGauges {
    const monoNow = mono();
    const wallNow = options.now();
    let identities = 0;
    for (const e of known.values()) if (!expired(e, monoNow)) identities += 1;
    let replayEntries = 0;
    for (const entry of replay.values())
      if (entry.until >= wallNow || entry.monoUntil >= monoNow) replayEntries += 1;
    const queuedBy = new Map<string, number>([...byId.keys()].map((id) => [id, 0]));
    // a lane key is the service id, or `<id>#<digest>` for credentials of the client
    const add = (key: string, n: number): void => {
      const id = key.split('#', 1)[0]!;
      const have = queuedBy.get(id);
      if (have !== undefined) queuedBy.set(id, have + n);
    };
    for (const [key, g] of gates) add(key, g.waiting.size);
    for (const [key, lane] of lanes) add(key, lane.solo.length + lane.normal.length);
    for (const [key, w] of openWindows) add(key, w.waiting.length);
    for (const [key, list] of delayedWindows) for (const d of list) add(key, d.w.waiting.length);
    const age: Record<string, number> = {};
    for (const [id, at] of serviceCalledAt)
      age[id] = Math.max(0, Math.floor((monoNow - at) / 1000));
    return {
      identities,
      replayEntries,
      queued: Object.fromEntries(queuedBy),
      lastGenTimeDeltaMs: Object.fromEntries(lastGenDelta),
      lastServiceCallAgeSeconds: age,
    };
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
    gauges,
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
