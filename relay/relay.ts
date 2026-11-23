import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  buildTimestampRequest,
  fromBase64Url,
  readTimestampResponse,
  toBase64Url,
  verifyTimestampToken,
  type Service,
} from '../src/index.ts';
import type { RelayKey } from './keys.ts';
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
   * Who may stamp: the accepted keys (id and verifier), or `'off'` to accept unsigned requests
   * (local development only; there is no default, so it cannot be forgotten).
   */
  keys: readonly RelayKey[] | 'off';
  /** Size of the replay cache (default `RELAY_LIMITS.authReplayEntries`); a parameter for tests. */
  authReplayEntries?: number;
}

/** A parsed `X-Zeitstempel-Auth` header whose form and time are fine; the MAC is not yet checked. */
interface Auth {
  kid: string;
  ts: number;
  mac: Uint8Array;
  macText: string;
}

/** Counters only: no address, no hash, no token ever leaves a request. */
export interface RelayStats {
  stamped: number;
  refused: Record<string, number>;
}

const JSON_TYPE = 'application/json';
const AUTH_FORM = /^v1\.([a-z][a-z0-9-]{0,31})\.(0|[1-9][0-9]{0,11})\.([A-Za-z0-9_-]{43})$/;
const AUTH_PREFIX = 'zeitstempel-auth-v1';
const STAMP_PATH = /^\/v1\/stamp\/([a-z][a-z0-9-]{0,31})$/;

export interface Relay {
  handle: (req: IncomingMessage, res: ServerResponse) => void;
  stats: () => RelayStats;
}

export function createRelay(options: RelayOptions): Relay {
  const usable = options.services.filter(
    (s) => options.allowPlainHttp || new URL(s.url).protocol === 'https:',
  );
  const byId = new Map(usable.map((s) => [s.id, s]));
  const stats: RelayStats = { stamped: 0, refused: {} };
  const windows = new Map<string, number[]>(); // service id → request times in the window
  const keyWindows = new Map<string, number[]>(); // key id → request times in the window (memory only)
  let total: number[] = [];
  const keyById = new Map(
    options.keys === 'off' ? [] : options.keys.map((k) => [k.id, k.verifier]),
  );
  // A key nobody holds: unknown ids still get the same HMAC work, so the answer tells nothing.
  const dummyVerifier = new Uint8Array(32);
  const replay = new Map<string, number>(); // mac → time (ms) after which a replay is out of the window
  const replayMax = options.authReplayEntries ?? RELAY_LIMITS.authReplayEntries;
  const windowMs = RELAY_LIMITS.authWindowSeconds * 1000;

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
            // Without this a browser hides Retry-After from the page's script.
            'Access-Control-Expose-Headers': 'Retry-After',
            Vary: 'Origin',
          }
        : { Vary: 'Origin' }),
      ...extra,
    });
    res.end(text);
  }

  /**
   * Counts a request against the window (total, per service, and per key when there is one); returns
   * the seconds to wait when over a limit.
   */
  function admit(serviceId: string, minIntervalMs: number, kid: string | null): number | null {
    const now = options.now();
    total = total.filter((t) => now - t < RELAY_LIMITS.windowMs);
    const own = (windows.get(serviceId) ?? []).filter((t) => now - t < RELAY_LIMITS.windowMs);
    const mine =
      kid === null
        ? []
        : (keyWindows.get(kid) ?? []).filter((t) => now - t < RELAY_LIMITS.windowMs);
    const ownLimit = Math.max(1, Math.floor(RELAY_LIMITS.windowMs / minIntervalMs));
    const overOwn = own.length >= ownLimit;
    const overKey = kid !== null && mine.length >= RELAY_LIMITS.perMinutePerKey;
    if (total.length >= RELAY_LIMITS.perMinuteTotal || overOwn || overKey) {
      const oldest = overKey ? mine[0]! : overOwn ? own[0]! : total[0]!;
      windows.set(serviceId, own);
      if (kid !== null) keyWindows.set(kid, mine);
      return Math.max(1, Math.ceil((RELAY_LIMITS.windowMs - (now - oldest)) / 1000));
    }
    total.push(now);
    own.push(now);
    windows.set(serviceId, own);
    if (kid !== null) {
      mine.push(now);
      keyWindows.set(kid, mine);
    }
    return null;
  }

  /** Form and time of the auth header, before the body is read; null for anything wrong. */
  function parseAuth(req: IncomingMessage): Auth | null {
    const value = req.headers['x-zeitstempel-auth'];
    if (typeof value !== 'string') return null;
    const m = AUTH_FORM.exec(value);
    if (!m) return null;
    const mac = fromBase64Url(m[3]!);
    if (!mac || mac.length !== 32) return null;
    const ts = Number(m[2]);
    if (Math.abs(options.now() - ts * 1000) > windowMs) return null;
    return { kid: m[1]!, ts, mac, macText: m[3]! };
  }

  /** The MAC over method, path, time and body, in constant time; same work for an unknown id. */
  function macMatches(auth: Auth, method: string, path: string, body: Uint8Array): boolean {
    const verifier = keyById.get(auth.kid);
    const message = `${AUTH_PREFIX}\n${method}\n${path}\n${auth.ts}\n${createHash('sha256').update(body).digest('hex')}`;
    const expected = createHmac('sha256', verifier ?? dummyVerifier)
      .update(message)
      .digest();
    return timingSafeEqual(expected, auth.mac) && verifier !== undefined;
  }

  /** Remembers a valid MAC; 'replay' if seen, or the seconds to wait when the cache is full. */
  function remember(auth: Auth): 'new' | 'replay' | number {
    const now = options.now();
    let soonest = Infinity;
    for (const [mac, until] of replay) {
      if (until < now) replay.delete(mac);
      else soonest = Math.min(soonest, until);
    }
    if (replay.has(auth.macText)) return 'replay';
    if (replay.size >= replayMax) return Math.max(1, Math.ceil((soonest - now) / 1000));
    replay.set(auth.macText, auth.ts * 1000 + windowMs);
    return 'new';
  }

  async function readBody(req: IncomingMessage): Promise<Uint8Array | null> {
    const declared = req.headers['content-length'];
    if (declared !== undefined && Number(declared) > RELAY_LIMITS.bodyBytes) return null;
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      size += (chunk as Buffer).length;
      if (size > RELAY_LIMITS.bodyBytes) return null;
      chunks.push(chunk as Buffer);
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
    const body = await readBody(req);
    if (!body) return send(res, 413, { error: 'too-large' }, origin, { Connection: 'close' });
    if (auth) {
      if (!macMatches(auth, req.method ?? '', path, body)) return unauthorized(res, origin);
      const seen = remember(auth);
      if (seen === 'replay') return unauthorized(res, origin);
      if (seen !== 'new') {
        return send(res, 429, { error: 'rate-limited' }, origin, { 'Retry-After': String(seen) });
      }
    }
    const hash = hashFrom(type, body);
    if (hash === 'unsupported') return send(res, 415, { error: 'unsupported-media-type' }, origin);
    if (hash === 'bad') return send(res, 400, { error: 'bad-hash' }, origin);

    const wait = admit(service.id, service.minIntervalMs, auth?.kid ?? null);
    if (wait !== null)
      return send(res, 429, { error: 'rate-limited' }, origin, { 'Retry-After': String(wait) });

    const nonce = options.random(8);
    const request = buildTimestampRequest(hash, nonce);
    if (!request.ok) return send(res, 500, { error: 'internal' }, origin);
    let answer;
    try {
      answer = await options.upstream(service, request.value);
    } catch (e) {
      const kind = e instanceof UpstreamError ? e.kind : 'failed';
      return send(res, kind === 'timeout' ? 504 : 502, { error: `upstream-${kind}` }, origin);
    }
    if (answer.status !== 200 || answer.contentType !== 'application/timestamp-reply') {
      return send(res, 502, { error: 'upstream-refused' }, origin);
    }
    const response = readTimestampResponse(answer.body);
    if (!response.ok)
      return send(res, 502, { error: 'upstream-invalid', reason: response.reason }, origin);
    const verified = await verifyTimestampToken(response.value.token, hash, service.anchorPems, {
      expectedNonce: nonce,
      now: new Date(options.now()),
      maxSkewMs: RELAY_LIMITS.maxSkewMs,
    });
    if (!verified.ok)
      return send(res, 502, { error: 'upstream-invalid', reason: verified.reason }, origin);
    stats.stamped += 1;
    return send(
      res,
      200,
      {
        service: service.id,
        genTime: verified.value.genTime,
        accuracyMs: verified.value.accuracyMs,
        serial: verified.value.serial,
        token: toBase64Url(response.value.token),
      },
      origin,
    );
  }

  /** One answer for every authentication failure: nothing says whether id, time or MAC was wrong. */
  function unauthorized(res: ServerResponse, origin: string | null): void {
    send(res, 401, { error: 'unauthorized' }, origin);
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

    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Methods': 'GET, POST',
        'Access-Control-Allow-Headers': 'Content-Type, X-Zeitstempel-Auth',
        'Access-Control-Max-Age': '600',
        ...(echo ? { 'Access-Control-Allow-Origin': echo } : {}),
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
      const auth = options.keys === 'off' ? null : parseAuth(req);
      if (options.keys !== 'off' && !auth) return unauthorized(res, echo);
      const service = byId.get(m[1]!);
      if (!service) return send(res, 404, { error: 'unknown-service' }, echo);
      stamp(req, res, service, echo, auth, url.pathname).catch(() => answerInternal(res, echo));
      return;
    }
    return send(res, 404, { error: 'not-found' }, echo);
  }

  return { handle, stats: () => ({ stamped: stats.stamped, refused: { ...stats.refused } }) };
}
