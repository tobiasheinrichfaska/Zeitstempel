import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  buildTimestampRequest,
  fromBase64Url,
  readTimestampResponse,
  toBase64Url,
  verifyTimestampToken,
  type Service,
} from '../src/index.ts';
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
}

/** Counters only: no address, no hash, no token ever leaves a request. */
export interface RelayStats {
  stamped: number;
  refused: Record<string, number>;
}

const JSON_TYPE = 'application/json';
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
  let total: number[] = [];

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

  /** Counts a request against the window; returns the seconds to wait when over a limit. */
  function admit(serviceId: string, minIntervalMs: number): number | null {
    const now = options.now();
    total = total.filter((t) => now - t < RELAY_LIMITS.windowMs);
    const own = (windows.get(serviceId) ?? []).filter((t) => now - t < RELAY_LIMITS.windowMs);
    const ownLimit = Math.max(1, Math.floor(RELAY_LIMITS.windowMs / minIntervalMs));
    if (total.length >= RELAY_LIMITS.perMinuteTotal || own.length >= ownLimit) {
      const oldest = own.length >= ownLimit ? own[0]! : total[0]!;
      windows.set(serviceId, own);
      return Math.max(1, Math.ceil((RELAY_LIMITS.windowMs - (now - oldest)) / 1000));
    }
    total.push(now);
    own.push(now);
    windows.set(serviceId, own);
    return null;
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
  ): Promise<void> {
    const type = String(req.headers['content-type'] ?? '')
      .split(';')[0]!
      .trim()
      .toLowerCase();
    const body = await readBody(req);
    if (!body) return send(res, 413, { error: 'too-large' }, origin, { Connection: 'close' });
    const hash = hashFrom(type, body);
    if (hash === 'unsupported') return send(res, 415, { error: 'unsupported-media-type' }, origin);
    if (hash === 'bad') return send(res, 400, { error: 'bad-hash' }, origin);

    const wait = admit(service.id, service.minIntervalMs);
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
        'Access-Control-Allow-Headers': 'Content-Type',
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
      const service = byId.get(m[1]!);
      if (!service) return send(res, 404, { error: 'unknown-service' }, echo);
      stamp(req, res, service, echo).catch(() => answerInternal(res, echo));
      return;
    }
    return send(res, 404, { error: 'not-found' }, echo);
  }

  return { handle, stats: () => ({ stamped: stats.stamped, refused: { ...stats.refused } }) };
}
