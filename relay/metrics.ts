// The /metrics endpoint: text in the Prometheus exposition format (version 0.0.4), counters and gauges only.
// Off unless RELAY_METRICS=1, and then only for a connection whose peer address is loopback. Everything else gets the
// answer of any unknown route (the relay's 404, no hint that the route exists).
//
// What it holds: the counters of `relay.stats()` (sums, never per key), and what the server can see of the answers it
// sends: the status per service (the service id is public data and only ids of the offered services are counted, so
// the number of series is fixed by the operator), the requests in progress per service and the time of the last
// answered stamp per service on the monotonic clock. It holds NO key id, hash, token, signature, address or path of a
// request: a label value comes from a closed list (service ids, status codes, refusal codes the relay itself sends).
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { RelayStats } from './relay.ts';
import { RELAY_LIMITS } from './limits.ts';

const STAMP_PATH = /^\/v1\/stamp\/([a-z][a-z0-9-]{0,31})$/;
/** The statuses the relay sends; any other number is counted as `other`, an answer that never completed as `none`. */
const STATUSES: ReadonlySet<number> = new Set([
  200, 204, 400, 401, 403, 404, 405, 413, 415, 429, 500, 502, 503, 504,
]);
/** A refusal code as the relay writes it (`not-found`, `upstream-too-old`); anything else is counted as `other`. */
const REASON_FORM = /^[a-z][a-z0-9-]{0,39}$/;

/** True for a peer address that only a process on this machine can have (127.0.0.0/8, ::1, and their IPv4-mapped form). */
export function isLoopbackPeer(address: string | undefined): boolean {
  if (address === undefined) return false;
  return (
    address === '::1' ||
    /^(?:::ffff:)?127(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$/i.test(address)
  );
}

const statusLabel = (code: number, finished: boolean): string =>
  !finished ? 'none' : STATUSES.has(code) ? String(code) : 'other';

export interface Metrics {
  /** Counts the answer to a request (call before the relay handles it). Never throws; touches nothing of the request. */
  observe: (req: IncomingMessage, res: ServerResponse) => void;
  /** Answers `GET /metrics` and returns true, or returns false and does nothing (the relay then answers as for any unknown route). */
  serve: (req: IncomingMessage, res: ServerResponse) => boolean;
  /** The text of the endpoint for the given counters. */
  render: (stats: RelayStats) => string;
}

export function createMetrics(options: {
  /** Ids of the offered services (the only service labels ever written). */
  serviceIds: readonly string[];
  stats: () => RelayStats;
  /** The monotonic clock in milliseconds (`performance.now()`). */
  mono: () => number;
  /** The peer address of a request; for tests. Default: the socket's remote address. */
  peerAddress?: (req: IncomingMessage) => string | undefined;
}): Metrics {
  const ids = [...new Set(options.serviceIds)].sort();
  const known = new Set(ids);
  const startedAt = options.mono();
  const responses = new Map<string, number>(); // status label -> count
  const perService = new Map<string, Map<string, number>>(); // service -> status label -> count
  const inflight = new Map<string, number>();
  const lastSuccess = new Map<string, number>(); // service -> mono ms of the last completed 200
  let scrapes = 0;
  const bump = (m: Map<string, number>, k: string): void => void m.set(k, (m.get(k) ?? 0) + 1);

  function observe(req: IncomingMessage, res: ServerResponse): void {
    try {
      const m = STAMP_PATH.exec(req.url ?? '');
      const service = m !== null && known.has(m[1]!) ? m[1]! : null;
      if (service !== null) bump(inflight, service);
      let done = false;
      res.once('close', () => {
        if (done) return;
        done = true;
        const finished = res.writableFinished;
        const label = statusLabel(res.statusCode, finished);
        bump(responses, label);
        if (service !== null) {
          inflight.set(service, Math.max(0, (inflight.get(service) ?? 0) - 1));
          let own = perService.get(service);
          if (own === undefined) perService.set(service, (own = new Map()));
          bump(own, label);
          if (finished && res.statusCode === 200) lastSuccess.set(service, options.mono());
        }
      });
    } catch {
      // counting must never touch the request
    }
  }

  function serve(req: IncomingMessage, res: ServerResponse): boolean {
    // exactly this target and method, no browser (`Origin`: a page must not read it), a peer on this machine
    if (req.method !== 'GET' || req.url !== '/metrics') return false;
    if (req.headers.origin !== undefined) return false;
    if (!isLoopbackPeer((options.peerAddress ?? ((r) => r.socket.remoteAddress))(req)))
      return false;
    scrapes += 1;
    const text = render(options.stats());
    res.writeHead(200, {
      'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
      'Content-Length': String(Buffer.byteLength(text)),
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(text);
    return true;
  }

  function render(stats: RelayStats): string {
    const out: string[] = [];
    const num = (v: unknown): number =>
      typeof v === 'number' && Number.isFinite(v) && v >= 0
        ? Math.min(Math.floor(v), Number.MAX_SAFE_INTEGER)
        : 0;
    const head = (name: string, type: 'counter' | 'gauge', help: string): void => {
      out.push(`# HELP ${name} ${help}`, `# TYPE ${name} ${type}`);
    };
    const plain = (name: string, type: 'counter' | 'gauge', help: string, v: number): void => {
      head(name, type, help);
      out.push(`${name} ${v}`);
    };
    const now = options.mono();
    plain(
      'zeitstempel_relay_uptime_seconds',
      'gauge',
      'Seconds since the process started (monotonic clock).',
      Math.max(0, Math.floor((now - startedAt) / 1000)),
    );
    plain(
      'zeitstempel_stamps_total',
      'counter',
      'Stamps obtained from a service (one per window in collecting operation).',
      num(stats.stamped),
    );
    plain(
      'zeitstempel_batched_total',
      'counter',
      'Requests answered with a receipt (collecting operation).',
      num(stats.batched),
    );
    plain(
      'zeitstempel_solo_total',
      'counter',
      'Solo stamps obtained (collecting operation).',
      num(stats.solo),
    );
    plain(
      'zeitstempel_solo_denied_total',
      'counter',
      'Solo requests refused for a key of type 1.',
      num(stats.soloDenied),
    );
    plain(
      'zeitstempel_key_reloads_total',
      'counter',
      'Key file reloads applied.',
      num(stats.keyReloads),
    );
    plain(
      'zeitstempel_key_reload_failed_total',
      'counter',
      'Key file reloads refused (invalid file, the old set stays).',
      num(stats.keyReloadFailed),
    );
    plain(
      'zeitstempel_key_file_writable_total',
      'counter',
      'Times the key file turned writable for group or others.',
      num(stats.keyFileWritable),
    );
    plain(
      'zeitstempel_key_revoked_total',
      'counter',
      'Valid signatures of a revoked key (sum over all keys).',
      num(stats.keyRevoked),
    );
    plain(
      'zeitstempel_key_expired_total',
      'counter',
      'Valid signatures of a key past its notAfter (sum over all keys).',
      num(stats.keyExpired),
    );
    plain(
      'zeitstempel_service_denied_total',
      'counter',
      'Requests refused because the key may not use the service (sum).',
      num(stats.serviceDenied),
    );
    plain(
      'zeitstempel_share_denied_total',
      'counter',
      'Requests refused with 429 key-share (sum).',
      num(stats.shareDenied),
    );

    // refusals by code, as the relay counts them; the number of codes is capped, the rest is `other`
    head(
      'zeitstempel_refused_total',
      'counter',
      'Refused requests by the relay code (busy, rate-limited, unauthorized, ...).',
    );
    const reasons = new Map<string, number>();
    let other = 0;
    for (const [reason, count] of Object.entries(stats.refused ?? {}).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    )) {
      if (
        REASON_FORM.test(reason) &&
        (reasons.size < RELAY_LIMITS.metricsMaxReasons || reasons.has(reason))
      ) {
        reasons.set(reason, num(count));
      } else other += num(count);
    }
    if (other > 0) reasons.set('other', (reasons.get('other') ?? 0) + other);
    for (const [reason, count] of reasons)
      out.push(`zeitstempel_refused_total{reason="${reason}"} ${count}`);

    head(
      'zeitstempel_http_responses_total',
      'counter',
      'Answers sent by status code (none: the connection ended before the answer was complete).',
    );
    for (const [label, count] of [...responses].sort()) {
      out.push(`zeitstempel_http_responses_total{status="${label}"} ${count}`);
    }
    head(
      'zeitstempel_stamp_responses_total',
      'counter',
      'Answers to stamp requests by service and status code (429 and 503 included).',
    );
    for (const id of ids) {
      for (const [label, count] of [...(perService.get(id) ?? [])].sort()) {
        out.push(`zeitstempel_stamp_responses_total{service="${id}",status="${label}"} ${count}`);
      }
    }
    head(
      'zeitstempel_stamp_inflight',
      'gauge',
      'Stamp requests in progress per service: waiting for a window or a slot, or at the service.',
    );
    for (const id of ids)
      out.push(`zeitstempel_stamp_inflight{service="${id}"} ${inflight.get(id) ?? 0}`);
    head(
      'zeitstempel_service_last_success_age_seconds',
      'gauge',
      'Seconds since the last stamp request of the service was answered with 200 (since the start while none was).',
    );
    for (const id of ids) {
      const since = lastSuccess.get(id) ?? startedAt;
      out.push(
        `zeitstempel_service_last_success_age_seconds{service="${id}"} ${Math.max(0, Math.floor((now - since) / 1000))}`,
      );
    }
    head(
      'zeitstempel_service_success_seen',
      'gauge',
      '1 once the service answered a stamp request with 200 since the start, else 0.',
    );
    for (const id of ids)
      out.push(`zeitstempel_service_success_seen{service="${id}"} ${lastSuccess.has(id) ? 1 : 0}`);
    plain('zeitstempel_metrics_scrapes_total', 'counter', 'Answers of this endpoint.', scrapes);

    let text = out.join('\n') + '\n';
    if (Buffer.byteLength(text) > RELAY_LIMITS.metricsMaxBytes) {
      // never reached with a sane list of services; a bound all the same
      const cut = text.slice(0, RELAY_LIMITS.metricsMaxBytes - 32);
      text = cut.slice(0, cut.lastIndexOf('\n') + 1) + '# truncated\n';
    }
    return text;
  }

  return { observe, serve, render };
}
