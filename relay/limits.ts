/** Every limit of the relay in one place; docs/relay.md lists them and a test ties the two together. */
export const RELAY_LIMITS = {
  /** Largest request body: a hash is 32 bytes; JSON with a base64url hash is about 60. */
  bodyBytes: 512,
  /** Largest answer taken from a service (a token with a chain is about 10 KB). */
  upstreamBytes: 65_536,
  /** The whole upstream call, connect to last byte. */
  upstreamTimeoutMs: 10_000,
  /**
   * The whole incoming request, from the first byte (also the time for the headers). Short on purpose: a
   * single client can hold `maxConnections` connections open this long (the relay knows no addresses, so
   * a limit per address belongs to the reverse proxy in front).
   */
  requestTimeoutMs: 5_000,
  /** Requests per minute over all services and clients: nothing is counted per client. */
  perMinuteTotal: 60,
  /**
   * Requests per minute for one key id (on top of the total). With the four shipped services (4 per
   * minute each at 15 s, 12 for FreeTSA at 5 s, 24 together) the total is never reached and this limit only
   * by a key that uses several services: the per-service counters, which are global and not per key, bite
   * first, so one valid key can use up a service for all others. There is no fairness per key at a service's
   * budget (a known limit, docs/relay.md). In collecting operation both count every request, not every stamp.
   */
  perMinutePerKey: 20,
  /** Allowed difference (seconds) between the time in a signed request and the relay's clock. */
  authWindowSeconds: 60,
  /**
   * Signed requests remembered against replay; when full, new ones wait (429, without costing budget).
   * An upper bound, not a typical size: an entry lives at most `2 * authWindowSeconds + requestTimeoutMs`
   * (125 s) and only admitted requests are written, at most `perMinuteTotal` per minute, so at most
   * 60 * ceil(125 / 60) = 180 entries exist at a time, whatever the number of keys. 512 leaves room
   * (a test ties this value to those limits).
   */
  authReplayEntries: 512,
  /** Share of the replay cache one key id may hold (a key that fills its share waits, the others do not). A safety net: the budget keeps a key far below it. */
  authReplayKeyShare: 0.5,
  /** Window of the counters. */
  windowMs: 60_000,
  /**
   * How far the time a service puts in its token may differ from the relay's clock, in both directions: it must
   * lie in [the moment the request went to the service - this, the relay's clock after the answer + this].
   * The lower bound keeps a service (or a middleman with an expired or leaked service key) from handing out
   * back-dated tokens; the upper bound is the old future limit, now 60 s instead of 5 minutes.
   */
  genTimeSlackMs: 60_000,
  /** Largest number of origins that may be configured. */
  maxOrigins: 16,
  /** Open connections at the same time; further ones are refused by the server. */
  maxConnections: 256,
  /**
   * Idle time of a connection between two requests when the relay listens on a loopback address only
   * (127.0.0.1, ::1, localhost): then only a reverse proxy on the same machine can connect, and it pools
   * connections. Longer than the idle timeout of usual proxies (60 s is common), so the proxy, not the relay,
   * closes a pooled connection (else a request can hit a connection that is just being closed).
   */
  keepAliveProxyMs: 65_000,
  /**
   * Idle time between two requests for any other binding (RELAY_HOST names another address): clients may
   * connect directly, and one client could hold all `maxConnections` places with idle connections for as long
   * as this lasts. So it is as short as the deadline of a request (`requestTimeoutMs`). A proxy on another
   * machine must then keep its idle timeout below this value or set RELAY_KEEPALIVE_MS (docs/relay.md).
   */
  keepAliveDirectMs: 5_000,
  /** RELAY_KEEPALIVE_MS: smallest accepted value. */
  keepAliveMinMs: 1_000,
  /** RELAY_KEEPALIVE_MS: largest accepted value. */
  keepAliveMaxMs: 120_000,
  /** RELAY_BATCH_MS: smallest accepted window (0 or empty means off). */
  batchMsMin: 1_000,
  /** RELAY_BATCH_MS: largest accepted window. */
  batchMsMax: 60_000,
  /** RELAY_BATCH_MAX: value when not set. */
  batchMaxDefault: 128,
  /** RELAY_BATCH_MAX: smallest accepted value. */
  batchMaxMin: 2,
  /** RELAY_BATCH_MAX: largest accepted value (the library accepts trees of this size). */
  batchMaxMax: 1_024,
  /**
   * Direct (solo) stamps one key may ask for per minute, on top of `perMinutePerKey` (memory only, never
   * logged). Low on purpose: a solo stamp takes a whole slot of a service.
   */
  soloPerMinutePerKey: 4,
  /** Solo requests that may wait for a slot, per service; a further one gets `503 busy`. */
  soloQueueMax: 6,
  /** RELAY_MAX_WAIT_MS: value when not set (how long a request may wait for a free slot, then `503 busy`). */
  maxWaitDefaultMs: 30_000,
  /** RELAY_MAX_WAIT_MS: smallest accepted value. */
  maxWaitMinMs: 1_000,
  /** RELAY_MAX_WAIT_MS: largest accepted value (the proxy and client time-outs must exceed it by 17 s). */
  maxWaitMaxMs: 60_000,
  /**
   * Credentials of a paid service sent by the app (`upstream` in the signed body; docs/relay.md, "Zugangsdaten zu
   * bezahlten Diensten"): longest user name of `basic` (printable ASCII, no colon).
   */
  upstreamUserMax: 64,
  /** Longest password of `basic` (printable ASCII). */
  upstreamPasswordMax: 128,
  /** Longest token of `bearer` and `header` (printable ASCII without space, quote and backslash). */
  upstreamTokenMax: 384,
  /**
   * Identities (different credentials of the app) the relay knows at the same time per service, memory only; an identity
   * that was idle for a window and has nothing waiting is dropped. A further new one gets `503 busy`.
   */
  upstreamIdentitiesMax: 64,
  /** How often the relay looks at the modification time of the key file (ms). */
  keyFileCheckMs: 5_000,
  /**
   * Largest key file the relay reads (bytes): 64 keys with long ids are about 12 KB. Larger files are refused
   * unread (a failure of the reload, the old set stays). The relay reads (and hashes) the file at every look, so
   * the cost is bounded by this.
   */
  keyFileMaxBytes: 65_536,
} as const;
