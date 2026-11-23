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
   * Requests per minute for one key id (on top of the total): a third of the total, so that one key
   * cannot use it up and at least three keys are needed to lock out the others. A legitimate app stays
   * below it anyway: the services' own limits (4 per minute each at 15 s) add up to 16 for the four
   * shipped services.
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
  /** Allowed difference between a token's time and the relay's clock. */
  maxSkewMs: 5 * 60_000,
  /** Largest number of origins that may be configured. */
  maxOrigins: 16,
  /** Open connections at the same time; further ones are refused by the server. */
  maxConnections: 256,
} as const;
