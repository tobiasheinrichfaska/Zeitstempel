/** Every limit of the relay in one place; docs/relay.md lists them and a test ties the two together. */
export const RELAY_LIMITS = {
  /** Largest request body: a hash is 32 bytes; JSON with a base64url hash is about 60. */
  bodyBytes: 512,
  /** Largest answer taken from a service (a token with a chain is about 10 KB). */
  upstreamBytes: 65_536,
  /** The whole upstream call, connect to last byte. */
  upstreamTimeoutMs: 10_000,
  /** The whole incoming request, from the first byte. */
  requestTimeoutMs: 10_000,
  /** Requests per minute over all services and clients: nothing is counted per client. */
  perMinuteTotal: 60,
  /** Requests per minute for one key id (on top of the total). */
  perMinutePerKey: 30,
  /** Allowed difference (seconds) between the time in a signed request and the relay's clock. */
  authWindowSeconds: 60,
  /** Signed requests remembered against replay; when full, new ones wait (429). */
  authReplayEntries: 4096,
  /** Share of the replay cache one key id may hold (a key that fills its share waits, the others do not). */
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
