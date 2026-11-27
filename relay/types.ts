import type { verify as verifySignatureNode } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import type { Service } from '../src/index.ts';
import type { UpstreamCredentials } from './credentials.ts';
import type { RelayKey } from './keys.ts';
import type { Upstream } from './upstream.ts';

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
  /**
   * Test parameter: the clock of the counters per minute of single operation (default: `monotonicNow`, so the monotonic
   * clock). Only a test sets it, to let the counters run on a clock it moves by hand while the minimum distance (which
   * always reads `monotonicNow`) is already over. Collecting operation ignores it (one clock for the whole planner).
   */
  countersNow?: () => number;
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

/**
 * Numbers only, read at the moment of the call (`relay.gauges()`): nothing per key, no hash, no address, no token. The service
 * ids are the ones of the offered services (the only labels that exist), so the size is fixed by the operator.
 */
export interface RelayGauges {
  /** Identities of the app (credentials of the client) open at once, over all services; those past their keep time are not counted. */
  identities: number;
  /** Entries of the replay cache whose head could still pass the window (expired ones that are not yet dropped are not counted). */
  replayEntries: number;
  /** Per offered service: requests that wait (in a window, a queue or for the minimum distance); not those at the service. */
  queued: Record<string, number>;
  /**
   * Per service with a known value: the absolute difference in ms between the `genTime` of its last verified token and the
   * relay's wall clock when the answer was read (includes the time of the call itself).
   */
  lastGenTimeDeltaMs: Record<string, number>;
  /** Per service that was called: seconds (whole, monotonic clock) since the last call to it was made. */
  lastServiceCallAgeSeconds: Record<string, number>;
}

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
  /** Read-only numbers for `/metrics` (see `RelayGauges`); changes nothing, drops nothing. */
  gauges: () => RelayGauges;
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

/** What the parts of the relay (`auth-head.ts`, `budgets.ts`, `identities.ts`, `obtain.ts`, `planner.ts`, `flush.ts`) share; built once by `createRelay`. */
export interface RelayContext {
  options: RelayOptions;
  stats: RelayStats;
  batch: RelayOptions['batch'];
  /** The window of the budget counters in ms (`options.budgetWindowMs`). */
  bw: number;
  maxWaitMs: number;
  /** The monotonic clock in ms. */
  mono: () => number;
  /** The clock of the planner and the counters per minute: the monotonic one (`mono`) in both operations. */
  tick: () => number;
  /** Does the relay run with authentication (`options.keys` is a list)? */
  authRequired: boolean;
  /** `closed` is true once `close()` ran: the waiting is over and new requests get `503 shutting-down`. */
  life: { closed: boolean };
  /** Counts a refusal code without an answer of the relay (`stats.refused`). */
  countOnce: (kind: string) => void;
}
