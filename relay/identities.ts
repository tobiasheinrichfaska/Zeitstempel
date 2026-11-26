import { isAuthHeaderName } from '../src/lib/services.ts';
import {
  credentialIdentity,
  credentialsFromClient,
  validCredentials,
  type UpstreamCredentials,
} from './credentials.ts';
import { RELAY_LIMITS } from './limits.ts';
import type { RelayContext, RelayService } from './types.ts';

/**
 * The credentials of paid services (checked at start; throws, no content) and the identities of the app that bring their own:
 * `forget(key)` drops what the other parts hold for an identity that is gone (budget times, gate, lane, last call, shares).
 */
export function createIdentities(
  ctx: RelayContext,
  usable: readonly RelayService[],
  byId: ReadonlyMap<string, RelayService>,
  forget: (key: string) => void,
) {
  const { options, mono, bw } = ctx;
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
        forget(key);
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

  return { known, expired, credentialsFor, identitiesFullWait, touchIdentity };
}
