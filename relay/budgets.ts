import type { KeyState } from './auth-head.ts';
import { RELAY_LIMITS } from './limits.ts';
import type { RelayContext } from './types.ts';

/** What the budgets need of the planner (it is made after them): the stamps still to come and the distance to the last call. */
export interface BudgetHooks {
  reservedStamp: (key: string, now: number) => number[];
  spacingMs: (key: string, minIntervalMs: number, now: number) => number;
}

/** The counters per minute: total, per service and identity (lane), per key, the share of a key, the solo stamps of a key. */
export function createBudgets(ctx: RelayContext, ks: KeyState, hooks: BudgetHooks) {
  const { options, tick, bw, batch } = ctx;
  const { reservedStamp, spacingMs } = hooks;
  // lane key (the service id; for credentials of the client `<id>#<digest>`) → times of the service's requests/slots in the window
  const windows = new Map<string, number[]>();
  const keyWindows = new Map<string, number[]>(); // key id → request times in the window (memory only)
  // `RELAY_KEY_SHARE`: per (key id, lane) the times of the admitted requests in the window (memory only, never output).
  // Entries whose times are all expired are dropped at every admission: the table holds the keys and lanes active in the last window.
  const keyShare = options.keyShare ?? 100;
  if (!(Number.isInteger(keyShare) && keyShare >= 10 && keyShare <= 100)) {
    throw new Error('relay keyShare is invalid'); // at start, no content
  }
  const shares = new Map<string, number[]>();
  let total: number[] = [];

  const soloWindows = new Map<string, number[]>(); // key id -> solo request times (memory only, never logged)

  /**
   * Looks at the budget (total, per service, and per key when there is one) WITHOUT spending it: the
   * seconds to wait when any limit is reached (the longest of all that apply, so a client that waits
   * that long is not refused by another limit), and `spend` to count the request once it is served.
   */
  function budget(
    laneKey: string,
    minIntervalMs: number,
    kid: string | null,
    /**
     * true: the service's own budget counts and is spent with the rest; false: the request joins a window that
     * is open already, the service's budget is not touched; 'defer': only the total and the key count here, the
     * slot of the service is taken later by the planner (`slotMs` says how long until one is free).
     */
    forService: boolean | 'defer' = true,
    /** A solo stamp: it also has to keep the minimum distance to the last call of the service (`slotMs` counts it). */
    forSolo = false,
  ): { wait: number | null; slotMs: number; spend: () => void; unspend: () => void } {
    const now = tick();
    // Times in the future (the clock was set back) count as `now`: a jump back must not lock the budget
    // for the length of the jump, and the wait stays within one window.
    const fresh = (times: number[]): number[] =>
      times.filter((t) => now - t < bw).map((t) => Math.min(t, now));
    total = fresh(total);
    const own = fresh(windows.get(laneKey) ?? []);
    const mine = kid === null ? [] : fresh(keyWindows.get(kid) ?? []);
    // an identity not known yet leaves nothing behind when the request is refused (written by `spend`)
    if (windows.has(laneKey)) windows.set(laneKey, own);
    if (kid !== null) keyWindows.set(kid, mine);
    const ownLimit = Math.max(1, Math.floor(bw / minIntervalMs));
    // the slot that frees first is the (length - limit + 1)-th oldest entry
    const until = (times: number[], limit: number): number =>
      Math.max(1, Math.ceil((bw - (now - times[times.length - limit]!)) / 1000));
    const waits: number[] = [];
    if (total.length >= RELAY_LIMITS.perMinuteTotal) {
      waits.push(until(total, RELAY_LIMITS.perMinuteTotal));
    }
    // In collecting operation the slot of an open window counts too: its stamp is still to come (`stampAt`).
    const booked = batch ? [...own, ...reservedStamp(laneKey, now)] : own;
    const countMs =
      booked.length >= ownLimit ? Math.max(1, bw - (now - booked[booked.length - ownLimit]!)) : 0;
    const slotMs = forSolo ? Math.max(countMs, spacingMs(laneKey, minIntervalMs, now)) : countMs;
    if (forService === true && own.length >= ownLimit) waits.push(until(own, ownLimit));
    const keyLimit =
      kid === null ? 0 : (ks.perMinuteOfKid.get(kid) ?? RELAY_LIMITS.perMinutePerKey);
    if (kid !== null && mine.length >= keyLimit) {
      waits.push(until(mine, keyLimit));
    }
    return {
      wait: waits.length === 0 ? null : Math.max(...waits),
      slotMs,
      spend: () => {
        total.push(now);
        if (forService === true) {
          own.push(now);
          windows.set(laneKey, own);
        }
        if (kid !== null) mine.push(now);
      },
      // nothing was sent to the service after all: the count comes back
      unspend: () => {
        removeOne(total, now);
        if (forService === true) removeOne(windows.get(laneKey), now);
        if (kid !== null) removeOne(keyWindows.get(kid), now);
      },
    };
  }

  /** Takes one entry with this value (the newest) out of a list of times; nothing when it is gone already. */
  function removeOne(list: number[] | undefined, value: number): void {
    const at = list?.lastIndexOf(value) ?? -1;
    if (at >= 0) list!.splice(at, 1);
  }

  /**
   * The share of one key at one lane (`RELAY_KEY_SHARE`): the seconds to wait when the key has used its part of the lane's
   * budget in the last window, and `spend`. A look writes nothing. Null at 100 (off).
   */
  function shareBudget(
    laneKey: string,
    kid: string,
    minIntervalMs: number,
  ): { wait: number | null; spend: () => void; unspend: () => void } | null {
    if (keyShare >= 100) return null;
    const now = tick();
    const id = `${kid}|${laneKey}`;
    const times = (shares.get(id) ?? []).filter((t) => now - t < bw).map((t) => Math.min(t, now));
    const laneLimit = Math.max(1, Math.floor(bw / minIntervalMs));
    const limit = Math.max(1, Math.floor((laneLimit * keyShare) / 100));
    return {
      wait:
        times.length >= limit
          ? Math.max(1, Math.ceil((bw - (now - times[times.length - limit]!)) / 1000))
          : null,
      spend: () => {
        times.push(now);
        shares.set(id, times);
        for (const [other, list] of shares) {
          if (
            other !== id &&
            (list.length === 0 || now - Math.min(list[list.length - 1]!, now) >= bw)
          ) {
            shares.delete(other);
          }
        }
      },
      unspend: () => {
        removeOne(shares.get(id), now);
        // an empty list is no list (nothing would ever age it out)
        if (shares.get(id)?.length === 0) shares.delete(id);
      },
    };
  }

  /** The solo requests of one key in the last window: the seconds to wait when the limit is reached, and `spend`. Memory only. */
  function soloBudget(kid: string): {
    wait: number | null;
    spend: () => void;
    unspend: () => void;
  } {
    const now = tick();
    const times = (soloWindows.get(kid) ?? [])
      .filter((t) => now - t < bw)
      .map((t) => Math.min(t, now));
    soloWindows.set(kid, times);
    const limit = RELAY_LIMITS.soloPerMinutePerKey;
    return {
      wait:
        times.length >= limit
          ? Math.max(1, Math.ceil((bw - (now - times[times.length - limit]!)) / 1000))
          : null,
      spend: () => void times.push(now),
      unspend: () => removeOne(soloWindows.get(kid), now),
    };
  }

  return { windows, shares, budget, shareBudget, soloBudget };
}
