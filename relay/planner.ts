import type { UpstreamCredentials } from './credentials.ts';
import { createFlush, LAPSED, answerAll } from './flush.ts';
import { WAIT_TOLERANCE_MS } from './limits.ts';
import type { Obtained, createObtain } from './obtain.ts';
import type { RelayContext, RelayService } from './types.ts';

/**
 * The gate of one lane (service and identity) in single operation: the monotonic time of the last call made, the
 * earliest time the next reservation may call (each reservation books `minIntervalMs` after the one before), and the
 * requests that wait for their time. Memory only, never output.
 */
export interface Gate {
  last: number;
  next: number;
  waiting: Set<GateWait>;
}

export interface GateWait {
  timer: ReturnType<typeof setTimeout> | null;
  resolve: (how: 'go' | 'busy' | 'closing' | 'gone' | 'lapsed') => void;
}

export interface Reply {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
  /** Nothing was sent to the service for this request: what it spent comes back. */
  unsent?: true;
}

export interface Waiting {
  hash: Uint8Array;
  resolve: (reply: Reply) => void;
  /** Is its key still valid? Looked at again when it is stamped. */
  valid: () => boolean;
}

export interface Window {
  service: RelayService;
  /** The lane (service and identity) this window belongs to; windows of different credentials are never merged. */
  key: string;
  creds: UpstreamCredentials | undefined;
  waiting: Waiting[];
  timer: ReturnType<typeof setTimeout> | null;
  /** When it will be stamped at the latest (opening + window length): the time its slot is booked for. */
  stampAt: number;
}

/** A request that waits for a slot of its service (not yet in a window, not yet stamped). */
export interface Queued extends Waiting {
  timer: ReturnType<typeof setTimeout> | null;
  /** The monotonic time its wait ends (arrival + `maxWaitMs`); the timer of the wait is real and a loop that stood still fires it late. */
  deadline: number;
  solo: boolean;
}

/**
 * The planner of one service: requests that wait for a slot. A slot is one stamp of the service (the budget
 * `60000 / minIntervalMs` per minute): a window takes one, a solo stamp takes one. They alternate when both wait.
 */
export interface Lane {
  service: RelayService;
  key: string;
  creds: UpstreamCredentials | undefined;
  solo: Queued[];
  normal: Queued[];
  lastWasSolo: boolean;
  timer: ReturnType<typeof setTimeout> | null;
}

/**
 * A window that is closed but must wait for the minimum distance to the last call of its service before it is
 * stamped; in the order of their stamps.
 */
export interface Delayed {
  at: number;
  w: Window;
  timer: ReturnType<typeof setTimeout> | null;
}

/**
 * The planner: when a call to a service may be made. Single operation: a gate per lane (service and identity) that keeps the
 * minimum distance. Collecting operation: windows, queues and slots per lane, solo stamps, the chain of windows that wait for
 * the distance. Everything on the monotonic clock; memory only, never output.
 */
export function createPlanner(
  ctx: RelayContext,
  windows: Map<string, number[]>,
  obtainer: ReturnType<typeof createObtain>,
) {
  const { stats, mono, tick, bw, batch, maxWaitMs, life } = ctx;
  const { obtain, stampBody } = obtainer;
  const { flush } = createFlush(ctx, obtainer);
  // ---- Single operation: the minimum distance ----

  const gates = new Map<string, Gate>();

  /** Milliseconds until a call of this lane may be made without coming closer than `minIntervalMs` to the one before (0: now). */
  function gateWaitMs(key: string, minIntervalMs: number): number {
    const g = gates.get(key);
    if (g === undefined) return 0;
    return Math.max(0, g.next - mono(), g.last + minIntervalMs - mono());
  }

  /**
   * One stamp in single operation, at least `minIntervalMs` after the call before it (on the monotonic clock, whatever
   * the wall clock does): it takes the next free time of its lane at once (so the order is the order of arrival) and
   * waits for it. The door has refused a time later than `maxWaitMs`; when the call is late because the ones before it
   * were (a loop that stood still), it is `503 busy` rather than later than the limit. `close()` ends the wait.
   */
  async function spaced(
    service: RelayService,
    key: string,
    hash: Uint8Array,
    creds: UpstreamCredentials | undefined,
    aborted: () => boolean,
    valid: () => boolean,
  ): Promise<Obtained | 'gone'> {
    const m = service.minIntervalMs;
    let g = gates.get(key);
    if (g === undefined) {
      g = { last: -Infinity, next: -Infinity, waiting: new Set() };
      gates.set(key, g);
    }
    const gate = g;
    const start = mono();
    const at = Math.max(start, gate.next, gate.last + m);
    gate.next = at + m;
    if (at <= start) {
      gate.last = start;
      return obtain(service, hash, creds);
    }
    const deadline = start + maxWaitMs;
    // The time this request booked is given back when it will not call after all (busy, client gone) and it is the last
    // of the chain: a gap in the middle is not filled (the order of arrival stays), but the end of the chain must not
    // wait for a call nobody makes. The distance to the call really made (`gate.last`) is checked at every call anyway.
    const giveBack = (): void => {
      if (gate.next === at + m) gate.next = at;
    };
    const how = await new Promise<'go' | 'busy' | 'closing' | 'gone' | 'lapsed'>((resolve) => {
      const entry: GateWait = { timer: null, resolve };
      gate.waiting.add(entry);
      const finish = (h: 'go' | 'busy' | 'closing' | 'gone' | 'lapsed'): void => {
        gate.waiting.delete(entry);
        entry.timer = null;
        resolve(h);
      };
      const look = (): void => {
        const t = mono();
        if (aborted()) {
          giveBack();
          return finish('gone');
        }
        // the key may have been revoked or removed while the request waited: no call for it
        if (!valid()) {
          giveBack();
          return finish('lapsed');
        }
        // the distance to the call that was made last, as it really was (a timer may fire late or a bit early)
        const due = Math.max(at, gate.last + m);
        // the door lets the last one through at the very limit, and every call before it may be a few ms late
        // (timers): the sum of those delays must not cost the request the slot the door promised
        // `t` counts too: a loop that stood still fires the timer long after `due`, and the call would then lie far
        // past the limit although the time it booked was within it
        if (Math.max(due, t) > deadline + WAIT_TOLERANCE_MS) {
          giveBack();
          return finish('busy');
        }
        if (due > t) {
          entry.timer = setTimeout(look, Math.ceil(due - t));
          return;
        }
        gate.last = t; // the call is made now: the next one counts from here
        finish('go');
      };
      entry.timer = setTimeout(look, Math.ceil(at - start));
    });
    if (how === 'closing') {
      return { ok: false, status: 503, body: { error: 'shutting-down' }, unsent: true };
    }
    if (how === 'gone') return 'gone';
    if (how === 'lapsed')
      return { ok: false, status: 401, body: { error: 'unauthorized' }, unsent: true };
    if (how === 'busy') {
      return {
        ok: false,
        status: 503,
        unsent: true,
        body: { error: 'busy' },
        headers: { 'Retry-After': String(Math.max(1, Math.ceil((gate.next - mono()) / 1000))) },
      };
    }
    return obtain(service, hash, creds);
  }

  // ---- Collecting operation ----

  const openWindows = new Map<string, Window>(); // lane key -> the window that takes requests

  const lanes = new Map<string, Lane>();
  const laneOf = (
    key: string,
    service: RelayService,
    creds: UpstreamCredentials | undefined,
  ): Lane => {
    let lane = lanes.get(key);
    if (lane === undefined) {
      lane = { service, key, creds, solo: [], normal: [], lastWasSolo: false, timer: null };
      lanes.set(key, lane);
    }
    return lane;
  };

  /** The time (`tick`: the monotonic clock) of the last call to a service per lane (service and identity); memory only, never output. */
  const lastCall = new Map<string, number>();
  const delayedWindows = new Map<string, Delayed[]>(); // lane key -> its delayed windows

  /**
   * The times the windows of a lane will stamp, still to come, in ascending order: the windows that wait for the
   * distance (at that time) and the open one (opening + window length, at most one window length ahead even if the
   * clock was set back).
   */
  function reservedStamp(key: string, now: number): number[] {
    const times = (delayedWindows.get(key) ?? []).map((d, i) =>
      Math.min(d.at, now + (i + 1) * d.w.service.minIntervalMs),
    );
    const open = openWindows.get(key);
    if (open !== undefined) times.push(Math.min(open.stampAt, now + batch!.windowMs));
    return times.sort((a, b) => a - b);
  }

  /**
   * Milliseconds until a call to the service of this lane may be made without coming closer than `minIntervalMs` to
   * the one before (0: now): the last call made, and the windows that are delayed and will call before it (all of them,
   * or only those before `before`). A time in the future (the clock was set back) counts as `now`; the k-th delayed
   * window counts at most k times `minIntervalMs` ahead (the chain of delayed windows lies one distance apart each, so
   * the k-th is that far ahead at the most; a clock that was set back cannot hold it longer).
   */
  function spacingMs(key: string, minIntervalMs: number, now: number, before?: Delayed): number {
    let last = -Infinity;
    const made = lastCall.get(key);
    if (made !== undefined) {
      // stored as `now` from here on (the same rule as for the budget): a clock that stays behind cannot hold it ahead
      if (made > now) lastCall.set(key, now);
      last = Math.min(made, now);
    }
    let position = 0;
    for (const d of delayedWindows.get(key) ?? []) {
      if (d === before) break;
      position += 1;
      last = Math.max(last, Math.min(d.at, now + position * minIntervalMs));
    }
    return last === -Infinity ? 0 : Math.max(0, last + minIntervalMs - now);
  }

  /**
   * Milliseconds until the service has a free slot (0: now). A slot is counted at the time of the STAMP, the
   * moment the service sees the call: the times of the stamps made, and for an open window the time it will be
   * stamped (`open + windowMs`, at the latest), for a window that waits for the distance the time it will call. So a
   * window holds its slot from its opening on, and the stamps that come before it count it already: in any minute
   * the service sees at most `bw / minIntervalMs` calls. The minimum distance to the last call is a second rule
   * (`spacingMs`) that the solo stamps and the stamps of the windows keep on top of this one.
   */
  function slotWaitMs(key: string, service: RelayService): number {
    const now = tick();
    // times in the future (the clock was set back) count as `now` and are stored so: a request that waits and looks again
    // (no new request passes `budget`) would else see the same future time every time and wait for the length of the jump
    const own = (windows.get(key) ?? []).filter((t) => now - t < bw).map((t) => Math.min(t, now));
    windows.set(key, own);
    // except the stamps that are still to come (windows, at most one window length ahead)
    const booked = [...own, ...reservedStamp(key, now)];
    const limit = Math.max(1, Math.floor(bw / service.minIntervalMs));
    return booked.length >= limit ? Math.max(1, bw - (now - booked[booked.length - limit]!)) : 0;
  }

  /** Books a call to the service at this moment: the budget and the last call (the distance counts from here). */
  function takeSlot(key: string): void {
    const now = tick();
    const own = windows.get(key) ?? [];
    own.push(now);
    windows.set(key, own);
    lastCall.set(key, now);
  }

  /** A request joins a window that is open (it takes no slot: the window has one). */
  function joinOpen(w: Window, hash: Uint8Array, valid: () => boolean): Promise<Reply> {
    return new Promise((resolve) => {
      w.waiting.push({ hash, resolve, valid });
      if (w.waiting.length >= batch!.max) closeWindow(w); // full: the next request waits for a slot
    });
  }

  /** Opens the window of a service with the requests that wait for it (the timer starts now). */
  function openWindowWith(lane: Lane, items: Waiting[]): void {
    const created: Window = {
      service: lane.service,
      key: lane.key,
      creds: lane.creds,
      waiting: items,
      timer: null,
      stampAt: tick() + batch!.windowMs,
    };
    created.timer = setTimeout(() => closeWindow(created), batch!.windowMs);
    openWindows.set(lane.key, created);
    if (items.length >= batch!.max) closeWindow(created);
  }

  /**
   * A request that needs a slot: it waits in the queue of its service (for the longest `maxWaitMs`, then
   * `503 busy`); `dispatch` serves it at once when a slot is free.
   */
  function enqueue(
    service: RelayService,
    key: string,
    creds: UpstreamCredentials | undefined,
    hash: Uint8Array,
    solo: boolean,
    valid: () => boolean,
  ): Promise<Reply> {
    return new Promise((resolve) => {
      const lane = laneOf(key, service, creds);
      const item: Queued = {
        hash,
        resolve,
        valid,
        timer: null,
        deadline: tick() + maxWaitMs,
        solo,
      };
      item.timer = setTimeout(() => dropBusy(lane, item), maxWaitMs);
      (solo ? lane.solo : lane.normal).push(item);
      dispatch(lane);
    });
  }

  /** A request leaves the queue of its lane with `503 busy` (its wait is over); false when it is not in the queue any more. */
  function dropBusy(lane: Lane, item: Queued): boolean {
    const list = item.solo ? lane.solo : lane.normal;
    const at = list.indexOf(item);
    if (at < 0) return false;
    list.splice(at, 1);
    if (item.timer !== null) clearTimeout(item.timer);
    const waitMs = Math.max(
      slotWaitMs(lane.key, lane.service),
      item.solo ? spacingMs(lane.key, lane.service.minIntervalMs, tick()) : 0,
    );
    item.resolve({
      status: 503,
      body: { error: 'busy' },
      headers: { 'Retry-After': String(Math.max(1, Math.ceil(waitMs / 1000))) },
      unsent: true,
    });
    return true;
  }

  /**
   * Gives free slots to the waiting requests: a solo request and a window alternate, so nothing starves. A window
   * needs a slot of the budget; a solo stamp needs one too and, on top, the minimum distance to the last call of the
   * service (a window keeps the distance when it stamps, see `stampWindow`).
   */
  function dispatch(lane: Lane): void {
    const service = lane.service;
    if (lane.timer !== null) clearTimeout(lane.timer);
    lane.timer = null;
    // a request whose wait is over (by the monotonic clock) gets no slot: after a stall the timer of this lane may fire
    // before the timer of the wait, and the stamp would lie past the limit
    const late = tick() - WAIT_TOLERANCE_MS;
    for (const item of [...lane.solo, ...lane.normal])
      if (item.deadline < late) dropBusy(lane, item);
    while (!life.closed && lane.solo.length + lane.normal.length > 0) {
      const countWait = slotWaitMs(lane.key, service);
      const soloWait = Math.max(countWait, spacingMs(lane.key, service.minIntervalMs, tick()));
      const canSolo = lane.solo.length > 0 && soloWait === 0;
      const canNormal = lane.normal.length > 0 && countWait === 0;
      if (!canSolo && !canNormal) {
        const wait = Math.min(
          lane.solo.length > 0 ? soloWait : Infinity,
          lane.normal.length > 0 ? countWait : Infinity,
        );
        lane.timer = setTimeout(() => dispatch(lane), wait);
        return;
      }
      const solo = canSolo && (!canNormal || !lane.lastWasSolo);
      lane.lastWasSolo = solo;
      if (solo) {
        takeSlot(lane.key); // the stamp is made now
        const item = lane.solo.shift()!;
        if (item.timer !== null) clearTimeout(item.timer);
        stampSolo(lane, item);
      } else {
        // the window takes the requests that wait, up to its size; the others wait for the next slot
        // (its slot is booked by the window itself: `stampAt` while it is open, the real stamp time at its close)
        const items = lane.normal.splice(0, batch!.max);
        for (const i of items) if (i.timer !== null) clearTimeout(i.timer);
        openWindowWith(lane, items);
      }
    }
  }

  /** A direct stamp of one hash (key type 2, no tree, no `batch` in the answer). */
  function stampSolo(lane: Lane, item: Waiting): void {
    const done = async (): Promise<void> => {
      if (!item.valid()) return item.resolve(LAPSED); // its key lapsed while it waited: no call
      const got = await obtain(lane.service, item.hash, lane.creds);
      if (!got.ok) return item.resolve({ status: got.status, body: got.body });
      stats.stamped += 1;
      stats.solo = (stats.solo ?? 0) + 1;
      item.resolve({ status: 200, body: stampBody(lane.service, got) });
    };
    done().catch(() => item.resolve({ status: 500, body: { error: 'internal' } }));
  }

  function closeWindow(w: Window): void {
    if (openWindows.get(w.key) !== w) return; // closed already (timer and full window meet)
    openWindows.delete(w.key);
    if (w.timer !== null) clearTimeout(w.timer);
    stampWindow(w);
    // a lane that waits for a slot looks again: a window that closed early frees its slot earlier than booked
    const waiting = lanes.get(w.key);
    if (waiting !== undefined && waiting.timer !== null) dispatch(waiting);
  }

  /**
   * The closed window calls the service: at once, or when the minimum distance to the last call is kept (a window that
   * closes full right after a solo stamp or another window would else come closer). Until then it holds its place
   * (`delayedWindows`: counted by the budget, the distance counts from it).
   */
  function stampWindow(w: Window): void {
    const now = tick();
    const wait = spacingMs(w.key, w.service.minIntervalMs, now);
    if (wait <= 0) return callService(w);
    const d: Delayed = { at: now + wait, w, timer: null };
    delayedWindows.set(w.key, [...(delayedWindows.get(w.key) ?? []), d]);
    armDelayed(d, wait);
  }

  function armDelayed(d: Delayed, ms: number): void {
    if (d.timer !== null) clearTimeout(d.timer);
    d.timer = setTimeout(() => fireDelayed(d), Math.ceil(ms));
  }

  /**
   * The wait is over (a timer of the length of the distance, on the monotonic clock like the distance itself). Windows
   * call in the order they closed: one that is not the first does not look again on its own (no polling): the one in
   * front arms it when that has called (or has to wait longer than it thought: a loop that stood still, a timer
   * that fired early).
   */
  function fireDelayed(d: Delayed): void {
    d.timer = null;
    const list = delayedWindows.get(d.w.key) ?? [];
    const index = list.indexOf(d);
    if (index < 0 || index > 0) return;
    const mi = d.w.service.minIntervalMs;
    // the distance again: the loop may have stood still while this and the one before were due
    const now = tick();
    const wait = spacingMs(d.w.key, mi, now, d);
    if (wait > 0) {
      d.at = now + wait;
      let before = d.at;
      for (const e of list.slice(1)) {
        // the windows behind it keep their distance to it
        before += mi;
        e.at = Math.max(e.at, before);
        before = e.at;
      }
      return armDelayed(d, wait);
    }
    list.splice(index, 1);
    if (list.length === 0) delayedWindows.delete(d.w.key);
    callService(d.w);
    // the next one calls one distance after this call (a timer of that length, once)
    const next = list[0];
    if (next !== undefined) armDelayed(next, Math.max(1, spacingMs(d.w.key, mi, tick(), next)));
  }

  /** The window is stamped now: the slot is booked at this time, then the tree is built and the service is called. */
  function callService(w: Window): void {
    takeSlot(w.key);
    flush(w).catch(() => answerAll(w.waiting, { status: 500, body: { error: 'internal' } }));
  }

  function close(): void {
    life.closed = true;
    for (const g of gates.values()) {
      for (const w of [...g.waiting]) {
        if (w.timer !== null) clearTimeout(w.timer);
        g.waiting.delete(w);
        w.resolve('closing');
      }
    }
    for (const w of [...openWindows.values()]) {
      openWindows.delete(w.key);
      if (w.timer !== null) clearTimeout(w.timer);
      answerAll(w.waiting, { status: 503, body: { error: 'shutting-down' }, unsent: true });
    }
    for (const list of [...delayedWindows.values()]) {
      for (const d of list) {
        if (d.timer !== null) clearTimeout(d.timer);
        answerAll(d.w.waiting, { status: 503, body: { error: 'shutting-down' }, unsent: true });
      }
    }
    delayedWindows.clear();
    for (const lane of lanes.values()) {
      if (lane.timer !== null) clearTimeout(lane.timer);
      lane.timer = null;
      const queued = [...lane.solo.splice(0), ...lane.normal.splice(0)];
      for (const q of queued) {
        if (q.timer !== null) clearTimeout(q.timer);
        q.resolve({ status: 503, body: { error: 'shutting-down' }, unsent: true });
      }
    }
  }

  return {
    gates,
    openWindows,
    lanes,
    delayedWindows,
    lastCall,
    gateWaitMs,
    spaced,
    joinOpen,
    enqueue,
    reservedStamp,
    spacingMs,
    close,
  };
}
