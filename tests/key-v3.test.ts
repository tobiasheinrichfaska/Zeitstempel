import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { toBase64Url } from '../src/index.ts';
import { loadKeyFile, readKeyFileFull, type RelayKey } from '../relay/keys.ts';
import { createKeyWatcher } from '../relay/keywatch.ts';
import { loadServices } from '../relay/load.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import type { RelayOptions } from '../relay/relay.ts';
import { createRelayServer } from '../relay/server.ts';
import type { Upstream } from '../relay/upstream.ts';
import { TEST_AUDIENCE, makeTestKey, nodeAuthHeaderMs, type TestKey } from './auth-helpers.ts';
import { sha256 } from './helpers.ts';
import { build, int, seq } from './token-builder.ts';
import { children, integerBytes, octets, parseDer } from '../src/lib/der.ts';

// Key file version 3 (docs/relay.md, "Schlüsseldatei Version 3"): per entry `revoked`, `notAfter`, `services`,
// `perMinute`; an expressly empty list blocks everybody at the next look; a deleted or invalid file keeps the old set.

const ALL = loadServices();
const SERVICES = ALL.filter((s) => s.id === 'freetsa' || s.id === 'sectigo');
const KNOWN = new Set(ALL.map((s) => s.id));
const SIGNER = build();
const ORIGIN = 'https://app.example';
const A = makeTestKey('app-a');
const B = makeTestKey('app-b');
const C = makeTestKey('app-c');
const unknownKey = makeTestKey('app-x'); // never in a file

const pub = (k: TestKey) => toBase64Url(k.publicKey);
const entry = (k: TestKey, more: Record<string, unknown> = {}) => ({
  id: k.id,
  publicKey: pub(k),
  ...more,
});
const file3 = (keys: unknown[], over: Record<string, unknown> = {}) => ({
  version: 3,
  keys,
  ...over,
});
const rk = (k: TestKey, more: Partial<RelayKey> = {}): RelayKey => ({
  id: k.id,
  publicKey: k.publicKey,
  ...more,
});

describe('key file version 3: the reader', () => {
  it('reads every new field and returns it', () => {
    const r = readKeyFileFull(
      file3([
        entry(A, { revoked: true }),
        entry(B, { notAfter: 1_900_000_000, services: ['freetsa', 'sectigo'], perMinute: 5 }),
        entry(C, { revoked: false, solo: true }),
      ]),
      KNOWN,
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.keys[0]).toMatchObject({ id: 'app-a', revoked: true });
    expect(r.value.keys[1]).toMatchObject({
      notAfter: 1_900_000_000,
      services: ['freetsa', 'sectigo'],
      perMinute: 5,
    });
    expect(r.value.keys[1]!.revoked).toBeUndefined();
    expect(r.value.keys[2]!.revoked).toBeUndefined(); // false is the same as absent
    expect(r.value.keys[2]!.solo).toBe(true);
  });

  it('version 2 stays readable and a v3 field in a version 2 file is a read error with the index', () => {
    expect(readKeyFileFull({ version: 2, keys: [entry(A, { solo: true })] }).ok).toBe(true);
    const fields: Record<string, unknown> = {
      revoked: true,
      notAfter: 1_900_000_000,
      services: ['freetsa'],
      perMinute: 3,
    };
    for (const [name, value] of Object.entries(fields)) {
      const r = readKeyFileFull({ version: 2, keys: [entry(A), entry(B, { [name]: value })] });
      expect(r, name).toMatchObject({ ok: false, detail: 'v3-field-in-v2-file in keys[1]' });
    }
    expect(readKeyFileFull({ version: 4, keys: [] })).toMatchObject({ ok: false });
  });

  it('is strict: each field has exactly its type and range, no unknown field, index in the error', () => {
    const bad: [string, Record<string, unknown>, string][] = [
      ['revoked as text', { revoked: 'true' }, 'revoked'],
      ['revoked as number', { revoked: 1 }, 'revoked'],
      ['revoked null', { revoked: null }, 'revoked'],
      ['notAfter fraction', { notAfter: 1_900_000_000.5 }, 'not-after'],
      ['notAfter text', { notAfter: '1900000000' }, 'not-after'],
      ['notAfter too small', { notAfter: 5 }, 'not-after'],
      ['notAfter too large', { notAfter: 1e12 }, 'not-after'],
      ['notAfter NaN-like', { notAfter: null }, 'not-after'],
      ['perMinute 0', { perMinute: 0 }, 'per-minute'],
      [
        'perMinute above the global limit',
        { perMinute: RELAY_LIMITS.perMinutePerKey + 1 },
        'per-minute',
      ],
      ['perMinute fraction', { perMinute: 1.5 }, 'per-minute'],
      ['perMinute text', { perMinute: '3' }, 'per-minute'],
      ['services empty', { services: [] }, 'services'],
      ['services 17 ids', { services: Array.from({ length: 17 }, (_, i) => `s${i}`) }, 'services'],
      ['services not an array', { services: 'freetsa' }, 'services'],
      ['services entry not a string', { services: [5] }, 'services'],
      ['services bad pattern', { services: ['FreeTSA'] }, 'services'],
      ['services duplicate', { services: ['freetsa', 'freetsa'] }, 'services'],
      ['services unknown id', { services: ['freetsa', 'nosuch'] }, 'services-unknown'],
      ['unknown field', { note: 'x' }, 'entry-fields'],
    ];
    for (const [name, more, rule] of bad) {
      const r = readKeyFileFull(file3([entry(A), entry(B, more)]), KNOWN);
      expect(r, name).toMatchObject({
        ok: false,
        reason: 'bad-key-file',
        detail: `${rule} in keys[1]`,
      });
    }
    // exactly at the edges
    expect(readKeyFileFull(file3([entry(A, { perMinute: 1 })]), KNOWN).ok).toBe(true);
    expect(
      readKeyFileFull(file3([entry(A, { perMinute: RELAY_LIMITS.perMinutePerKey })]), KNOWN).ok,
    ).toBe(true);
    const sixteen = ALL.map((s) => s.id).slice(0, 4);
    expect(readKeyFileFull(file3([entry(A, { services: sixteen })]), KNOWN).ok).toBe(true);
  });

  it('an unknown service id is checked only when the known ids are given; the message names no content', () => {
    expect(readKeyFileFull(file3([entry(A, { services: ['nosuch'] })])).ok).toBe(true);
    const text = JSON.stringify(file3([entry(A), entry(B, { services: ['nosuch-secretish'] })]));
    try {
      loadKeyFile('/x/keys.json', () => text, KNOWN);
      expect.unreachable();
    } catch (e) {
      const m = (e as Error).message;
      expect(m).toContain('services-unknown in keys[1]');
      expect(m).not.toContain('nosuch-secretish');
      expect(m).not.toContain(pub(B));
    }
  });

  it('an expressly empty list is valid in both versions (nobody may stamp)', () => {
    for (const version of [2, 3]) {
      const r = readKeyFileFull({ version, keys: [] });
      expect(r).toEqual({ ok: true, value: { keys: [] } });
    }
    // not an empty list: no list, or something else than a list
    expect(readKeyFileFull({ version: 3 })).toMatchObject({ ok: false });
    expect(readKeyFileFull({ version: 3, keys: {} })).toMatchObject({ ok: false });
    expect(readKeyFileFull({ version: 3, keys: null })).toMatchObject({ ok: false });
    expect(readKeyFileFull({ version: 3, keys: [], restartAfter: 1_900_000_000 }).ok).toBe(true);
  });
});

// ---- the relay ----

const genTimeText = (ms: number) =>
  new Date(ms)
    .toISOString()
    .replace(/[-:T]/g, '')
    .replace(/\.\d+Z$/, 'Z');
const imprintOf = (request: Uint8Array): Uint8Array =>
  octets(children(children(parseDer(request))[1]!)[1]!);
function replyFor(request: Uint8Array, atMs: number): Uint8Array {
  const parts = children(parseDer(request));
  const made = build({
    keys: SIGNER.keys,
    hash: imprintOf(request),
    nonceBytes: integerBytes(parts[2]!),
    genTime: genTimeText(atMs),
  });
  return seq(seq(int(0)), made.token);
}

interface Harness {
  calls: string[]; // one entry for every call that reached the (stub) service
  verifications: { n: number };
  clock: { ms: number | null; offset: number };
  relay: ReturnType<typeof createRelayServer>['relay'];
  send: (
    key: TestKey,
    n: number,
    over?: { service?: string; head?: string; raw?: string },
  ) => Promise<Response>;
  close: () => Promise<void>;
}

async function start(keys: RelayKey[], batch: RelayOptions['batch'] = undefined): Promise<Harness> {
  const calls: string[] = [];
  const clock = { ms: null as number | null, offset: 0 };
  const verifications = { n: 0 };
  const stub: Upstream = async (_target, body) => {
    calls.push('call');
    return {
      status: 200,
      contentType: 'application/timestamp-reply',
      body: replyFor(body, clock.ms ?? Date.now() + clock.offset),
    };
  };
  const { verify } = await import('node:crypto');
  const options: RelayOptions = {
    services: SERVICES.map((s) => ({
      ...s,
      minIntervalMs: 1,
      anchorPems: [...s.anchorPems, SIGNER.caPem],
    })),
    origins: [ORIGIN],
    allowPlainHttp: false,
    upstream: stub,
    random: (n) => new Uint8Array(randomBytes(n)),
    now: () => clock.ms ?? Date.now() + clock.offset,
    keys,
    audience: TEST_AUDIENCE,
    verifySignature: ((...args: Parameters<typeof verify>) => {
      verifications.n += 1;
      return verify(...args);
    }) as typeof verify,
    ...(batch === undefined ? {} : { batch }),
  };
  const { server, relay } = createRelayServer(options);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const send: Harness['send'] = (key, n, o = {}) => {
    const path = `/v1/stamp/${o.service ?? 'freetsa'}`;
    const text = o.raw ?? JSON.stringify({ hash: toBase64Url(sha256(`v3-${n}`)) });
    const now = clock.ms ?? Date.now() + clock.offset;
    const head =
      o.head ?? nodeAuthHeaderMs(key, key.id, 'POST', path, now, new TextEncoder().encode(text));
    return fetch(base + path, {
      method: 'POST',
      body: text,
      headers: { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': head },
    });
  };
  return {
    calls,
    verifications,
    clock,
    relay,
    send,
    close: () =>
      new Promise((r) => {
        relay.close();
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}

describe('a revoked key is refused like an unknown one', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('gives the same 401 (status, body, headers) as an unknown key, counts it globally and does no work', async () => {
    h = await start([rk(A), rk(B, { revoked: true })]);
    const unknown = await h.send(unknownKey, 1);
    const revoked = await h.send(B, 2);
    expect(revoked.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(await revoked.text()).toBe(await unknown.text());
    const names = (r: Response) => [...r.headers.keys()].filter((k) => k !== 'date').sort();
    expect(names(revoked)).toEqual(names(unknown));
    expect(revoked.headers.get('content-length')).toBe(unknown.headers.get('content-length'));
    expect(h.calls).toHaveLength(0); // no service was called
    expect(h.relay.stats()).toEqual({
      stamped: 0,
      refused: { unauthorized: 2 },
      keyRevoked: 1,
    });
    expect(JSON.stringify(h.relay.stats())).not.toContain('app-b'); // no number or name per key
    // a valid key still works, and the revoked key's attempts spent no budget of it: its window stays empty
    expect((await h.send(A, 3)).status).toBe(200);
  });

  it('does the same work for revoked, expired, unknown and valid: exactly one signature check each', async () => {
    h = await start([rk(A), rk(B, { revoked: true }), rk(C, { notAfter: 1_000_000_000 })]);
    const counts: number[] = [];
    let n = 10;
    for (const key of [unknownKey, B, C, A]) {
      const before = h.verifications.n;
      await h.send(key, n++);
      counts.push(h.verifications.n - before);
    }
    expect(counts).toEqual([1, 1, 1, 1]);
  });

  it('counts a revoked key only for a valid signature (a guessed id with a wrong signature is no use of the key)', async () => {
    h = await start([rk(B, { revoked: true })]);
    const forged = nodeAuthHeaderMs(
      unknownKey,
      'app-b',
      'POST',
      '/v1/stamp/freetsa',
      Date.now(),
      new TextEncoder().encode(JSON.stringify({ hash: toBase64Url(sha256('v3-20')) })),
    );
    expect((await h.send(B, 20, { head: forged })).status).toBe(401);
    expect(h.relay.stats().keyRevoked).toBeUndefined();
    expect((await h.send(B, 21)).status).toBe(401);
    expect(h.relay.stats().keyRevoked).toBe(1);
  });

  it('takes effect with the next set: counters and the replay cache stay', async () => {
    h = await start([rk(A), rk(B)]);
    expect((await h.send(B, 30)).status).toBe(200);
    const before = h.relay.stats();
    h.relay.setKeys([rk(A), rk(B, { revoked: true })]);
    expect((await h.send(B, 31)).status).toBe(401);
    expect(h.relay.stats()).toMatchObject({ stamped: before.stamped, keyRevoked: 1 });
    // lifted again: the key works at once
    h.relay.setKeys([rk(A), rk(B)]);
    expect((await h.send(B, 32)).status).toBe(200);
    expect(h.relay.stats().keyRevoked).toBe(1);
  });

  it('an empty set blocks everybody at once (every call 401, no service call)', async () => {
    h = await start([rk(A)]);
    expect((await h.send(A, 40)).status).toBe(200);
    h.relay.setKeys([]);
    expect((await h.send(A, 41)).status).toBe(401);
    expect((await h.send(B, 42)).status).toBe(401);
    expect(h.calls).toHaveLength(1);
  });

  it('also in collecting operation', async () => {
    h = await start([rk(A, { revoked: true })], { windowMs: 1000, max: 10 });
    expect((await h.send(A, 50)).status).toBe(401);
    expect(h.relay.stats().keyRevoked).toBe(1);
  });
});

describe('notAfter', () => {
  let h: Harness;
  afterEach(() => h.close());
  const T = 1_900_000_000; // Unix seconds

  it('the key counts up to 1 ms before notAfter and is refused from notAfter on (the relay wall clock)', async () => {
    h = await start([rk(A, { notAfter: T })]);
    h.clock.ms = T * 1000 - 1000 - 1; // 1 ms before the second
    expect((await h.send(A, 60)).status).toBe(200);
    h.clock.ms = T * 1000 - 1;
    expect((await h.send(A, 61)).status).toBe(200);
    expect(h.relay.stats().keyExpired).toBeUndefined();
    h.clock.ms = T * 1000;
    const res = await h.send(A, 62);
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'unauthorized' }); // the same answer as for an unknown key
    expect(h.relay.stats().keyExpired).toBe(1);
    expect(h.relay.stats().keyRevoked).toBeUndefined();
    h.clock.ms = T * 1000 + 3_600_000;
    expect((await h.send(A, 63)).status).toBe(401);
    expect(h.relay.stats().keyExpired).toBe(2);
  });

  it('is judged at each request: a key set in the future works, then stops without a reload', async () => {
    h = await start([rk(A, { notAfter: Math.floor(Date.now() / 1000) + 3 })]);
    expect((await h.send(A, 64)).status).toBe(200);
    h.clock.offset = 10_000;
    expect((await h.send(A, 65)).status).toBe(401);
  });
});

describe('services of a key', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('another service is 403 service-not-allowed before any work; the named one works; others are untouched', async () => {
    h = await start([rk(A, { services: ['sectigo'], perMinute: 1 }), rk(B)]);
    const denied = await h.send(A, 70, { service: 'freetsa' });
    expect(denied.status).toBe(403);
    expect(await denied.json()).toEqual({ error: 'service-not-allowed' });
    // the same signed request again: still 403 (no replay entry was written), and no budget is spent
    const text = JSON.stringify({ hash: toBase64Url(sha256('v3-71')) });
    const head = nodeAuthHeaderMs(
      A,
      A.id,
      'POST',
      '/v1/stamp/freetsa',
      Date.now(),
      new TextEncoder().encode(text),
    );
    for (let i = 0; i < 3; i++) {
      expect((await h.send(A, 71, { raw: text, head })).status).toBe(403);
    }
    expect(h.calls).toHaveLength(0);
    // the key's own limit is 1 per minute: had the 403s spent budget, this would be 429
    expect((await h.send(A, 72, { service: 'sectigo' })).status).toBe(200);
    expect((await h.send(B, 73, { service: 'freetsa' })).status).toBe(200); // a key without the field: all services
    expect(h.relay.stats()).toMatchObject({
      serviceDenied: 4,
      refused: { 'service-not-allowed': 4 },
    });
  });

  it('is checked in collecting operation as well, before a window is opened', async () => {
    h = await start([rk(A, { services: ['sectigo'] })], { windowMs: 1000, max: 10 });
    expect((await h.send(A, 74, { service: 'freetsa' })).status).toBe(403);
    expect(h.relay.stats().serviceDenied).toBe(1);
    expect(h.relay.stats().batched).toBe(0);
  });

  it('a reload that changes the list takes effect at once', async () => {
    h = await start([rk(A)]);
    expect((await h.send(A, 75)).status).toBe(200);
    h.relay.setKeys([rk(A, { services: ['sectigo'] })]);
    expect((await h.send(A, 76)).status).toBe(403);
    h.relay.setKeys([rk(A)]);
    expect((await h.send(A, 77)).status).toBe(200);
  });
});

describe('perMinute of a key', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('a key with its own limit gets 429 above it (Retry-After), other keys are untouched', async () => {
    h = await start([rk(A, { perMinute: 2 }), rk(B)]);
    expect((await h.send(A, 80)).status).toBe(200);
    expect((await h.send(A, 81)).status).toBe(200);
    const third = await h.send(A, 82);
    expect(third.status).toBe(429);
    expect(Number(third.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    expect((await h.send(B, 83)).status).toBe(200);
    expect((await h.send(B, 84)).status).toBe(200);
    expect((await h.send(B, 85)).status).toBe(200); // B has the general limit
  });

  it('a key without the field keeps perMinutePerKey', async () => {
    h = await start([rk(A)]);
    for (let i = 0; i < RELAY_LIMITS.perMinutePerKey; i++) {
      expect((await h.send(A, 100 + i)).status, String(i)).toBe(200);
    }
    expect((await h.send(A, 200)).status).toBe(429);
  });

  it('the limit of the new set counts after a reload (the times already counted stay)', async () => {
    h = await start([rk(A)]);
    expect((await h.send(A, 210)).status).toBe(200);
    expect((await h.send(A, 211)).status).toBe(200);
    h.relay.setKeys([rk(A, { perMinute: 2 })]);
    expect((await h.send(A, 212)).status).toBe(429);
  });

  it('a value outside 1 to perMinutePerKey is refused by setKeys, and nothing changes', async () => {
    h = await start([rk(A)]);
    for (const perMinute of [0, RELAY_LIMITS.perMinutePerKey + 1, 1.5]) {
      expect(() => h.relay.setKeys([rk(A, { perMinute })])).toThrow();
    }
    expect((await h.send(A, 220)).status).toBe(200);
  });
});

describe('the key file read again: revoke, empty list, deleted and invalid file', () => {
  let h: Harness;
  let dir: string;
  let path: string;
  let nowMs: number;
  let watcher: ReturnType<typeof createKeyWatcher>;
  const events: string[] = [];
  const warnings: string[] = [];
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'zeitstempel-v3-'));
    path = join(dir, 'keys.json');
    events.length = 0;
    warnings.length = 0;
    nowMs = Date.now();
  });
  afterEach(async () => {
    watcher?.stop();
    await h.close();
    chmodSync(dir, 0o700);
    rmSync(dir, { recursive: true, force: true });
  });
  const write = (data: unknown) =>
    writeFileSync(path, typeof data === 'string' ? data : JSON.stringify(data));

  async function begin(initial: unknown): Promise<void> {
    write(initial);
    h = await start(loadKeyFile(path, undefined, KNOWN).keys);
    watcher = createKeyWatcher({
      path,
      load: (p) => loadKeyFile(p, undefined, KNOWN),
      apply: (list) => h.relay.setKeys(list),
      now: () => nowMs,
      startMs: nowMs,
      onRestart: () => void events.push('restart'),
      onReloaded: () => {
        events.push('reloaded');
        h.relay.noteKeyReload(true);
      },
      onFailed: () => {
        events.push('failed');
        h.relay.noteKeyReload(false);
      },
    });
    watcher.check(); // the first look: confirms the start
  }

  it('an entry turned to revoked stops at the next look; stamps and replay stay; lifting works again', async () => {
    await begin(file3([entry(A), entry(B)]));
    expect((await h.send(B, 300)).status).toBe(200);
    write(file3([entry(A), entry(B, { revoked: true })]));
    watcher.check(); // what the timer does every keyFileCheckMs
    expect(RELAY_LIMITS.keyFileCheckMs).toBeLessThanOrEqual(5_000);
    expect((await h.send(B, 301)).status).toBe(401);
    expect((await h.send(A, 302)).status).toBe(200);
    expect(h.relay.stats()).toMatchObject({ stamped: 2, keyRevoked: 1, keyReloads: 1 });
    write(file3([entry(A), entry(B)]));
    watcher.check();
    expect((await h.send(B, 303)).status).toBe(200);
  });

  it('an expressly empty list blocks every key at the next look', async () => {
    await begin(file3([entry(A), entry(B)]));
    expect((await h.send(A, 310)).status).toBe(200);
    write(file3([]));
    watcher.check();
    expect(events).toEqual(['reloaded']);
    expect((await h.send(A, 311)).status).toBe(401);
    expect((await h.send(B, 312)).status).toBe(401);
    expect(h.relay.stats().keyReloadFailed).toBeUndefined();
    write(file3([entry(A)]));
    watcher.check();
    expect((await h.send(A, 313)).status).toBe(200);
  });

  it('a start with an empty list is valid; the first key added is valid at the next look', async () => {
    await begin(file3([]));
    expect((await h.send(A, 320)).status).toBe(401);
    write(file3([entry(A)]));
    watcher.check();
    expect((await h.send(A, 321)).status).toBe(200);
  });

  it('a deleted file keeps the old set (not the empty one), counted once', async () => {
    await begin(file3([entry(A)]));
    unlinkSync(path);
    watcher.check();
    watcher.check();
    expect(events).toEqual(['failed']);
    expect((await h.send(A, 330)).status).toBe(200);
    expect(h.relay.stats().keyReloadFailed).toBe(1);
    write(file3([entry(B)])); // the file is back: the new set counts
    watcher.check();
    expect((await h.send(A, 331)).status).toBe(401);
    expect((await h.send(B, 332)).status).toBe(200);
  });

  it('unreadable, invalid, v3 field in a version 2 file, unknown service id: each keeps the old set', async () => {
    await begin(file3([entry(A)]));
    const bad: unknown[] = [
      '{ not json',
      { version: 3, keys: [{ id: 'Bad', publicKey: 'x' }] },
      { version: 2, keys: [entry(B, { revoked: true })] },
      file3([entry(B, { services: ['nosuch'] })]),
      file3([entry(B, { perMinute: 21 })]),
      file3([entry(B, { revoked: 'yes' })]),
    ];
    let n = 340;
    for (const b of bad) {
      write(b);
      watcher.check();
      expect((await h.send(A, n++)).status).toBe(200);
      expect((await h.send(B, n++)).status).toBe(401);
    }
    expect(events.filter((e) => e === 'failed')).toHaveLength(bad.length);
    expect(h.relay.stats().keyReloads).toBeUndefined();
  });
});

describe('scripts/make-key.ts prints a version 3 entry', () => {
  const run = (...args: string[]) =>
    spawnSync(process.execPath, ['scripts/make-key.ts', ...args], {
      cwd: new URL('..', import.meta.url),
      encoding: 'utf8',
      timeout: 15_000,
    });
  const entryOf = (r: ReturnType<typeof run>) =>
    JSON.parse(r.stdout.trimEnd().split('\n')[1]!) as Record<string, unknown>;

  it('without flags: id and publicKey only; --solo stays compatible', () => {
    expect(Object.keys(entryOf(run('app-1'))).sort()).toEqual(['id', 'publicKey']);
    expect(entryOf(run('app-1', '--solo'))).toMatchObject({ id: 'app-1', solo: true });
    expect(entryOf(run('--solo', 'app-1'))).toMatchObject({ solo: true });
  });
  it('--not-after, --services and --per-minute make the fields, and the reader takes the entry in a version 3 file', () => {
    const r = run(
      'app-2',
      '--solo',
      '--not-after',
      '1900000000',
      '--services',
      'freetsa,sectigo',
      '--per-minute',
      '5',
    );
    expect(r.status).toBe(0);
    const e = entryOf(r);
    expect(e).toMatchObject({
      id: 'app-2',
      solo: true,
      notAfter: 1_900_000_000,
      services: ['freetsa', 'sectigo'],
      perMinute: 5,
    });
    expect(readKeyFileFull({ version: 3, keys: [e] }, KNOWN).ok).toBe(true);
    expect(readKeyFileFull({ version: 2, keys: [e] }).ok).toBe(false);
    expect(r.stderr).toContain('"version": 3');
  });
  it('refuses wrong values and prints no key', () => {
    const bad = [
      ['app-3', '--not-after', 'soon'],
      ['app-3', '--not-after', '5'],
      ['app-3', '--per-minute', '0'],
      ['app-3', '--per-minute', '21'],
      ['app-3', '--services', ''],
      ['app-3', '--services', 'a,,b'],
      ['app-3', '--services', 'FreeTSA'],
      ['app-3', '--services', 'freetsa,freetsa'],
      ['app-3', '--services'],
      ['app-3', '--unknown'],
      ['app-3', '--not-after', '1900000000', '--not-after', '1900000001'],
    ];
    for (const args of bad) {
      const r = run(...args);
      expect(r.status, args.join(' ')).toBe(2);
      expect(r.stdout, args.join(' ')).toBe('');
    }
  });
});
