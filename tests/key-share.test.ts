import { spawn } from 'node:child_process';
import { createServer, type AddressInfo } from 'node:net';
import { toBase64Url } from '../src/index.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import { buildRelayOptions, readConfig, readSettings } from '../relay/main.ts';
import { createRelay } from '../relay/relay.ts';
import { nodeAuthHeaderMs } from './auth-helpers.ts';
import {
  KEY_A,
  KEY_B,
  KEY_C,
  KEY_D,
  KEY_F,
  SERVICES,
  sha256,
  sleep,
  solo,
  start,
  type Harness,
} from './spacing-harness.ts';

// `RELAY_KEY_SHARE`: ONE key may use at most `max(1, floor(budget * percent / 100))` of the places a service has per
// sliding minute (per lane: service and identity); more is `429 key-share` with `Retry-After`, and a refused request
// spends nothing (no total, no key budget, no replay entry). Single operation: every request counts (admission, wall
// clock like the other counters of that operation); collecting operation: the solo stamps (a window is one place for all
// its hashes). 100 (the default) is off. The budget of the tests: window 1000 ms and a distance of 83 ms = 12 places
// (like FreeTSA 12 per minute), or 250 ms = 4 places (like a 15 s service).

const FREETSA = { minIntervalMs: 83, budgetWindowMs: 1000 };
const SLOW = { minIntervalMs: 250, budgetWindowMs: 1000 };
const h1 = (tag: string, i: number) => sha256(`${tag}${i}`);
const statuses = (rs: Response[]) => rs.map((r) => r.status);

describe('RELAY_KEY_SHARE in single operation', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('50 percent of a budget of 12 (FreeTSA): one key gets 6 places, the 7th is 429 key-share, a second key still gets its places', async () => {
    h = await start({ batch: null, ...FREETSA, keyShare: 50, maxWaitMs: 10_000 });
    const a = await Promise.all(
      Array.from({ length: 8 }, (_, i) => h.stamp(h1('a', i), { key: KEY_A })),
    );
    expect(statuses(a)).toEqual([200, 200, 200, 200, 200, 200, 429, 429]);
    const refused = a[6]!;
    expect(await refused.json()).toEqual({ error: 'key-share' });
    expect(refused.headers.get('retry-after')).toBe('1');
    // the other key gets its places although the first one was greedy: 6 of the 12
    const f = await Promise.all(
      Array.from({ length: 7 }, (_, i) => h.stamp(h1('f', i), { key: KEY_F })),
    );
    // 6 + 6 places are all 12 of the service: the 7th request of the second key meets the budget of the service itself
    expect(statuses(f)).toEqual([200, 200, 200, 200, 200, 200, 429]);
    expect(await f[6]!.json()).toEqual({ error: 'rate-limited' });
    expect(h.calls).toHaveLength(12);
    expect(h.stats()).toEqual({
      stamped: 12,
      refused: { 'key-share': 2, 'rate-limited': 1 },
      shareDenied: 2,
    });
  });

  it('50 percent of a budget of 4 (a 15 s service): 2 places per key', async () => {
    h = await start({ batch: null, ...SLOW, keyShare: 50, maxWaitMs: 10_000 });
    const a = await Promise.all(
      Array.from({ length: 3 }, (_, i) => h.stamp(h1('a', i), { key: KEY_A })),
    );
    expect(statuses(a)).toEqual([200, 200, 429]);
    const f = await Promise.all(
      Array.from({ length: 3 }, (_, i) => h.stamp(h1('f', i), { key: KEY_F })),
    );
    expect(statuses(f)).toEqual([200, 200, 429]);
  });

  it('max(1, ...): a small share of a small budget is still one place per key, so every key gets one', async () => {
    h = await start({
      batch: null,
      minIntervalMs: 250,
      budgetWindowMs: 1000,
      keyShare: 10,
      maxWaitMs: 10_000,
    }); // 4 places, 3 keys
    const keys = [KEY_A, KEY_F, KEY_B];
    const first = await Promise.all(keys.map((k, i) => h.stamp(h1('first', i), { key: k })));
    expect(statuses(first)).toEqual([200, 200, 200]);
    const again = await Promise.all(keys.map((k, i) => h.stamp(h1('again', i), { key: k })));
    expect(again.map((r) => r.status)).toEqual([429, 429, 429]);
    expect(await again[0]!.json()).toEqual({ error: 'key-share' });
  });

  it('a refused request spends nothing: no total budget (60), no replay entry, no place', async () => {
    h = await start({ batch: null, ...FREETSA, keyShare: 10, maxWaitMs: 10_000 }); // 1 place per key
    expect((await h.stamp(h1('x', 0), { key: KEY_A })).status).toBe(200);
    // 70 refusals are more than the total budget per minute (60): if they cost total budget, the key below would be refused
    const many = await Promise.all(
      Array.from({ length: 70 }, (_, i) => h.stamp(h1('x', i + 1), { key: KEY_A })),
    );
    expect(new Set(statuses(many))).toEqual(new Set([429]));
    expect((await h.stamp(h1('y', 0), { key: KEY_F })).status).toBe(200);
    expect(h.calls).toHaveLength(2);
    // the very head of a refused request is no replay: once the key has its place again the same head passes
    const text = JSON.stringify({ hash: toBase64Url(h1('z', 0)) });
    const head = () =>
      nodeAuthHeaderMs(
        KEY_C,
        KEY_C.id,
        'POST',
        '/v1/stamp/freetsa',
        Date.now() + h.clock.offset,
        new TextEncoder().encode(text),
      );
    const fixed = head();
    expect((await h.stamp(h1('c', 0), { key: KEY_C })).status).toBe(200); // the place of C
    const refusedOnce = await h.stamp(h1('z', 0), { key: KEY_C, raw: text, head: fixed });
    expect(refusedOnce.status).toBe(429);
    h.mono.offset += 1100; // the window of the counters is over
    await sleep(100);
    const again = await h.stamp(h1('z', 0), { key: KEY_C, raw: text, head: fixed });
    expect(again.status).toBe(200); // a replay entry would make it 401
  });

  it('Retry-After is the time until the oldest place of the key frees', async () => {
    h = await start({
      batch: null,
      minIntervalMs: 500,
      budgetWindowMs: 6000,
      keyShare: 10,
      maxWaitMs: 10_000,
    });
    expect((await h.stamp(h1('r', 0), { key: KEY_A })).status).toBe(200);
    const r1 = await h.stamp(h1('r', 1), { key: KEY_A });
    expect(r1.status).toBe(429);
    expect(r1.headers.get('retry-after')).toBe('6');
    h.mono.offset += 3000;
    const r2 = await h.stamp(h1('r', 2), { key: KEY_A });
    expect(r2.headers.get('retry-after')).toBe('3');
    h.mono.offset += 3100;
    expect((await h.stamp(h1('r', 3), { key: KEY_A })).status).toBe(200);
  });

  it('with the default (not set) and with 100 nothing changes: one key uses the whole budget, the 13th is the old rate-limited', async () => {
    for (const keyShare of [undefined, 100]) {
      h = await start({
        batch: null,
        ...FREETSA,
        ...(keyShare === undefined ? {} : { keyShare }),
        maxWaitMs: 10_000,
      });
      const a = await Promise.all(
        Array.from({ length: 13 }, (_, i) => h.stamp(h1('d', i), { key: KEY_A })),
      );
      expect(statuses(a)).toEqual([...Array(12).fill(200), 429]);
      expect(await a[12]!.json()).toEqual({ error: 'rate-limited' });
      expect(h.stats().shareDenied).toBeUndefined();
      expect(h.relay.heldForTests().shares).toBe(0); // nothing is written when it is off
      await h.close();
    }
    h = await start({ batch: null }); // for afterEach
  });

  it('when the budget of the service is the reason too, the code stays rate-limited (and shareDenied does not count)', async () => {
    h = await start({ batch: null, ...SLOW, keyShare: 50, maxWaitMs: 10_000 });
    await Promise.all([KEY_F, KEY_F, KEY_A, KEY_A].map((k, i) => h.stamp(h1('s', i), { key: k })));
    // the service has no place left (4 of 4); A has used its 2 as well
    const res = await h.stamp(h1('s', 9), { key: KEY_A });
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: 'rate-limited' });
    expect(h.stats().shareDenied).toBeUndefined();
  });

  it('two identities (credentials of the app) are two lanes, each with its own share of the key', async () => {
    h = await start({ batch: null, bearer: true, ...FREETSA, keyShare: 50, maxWaitMs: 10_000 });
    const withToken = (i: number, t: string) => ({
      hash: toBase64Url(h1(t, i)),
      upstream: { token: t },
    });
    const one = await Promise.all(
      Array.from({ length: 7 }, (_, i) =>
        h.stamp(h1('t', i), { key: KEY_A, body: withToken(i, 'token-one') }),
      ),
    );
    expect(statuses(one)).toEqual([200, 200, 200, 200, 200, 200, 429]);
    const two = await Promise.all(
      Array.from({ length: 7 }, (_, i) =>
        h.stamp(h1('t', i), { key: KEY_A, body: withToken(i, 'token-two') }),
      ),
    );
    expect(statuses(two)).toEqual([200, 200, 200, 200, 200, 200, 429]);
  });

  it('reading the key file again (setKeys) does not change the counters', async () => {
    h = await start({ batch: null, ...FREETSA, keyShare: 10, maxWaitMs: 10_000 });
    expect((await h.stamp(h1('k', 0), { key: KEY_A })).status).toBe(200);
    const same = [KEY_A, KEY_F].map((k) => ({ id: k.id, publicKey: k.publicKey }));
    h.relay.setKeys(same);
    expect((await h.stamp(h1('k', 1), { key: KEY_A })).status).toBe(429);
    h.relay.setKeys(same);
    expect((await h.stamp(h1('k', 2), { key: KEY_A })).status).toBe(429);
  });

  it('the table is bounded: counters of keys that were idle for a window are dropped at the next admission', async () => {
    h = await start({ batch: null, ...FREETSA, keyShare: 50, maxWaitMs: 10_000 });
    for (const k of [KEY_A, KEY_F, KEY_B, KEY_C]) {
      expect((await h.stamp(h1('m', 0), { key: k })).status).toBe(200);
    }
    expect(h.relay.heldForTests().shares).toBe(4);
    h.mono.offset += 1100;
    expect((await h.stamp(h1('m', 1), { key: KEY_D })).status).toBe(200);
    expect(h.relay.heldForTests().shares).toBe(1);
  });

  it('without a key (authentication off) there is no share to count', async () => {
    h = await start({ batch: null, ...FREETSA, keyShare: 10, keys: 'off', maxWaitMs: 10_000 });
    const rs = await Promise.all(Array.from({ length: 3 }, (_, i) => h.stamp(h1('o', i))));
    expect(statuses(rs)).toEqual([200, 200, 200]);
    expect(h.relay.heldForTests().shares).toBe(0);
  });
});

describe('RELAY_KEY_SHARE in collecting operation', () => {
  let h: Harness;
  afterEach(() => h.close());

  it('solo stamps: a key of type 2 gets its part of the places, another one still gets some (25 percent of 12 = 3)', async () => {
    h = await start({
      batch: { windowMs: 100, max: 100 },
      ...FREETSA,
      keyShare: 25,
      maxWaitMs: 10_000,
    });
    const c = await Promise.all(
      Array.from({ length: 4 }, (_, i) =>
        h.stamp(h1('c', i), { key: KEY_C, body: solo(h1('c', i)) }),
      ),
    );
    expect(statuses(c)).toEqual([200, 200, 200, 429]);
    expect(await c[3]!.json()).toEqual({ error: 'key-share' });
    expect(Number(c[3]!.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    const d = await Promise.all(
      Array.from({ length: 4 }, (_, i) =>
        h.stamp(h1('d', i), { key: KEY_D, body: solo(h1('d', i)) }),
      ),
    );
    expect(statuses(d)).toEqual([200, 200, 200, 429]);
    expect(h.stats().shareDenied).toBe(2);
  });

  it('hashes in a window share ONE place: a key may send more than its share of hashes into an open window', async () => {
    h = await start({
      batch: { windowMs: 300, max: 100 },
      ...FREETSA,
      keyShare: 10,
      maxWaitMs: 10_000,
    });
    const a = await Promise.all(
      Array.from({ length: 10 }, (_, i) => h.stamp(h1('w', i), { key: KEY_A })),
    );
    expect(statuses(a)).toEqual(Array(10).fill(200)); // 10 hashes, a share of 1: no refusal
    expect(h.calls).toHaveLength(1); // one stamp for the window
    expect(h.stats().shareDenied).toBeUndefined();
  });
});

describe('RELAY_KEY_SHARE is read strictly', () => {
  const base = { RELAY_SERVICES: 'freetsa', RELAY_AUTH: 'off' };

  it('not set is 100 (off); 10 to 100 are accepted', () => {
    expect(readSettings(base).keyShare).toBe(100);
    for (const v of ['10', '50', '99', '100']) {
      expect(readSettings({ ...base, RELAY_KEY_SHARE: v }).keyShare, v).toBe(Number(v));
    }
  });

  it('0, 9, 101, 5.5, abc, empty and other spellings end the start with a German line', () => {
    for (const v of ['0', '9', '101', '5.5', 'abc', '', ' 50', '5e1', '-10', '0x32', '1000']) {
      expect(() => readSettings({ ...base, RELAY_KEY_SHARE: v }), JSON.stringify(v)).toThrow(
        /RELAY_KEY_SHARE: ungültig \(ganze Zahl von 10 bis 100 Prozent erwartet/,
      );
    }
  });

  it('the limits are the ones of the documentation (10 and 100)', () => {
    expect([RELAY_LIMITS.keyShareMin, RELAY_LIMITS.keyShareMax]).toEqual([10, 100]);
  });

  it('createRelay refuses a share that is not a whole number from 10 to 100', () => {
    const options = buildRelayOptions(
      readConfig({ ...base, PORT: '8080' }, () => SERVICES),
      {
        upstream: async () => ({ status: 500, contentType: '', body: new Uint8Array() }),
        random: () => new Uint8Array(32),
        now: () => Date.now(),
      },
    );
    expect(() => createRelay({ ...options, keyShare: 5 })).toThrow('relay keyShare is invalid');
    expect(() => createRelay({ ...options, keyShare: 50.5 })).toThrow('relay keyShare is invalid');
    expect(() => createRelay({ ...options, keyShare: 101 })).toThrow('relay keyShare is invalid');
    expect(() => createRelay({ ...options, keyShare: 50 })).not.toThrow();
  });

  it('main hands the setting to the relay (and nothing at 100)', () => {
    const deps = {
      upstream: async () => ({ status: 500, contentType: '', body: new Uint8Array() }),
      random: () => new Uint8Array(32),
      now: () => Date.now(),
    };
    const at = (v: string | undefined) =>
      buildRelayOptions(
        readConfig(
          { ...base, PORT: '8080', ...(v === undefined ? {} : { RELAY_KEY_SHARE: v }) },
          () => SERVICES,
        ),
        deps,
      );
    expect(at('50').keyShare).toBe(50);
    expect(at('100').keyShare).toBeUndefined();
    expect(at(undefined).keyShare).toBeUndefined();
  });
});

describe('RELAY_KEY_SHARE in the process (relay/main.ts)', () => {
  const ROOT = new URL('..', import.meta.url);
  const run = (extra: Record<string, string>, port: number) =>
    spawn(process.execPath, ['relay/main.ts'], {
      cwd: ROOT,
      env: {
        PATH: process.env.PATH ?? '',
        PORT: String(port),
        RELAY_SERVICES: 'freetsa',
        RELAY_AUTH: 'off',
        ...extra,
      },
    });
  const freePort = async (): Promise<number> => {
    const s = createServer();
    await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
    const { port } = s.address() as AddressInfo;
    await new Promise<void>((r) => s.close(() => r()));
    return port;
  };

  it.each(['0', '9', '101', '5.5', 'abc', ''])(
    'RELAY_KEY_SHARE=%j ends the start with a German config-error line and exit code 1',
    async (value) => {
      const child = run({ RELAY_KEY_SHARE: value }, await freePort());
      let err = '';
      let out = '';
      child.stderr!.on('data', (c: Buffer) => (err += c.toString('utf8')));
      child.stdout!.on('data', (c: Buffer) => (out += c.toString('utf8')));
      const code = await new Promise((r) => child.on('exit', (c) => r(c)));
      expect(code).toBe(1);
      const line = JSON.parse(err.trim().split('\n')[0]!) as { event: string; message: string };
      expect(line.event).toBe('config-error');
      expect(line.message).toMatch(
        /^RELAY_KEY_SHARE: ungültig \(ganze Zahl von 10 bis 100 Prozent/,
      );
      expect(out).not.toContain('"event":"start"');
    },
    15_000,
  );

  it('RELAY_KEY_SHARE=50 starts the relay', async () => {
    const child = run({ RELAY_KEY_SHARE: '50' }, await freePort());
    try {
      const started = await new Promise<boolean>((resolve) => {
        let out = '';
        child.stdout!.on('data', (c: Buffer) => {
          out += c.toString('utf8');
          if (out.includes('"event":"start"')) resolve(true);
        });
        child.on('exit', () => resolve(false));
      });
      expect(started).toBe(true);
    } finally {
      child.kill('SIGKILL');
    }
  }, 15_000);
});
