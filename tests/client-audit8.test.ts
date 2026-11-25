import { createRelayClient, CLIENT_LIMITS } from '../src/client/index.ts';
import type { ClientFailure, Evidence, RelayClientOptions } from '../src/client/index.ts';
import { sha256 } from './helpers.ts';
import {
  KEY_1,
  TEST_AUDIENCE,
  TRUST,
  headParts,
  hashOf,
  okBody,
  sleep,
  startFake,
  startRelay,
  type FakeRelay,
} from './client-harness.ts';

// Findings of audit 8 (client): F1 (stamp never rejects, whatever the signal), F2 (an abort during the read of a 429 body
// ends the call at once), F3 (solo asked, a collected receipt is no answer), F4 (the default of maxClockOffsetMs), and the
// gaps the mutation run showed (what is remembered of the clock, the clock of the check).

const options = (origin: string, over: Partial<RelayClientOptions> = {}): RelayClientOptions => ({
  relayUrl: origin,
  audience: TEST_AUDIENCE,
  keyId: KEY_1.id,
  privateKey: KEY_1.privateKey,
  trust: TRUST,
  services: ['freetsa'],
  ...over,
});
function make(o: RelayClientOptions) {
  const r = createRelayClient(o);
  if (!r.ok) throw new Error(`client: ${r.reason} ${r.detail ?? ''}`);
  return r.value;
}
const failure = (r: { ok: boolean }): ClientFailure => {
  expect(r.ok).toBe(false);
  return r as ClientFailure;
};
const hash = sha256('audit 8');

describe('F1: stamp never rejects, also with a hostile signal', () => {
  let fake: FakeRelay;
  beforeEach(async () => {
    fake = await startFake((s) => ({
      status: 200,
      json: okBody('freetsa', hashOf(s), Date.now()),
    }));
  });
  afterEach(() => fake.close());

  const hostile: [string, () => unknown][] = [
    [
      'a proxy whose prototype lookup throws',
      () =>
        new Proxy(
          {},
          {
            getPrototypeOf() {
              throw new Error('boom');
            },
          },
        ),
    ],
    [
      'an AbortSignal whose addEventListener throws',
      () => {
        const signal = new AbortController().signal;
        Object.defineProperty(signal, 'addEventListener', {
          value: () => {
            throw new Error('boom');
          },
        });
        return signal;
      },
    ],
    [
      'an AbortSignal whose aborted getter throws',
      () => {
        const signal = new AbortController().signal;
        Object.defineProperty(signal, 'aborted', {
          get() {
            throw new Error('boom');
          },
        });
        return signal;
      },
    ],
  ];
  for (const [name, make_] of hostile) {
    it(`${name}: a failure with a code, nothing sent`, async () => {
      const client = make(options(fake.origin));
      const r = await client.stamp(hash, { signal: make_() as AbortSignal });
      expect(failure(r).reason).toBe('bad-options');
      expect(fake.seen).toHaveLength(0);
    });
  }

  it('a signal whose removeEventListener throws does not turn a good stamp into a rejection', async () => {
    const signal = new AbortController().signal;
    Object.defineProperty(signal, 'removeEventListener', {
      value: () => {
        throw new Error('boom');
      },
    });
    const r = await make(options(fake.origin)).stamp(hash, { signal });
    expect(r.ok).toBe(true);
  });
});

describe('F2: an abort while the body of a 429 is read ends the call at once', () => {
  it('aborted comes long before the Retry-After', async () => {
    const slowBody = async () => {
      await sleep(300);
      return '{"error":"rate-limited"}';
    };
    const client = make(
      options('http://127.0.0.1:9', {
        fetch: async () => ({
          status: 429,
          headers: { get: (n: string) => (n === 'Retry-After' ? '8' : null) },
          text: slowBody,
        }),
      }),
    );
    const ctl = new AbortController();
    setTimeout(() => ctl.abort(), 100);
    const t0 = Date.now();
    expect(failure(await client.stamp(hash, { signal: ctl.signal })).reason).toBe('aborted');
    expect(Date.now() - t0).toBeLessThan(2000);
  }, 15_000);
});

describe('F3: a stamp asked for solo is never a collected receipt', () => {
  it('a relay that answers a solo request with a batch receipt gives bad-response', async () => {
    const relay = await startRelay({ batch: { windowMs: 100, max: 10 } });
    let answer: unknown;
    try {
      const real = await make(options(relay.origin)).stamp(hash);
      if (!real.ok) throw new Error(`no evidence: ${JSON.stringify(real)}`);
      const e = real.value as Evidence;
      expect(e.kind).toBe('batch');
      answer = {
        service: e.service,
        genTime: e.genTime,
        accuracyMs: null,
        serial: '01',
        token: e.token,
        batch: e.batch,
      };
    } finally {
      await relay.close();
    }
    const fake = await startFake(() => ({ status: 200, json: answer }));
    try {
      const client = make(options(fake.origin));
      const solo = await client.stamp(hash, { mode: 'solo' });
      expect(failure(solo)).toMatchObject({ reason: 'bad-response', detail: 'mode' });
      // the same answer to a normal request is fine: the receipt is valid for this hash
      expect((await client.stamp(hash)).ok).toBe(true);
    } finally {
      await fake.close();
    }
  });
});

describe('F4 and the clock: what the relay Date may correct, and what is kept', () => {
  let fake: FakeRelay | undefined;
  afterEach(() => fake?.close());
  const T0 = Math.floor(Date.now() / 1000) * 1000;
  const httpDate = (ms: number) => new Date(ms).toUTCString();

  /** 401 with a `Date` `offsetMs` ahead of the clock of the client, then whatever `then` says. */
  async function withOffset(
    offsetMs: number,
    over: Partial<RelayClientOptions>,
    then: (n: number) => 'ok' | number,
  ) {
    fake = await startFake((s, n) => {
      if (n === 0) {
        return {
          status: 401,
          headers: { Date: httpDate(T0 + offsetMs) },
          json: { error: 'unauthorized' },
        };
      }
      const r = then(n);
      return r === 'ok'
        ? { status: 200, json: okBody('freetsa', hashOf(s), T0 + offsetMs) }
        : {
            status: r,
            json: { error: 'unauthorized' },
            headers: { Date: httpDate(T0 + offsetMs) },
          };
    });
    return make(options(fake.origin, { now: () => T0, ...over }));
  }

  it('the default is a little above the relay window of 60 s', () => {
    expect(CLIENT_LIMITS.DEFAULT_MAX_CLOCK_OFFSET_MS).toBe(65_000);
  });

  it('by default 65 s are corrected, 66 s are not (exact limit)', async () => {
    let client = await withOffset(65_000, {}, () => 'ok');
    expect((await client.stamp(hash)).ok).toBe(true);
    expect(fake!.seen).toHaveLength(2);
    await fake?.close();
    client = await withOffset(66_000, {}, () => 'ok');
    expect(failure(await client.stamp(hash))).toMatchObject({ status: 401 });
    expect(fake!.seen).toHaveLength(1);
  });

  it('an explicit maxClockOffsetMs is exact too (5 s yes, 6 s no)', async () => {
    let client = await withOffset(5_000, { maxClockOffsetMs: 5_000 }, () => 'ok');
    expect((await client.stamp(hash)).ok).toBe(true);
    await fake?.close();
    client = await withOffset(6_000, { maxClockOffsetMs: 5_000 }, () => 'ok');
    expect(failure(await client.stamp(hash))).toMatchObject({ status: 401 });
  });

  it('the correction is no attempt: maxAttempts 1 still sends the corrected head', async () => {
    const client = await withOffset(30_000, { maxAttempts: 1 }, () => 'ok');
    expect((await client.stamp(hash)).ok).toBe(true);
    expect(fake!.seen).toHaveLength(2);
  });

  it('the offset is kept after the corrected head was taken, and used at once by the next call', async () => {
    const client = await withOffset(30_000, {}, () => 'ok');
    expect((await client.stamp(hash)).ok).toBe(true);
    expect((await client.stamp(hash)).ok).toBe(true);
    expect(fake!.seen).toHaveLength(3);
    expect(headParts(fake!.seen[0]!.head).ts).toBe(T0);
    expect(headParts(fake!.seen[1]!.head).ts).toBe(T0 + 30_000);
    expect(headParts(fake!.seen[2]!.head).ts).toBe(T0 + 30_000);
  });

  it('the correction is no attempt (maxAttempts 2): 401, then a 429 that is retried, then the stamp', async () => {
    fake = await startFake((s, n) =>
      n === 0
        ? { status: 401, headers: { Date: httpDate(T0 + 30_000) }, json: { error: 'unauthorized' } }
        : n === 1
          ? { status: 429, headers: { 'Retry-After': '0' }, json: { error: 'rate-limited' } }
          : { status: 200, json: okBody('freetsa', hashOf(s), T0 + 30_000) },
    );
    const client = make(options(fake.origin, { now: () => T0, maxAttempts: 2 }));
    expect((await client.stamp(hash)).ok).toBe(true);
    expect(fake.seen).toHaveLength(3);
  });

  it('the offset is kept once the relay took the corrected head, whatever came after (here a 502): the next head starts from it', async () => {
    const client = await withOffset(30_000, {}, () => 502);
    expect(failure(await client.stamp(hash))).toMatchObject({ reason: 'relay-error', status: 502 });
    expect(failure(await client.stamp(hash))).toMatchObject({ status: 502 });
    expect(headParts(fake!.seen[2]!.head).ts).toBe(T0 + 30_000);
  });

  it('a correction the relay refuses again (a second 401) is dropped: the next call starts from the clock again', async () => {
    const client = await withOffset(30_000, {}, () => 401);
    expect(failure(await client.stamp(hash))).toMatchObject({ status: 401 });
    expect(fake!.seen).toHaveLength(2);
    expect(failure(await client.stamp(hash))).toMatchObject({ status: 401 });
    // third send is the first head of the second call: the clock of the app, not the refused offset
    expect(headParts(fake!.seen[2]!.head).ts).toBe(T0);
  });
});

describe('the check of a token uses the time of the answer, not the time of the send', () => {
  it('a token a little ahead of the send time passes when the answer came later (receivedAtMs is the later time)', async () => {
    const T = Math.floor(Date.now() / 1000) * 1000;
    // the first reading is the send time, the next one the time the answer is checked
    const readings = [T, T + 600_000];
    const fake = await startFake((s) => ({
      status: 200,
      json: okBody('freetsa', hashOf(s), T + 400_000), // 400 s ahead of the send, 200 s before the check
    }));
    try {
      let n = 0;
      const client = make(options(fake.origin, { now: () => readings[Math.min(n++, 1)]! }));
      const r = await client.stamp(hash);
      expect(r.ok).toBe(true);
      if (r.ok) expect((r.value as Evidence).receivedAtMs).toBe(T + 600_000);
    } finally {
      await fake.close();
    }
  });
});
