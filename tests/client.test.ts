import {
  createRelayClient,
  verifyEvidence,
  readEvidence,
  serializeEvidence,
} from '../src/client/index.ts';
import type { ClientFailure, Evidence, RelayClientOptions } from '../src/client/index.ts';
import { toBase64Url } from '../src/index.ts';
import { sha256 } from './helpers.ts';
import {
  KEY_1,
  KEY_2,
  TEST_AUDIENCE,
  TRUST,
  headParts,
  headVerifies,
  hashOf,
  okBody,
  sleep,
  startFake,
  startRelay,
  type FakeRelay,
  type RealRelay,
} from './client-harness.ts';
import { fixtureText } from './helpers.ts';

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
const evidenceOf = (r: { ok: boolean }): Evidence => {
  if (!r.ok) throw new Error(`no evidence: ${JSON.stringify(r)}`);
  return (r as unknown as { value: Evidence }).value;
};

describe('against a real relay (single operation)', () => {
  let relay: RealRelay;
  beforeAll(async () => {
    relay = await startRelay();
  });
  afterAll(() => relay.close());

  it('stamps, gives evidence that verifies, and verifyEvidence repeats it without the relay', async () => {
    const client = make(options(relay.origin));
    const hash = sha256('single one');
    const before = Date.now();
    const evidence = evidenceOf(await client.stamp(hash));
    expect(evidence).toMatchObject({ v: 1, kind: 'single', service: 'freetsa', hashAlg: 'sha256' });
    expect(evidence.hash).toBe(toBase64Url(hash));
    expect(evidence.receivedAtMs).toBeGreaterThanOrEqual(before);
    expect(Date.parse(evidence.genTime)).toBeGreaterThanOrEqual(before - 1000);
    expect(evidence.batch).toBeUndefined();
    // the evidence survives a trip through text, and is checked with no relay and no network
    const text = serializeEvidence(evidence);
    expect(text.ok).toBe(true);
    const verified = await verifyEvidence(text.ok ? text.value : '', hash, { trust: TRUST });
    expect(verified).toMatchObject({ ok: true, value: { kind: 'single', service: 'freetsa' } });
    expect((await verifyEvidence(evidence, sha256('other'), { trust: TRUST })).ok).toBe(false);
  });

  it('a second stamp is spaced by the relay and also verifies', async () => {
    const client = make(options(relay.origin));
    const a = evidenceOf(await client.stamp(sha256('spaced a')));
    const b = evidenceOf(await client.stamp(sha256('spaced b')));
    expect(a.token).not.toBe(b.token);
  });

  it('an unknown service in the call is bad-options and nothing is sent', async () => {
    const calls: string[] = [];
    const client = make(
      options(relay.origin, {
        services: ['freetsa', 'sectigo'],
        fetch: (url, init) => {
          calls.push(url);
          return fetch(url, init as RequestInit);
        },
      }),
    );
    const r = failure(await client.stamp(sha256('x'), { service: 'nothing' } as never));
    expect(r.reason).toBe('bad-options');
    expect(calls).toHaveLength(0);
  });
});

describe('against a real relay (collecting operation)', () => {
  let relay: RealRelay;
  beforeAll(async () => {
    relay = await startRelay({ batch: { windowMs: 300, max: 50 } });
  });
  afterAll(() => relay.close());

  it('parallel stamps share one token, and each proof holds for its own hash only', async () => {
    const client = make(options(relay.origin));
    const hashes = [1, 2, 3, 4].map((n) => sha256(`batch ${n}`));
    const results = await Promise.all(hashes.map((h) => client.stamp(h)));
    const evidence = results.map(evidenceOf);
    for (const e of evidence) expect(e.kind).toBe('batch');
    expect(new Set(evidence.map((e) => e.token)).size).toBe(1);
    expect(relay.upstreamCalls).toHaveLength(1);
    for (let i = 0; i < hashes.length; i += 1) {
      for (let j = 0; j < hashes.length; j += 1) {
        const r = await verifyEvidence(evidence[i]!, hashes[j]!, { trust: TRUST });
        if (i === j) expect(r).toMatchObject({ ok: true, value: { kind: 'batch' } });
        else expect(r).toMatchObject({ ok: false, reason: 'evidence-hash-mismatch' });
      }
    }
    // a proof moved to another hash's evidence ends in imprint-mismatch
    const swapped = { ...evidence[0]!, hash: evidence[1]!.hash };
    expect(await verifyEvidence(swapped, hashes[1]!, { trust: TRUST })).toMatchObject({
      ok: false,
      reason: 'imprint-mismatch',
    });
  });

  it('a type 2 key gets a solo stamp: single evidence, no tree', async () => {
    const client = make(options(relay.origin, { keyId: KEY_2.id, privateKey: KEY_2.privateKey }));
    const e = evidenceOf(await client.stamp(sha256('solo one'), { mode: 'solo' }));
    expect(e.kind).toBe('single');
    expect(e.batch).toBeUndefined();
    expect((await verifyEvidence(e, sha256('solo one'), { trust: TRUST })).ok).toBe(true);
  });

  it('a type 1 key asking for solo gets 403 solo-not-allowed and no second service is tried', async () => {
    const calls: string[] = [];
    const client = make(
      options(relay.origin, {
        services: ['freetsa', 'sectigo'],
        fetch: (url, init) => {
          calls.push(url);
          return fetch(url, init as RequestInit);
        },
      }),
    );
    const r = failure(await client.stamp(sha256('solo denied'), { mode: 'solo' }));
    expect(r).toMatchObject({ reason: 'relay-error', status: 403, code: 'solo-not-allowed' });
    expect(calls).toHaveLength(1);
  });

  it('a clock that is 90 s ahead gets 401, is corrected once by the relay Date, and the offset is kept', async () => {
    let sends = 0;
    const client = make(
      options(relay.origin, {
        now: () => Date.now() + 90_000,
        fetch: (url, init) => {
          sends += 1;
          return fetch(url, init as RequestInit);
        },
      }),
    );
    const e = evidenceOf(await client.stamp(sha256('clock a')));
    expect(sends).toBe(2);
    // receivedAtMs is the corrected clock: close to the true time, not 90 s ahead
    expect(Math.abs(e.receivedAtMs - Date.now())).toBeLessThan(10_000);
    evidenceOf(await client.stamp(sha256('clock b')));
    expect(sends).toBe(3); // the second call signs with the corrected clock at once
  });

  it('a clock 5 minutes off is not corrected by default (cap 2 minutes): 401 stays, one send', async () => {
    let sends = 0;
    const client = make(
      options(relay.origin, {
        now: () => Date.now() - 300_000,
        fetch: (url, init) => {
          sends += 1;
          return fetch(url, init as RequestInit);
        },
      }),
    );
    expect(failure(await client.stamp(sha256('clock c')))).toMatchObject({
      reason: 'relay-error',
      status: 401,
    });
    expect(sends).toBe(1);
  });

  it('with a larger maxClockOffsetMs the same clock is corrected', async () => {
    const client = make(
      options(relay.origin, { now: () => Date.now() - 300_000, maxClockOffsetMs: 600_000 }),
    );
    evidenceOf(await client.stamp(sha256('clock d')));
  });

  it('a wrong key stays 401 after the one correction: exactly two sends', async () => {
    let sends = 0;
    const client = make(
      options(relay.origin, {
        keyId: 'unknown-key',
        fetch: (url, init) => {
          sends += 1;
          return fetch(url, init as RequestInit);
        },
      }),
    );
    expect(failure(await client.stamp(sha256('bad key')))).toMatchObject({ status: 401 });
    expect(sends).toBe(2);
  });
});

describe('against a fake relay', () => {
  let fake: FakeRelay | null = null;
  afterEach(async () => {
    await fake?.close();
    fake = null;
  });
  const hash = sha256('fake');

  it('sends the signed body: path, content type, hash, mode only for solo, a valid head', async () => {
    fake = await startFake((s) => ({
      status: 200,
      json: okBody('freetsa', hashOf(s), Date.now()),
    }));
    const client = make(options(fake.origin, { keyId: KEY_2.id, privateKey: KEY_2.privateKey }));
    evidenceOf(await client.stamp(hash));
    evidenceOf(await client.stamp(hash, { mode: 'solo' }));
    evidenceOf(await client.stamp(hash, { mode: 'normal' }));
    const [a, b, c] = fake.seen;
    expect(a!.path).toBe('/v1/stamp/freetsa');
    expect(a!.contentType).toBe('application/json');
    expect(JSON.parse(new TextDecoder().decode(a!.body))).toEqual({ hash: toBase64Url(hash) });
    expect(JSON.parse(new TextDecoder().decode(b!.body))).toEqual({
      hash: toBase64Url(hash),
      mode: 'solo',
    });
    expect(JSON.parse(new TextDecoder().decode(c!.body))).toEqual({ hash: toBase64Url(hash) });
    for (const s of fake.seen) expect(headVerifies(s, KEY_2)).toBe(true);
    expect(new Set(fake.seen.map((s) => headParts(s.head).jti)).size).toBe(3);
  });

  it('asks fetch for no redirect, no credentials, no cache', async () => {
    fake = await startFake((s) => ({
      status: 200,
      json: okBody('freetsa', hashOf(s), Date.now()),
    }));
    const inits: unknown[] = [];
    const client = make(
      options(fake.origin, {
        fetch: (url, init) => {
          inits.push(init);
          return fetch(url, init as RequestInit);
        },
      }),
    );
    evidenceOf(await client.stamp(hash));
    expect(inits[0]).toMatchObject({ redirect: 'error', credentials: 'omit', cache: 'no-store' });
  });

  describe('429 and 503 busy', () => {
    it('waits for Retry-After, signs a NEW head (new jti) and succeeds', async () => {
      fake = await startFake((s, n) =>
        n === 0
          ? { status: 429, headers: { 'Retry-After': '1' }, json: { error: 'rate-limited' } }
          : { status: 200, json: okBody('freetsa', hashOf(s), Date.now()) },
      );
      const client = make(options(fake.origin));
      const t0 = Date.now();
      evidenceOf(await client.stamp(hash));
      expect(Date.now() - t0).toBeGreaterThanOrEqual(900);
      expect(fake.seen).toHaveLength(2);
      expect(headParts(fake.seen[0]!.head).jti).not.toBe(headParts(fake.seen[1]!.head).jti);
      expect(fake.seen[1]!.head).not.toBe(fake.seen[0]!.head);
    });
    it('gives up after maxAttempts (per service) with the relay error', async () => {
      fake = await startFake(() => ({
        status: 503,
        headers: { 'Retry-After': '0' },
        json: { error: 'busy' },
      }));
      const client = make(options(fake.origin, { maxAttempts: 2 }));
      expect(failure(await client.stamp(hash))).toMatchObject({
        reason: 'relay-error',
        status: 503,
        code: 'busy',
      });
      expect(fake.seen).toHaveLength(2);
    });
    it('does not wait for a Retry-After beyond the deadline', async () => {
      fake = await startFake(() => ({
        status: 429,
        headers: { 'Retry-After': '120' },
        json: { error: 'rate-limited' },
      }));
      const client = make(options(fake.origin, { timeoutMs: 5000 }));
      const t0 = Date.now();
      expect(failure(await client.stamp(hash))).toMatchObject({ status: 429 });
      expect(Date.now() - t0).toBeLessThan(2000);
      expect(fake.seen).toHaveLength(1);
    });
  });

  describe('failover', () => {
    for (const [name, answer] of [
      ['502', { status: 502, json: { error: 'upstream-failed' } }],
      ['504', { status: 504, json: { error: 'upstream-timeout' } }],
      ['500', { status: 500, json: { error: 'internal' } }],
      ['503 shutting-down', { status: 503, json: { error: 'shutting-down' } }],
      ['a dropped connection', { status: 200, drop: true }],
    ] as const) {
      it(`goes to the next service after ${name}`, async () => {
        fake = await startFake((s, n) =>
          n === 0 ? answer : { status: 200, json: okBody('sectigo', hashOf(s), Date.now()) },
        );
        const client = make(options(fake.origin, { services: ['freetsa', 'sectigo'] }));
        const e = evidenceOf(await client.stamp(hash));
        expect(e.service).toBe('sectigo');
        expect(fake.seen.map((s) => s.path)).toEqual(['/v1/stamp/freetsa', '/v1/stamp/sectigo']);
        expect(headParts(fake.seen[0]!.head).jti).not.toBe(headParts(fake.seen[1]!.head).jti);
      });
    }
    it('reports the last failure when every service fails', async () => {
      fake = await startFake(() => ({
        status: 502,
        json: { error: 'upstream-failed', reason: 'rejected' },
      }));
      const client = make(options(fake.origin, { services: ['freetsa', 'sectigo'] }));
      expect(failure(await client.stamp(hash))).toMatchObject({
        reason: 'relay-error',
        status: 502,
        code: 'upstream-failed',
      });
      expect(fake.seen).toHaveLength(2);
    });
    it('an explicit service is the only one tried', async () => {
      fake = await startFake(() => ({ status: 502, json: { error: 'upstream-failed' } }));
      const client = make(options(fake.origin, { services: ['freetsa', 'sectigo'] }));
      failure(await client.stamp(hash, { service: 'sectigo' }));
      expect(fake.seen.map((s) => s.path)).toEqual(['/v1/stamp/sectigo']);
    });
    for (const [status, code] of [
      [400, 'bad-hash'],
      [403, 'service-not-allowed'],
      [403, 'origin-not-allowed'],
      [404, 'unknown-service'],
      [413, 'too-large'],
      [415, 'unsupported-media-type'],
    ] as const) {
      it(`never goes to the next service after ${status} ${code}`, async () => {
        fake = await startFake(() => ({ status, json: { error: code } }));
        const client = make(options(fake.origin, { services: ['freetsa', 'sectigo'] }));
        expect(failure(await client.stamp(hash))).toMatchObject({
          reason: 'relay-error',
          status,
          code,
        });
        expect(fake.seen).toHaveLength(1);
      });
    }
    it('never goes to the next service after a 401 that stays', async () => {
      fake = await startFake(() => ({ status: 401, json: { error: 'unauthorized' } }));
      const client = make(options(fake.origin, { services: ['freetsa', 'sectigo'] }));
      expect(failure(await client.stamp(hash))).toMatchObject({ status: 401 });
      expect(fake.seen).toHaveLength(2); // the one correction, then it ends
      expect(fake.seen.every((s) => s.path === '/v1/stamp/freetsa')).toBe(true);
      expect(headParts(fake.seen[0]!.head).jti).not.toBe(headParts(fake.seen[1]!.head).jti);
    });
  });

  describe('what the client refuses to accept', () => {
    it('a token of another CA: untrusted-chain, no evidence', async () => {
      fake = await startFake((s) => ({
        status: 200,
        json: okBody('freetsa', hashOf(s), Date.now()),
      }));
      const other = fixtureText('other-root.pem');
      const client = make(options(fake.origin, { trust: [other] }));
      expect(failure(await client.stamp(hash))).toMatchObject({ reason: 'untrusted-chain' });
    });
    it('a token with a genTime older than the send time minus the slack: time-too-old', async () => {
      fake = await startFake((s) => ({
        status: 200,
        json: okBody('freetsa', hashOf(s), Date.now() - 10 * 60_000),
      }));
      const client = make(options(fake.origin));
      expect(failure(await client.stamp(hash))).toMatchObject({ reason: 'time-too-old' });
    });
    it('the slack decides: 30 s old passes by default, not with a slack of 5 s', async () => {
      fake = await startFake((s) => ({
        status: 200,
        json: okBody('freetsa', hashOf(s), Date.now() - 30_000),
      }));
      evidenceOf(await make(options(fake.origin)).stamp(hash));
      expect(
        failure(await make(options(fake.origin, { minGenTimeSlackMs: 5000 })).stamp(hash)),
      ).toMatchObject({ reason: 'time-too-old' });
    });
    it('a token for another hash: imprint-mismatch', async () => {
      fake = await startFake(() => ({
        status: 200,
        json: okBody('freetsa', sha256('somebody else'), Date.now()),
      }));
      expect(failure(await make(options(fake.origin)).stamp(hash))).toMatchObject({
        reason: 'imprint-mismatch',
      });
    });
    it('a 200 that is no relay answer: bad-response', async () => {
      const bodies = [
        { text: 'not json' },
        { json: [] },
        { json: { service: 'freetsa' } },
        { json: { service: 'sectigo', token: 'AAAA' } },
        { json: { service: 'freetsa', token: '!!' } },
        { json: { service: 'freetsa', token: 'AAAA', extra: 1 } },
      ];
      for (const b of bodies) {
        fake = await startFake(() => ({ status: 200, ...b }));
        expect(failure(await make(options(fake.origin)).stamp(hash)).reason).toBe('bad-response');
        await fake.close();
        fake = null;
      }
    });
    it('a token that is garbage: a library code, never an evidence', async () => {
      fake = await startFake(() => ({
        status: 200,
        json: { service: 'freetsa', token: toBase64Url(new Uint8Array(40)) },
      }));
      const r = failure(await make(options(fake.origin)).stamp(hash));
      expect(['malformed', 'trailing-bytes', 'bad-structure']).toContain(r.reason);
    });
  });

  describe('abort and deadline', () => {
    it('signal aborts a waiting call', async () => {
      fake = await startFake((s) => ({
        status: 200,
        json: okBody('freetsa', hashOf(s), Date.now()),
        delayMs: 3000,
      }));
      const ctl = new AbortController();
      const client = make(options(fake.origin));
      const p = client.stamp(hash, { signal: ctl.signal });
      setTimeout(() => ctl.abort(), 100);
      const t0 = Date.now();
      expect(failure(await p).reason).toBe('aborted');
      expect(Date.now() - t0).toBeLessThan(1500);
    });
    it('an already aborted signal sends nothing', async () => {
      fake = await startFake(() => ({ status: 500 }));
      const ctl = new AbortController();
      ctl.abort();
      expect(
        failure(await make(options(fake.origin)).stamp(hash, { signal: ctl.signal })).reason,
      ).toBe('aborted');
      expect(fake.seen).toHaveLength(0);
    });
    it('signal aborts the wait for Retry-After', async () => {
      fake = await startFake(() => ({
        status: 429,
        headers: { 'Retry-After': '20' },
        json: { error: 'rate-limited' },
      }));
      const ctl = new AbortController();
      const client = make(options(fake.origin));
      const p = client.stamp(hash, { signal: ctl.signal });
      setTimeout(() => ctl.abort(), 150);
      expect(failure(await p).reason).toBe('aborted');
    });
    it('timeoutMs ends the whole call with timeout', async () => {
      fake = await startFake(() => ({ status: 200, json: {}, delayMs: 5000 }));
      const client = make(options(fake.origin, { timeoutMs: 1000 }));
      const t0 = Date.now();
      expect(failure(await client.stamp(hash)).reason).toBe('timeout');
      expect(Date.now() - t0).toBeLessThan(2500);
    });
  });

  describe('arguments', () => {
    it('a wrong hash, mode, service, signal or option object is bad-hash / bad-options, nothing is sent', async () => {
      fake = await startFake(() => ({ status: 500 }));
      const client = make(options(fake.origin));
      expect(failure(await client.stamp(new Uint8Array(31))).reason).toBe('bad-hash');
      expect(failure(await client.stamp('x' as never)).reason).toBe('bad-hash');
      for (const o of [
        { mode: 'fast' },
        { service: 'nope' },
        { signal: {} },
        { extra: 1 },
        5,
        null,
      ]) {
        expect(failure(await client.stamp(hash, o as never)).reason, JSON.stringify(o)).toBe(
          'bad-options',
        );
      }
      expect(fake.seen).toHaveLength(0);
    });
    it('a clock that answers no number is bad-options', async () => {
      fake = await startFake(() => ({ status: 500 }));
      const client = make(options(fake.origin, { now: () => NaN }));
      expect(failure(await client.stamp(hash)).reason).toBe('bad-options');
      expect(fake.seen).toHaveLength(0);
    });
    it('a random that gives no 16 bytes is bad-options', async () => {
      fake = await startFake(() => ({ status: 500 }));
      const client = make(options(fake.origin, { random: () => new Uint8Array(3) }));
      expect(failure(await client.stamp(hash)).reason).toBe('bad-options');
    });
    it('a key that is no key is bad-key from the signing', async () => {
      fake = await startFake(() => ({ status: 500 }));
      const client = make(options(fake.origin, { privateKey: new Uint8Array(20) }));
      expect(failure(await client.stamp(hash)).reason).toBe('bad-key');
      expect(fake.seen).toHaveLength(0);
    });
    it('a hostile fetch (throws, returns junk) never makes stamp throw', async () => {
      for (const f of [
        () => {
          throw new Error('x');
        },
        () => Promise.resolve(null),
        () => Promise.resolve({ status: 'no' }),
        () =>
          Promise.resolve({ status: 200, headers: {}, text: () => Promise.reject(new Error('x')) }),
      ]) {
        const client = make(options('http://127.0.0.1:9', { fetch: f as never }));
        expect(typeof failure(await client.stamp(hash)).reason).toBe('string');
      }
    });
  });
});

describe('createRelayClient checks its options', () => {
  const good = options('https://relay.example');
  const code = (o: unknown) => {
    const r = createRelayClient(o as RelayClientOptions);
    return r.ok ? 'ok' : r.reason;
  };
  it('accepts good options and never throws', () => {
    expect(code(good)).toBe('ok');
    expect(code(options('http://localhost:8080'))).toBe('ok');
    expect(code(options('http://127.0.0.1:8080/'))).toBe('ok');
  });
  it('refuses bad ones with a code', () => {
    const table: [string, unknown, string][] = [
      ['null', null, 'bad-options'],
      ['array', [], 'bad-options'],
      ['missing relayUrl', { ...good, relayUrl: undefined }, 'bad-options'],
      ['unknown field', { ...good, extra: 1 }, 'bad-options'],
      [
        'plain http away from localhost',
        { ...good, relayUrl: 'http://relay.example' },
        'bad-options',
      ],
      ['a path', { ...good, relayUrl: 'https://relay.example/v1' }, 'bad-options'],
      ['a query', { ...good, relayUrl: 'https://relay.example/?a=b' }, 'bad-options'],
      ['credentials', { ...good, relayUrl: 'https://u:p@relay.example' }, 'bad-options'],
      ['ftp', { ...good, relayUrl: 'ftp://relay.example' }, 'bad-options'],
      ['not a url', { ...good, relayUrl: 'relay' }, 'bad-options'],
      ['audience with a space', { ...good, audience: 'a b' }, 'bad-options'],
      ['audience empty', { ...good, audience: '' }, 'bad-options'],
      ['key id', { ...good, keyId: 'Bad Id' }, 'bad-key-id'],
      ['key of a wrong type', { ...good, privateKey: 'text' }, 'bad-key'],
      ['key empty', { ...good, privateKey: new Uint8Array(0) }, 'bad-key'],
      ['key too long', { ...good, privateKey: new Uint8Array(300) }, 'bad-key'],
      ['trust not a list', { ...good, trust: TRUST[0] }, 'bad-options'],
      ['trust empty', { ...good, trust: [] }, 'bad-options'],
      ['trust entry no text', { ...good, trust: [5] }, 'bad-options'],
      ['trust entry no pem', { ...good, trust: ['hello'] }, 'bad-pem'],
      ['too many trust anchors', { ...good, trust: Array(65).fill(TRUST[0]) }, 'bad-options'],
      ['services empty', { ...good, services: [] }, 'bad-options'],
      ['services doubled', { ...good, services: ['a', 'a'] }, 'bad-options'],
      ['services bad id', { ...good, services: ['A'] }, 'bad-options'],
      [
        'too many services',
        { ...good, services: Array.from({ length: 17 }, (_, i) => `s${i}`) },
        'bad-options',
      ],
      ['fetch no function', { ...good, fetch: 1 }, 'bad-options'],
      ['now no function', { ...good, now: 1 }, 'bad-options'],
      ['random no function', { ...good, random: 1 }, 'bad-options'],
      ['timeoutMs low', { ...good, timeoutMs: 10 }, 'bad-options'],
      ['timeoutMs NaN', { ...good, timeoutMs: NaN }, 'bad-options'],
      ['timeoutMs string', { ...good, timeoutMs: '5000' }, 'bad-options'],
      ['maxAttempts 0', { ...good, maxAttempts: 0 }, 'bad-options'],
      ['maxAttempts 1.5', { ...good, maxAttempts: 1.5 }, 'bad-options'],
      ['maxAttempts 11', { ...good, maxAttempts: 11 }, 'bad-options'],
      ['slack negative', { ...good, minGenTimeSlackMs: -1 }, 'bad-options'],
      ['slack too big', { ...good, minGenTimeSlackMs: 4_000_000 }, 'bad-options'],
      ['offset cap negative', { ...good, maxClockOffsetMs: -1 }, 'bad-options'],
      ['explicit undefined timeoutMs', { ...good, timeoutMs: undefined }, 'bad-options'],
    ];
    for (const [name, o, expected] of table) expect(code(o), name).toBe(expected);
  });
  it('survives hostile input: a getter, a throwing proxy, a class instance', () => {
    const getter = { ...good };
    Object.defineProperty(getter, 'keyId', { get: () => 'app-one', enumerable: true });
    expect(code(getter)).toBe('bad-options');
    const thrower = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error('x');
        },
        getPrototypeOf() {
          throw new Error('x');
        },
      },
    );
    expect(code(thrower)).toBe('bad-options');
    class Options {
      relayUrl = good.relayUrl;
    }
    expect(code(new Options())).toBe('bad-options');
    const listProxy = new Proxy([], {
      get() {
        throw new Error('x');
      },
    });
    expect(code({ ...good, trust: listProxy })).toBe('bad-options');
    expect(code({ ...good, services: listProxy })).toBe('bad-options');
  });
  it('copies what it is given: a later change of the lists or of the key bytes changes nothing', async () => {
    const trust = [...TRUST];
    const services = ['freetsa'];
    const key = new Uint8Array(KEY_1.privateKey);
    const fake = await startFake((s) => ({
      status: 200,
      json: okBody('freetsa', hashOf(s), Date.now()),
    }));
    try {
      const client = make(options(fake.origin, { trust, services, privateKey: key }));
      trust.length = 0;
      services[0] = 'sectigo';
      key.fill(0);
      evidenceOf(await client.stamp(sha256('copy')));
    } finally {
      await fake.close();
    }
  });
  it('takes a non-extractable CryptoKey', async () => {
    const key = await crypto.subtle.importKey(
      'pkcs8',
      KEY_1.privateKey as BufferSource,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    );
    const fake = await startFake((s) => ({
      status: 200,
      json: okBody('freetsa', hashOf(s), Date.now()),
    }));
    try {
      const client = make(options(fake.origin, { privateKey: key }));
      evidenceOf(await client.stamp(sha256('cryptokey')));
      expect(headVerifies(fake.seen[0]!, KEY_1)).toBe(true);
    } finally {
      await fake.close();
    }
  });
});

describe('the readme example', () => {
  it('runs against a relay: stamp, store as text, check later', async () => {
    const relay = await startRelay();
    try {
      // --- the example of README.md (with this test's relay, key and anchors) ---
      const client = createRelayClient({
        relayUrl: relay.origin,
        audience: TEST_AUDIENCE,
        keyId: KEY_1.id,
        privateKey: KEY_1.privateKey,
        trust: TRUST,
        services: ['freetsa', 'sectigo'],
      });
      if (!client.ok) throw new Error(client.reason);
      const hash = sha256('contract.pdf');
      const stamped = await client.value.stamp(hash);
      if (!stamped.ok) throw new Error(stamped.reason);
      const stored = serializeEvidence(stamped.value);
      if (!stored.ok) throw new Error(stored.reason);
      // later, without the relay and without a network:
      const checked = await verifyEvidence(
        readEvidence(stored.value).ok ? stored.value : '',
        hash,
        {
          trust: TRUST,
        },
      );
      expect(checked.ok).toBe(true);
      // ---
      await sleep(0);
    } finally {
      await relay.close();
    }
  });
});
