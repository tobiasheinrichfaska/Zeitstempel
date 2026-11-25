import {
  EVIDENCE_LIMITS,
  readEvidence,
  serializeEvidence,
  verifyEvidence,
  type Evidence,
} from '../src/client/index.ts';
import {
  fromBase64Url,
  readTimestampResponse,
  toBase64Url,
  verifyTimestampToken,
} from '../src/index.ts';
import { fixture, fixtureText, sha256 } from './helpers.ts';

// Evidence from a REAL recorded answer (FreeTSA, 2026-11-23): checked with no relay, no network and the clock of
// the day it was made, because the certificates are judged at the stamped time.
const ROOT = fixtureText('cacert.pem');
const HASH = sha256('probe');
const response = readTimestampResponse(fixture('freetsa.tsr'));
if (!response.ok) throw new Error('fixture unreadable');
const TOKEN = response.value.token;
const verifiedToken = await verifyTimestampToken(TOKEN, HASH, [ROOT]);
if (!verifiedToken.ok) throw new Error('fixture does not verify');

const GOOD: Evidence = {
  v: 1,
  kind: 'single',
  service: 'freetsa',
  hash: toBase64Url(HASH),
  hashAlg: 'sha256',
  receivedAtMs: Date.parse('2026-11-23T13:06:00.000Z'),
  token: toBase64Url(TOKEN),
  policy: verifiedToken.value.policy,
  genTime: verifiedToken.value.genTime,
  signerNotAfter: verifiedToken.value.signerNotAfter,
};
const code = (r: { ok: boolean; reason?: string }) => (r.ok ? 'ok' : r.reason);
const detail = (r: { ok: boolean; detail?: string }) => (r.ok ? 'ok' : r.detail);

describe('readEvidence', () => {
  it('reads good evidence into a fresh copy', () => {
    const r = readEvidence(GOOD);
    expect(r).toEqual({ ok: true, value: GOOD });
    if (r.ok) expect(r.value).not.toBe(GOOD);
  });
  it('the optional fields may be left out', () => {
    const minimal: Partial<Evidence> = { ...GOOD };
    delete minimal.policy;
    delete minimal.signerNotAfter;
    expect(readEvidence(minimal).ok).toBe(true);
  });
  it('reads JSON text too, and refuses text that is no JSON or too long', () => {
    expect(readEvidence(JSON.stringify(GOOD)).ok).toBe(true);
    expect(detail(readEvidence('{'))).toBe('json');
    expect(code(readEvidence('x'.repeat(EVIDENCE_LIMITS.MAX_JSON_CHARS + 1)))).toBe('bad-evidence');
  });
  it('round trip: serialize, read, serialize again gives the same text', () => {
    const a = serializeEvidence(GOOD);
    expect(a.ok).toBe(true);
    if (!a.ok) return;
    const back = readEvidence(a.value);
    expect(back).toEqual({ ok: true, value: GOOD });
    expect(back.ok && serializeEvidence(back.value)).toEqual(a);
  });
  it('the canonical text has a fixed field order whatever the order of the input', () => {
    const shuffled = Object.fromEntries(Object.entries(GOOD).reverse()) as unknown as Evidence;
    const a = serializeEvidence(GOOD);
    const b = serializeEvidence(shuffled);
    expect(a).toEqual(b);
    if (a.ok) {
      expect(Object.keys(JSON.parse(a.value))).toEqual([
        'v',
        'kind',
        'service',
        'hash',
        'hashAlg',
        'receivedAtMs',
        'token',
        'policy',
        'genTime',
        'signerNotAfter',
      ]);
      expect(a.value).not.toMatch(/\s/);
    }
  });
  it('a batch receipt keeps its order and values', () => {
    const salt = toBase64Url(new Uint8Array(32).fill(7));
    const node = toBase64Url(new Uint8Array(32).fill(9));
    const batch = { v: 1 as const, size: 3, index: 1, salt, path: [node, node] };
    const e: Evidence = { ...GOOD, kind: 'batch', batch };
    const text = serializeEvidence(e);
    expect(text.ok && text.value).toContain(
      `"batch":{"v":1,"size":3,"index":1,"salt":"${salt}","path":["${node}","${node}"]}`,
    );
    expect(text.ok && readEvidence(text.value)).toEqual({ ok: true, value: e });
  });

  const refuse = (name: string, evidence: unknown, field?: string) =>
    it(`refuses ${name}`, () => {
      const r = readEvidence(evidence);
      expect(code(r), name).toBe('bad-evidence');
      if (field !== undefined) expect(detail(r)).toBe(field);
    });
  refuse('null', null, 'object');
  refuse('an array', [], 'object');
  refuse('a number', 5, 'object');
  refuse('an unknown field', { ...GOOD, note: 'hi' }, 'object');
  refuse('an unknown field named like a prototype key', JSON.parse('{"__proto__":1}'), 'object');
  refuse('version 2', { ...GOOD, v: 2 }, 'v');
  refuse('version "1"', { ...GOOD, v: '1' }, 'v');
  refuse('a field that is undefined', { ...GOOD, token: undefined }, 'token');
  refuse(
    'a missing field',
    Object.fromEntries(Object.entries(GOOD).filter(([k]) => k !== 'token')),
    'object',
  );
  refuse('a kind that is none', { ...GOOD, kind: 'many' }, 'kind');
  refuse('a service id with capitals', { ...GOOD, service: 'FreeTSA' }, 'service');
  refuse('a hash of 31 bytes', { ...GOOD, hash: toBase64Url(new Uint8Array(31)) }, 'hash');
  refuse('a hash with padding', { ...GOOD, hash: toBase64Url(HASH) + '=' }, 'hash');
  refuse(
    'a hash in plain base64',
    { ...GOOD, hash: Buffer.from(HASH).toString('base64').replace(/[-]/g, '+') + 'A' },
    'hash',
  );
  refuse('another hash algorithm', { ...GOOD, hashAlg: 'sha1' }, 'hashAlg');
  refuse('receivedAtMs in seconds', { ...GOOD, receivedAtMs: 1_700_000_000 }, 'receivedAtMs');
  refuse('receivedAtMs with a fraction', { ...GOOD, receivedAtMs: 1.7e12 + 0.5 }, 'receivedAtMs');
  refuse('receivedAtMs far too large', { ...GOOD, receivedAtMs: 1e16 }, 'receivedAtMs');
  refuse('a token that is empty', { ...GOOD, token: '' }, 'token');
  refuse('a token that is no base64url', { ...GOOD, token: 'a+b/' }, 'token');
  refuse('a token longer than the limit', { ...GOOD, token: 'A'.repeat(400_000) }, 'token');
  it('refuses a hash that spells the same bytes another way (spare bits set)', () => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alphabet.indexOf(GOOD.hash.slice(-1));
    const other = alphabet[last ^ 1]!; // the same 256 bits, a different last character
    const twin = GOOD.hash.slice(0, -1) + other;
    expect(fromBase64Url(twin)).toBeNull(); // the library's reader is strict about it already
    expect(detail(readEvidence({ ...GOOD, hash: twin }))).toBe('hash');
  });
  refuse('a genTime without milliseconds', { ...GOOD, genTime: '2026-11-23T13:05:56Z' }, 'genTime');
  refuse('a genTime that is no date', { ...GOOD, genTime: '2026-13-45T13:05:56.000Z' }, 'genTime');
  refuse(
    'a genTime with an offset',
    { ...GOOD, genTime: '2026-11-23T13:05:56.000+01:00' },
    'genTime',
  );
  refuse('a signerNotAfter that is a number', { ...GOOD, signerNotAfter: 5 }, 'signerNotAfter');
  refuse('a policy that is no OID', { ...GOOD, policy: 'x.y' }, 'policy');
  refuse('a policy that is too long', { ...GOOD, policy: '1.' + '2'.repeat(300) }, 'policy');
  refuse('a single stamp with a batch receipt', { ...GOOD, batch: { v: 1 } }, 'batch');
  refuse('a batch stamp without a receipt', { ...GOOD, kind: 'batch' }, 'batch');
  const goodBatch = {
    v: 1,
    size: 2,
    index: 0,
    salt: toBase64Url(new Uint8Array(32)),
    path: [toBase64Url(new Uint8Array(32))],
  };
  for (const [name, over] of [
    ['version 2', { v: 2 }],
    ['size 0', { size: 0 }],
    ['size 1025', { size: 1025 }],
    ['index equal to size', { index: 2 }],
    ['index negative', { index: -1 }],
    ['a short salt', { salt: toBase64Url(new Uint8Array(31)) }],
    ['a path of 11', { path: Array(11).fill(toBase64Url(new Uint8Array(32))) }],
    ['a path entry of 31 bytes', { path: [toBase64Url(new Uint8Array(31))] }],
    ['a path that is no list', { path: 'x' }],
    ['an extra field', { more: 1 }],
  ] as const) {
    refuse(
      `a receipt with ${name}`,
      { ...GOOD, kind: 'batch', batch: { ...goodBatch, ...over } },
      'batch',
    );
  }

  it('refuses a getter, without calling it twice', () => {
    let reads = 0;
    const evil = { ...GOOD };
    Object.defineProperty(evil, 'hash', {
      enumerable: true,
      get: () => {
        reads += 1;
        return GOOD.hash;
      },
    });
    expect(code(readEvidence(evil))).toBe('bad-evidence');
    expect(reads).toBe(0); // a getter is never run
  });
  it('refuses a class instance and an object with a foreign prototype', () => {
    class E {
      v = 1;
    }
    expect(code(readEvidence(new E()))).toBe('bad-evidence');
    expect(code(readEvidence(Object.assign(Object.create({ inherited: 1 }), GOOD)))).toBe(
      'bad-evidence',
    );
  });
  it('accepts an object without a prototype', () => {
    expect(readEvidence(Object.assign(Object.create(null), GOOD)).ok).toBe(true);
  });
  it('survives a Proxy whose traps throw, and a Proxy that lies', () => {
    const traps = ['ownKeys', 'getPrototypeOf', 'getOwnPropertyDescriptor'] as const;
    for (const trap of traps) {
      const p = new Proxy(
        { ...GOOD },
        {
          [trap]() {
            throw new Error('x');
          },
        },
      );
      expect(code(readEvidence(p)), trap).toBe('bad-evidence');
    }
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    expect(code(readEvidence(revoked.proxy))).toBe('bad-evidence');
    let n = 0;
    const flipping = new Proxy(
      { ...GOOD },
      {
        getOwnPropertyDescriptor(t, k) {
          const d = Reflect.getOwnPropertyDescriptor(t, k);
          if (k === 'service' && d) return { ...d, value: n++ === 0 ? 'freetsa' : 'x' };
          return d;
        },
      },
    );
    const r = readEvidence(flipping);
    // the value that was checked is the value that is used: whatever it is, it reads and writes back the same
    if (r.ok)
      expect(
        readEvidence(
          serializeEvidence(r.value).ok
            ? (serializeEvidence(r.value) as { value: string }).value
            : '',
        ),
      ).toEqual(r);
  });
  it('a path list that is a Proxy whose length lies is cut by the limit', () => {
    const path = new Proxy([], { get: (t, k) => (k === 'length' ? 1e9 : Reflect.get(t, k)) });
    expect(code(readEvidence({ ...GOOD, kind: 'batch', batch: { ...goodBatch, path } }))).toBe(
      'bad-evidence',
    );
  });
  it('the result shares nothing with the input (a later change of the input changes nothing)', () => {
    const input = {
      ...GOOD,
      kind: 'batch' as const,
      batch: { ...goodBatch, path: [...goodBatch.path] },
    };
    const r = readEvidence(input);
    input.batch.path[0] = 'changed';
    input.batch.index = 1;
    expect(r.ok && r.value.batch).toEqual(goodBatch);
  });
  it('serializeEvidence refuses bad evidence with a code and never throws', () => {
    for (const bad of [
      null,
      5,
      { ...GOOD, v: 2 },
      new Proxy(
        {},
        {
          ownKeys() {
            throw new Error('x');
          },
        },
      ),
    ]) {
      expect(code(serializeEvidence(bad as never))).toBe('bad-evidence');
    }
  });
});

describe('verifyEvidence', () => {
  it('verifies the real recorded token with no relay and no clock rule', async () => {
    const r = await verifyEvidence(GOOD, HASH, { trust: [ROOT] });
    expect(r).toMatchObject({
      ok: true,
      value: {
        kind: 'single',
        service: 'freetsa',
        genTime: '2026-11-23T13:05:56.000Z',
        policy: '1.2.3.4.1',
        receivedAtMs: GOOD.receivedAtMs,
      },
    });
  });
  it('takes the evidence as text, too', async () => {
    const text = serializeEvidence(GOOD);
    expect((await verifyEvidence(text.ok ? text.value : '', HASH, { trust: [ROOT] })).ok).toBe(
      true,
    );
  });
  it('compares the hash first: another hash is evidence-hash-mismatch', async () => {
    expect(code(await verifyEvidence(GOOD, sha256('not probe'), { trust: [ROOT] }))).toBe(
      'evidence-hash-mismatch',
    );
  });
  it('the hash comparison also comes before the token: a hash that does not match with a broken token', async () => {
    const broken = { ...GOOD, token: toBase64Url(new Uint8Array(30)) };
    expect(code(await verifyEvidence(broken, sha256('not probe'), { trust: [ROOT] }))).toBe(
      'evidence-hash-mismatch',
    );
  });
  it('a hash that is no 32 bytes is bad-hash', async () => {
    for (const h of [new Uint8Array(31), 'x', null, new Uint16Array(16)]) {
      expect(code(await verifyEvidence(GOOD, h as never, { trust: [ROOT] }))).toBe('bad-hash');
    }
  });
  it('evidence that does not read is bad-evidence', async () => {
    expect(code(await verifyEvidence({ ...GOOD, v: 2 }, HASH, { trust: [ROOT] }))).toBe(
      'bad-evidence',
    );
    expect(code(await verifyEvidence(null, HASH, { trust: [ROOT] }))).toBe('bad-evidence');
  });
  it('a wrong anchor is untrusted-chain', async () => {
    const other = fixtureText('other-root.pem');
    expect(code(await verifyEvidence(GOOD, HASH, { trust: [other] }))).toBe('untrusted-chain');
  });
  it('a token with changed bytes fails in the library, not as a form error', async () => {
    const bytes = fromBase64Url(GOOD.token)!;
    bytes[bytes.length - 5] = bytes[bytes.length - 5]! ^ 1;
    const r = await verifyEvidence({ ...GOOD, token: toBase64Url(bytes) }, HASH, { trust: [ROOT] });
    expect(r.ok).toBe(false);
    expect(code(r)).not.toBe('bad-evidence');
  });
  it('facts the evidence repeats must agree with the token', async () => {
    for (const over of [
      { genTime: '2026-11-23T13:05:57.000Z' },
      { policy: '1.2.3.4.2' },
      { signerNotAfter: '2030-01-01T00:00:00.000Z' },
    ]) {
      const r = await verifyEvidence({ ...GOOD, ...over }, HASH, { trust: [ROOT] });
      expect(code(r)).toBe('bad-evidence');
      expect(detail(r)).toBe(Object.keys(over)[0]);
    }
  });
  it('passes the verification options through: minGenTime, expectedPolicy, now', async () => {
    const trust = [ROOT];
    expect(
      code(
        await verifyEvidence(GOOD, HASH, { trust, minGenTime: new Date('2026-11-24T00:00:00Z') }),
      ),
    ).toBe('time-too-old');
    expect(code(await verifyEvidence(GOOD, HASH, { trust, expectedPolicy: '1.9' }))).toBe(
      'policy-mismatch',
    );
    expect(
      code(await verifyEvidence(GOOD, HASH, { trust, now: new Date('2026-11-23T12:00:00Z') })),
    ).toBe('time-in-future');
    expect(
      (
        await verifyEvidence(GOOD, HASH, {
          trust,
          minGenTime: new Date('2026-11-23T13:00:00Z'),
          expectedPolicy: ['1.2.3.4.1'],
        })
      ).ok,
    ).toBe(true);
  });
  it('checks its options: bad-options', async () => {
    for (const o of [
      undefined,
      null,
      {},
      { trust: 'x' },
      { trust: [ROOT], expectedNonce: new Uint8Array(8) },
      { trust: [ROOT], unknown: 1 },
      { trust: [ROOT], now: 5 },
      { trust: [ROOT], minGenTime: 'yesterday' },
    ]) {
      expect(code(await verifyEvidence(GOOD, HASH, o as never)), JSON.stringify(o)).toBe(
        'bad-options',
      );
    }
  });
  it('never throws for hostile arguments', async () => {
    const boom = new Proxy(
      {},
      {
        get() {
          throw new Error('x');
        },
        ownKeys() {
          throw new Error('x');
        },
        getPrototypeOf() {
          throw new Error('x');
        },
      },
    );
    for (const args of [
      [boom, HASH, { trust: [ROOT] }],
      [GOOD, boom, { trust: [ROOT] }],
      [GOOD, HASH, boom],
    ] as const) {
      const r = await verifyEvidence(...(args as unknown as Parameters<typeof verifyEvidence>));
      expect(r.ok).toBe(false);
    }
  });
});
