import {
  EVIDENCE_LIMITS,
  readEvidence,
  serializeEvidence,
  verifyEvidence,
  type Evidence,
} from '../src/client/index.ts';
import { toBase64Url, verifyRenewalChain } from '../src/index.ts';
import { buildCrl } from './crl-builder.ts';
import { BASE, HASH, TRUST, evidenceOf, makeChain, sha, type Step } from './renewal-helpers.ts';

const code = (r: { ok: boolean; reason?: string }) => (r.ok ? 'ok' : r.reason);
const detail = (r: { ok: boolean; detail?: string }) => (r.ok ? 'ok' : r.detail);

const STEPS: Step[] = [
  { at: '2026-01-01T00:00:00Z', validity: ['20200101000000Z', '20260701000000Z'] },
  { at: '2026-06-01T00:00:00Z', validity: ['20200101000000Z', '20261120000000Z'] },
  { at: '2026-11-01T00:00:00Z' },
];

async function make(steps: Step[] = STEPS): Promise<Evidence> {
  const links = await makeChain(HASH, steps);
  const r = await verifyRenewalChain({ hash: HASH, links, trust: TRUST });
  if (!r.ok) throw new Error(`chain: ${r.reason}`);
  return evidenceOf(
    HASH,
    links,
    r.value.links.map((l) => ({
      genTime: l.genTime,
      signerNotAfter: l.signerNotAfter,
      policy: l.policy,
    })),
  );
}
const verify = (e: unknown, o: object = {}, hash = HASH) =>
  verifyEvidence(e, hash, { trust: TRUST, ...o });

describe('readEvidence and serializeEvidence with renewals', () => {
  it('reads evidence with renewals into a fresh copy and writes the canonical text back', async () => {
    const e = await make();
    expect(e.renewals).toHaveLength(2);
    const r = readEvidence(e);
    expect(r).toEqual({ ok: true, value: e });
    if (r.ok) {
      expect(r.value).not.toBe(e);
      expect(r.value.renewals![0]).not.toBe(e.renewals![0]);
    }
    const text = serializeEvidence(e);
    expect(text.ok).toBe(true);
    if (!text.ok) return;
    expect(readEvidence(text.value)).toEqual({ ok: true, value: e });
    expect(serializeEvidence((readEvidence(text.value) as { value: Evidence }).value)).toEqual(
      text,
    );
  });
  it('the canonical text puts renewals last, each with a fixed field order and no hash', async () => {
    const e = await make();
    const text = serializeEvidence(e);
    if (!text.ok) throw new Error('serialize');
    const parsed = JSON.parse(text.value) as Record<string, unknown>;
    expect(Object.keys(parsed).at(-1)).toBe('renewals');
    const first = (parsed.renewals as Record<string, unknown>[])[0]!;
    expect(Object.keys(first)).toEqual([
      'kind',
      'service',
      'receivedAtMs',
      'token',
      'policy',
      'genTime',
      'signerNotAfter',
    ]);
    // the order of the input does not matter
    const shuffled = {
      ...Object.fromEntries(Object.entries(e).reverse()),
      renewals: e.renewals!.map((r) => Object.fromEntries(Object.entries(r).reverse())),
    };
    expect(serializeEvidence(shuffled as unknown as Evidence)).toEqual(text);
  });
  it('a batch receipt of a renewal keeps its order', async () => {
    const e = await make();
    const node = toBase64Url(new Uint8Array(32).fill(9));
    const batch = { v: 1 as const, size: 3, index: 1, salt: node, path: [node, node] };
    const withBatch = {
      ...e,
      renewals: [{ ...e.renewals![0]!, kind: 'batch' as const, batch }, e.renewals![1]!],
    };
    const text = serializeEvidence(withBatch);
    expect(text.ok && text.value).toContain(
      `"batch":{"v":1,"size":3,"index":1,"salt":"${node}","path":["${node}","${node}"]}`,
    );
    expect(text.ok && readEvidence(text.value)).toEqual({ ok: true, value: withBatch });
  });
  it('evidence of version 1 without the field reads and writes as before', async () => {
    const plain = await make([STEPS[0]!]);
    expect('renewals' in plain).toBe(false);
    const text = serializeEvidence(plain);
    expect(text.ok && text.value).not.toContain('renewals');
    expect(readEvidence(plain)).toEqual({ ok: true, value: plain });
  });

  const refuse = (name: string, make: (e: Evidence) => unknown, field: string) =>
    it(`refuses ${name}`, async () => {
      const r = readEvidence(make(await makeEvidence()));
      expect(code(r)).toBe('bad-evidence');
      expect(detail(r)).toBe(field);
    });
  let cached: Evidence | undefined;
  const makeEvidence = async () => (cached ??= await make());
  const link = (e: Evidence, i: number) => e.renewals![i]!;
  const withLink = (e: Evidence, i: number, over: object) => ({
    ...e,
    renewals: e.renewals!.map((r, j) => (j === i ? { ...r, ...over } : r)),
  });
  refuse('an empty list', (e) => ({ ...e, renewals: [] }), 'renewals');
  refuse('a list that is none', (e) => ({ ...e, renewals: 'x' }), 'renewals');
  refuse('undefined renewals', (e) => ({ ...e, renewals: undefined }), 'renewals');
  refuse('a link that is no object', (e) => ({ ...e, renewals: [1] }), 'renewals[0]');
  refuse(
    'a hash in a link (a link has none of its own)',
    (e) => withLink(e, 0, { hash: e.hash }),
    'renewals[0]',
  );
  refuse('a version in a link', (e) => withLink(e, 1, { v: 1 }), 'renewals[1]');
  refuse('an unknown field in a link', (e) => withLink(e, 1, { note: 'x' }), 'renewals[1]');
  refuse(
    'a link without a token',
    (e) => ({ ...e, renewals: [{ ...link(e, 0), token: undefined }] }),
    'renewals[0].token',
  );
  refuse(
    'a link with a field missing',
    (e) => ({
      ...e,
      renewals: [Object.fromEntries(Object.entries(link(e, 0)).filter(([k]) => k !== 'genTime'))],
    }),
    'renewals[0]',
  );
  refuse('a bad kind in a link', (e) => withLink(e, 0, { kind: 'many' }), 'renewals[0].kind');
  refuse(
    'a bad service in a link',
    (e) => withLink(e, 1, { service: 'Free' }),
    'renewals[1].service',
  );
  refuse(
    'a bad time in a link',
    (e) => withLink(e, 1, { receivedAtMs: 5 }),
    'renewals[1].receivedAtMs',
  );
  refuse(
    'a token that is not canonical base64url',
    (e) => withLink(e, 0, { token: link(e, 0).token + '=' }),
    'renewals[0].token',
  );
  refuse(
    'a bad genTime in a link',
    (e) => withLink(e, 0, { genTime: '2026-01-01' }),
    'renewals[0].genTime',
  );
  refuse(
    'a batch receipt in a single link',
    (e) => withLink(e, 0, { batch: { v: 1, size: 1, index: 0, salt: 'x', path: [] } }),
    'renewals[0].batch',
  );
  refuse(
    'kind batch without a receipt in a link',
    (e) => withLink(e, 0, { kind: 'batch' }),
    'renewals[0].batch',
  );
  refuse('a bad policy in a link', (e) => withLink(e, 0, { policy: 'x' }), 'renewals[0].policy');
  refuse(
    'a bad signerNotAfter in a link',
    (e) => withLink(e, 0, { signerNotAfter: 'x' }),
    'renewals[0].signerNotAfter',
  );
  it('refuses a getter in a link and a throwing proxy, never runs the getter', async () => {
    const e = await make();
    let ran = false;
    const l = { ...e.renewals![0]! };
    Object.defineProperty(l, 'token', {
      enumerable: true,
      get: () => {
        ran = true;
        return 'x';
      },
    });
    expect(code(readEvidence({ ...e, renewals: [l] }))).toBe('bad-evidence');
    expect(ran).toBe(false);
    const boom = new Proxy(
      {},
      {
        get: () => {
          throw new Error('x');
        },
        ownKeys: () => {
          throw new Error('x');
        },
        getPrototypeOf: () => {
          throw new Error('x');
        },
      },
    );
    expect(code(readEvidence({ ...e, renewals: [boom] }))).toBe('bad-evidence');
    expect(code(readEvidence({ ...e, renewals: boom }))).toBe('bad-evidence');
  });
  it('at most MAX_RENEWALS renewals: 63 are read, 64 are refused', async () => {
    const e = await make();
    const many = (n: number) => ({
      ...e,
      renewals: Array.from({ length: n }, () => e.renewals![0]!),
    });
    expect(EVIDENCE_LIMITS.MAX_RENEWALS).toBe(63);
    expect(readEvidence(many(63)).ok).toBe(true);
    expect(detail(readEvidence(many(64)))).toBe('renewals');
  });
  it('reads a list by length and index, never through the iterator', async () => {
    const e = await make();
    const list = [...e.renewals!];
    Object.defineProperty(list, Symbol.iterator, {
      value: () => {
        throw new Error('iterated');
      },
    });
    expect(readEvidence({ ...e, renewals: list }).ok).toBe(true);
  });
});

describe('verifyEvidence with renewals', () => {
  it('verifies the chain and reports the original stamp plus the chain facts', async () => {
    const e = await make();
    const r = await verify(e);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value).toMatchObject({
      kind: 'single',
      service: 'freetsa',
      genTime: '2026-01-01T00:00:00.000Z',
      signerNotAfter: '2026-07-01T00:00:00.000Z',
      renewalLinks: 2,
      lastGenTime: '2026-11-01T00:00:00.000Z',
      lastSignerNotAfter: '2040-01-01T00:00:00.000Z',
    });
    expect(r.value.weakestLink).toEqual({
      index: 1,
      marginMs: Date.parse('2026-11-20T00:00:00Z') - Date.parse('2026-11-01T00:00:00Z'),
    });
    expect(r.value).not.toHaveProperty('renewedAt');
    expect(r.value).not.toHaveProperty('marginMs');
  });
  it('evidence without renewals has none of the chain fields', async () => {
    const plain = await make([STEPS[0]!]);
    const r = await verify(plain);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    for (const key of ['renewalLinks', 'weakestLink', 'lastGenTime', 'lastSignerNotAfter']) {
      expect(r.value).not.toHaveProperty(key);
    }
  });
  it('the evidence is checked against the given hash first', async () => {
    const e = await make();
    expect(code(await verify(e, {}, sha(Uint8Array.of(1))))).toBe('evidence-hash-mismatch');
  });
  it('works from text too', async () => {
    const text = serializeEvidence(await make());
    expect(text.ok && (await verify(text.value)).ok).toBe(true);
  });
  it('a renewal moved, doubled, dropped from the front or replaced is refused', async () => {
    const e = await make([
      { at: '2026-01-01T00:00:00Z' },
      { at: '2026-06-01T00:00:00Z' },
      { at: '2026-11-01T00:00:00Z' },
    ]);
    const [r1, r2] = e.renewals!;
    expect(code(await verify({ ...e, renewals: [r2, r1] }))).toBe('bad-renewal'); // times fall
    expect(code(await verify({ ...e, renewals: [r1, r1] }))).toBe('imprint-mismatch');
    expect(code(await verify({ ...e, renewals: [r2] }))).toBe('imprint-mismatch');
    const other = await make([
      { at: '2026-01-01T00:00:00Z' },
      { at: '2026-06-01T00:00:01Z' },
      { at: '2026-11-01T00:00:00Z' },
    ]);
    expect(code(await verify({ ...e, renewals: [other.renewals![0]!, r2!] }))).toBe(
      'imprint-mismatch',
    );
  });
  it('the last renewal can be cut off: the shorter chain is still a chain', async () => {
    const e = await make();
    const r = await verify({ ...e, renewals: [e.renewals![0]!] });
    expect(r.ok && r.value.renewalLinks).toBe(1);
  });
  it('the chain of another hash does not carry over', async () => {
    const e = await make();
    const other = await makeChain(sha(Uint8Array.of(3)), STEPS);
    const swapped = {
      ...e,
      renewals: e.renewals!.map((r, i) => ({ ...r, token: toBase64Url(other[i + 1]!.token) })),
    };
    expect(code(await verify(swapped))).toBe('imprint-mismatch');
  });
  it('the repeated facts of a renewal are compared with the check (bad-evidence, with the field)', async () => {
    const e = await make();
    const wrong = (over: object) => ({
      ...e,
      renewals: e.renewals!.map((r, j) => (j === 1 ? { ...r, ...over } : r)),
    });
    const a = await verify(wrong({ genTime: '2026-11-01T00:00:01.000Z' }));
    expect([code(a), detail(a)]).toEqual(['bad-evidence', 'renewals[1].genTime']);
    const b = await verify(wrong({ policy: '1.2.3.5' }));
    expect([code(b), detail(b)]).toEqual(['bad-evidence', 'renewals[1].policy']);
    const c = await verify(wrong({ signerNotAfter: '2041-01-01T00:00:00.000Z' }));
    expect([code(c), detail(c)]).toEqual(['bad-evidence', 'renewals[1].signerNotAfter']);
    const d = await verify({ ...e, genTime: '2026-01-01T00:00:01.000Z' });
    expect([code(d), detail(d)]).toEqual(['bad-evidence', 'genTime']);
    // a renewal without the optional facts is fine
    const bare = {
      ...e,
      renewals: e.renewals!.map((r) => {
        const rest: Record<string, unknown> = { ...r };
        delete rest.policy;
        delete rest.signerNotAfter;
        return rest;
      }),
    };
    expect((await verify(bare)).ok).toBe(true);
  });
  it('a renewal after the signer ended is renewal-too-late', async () => {
    const steps = [
      {
        at: '2026-01-01T00:00:00Z',
        validity: ['20200101000000Z', '20260301000000Z'] as [string, string],
      },
      { at: '2026-04-01T00:00:00Z' },
    ];
    const links = await makeChain(HASH, steps);
    // the repeated facts are never reached: the chain says no first
    const e = evidenceOf(
      HASH,
      links,
      steps.map((s) => ({
        genTime: new Date(s.at).toISOString(),
        signerNotAfter: '2040-01-01T00:00:00.000Z',
        policy: '1.2.3.4',
      })),
    );
    expect(code(await verify(e))).toBe('renewal-too-late');
  });
  it('now and at count for the last link only; minGenTime for the first', async () => {
    const e = await make();
    expect((await verify(e, { now: new Date('2026-12-02T00:00:00Z') })).ok).toBe(true);
    expect(code(await verify(e, { at: new Date('2041-01-01T00:00:00Z') }))).toBe(
      'certificate-not-valid-at-time',
    );
    expect(code(await verify(e, { minGenTime: new Date('2026-01-02T00:00:00Z') }))).toBe(
      'time-too-old',
    );
  });
  it('crls are passed on to the chain', async () => {
    const e = await make([
      { at: '2026-02-01T00:00:00Z', serial: 21 },
      { at: '2026-03-01T00:00:00Z', serial: 22 },
    ]);
    const list = (serial: number, date: string) =>
      buildCrl({
        key: BASE.keys.ca,
        issuer: 'CA',
        thisUpdate: '20260101000000Z',
        nextUpdate: '20270101000000Z',
        entries: [{ serial, date }],
      });
    expect(code(await verify(e, { crls: [list(21, '20260115000000Z')] }))).toBe('revoked');
    expect(code(await verify(e, { crls: [list(22, '20260115000000Z')] }))).toBe('revoked');
    expect((await verify(e, { crls: [list(23, '20260115000000Z')] })).ok).toBe(true);
  });
  it('expectedNonce stays unavailable, other bad options are bad-options', async () => {
    const e = await make();
    expect(code(await verify(e, { expectedNonce: Uint8Array.of(1) }))).toBe('bad-options');
    expect(code(await verify(e, { maxSkewMs: -1 }))).toBe('bad-options');
  });
});
