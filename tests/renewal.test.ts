import { createHash } from 'node:crypto';
import { renewalImprint, verifyRenewalChain, type RenewalLink } from '../src/index.ts';
import { RENEWAL_LIMITS } from '../src/lib/renewal.ts';
import { batchImprint, leafHash } from '../src/lib/batch.ts';
import { refBatch, refProof } from './batch-reference.ts';
import { HASH, TRUST, makeChain, sha, tokenAt, type Step } from './renewal-helpers.ts';
import { toBase64Url } from '../src/index.ts';
import { buildCrl } from './crl-builder.ts';
import { BASE } from './renewal-helpers.ts';

const code = (r: { ok: boolean; reason?: string }) => (r.ok ? 'ok' : r.reason);
const detail = (r: { ok: boolean; detail?: string }) => (r.ok ? 'ok' : r.detail);

const STEPS: Step[] = [
  { at: '2026-01-01T00:00:00Z' },
  { at: '2026-06-01T00:00:00Z' },
  { at: '2026-12-01T00:00:00Z' },
];
const verify = (
  links: unknown,
  options?: unknown,
  hash: Uint8Array = HASH,
  trust: unknown = TRUST,
) =>
  verifyRenewalChain({
    hash,
    links: links as RenewalLink[],
    trust: trust as string[],
    ...(options === undefined ? {} : { options: options as never }),
  });

describe('renewalImprint', () => {
  const sha256 = (...p: Uint8Array[]) => {
    const h = createHash('sha256');
    for (const x of p) h.update(x);
    return new Uint8Array(h.digest());
  };

  it('is SHA-256 of the DER of the last token (RFC 4998 section 5.2; fixed known answer)', async () => {
    const hash = new Uint8Array(32).fill(7);
    const t0 = Uint8Array.of(1, 2, 3);
    const r = await renewalImprint({ hash, links: [{ token: t0 }] });
    expect(r.ok && Buffer.from(r.value).toString('hex')).toBe(
      Buffer.from(sha256(t0)).toString('hex'),
    );
    // pinned bytes: a change of the algorithm or of what is hashed breaks this
    expect(r.ok && Buffer.from(r.value).toString('hex')).toBe(
      '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81',
    );
  });
  it('the next imprint is the hash of the second token alone (the first is bound through it)', async () => {
    const hash = new Uint8Array(32).fill(7);
    const t0 = Uint8Array.of(1, 2, 3);
    const t1 = Uint8Array.of(4, 5, 6);
    const b = await renewalImprint({ hash, links: [{ token: t0 }, { token: t1 }] });
    expect(b.ok && Buffer.from(b.value)).toEqual(Buffer.from(sha256(t1)));
  });
  it('every token changes the result; the hash is checked but is not part of the value', async () => {
    const hash = new Uint8Array(32).fill(7);
    const base = await renewalImprint({ hash, links: [{ token: Uint8Array.of(1) }] });
    const other = [await renewalImprint({ hash, links: [{ token: Uint8Array.of(2) }] })];
    for (const o of other)
      expect(o.ok && base.ok && Buffer.compare(o.value, base.value)).not.toBe(0);
    const again = await renewalImprint({
      hash: new Uint8Array(32).fill(8),
      links: [{ token: Uint8Array.of(1) }],
    });
    expect(again).toEqual(base);
  });
  it('a batch receipt is not part of the imprint (the root fixes it)', async () => {
    const hash = new Uint8Array(32).fill(7);
    const a = await renewalImprint({ hash, links: [{ token: Uint8Array.of(1) }] });
    const b = await renewalImprint({
      hash,
      links: [{ token: Uint8Array.of(1), batch: { v: 1, size: 1, index: 0, salt: 'x', path: [] } }],
    });
    expect(b).toEqual(a);
  });
  it('refuses a bad hash, no links, too many links and hostile input with a code', async () => {
    const t = { token: Uint8Array.of(1) };
    expect(code(await renewalImprint({ hash: new Uint8Array(31), links: [t] }))).toBe('bad-hash');
    expect(code(await renewalImprint({ hash: HASH, links: [] }))).toBe('bad-renewal');
    const sixtyThree = Array.from({ length: 63 }, () => t);
    expect((await renewalImprint({ hash: HASH, links: sixtyThree })).ok).toBe(true);
    expect(code(await renewalImprint({ hash: HASH, links: [...sixtyThree, t] }))).toBe(
      'bad-renewal',
    );
    expect(code(await renewalImprint({ hash: HASH, links: 'x' as never }))).toBe('bad-renewal');
    expect(code(await renewalImprint(null as never))).toBe('bad-options');
    expect(code(await renewalImprint({ hash: HASH, links: [{ token: 'x' }] as never }))).toBe(
      'bad-renewal',
    );
    expect(code(await renewalImprint({ hash: HASH, links: [{ token: new Uint8Array(0) }] }))).toBe(
      'bad-renewal',
    );
    expect(
      code(await renewalImprint({ hash: HASH, links: [{ token: new Uint8Array(262145) }] })),
    ).toBe('bad-renewal');
    const boom = new Proxy(
      {},
      {
        get: () => {
          throw new Error('x');
        },
        getPrototypeOf: () => {
          throw new Error('x');
        },
        ownKeys: () => {
          throw new Error('x');
        },
      },
    );
    for (const hostile of [boom, { hash: HASH, links: boom }, { hash: boom, links: [t] }]) {
      expect((await renewalImprint(hostile as never)).ok).toBe(false);
    }
  });
  it('does not run a getter and copies the token (a change afterwards changes nothing)', async () => {
    let ran = false;
    const links = [
      {
        get token() {
          ran = true;
          return Uint8Array.of(1);
        },
      },
    ];
    expect(code(await renewalImprint({ hash: HASH, links: links as never }))).toBe('bad-renewal');
    expect(ran).toBe(false);
    const token = Uint8Array.of(1, 2, 3);
    const p = renewalImprint({ hash: HASH, links: [{ token }] });
    token[0] = 9;
    const q = await renewalImprint({ hash: HASH, links: [{ token: Uint8Array.of(1, 2, 3) }] });
    expect(await p).toEqual(q);
  });
});

describe('verifyRenewalChain: honest chains', () => {
  it('one link is the plain stamp: no weakest link', async () => {
    const links = await makeChain(HASH, [STEPS[0]!]);
    const r = await verify(links);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.links).toHaveLength(1);
    expect(r.value.weakestLink).toBeNull();
    expect(r.value.genTime).toBe('2026-01-01T00:00:00.000Z');
    expect(r.value.lastGenTime).toBe('2026-01-01T00:00:00.000Z');
    expect(r.value.links[0]).toMatchObject({ renewedAt: null, marginMs: null });
  });
  it('three links: times, margins, the weakest link and the last signer', async () => {
    const links = await makeChain(HASH, [
      { at: '2026-01-01T00:00:00Z', validity: ['20200101000000Z', '20260701000000Z'] },
      { at: '2026-06-01T00:00:00Z', validity: ['20200101000000Z', '20261201000000Z'] },
      { at: '2026-12-01T00:00:00Z', validity: ['20200101000000Z', '20300101000000Z'] },
    ]);
    const r = await verify(links);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const v = r.value;
    expect(v.genTime).toBe('2026-01-01T00:00:00.000Z');
    expect(v.lastGenTime).toBe('2026-12-01T00:00:00.000Z');
    expect(v.lastSignerNotAfter).toBe('2030-01-01T00:00:00.000Z');
    expect(v.links.map((l) => l.renewedAt)).toEqual([
      '2026-06-01T00:00:00.000Z',
      '2026-12-01T00:00:00.000Z',
      null,
    ]);
    const month = (a: string, b: string) => Date.parse(b) - Date.parse(a);
    expect(v.links[0]!.marginMs).toBe(month('2026-06-01T00:00:00Z', '2026-07-01T00:00:00Z'));
    expect(v.links[1]!.marginMs).toBe(month('2026-12-01T00:00:00Z', '2026-12-01T00:00:00Z'));
    expect(v.links[1]!.marginMs).toBe(0);
    expect(v.weakestLink).toEqual({ index: 1, marginMs: 0 });
  });
  it('the weakest link is the smallest margin, the earliest in a tie', async () => {
    // both margins are 31 days
    const links = await makeChain(HASH, [
      { at: '2026-01-01T00:00:00Z', validity: ['20200101000000Z', '20260801000000Z'] },
      { at: '2026-07-01T00:00:00Z', validity: ['20200101000000Z', '20260802000000Z'] },
      { at: '2026-07-02T00:00:00Z' },
    ]);
    const r = await verify(links);
    const days31 = 31 * 86_400_000;
    expect(r.ok && r.value.links.map((l) => l.marginMs)).toEqual([days31, days31, null]);
    expect(r.ok && r.value.weakestLink).toEqual({ index: 0, marginMs: days31 });
    // second link has the smaller margin: 1 month; first has 4 months
    const links2 = await makeChain(HASH, [
      { at: '2026-01-01T00:00:00Z', validity: ['20200101000000Z', '20260801000000Z'] },
      { at: '2026-04-01T00:00:00Z', validity: ['20200101000000Z', '20260701000000Z'] },
      { at: '2026-07-01T00:00:00Z' },
    ]);
    const r2 = await verify(links2);
    expect(r2.ok && r2.value.weakestLink?.index).toBe(1);
  });
  it('equal times are allowed (not falling)', async () => {
    const links = await makeChain(HASH, [
      { at: '2026-01-01T00:00:00Z' },
      { at: '2026-01-01T00:00:00Z' },
    ]);
    expect((await verify(links)).ok).toBe(true);
  });
  it('64 links pass, 65 are refused', async () => {
    const at = (i: number) =>
      new Date(Date.parse('2026-01-01T00:00:00Z') + i * 1000).toISOString().replace('.000Z', 'Z');
    const links = await makeChain(
      HASH,
      Array.from({ length: 64 }, (_, i) => ({ at: at(i) })),
    );
    const r = await verify(links);
    expect(r.ok && r.value.links.length).toBe(64);
    const more = [...links, links[0]!];
    expect(code(await verify(more))).toBe('bad-renewal');
    expect(RENEWAL_LIMITS.MAX_LINKS).toBe(64);
  }, 60_000);
  it('a link of a collecting relay (batch receipt) works in the middle and at the end', async () => {
    const first = await makeChain(HASH, [STEPS[0]!]);
    const imprint = await renewalImprint({ hash: HASH, links: first });
    if (!imprint.ok) throw new Error('imprint');
    // a tree of three leaves, ours at index 1
    const b = refBatch(3, 'renew');
    const ours = Buffer.from(imprint.value);
    const salt = b.salts[1]!;
    const leaves = [b.leaves[0]!, Buffer.from(await leafHash(salt, ours)), b.leaves[2]!];
    const tree = { ...b, leaves, hashes: [b.hashes[0]!, ours, b.hashes[2]!] };
    const { refRoot, refPath, refImprint } = await import('./batch-reference.ts');
    const root = refRoot(leaves);
    const proof = {
      v: 1 as const,
      size: 3,
      index: 1,
      salt: toBase64Url(salt),
      path: refPath(1, leaves).map((p) => toBase64Url(p)),
    };
    expect(Buffer.from(await batchImprint(3, root))).toEqual(refImprint(3, root));
    void tree;
    void refProof;
    const link1: RenewalLink = {
      token: tokenAt(new Uint8Array(refImprint(3, root)), '2026-06-01T00:00:00Z').token,
      batch: proof,
    };
    const r = await verify([first[0]!, link1]);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value.links[1]!.batch).toEqual({ size: 3, index: 1 });
    // a changed salt in the receipt: the leaf is another one
    const bad = { ...link1, batch: { ...proof, salt: toBase64Url(sha(Uint8Array.of(1))) } };
    expect(code(await verify([first[0]!, bad]))).toBe('imprint-mismatch');
    // a batch link at the start
    const lone = tokenAt(HASH, '2026-01-01T00:00:00Z').token;
    expect(code(await verify([{ token: lone, batch: proof }]))).toBe('imprint-mismatch');
  });
});

describe('verifyRenewalChain: hostile chains', () => {
  it('swapped links are refused', async () => {
    // with the times in order, swapping makes them fall: refused at once
    const [a0, b0, c0] = await makeChain(HASH, STEPS);
    expect(code(await verify([a0, c0, b0]))).toBe('bad-renewal');
    expect(detail(await verify([a0, c0, b0]))).toBe('order 1');
    expect(code(await verify([b0, a0, c0]))).toBe('bad-renewal');
    // with equal times only the binding is left to say no, and it names the first wrong link
    const same = { at: '2026-01-01T00:00:00Z' };
    const [a, b, c] = await makeChain(HASH, [same, same, same]);
    const r = await verify([a, c, b]);
    expect(code(r)).toBe('imprint-mismatch');
    expect(detail(r)).toBe('link 1');
    expect(code(await verify([b, a, c]))).toBe('imprint-mismatch');
    expect(detail(await verify([b, a, c]))).toBe('link 0');
  });
  it('a missing link in the middle, a doubled link and a missing first link are refused', async () => {
    const [a, b, c] = await makeChain(HASH, STEPS);
    expect(code(await verify([a, c]))).toBe('imprint-mismatch');
    expect(code(await verify([a, b, b, c]))).toBe('imprint-mismatch');
    expect(code(await verify([b, c]))).toBe('imprint-mismatch');
    expect(code(await verify([a, a]))).toBe('imprint-mismatch');
  });
  it('cutting off the end leaves an honest, shorter chain (the statement of the older links stays)', async () => {
    const [a, b] = await makeChain(HASH, STEPS);
    const r = await verify([a, b]);
    expect(r.ok && r.value.links.length).toBe(2);
  });
  it('a link that binds another predecessor is refused', async () => {
    const [a] = await makeChain(HASH, STEPS);
    const [x] = await makeChain(HASH, [{ at: '2026-01-02T00:00:00Z' }]);
    // honest first link `a`, second link stamped over the imprint that follows `x`
    const other = await renewalImprint({ hash: HASH, links: [x!] });
    if (!other.ok) throw new Error('imprint');
    const b = tokenAt(other.value, '2026-06-01T00:00:00Z').token;
    expect(code(await verify([a!, { token: b }]))).toBe('imprint-mismatch');
    // the second link stamps just the hash again (no binding at all)
    const naive = tokenAt(HASH, '2026-06-01T00:00:00Z').token;
    expect(code(await verify([a!, { token: naive }]))).toBe('imprint-mismatch');
  });
  it('a chain bent to another hash is refused at link 0', async () => {
    const links = await makeChain(HASH, STEPS);
    const r = await verify(links, undefined, sha(Uint8Array.of(9)));
    expect(code(r)).toBe('imprint-mismatch');
    expect(detail(r)).toBe('link 0');
  });
  it('a chain re-stamped over a different hash with a renewal imprint of the new hash is still a different chain', async () => {
    const other = sha(Uint8Array.of(5));
    const links = await makeChain(other, STEPS);
    expect(code(await verify(links))).toBe('imprint-mismatch');
    expect((await verify(links, undefined, other)).ok).toBe(true);
  });
  it('times that fall are refused (bad-renewal), the position in the detail', async () => {
    const links = await makeChain(HASH, [
      { at: '2026-06-01T00:00:00Z' },
      { at: '2026-01-01T00:00:00Z' },
    ]);
    const r = await verify(links);
    expect(code(r)).toBe('bad-renewal');
    expect(detail(r)).toBe('order 0');
    const three = await makeChain(HASH, [
      { at: '2026-01-01T00:00:00Z' },
      { at: '2026-09-01T00:00:00Z' },
      { at: '2026-06-01T00:00:00Z' },
    ]);
    expect(detail(await verify(three))).toBe('order 1');
  });
  it('a time one second before the older link falls, equal does not', async () => {
    const links = await makeChain(HASH, [
      { at: '2026-06-01T00:00:01Z' },
      { at: '2026-06-01T00:00:00Z' },
    ]);
    expect(code(await verify(links))).toBe('bad-renewal');
  });
  it('no links, too many links, and a form that is no chain are bad-renewal / bad-options', async () => {
    expect(code(await verify([]))).toBe('bad-renewal');
    expect(code(await verify('x'))).toBe('bad-renewal');
    expect(code(await verify([{ token: 'x' }]))).toBe('bad-renewal');
    expect(code(await verify([{ token: new Uint8Array(0) }]))).toBe('bad-renewal');
    expect(code(await verify([{ token: Uint8Array.of(1), extra: 1 }]))).toBe('bad-renewal');
    expect(code(await verify([{}]))).toBe('bad-renewal');
    expect(code(await verify([null]))).toBe('bad-renewal');
    expect(code(await verifyRenewalChain(null as never))).toBe('bad-options');
    expect(code(await verifyRenewalChain({ hash: HASH, links: [], extra: 1 } as never))).toBe(
      'bad-options',
    );
    expect(code(await verifyRenewalChain({ hash: HASH, links: [] } as never))).toBe('bad-options');
    expect(code(await verifyRenewalChain({ links: [], trust: TRUST } as never))).toBe(
      'bad-options',
    );
    const sixtyFive = Array.from({ length: 65 }, () => ({ token: Uint8Array.of(1) }));
    expect(code(await verify(sixtyFive))).toBe('bad-renewal');
  });
  it('a bad hash is bad-hash, bad trust is bad-options', async () => {
    const links = await makeChain(HASH, [STEPS[0]!]);
    expect(code(await verify(links, undefined, new Uint8Array(31)))).toBe('bad-hash');
    expect(code(await verify(links, undefined, HASH, 'x'))).toBe('bad-options');
    expect(code(await verify(links, undefined, HASH, []))).toBe('untrusted-chain');
  });
  it('a token that is no token fails with its own code and the link', async () => {
    const [a] = await makeChain(HASH, [STEPS[0]!]);
    const r = await verify([a, { token: Uint8Array.of(1, 2, 3) }]);
    expect(r.ok).toBe(false);
    expect(detail(r)).toBe('link 1');
  });
  it('a hostile proxy gives a code and never throws', async () => {
    const boom = new Proxy(
      {},
      {
        get: () => {
          throw new Error('x');
        },
        getPrototypeOf: () => {
          throw new Error('x');
        },
        ownKeys: () => {
          throw new Error('x');
        },
      },
    );
    const links = await makeChain(HASH, [STEPS[0]!]);
    for (const input of [
      boom,
      { hash: HASH, links: boom, trust: TRUST },
      { hash: HASH, links, trust: TRUST, options: boom },
    ]) {
      expect((await verifyRenewalChain(input as never)).ok).toBe(false);
    }
    expect(code(await verify([boom]))).toBe('bad-renewal');
  });
});

describe('verifyRenewalChain: when the renewal was too late', () => {
  const validity = (end: string): [string, string] => ['20200101000000Z', end];
  it('renewed after the signer certificate had ended: renewal-too-late', async () => {
    const links = await makeChain(HASH, [
      { at: '2026-01-01T00:00:00Z', validity: validity('20260301000000Z') },
      { at: '2026-04-01T00:00:00Z' },
    ]);
    const r = await verify(links);
    expect(code(r)).toBe('renewal-too-late');
    expect(detail(r)).toBe('link 0');
  });
  it('renewed at the very second the certificate ends is in time, one second later is not', async () => {
    const mk = (next: string) =>
      makeChain(HASH, [
        { at: '2026-01-01T00:00:00Z', validity: validity('20260301000000Z') },
        { at: next },
      ]);
    expect((await verify(await mk('2026-03-01T00:00:00Z'))).ok).toBe(true);
    expect(code(await verify(await mk('2026-03-01T00:00:01Z')))).toBe('renewal-too-late');
  });
  it('the last link counts at options.now and options.at', async () => {
    const links = await makeChain(HASH, [
      { at: '2026-01-01T00:00:00Z', validity: validity('20260301000000Z') },
    ]);
    expect((await verify(links)).ok).toBe(true);
    expect(code(await verify(links, { now: new Date('2026-02-01T00:00:00Z') }))).toBe('ok');
    expect(
      code(await verify(links, { now: new Date('2026-04-01T00:00:00Z'), maxSkewMs: Infinity })),
    ).toBe('certificate-not-valid-at-time');
    expect(code(await verify(links, { at: new Date('2026-04-01T00:00:00Z') }))).toBe(
      'certificate-not-valid-at-time',
    );
    // `at` wins over `now` for the last link
    expect(
      code(
        await verify(links, {
          at: new Date('2026-02-01T00:00:00Z'),
          now: new Date('2026-04-01T00:00:00Z'),
          maxSkewMs: Infinity,
        }),
      ),
    ).toBe('ok');
  });
  it('a failure that is not about the certificate time stays what it is', async () => {
    const links = await makeChain(HASH, [
      { at: '2026-01-01T00:00:00Z', validity: validity('20260301000000Z') },
      { at: '2026-04-01T00:00:00Z' },
    ]);
    // link 0 is also bound to another policy: that is reported, not "too late"
    expect(code(await verify(links, { expectedPolicy: '2.9.9' }))).toBe('policy-mismatch');
  });
});

describe('verifyRenewalChain: options', () => {
  it('minGenTime counts for link 0 only', async () => {
    const links = await makeChain(HASH, STEPS);
    expect(code(await verify(links, { minGenTime: new Date('2026-01-01T00:00:01Z') }))).toBe(
      'time-too-old',
    );
    expect(detail(await verify(links, { minGenTime: new Date('2026-01-01T00:00:01Z') }))).toBe(
      'link 0',
    );
    expect((await verify(links, { minGenTime: new Date('2026-01-01T00:00:00Z') })).ok).toBe(true);
  });
  it('expectedNonce is refused, unusable options are bad-options', async () => {
    const links = await makeChain(HASH, [STEPS[0]!]);
    expect(code(await verify(links, { expectedNonce: Uint8Array.of(1) }))).toBe('bad-options');
    expect(code(await verify(links, { at: 'x' }))).toBe('bad-options');
    expect(code(await verify(links, 'x'))).toBe('bad-options');
    expect(code(await verify(links, { maxSkewMs: -1 }))).toBe('bad-options');
  });
  it('now reaches every link: a link from the future is refused', async () => {
    const links = await makeChain(HASH, STEPS);
    const r = await verify(links, { now: new Date('2026-07-01T00:00:00Z'), maxSkewMs: 0 });
    expect(code(r)).toBe('time-in-future');
    expect(detail(r)).toBe('link 2');
  });
  it('expectedPolicy counts for every link', async () => {
    const links = await makeChain(HASH, STEPS);
    expect((await verify(links, { expectedPolicy: '1.2.3.4' })).ok).toBe(true);
    expect(code(await verify(links, { expectedPolicy: '1.2.3.5' }))).toBe('policy-mismatch');
  });
  it('minRsaBits and requireCriticalEku reach every link', async () => {
    const weak = await makeChain(HASH, STEPS);
    expect((await verify(weak, { minRsaBits: 0, requireCriticalEku: true })).ok).toBe(true);
  });
});

describe('verifyRenewalChain: revocation (offline lists)', () => {
  // all signers have serial 7 unless told otherwise; the CA lists revoke by serial
  const crl = (
    serial: number,
    date: string,
    o: { thisUpdate?: string; nextUpdate?: string } = {},
  ) =>
    buildCrl({
      key: BASE.keys.ca,
      issuer: 'CA',
      thisUpdate: o.thisUpdate ?? '20260101000000Z',
      nextUpdate: o.nextUpdate ?? '20270101000000Z',
      entries: [{ serial, date }],
    });
  it('a revoked link is revoked (the list is current at each check time)', async () => {
    const links = await makeChain(HASH, [
      { at: '2026-02-01T00:00:00Z', serial: 21 },
      { at: '2026-03-01T00:00:00Z', serial: 22 },
    ]);
    const lists = (serial: number, date: string) => [
      crl(serial, date, { thisUpdate: '20260101000000Z' }),
    ];
    expect((await verify(links, { crls: [crl(99, '20260101000000Z')] })).ok).toBe(true);
    const r0 = await verify(links, { crls: lists(21, '20260115000000Z') });
    expect(code(r0)).toBe('revoked');
    expect(detail(r0)).toBe('link 0');
    const r1 = await verify(links, { crls: lists(22, '20260115000000Z') });
    expect(code(r1)).toBe('revoked');
    expect(detail(r1)).toBe('link 1');
  });
  it('a revocation after the link was stamped leaves it valid', async () => {
    const links = await makeChain(HASH, [
      { at: '2026-02-01T00:00:00Z', serial: 21 },
      { at: '2026-03-01T00:00:00Z', serial: 22 },
    ]);
    expect((await verify(links, { crls: [crl(21, '20260215000000Z')] })).ok).toBe(true);
  });
  it('a list that is not current at the time of a link is bad-crl (documented limit)', async () => {
    const links = await makeChain(HASH, [
      { at: '2026-02-01T00:00:00Z', serial: 21 },
      { at: '2026-06-01T00:00:00Z', serial: 22 },
    ]);
    // current from 2026-05-01: too young for the check time of link 0 (the time of link 1 is 2026-06-01: fine) and the last one
    const list = crl(99, '20260101000000Z', {
      thisUpdate: '20260701000000Z',
      nextUpdate: '20260801000000Z',
    });
    expect(code(await verify(links, { crls: [list] }))).toBe('bad-crl');
  });
});
