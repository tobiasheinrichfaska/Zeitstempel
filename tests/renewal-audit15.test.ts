// Audit 15 of the renewal chain: the size of the evidence text, the end of the whole certificate chain, the options
// that reach every link, and the places where `renew` must refuse before it spends a stamp.
import {
  createRelayClient,
  readEvidence,
  serializeEvidence,
  verifyEvidence,
  type ClientFailure,
  type Evidence,
  type RelayClientOptions,
} from '../src/client/index.ts';
import {
  fromBase64Url,
  renewalImprint,
  toBase64Url,
  verifyRenewalChain,
  verifyTimestampToken,
  type RenewalLink,
} from '../src/index.ts';
import {
  KEY_1,
  SIGNER,
  TEST_AUDIENCE,
  TRUST as HARNESS_TRUST,
  hashOf,
  makeToken,
  okBody,
  startFake,
  startRelay,
  type FakeRelay,
  type RealRelay,
} from './client-harness.ts';
import { sha256 } from './helpers.ts';
import { HASH, TRUST, makeChain, sha, tokenAt } from './renewal-helpers.ts';
import { padToken } from './token-pad.ts';
import { build } from './token-builder.ts';

const code = (r: { ok: boolean; reason?: string }) => (r.ok ? 'ok' : r.reason);
const detail = (r: { ok: boolean; detail?: string }) => (r.ok ? 'ok' : r.detail);
const gts = (iso: string) => iso.replace(/[-:T]/g, '').replace(/\.\d+Z$/, 'Z');
const NONCE = Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8);

const verify = (links: RenewalLink[], trust: string[], options?: object, hash = HASH) =>
  verifyRenewalChain({ hash, links, trust, ...(options === undefined ? {} : { options }) });

/** A chain of tokens made by one builder result `b` (its keys and certificates), each stamping the imprint of the one before. */
async function chainWith(
  b: ReturnType<typeof build>,
  opts: object[],
  times: string[],
): Promise<RenewalLink[]> {
  const links: RenewalLink[] = [];
  for (const [i, at] of times.entries()) {
    const imprint = i === 0 ? HASH : sha(links[i - 1]!.token);
    links.push({
      token: build({ keys: b.keys, hash: imprint, nonceBytes: NONCE, genTime: gts(at), ...opts[i] })
        .token,
    });
  }
  return links;
}

describe('the end of the WHOLE chain counts (chainNotAfter)', () => {
  const INT = { validity: ['20200101000000Z', '20260401000000Z'] as [string, string] };
  it('an intermediate that ends before the signer sets the margin and the date to renew before', async () => {
    const b = build({ intermediate: INT });
    const links = await chainWith(
      b,
      [{ intermediate: INT }, { intermediate: INT }],
      ['2026-01-01T00:00:00Z', '2026-03-01T00:00:00Z'],
    );
    const r = await verify(links, [b.caPem]);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const cut = Date.parse('2026-04-01T00:00:00Z');
    expect(r.value.links[0]!.signerNotAfter).toBe('2040-01-01T00:00:00.000Z');
    expect(r.value.links[0]!.chainNotAfter).toBe('2026-04-01T00:00:00.000Z');
    expect(r.value.links[0]!.marginMs).toBe(cut - Date.parse('2026-03-01T00:00:00Z'));
    expect(r.value.weakestLink).toEqual({
      index: 0,
      marginMs: cut - Date.parse('2026-03-01T00:00:00Z'),
    });
    expect(r.value.lastSignerNotAfter).toBe('2040-01-01T00:00:00.000Z');
    expect(r.value.lastChainNotAfter).toBe('2026-04-01T00:00:00.000Z');
    // the same chain judged after the end of the intermediate: the old reading would have said "fine"
    const late = await verify(links, [b.caPem], { at: new Date('2026-05-01T00:00:00Z') });
    expect(code(late)).toBe('certificate-not-valid-at-time');
  });
  it('the trust anchor ends first: it counts too (it is checked at the same time)', async () => {
    const b = build({ caValidity: ['20200101000000Z', '20260601000000Z'] });
    const links = await chainWith(
      b,
      [{ caValidity: ['20200101000000Z', '20260601000000Z'] }],
      ['2026-01-01T00:00:00Z'],
    );
    const r = await verifyTimestampToken(links[0]!.token, HASH, [b.caPem]);
    expect(r.ok && r.value.chainNotAfter).toBe('2026-06-01T00:00:00.000Z');
    expect(r.ok && r.value.signerNotAfter).toBe('2040-01-01T00:00:00.000Z');
    const at = await verifyTimestampToken(links[0]!.token, HASH, [b.caPem], {
      at: new Date('2026-06-02T00:00:00Z'),
    });
    expect(code(at)).toBe('certificate-not-valid-at-time');
  });
  it('without an intermediate the signer ends first: chainNotAfter is the signer end, never later', async () => {
    const links = await makeChain(HASH, [
      { at: '2026-01-01T00:00:00Z', validity: ['20200101000000Z', '20260701000000Z'] },
      { at: '2026-06-01T00:00:00Z' },
    ]);
    const r = await verify(links, TRUST);
    expect(r.ok && r.value.links[0]!.chainNotAfter).toBe(r.ok && r.value.links[0]!.signerNotAfter);
    expect(r.ok && r.value.links[0]!.chainNotAfter).toBe('2026-07-01T00:00:00.000Z');
  });
  it('verifyEvidence reports lastChainNotAfter for a renewed evidence', async () => {
    const b = build({ intermediate: INT });
    const links = await chainWith(
      b,
      [{ intermediate: INT }, { intermediate: INT }],
      ['2026-01-01T00:00:00Z', '2026-03-01T00:00:00Z'],
    );
    const chain = await verify(links, [b.caPem]);
    if (!chain.ok) throw new Error('chain');
    const one = (i: number) => ({
      kind: 'single' as const,
      service: 'freetsa',
      receivedAtMs: Date.parse(chain.value.links[i]!.genTime),
      token: toBase64Url(links[i]!.token),
      policy: chain.value.links[i]!.policy,
      genTime: chain.value.links[i]!.genTime,
      signerNotAfter: chain.value.links[i]!.signerNotAfter,
    });
    const evidence = {
      v: 1,
      ...one(0),
      hash: toBase64Url(HASH),
      hashAlg: 'sha256',
      renewals: [one(1)],
    } as Evidence;
    const v = await verifyEvidence(evidence, HASH, { trust: [b.caPem] });
    expect(v.ok && v.value.lastChainNotAfter).toBe('2026-04-01T00:00:00.000Z');
    expect(v.ok && v.value.lastSignerNotAfter).toBe('2040-01-01T00:00:00.000Z');
  });
});

describe('verifyRenewalChain: the options reach EVERY link, with values that are not the defaults', () => {
  it('minRsaBits: a weak RSA key in any link is weak-key (link named); 0 turns it off', async () => {
    const rsa = build({ rsa: { tsa: 2048 } });
    const ec = tokenAt(HASH, '2026-01-01T00:00:00Z');
    const t0 = build({
      keys: rsa.keys,
      hash: HASH,
      nonceBytes: NONCE,
      genTime: gts('2026-01-01T00:00:00Z'),
    }).token;
    const t1 = tokenAt(sha(t0), '2026-02-01T00:00:00Z').token;
    const r0 = await verify([{ token: t0 }, { token: t1 }], [rsa.caPem, ...TRUST], {
      minRsaBits: 3072,
    });
    expect([code(r0), detail(r0)]).toEqual(['weak-key', 'link 0']);
    // the RSA signer in the LAST link
    const u0 = ec.token;
    const u1 = build({
      keys: rsa.keys,
      hash: sha(u0),
      nonceBytes: NONCE,
      genTime: gts('2026-02-01T00:00:00Z'),
    }).token;
    const r1 = await verify([{ token: u0 }, { token: u1 }], [rsa.caPem, ...TRUST], {
      minRsaBits: 3072,
    });
    expect([code(r1), detail(r1)]).toEqual(['weak-key', 'link 1']);
    expect(
      (await verify([{ token: u0 }, { token: u1 }], [rsa.caPem, ...TRUST], { minRsaBits: 0 })).ok,
    ).toBe(true);
  });
  it('requireCriticalEku: false lets a link with a non-critical EKU pass, the default refuses it (link named)', async () => {
    const t0 = tokenAt(HASH, '2026-01-01T00:00:00Z').token;
    const t1 = tokenAt(sha(t0), '2026-02-01T00:00:00Z', { ekuCritical: false }).token;
    const links = [{ token: t0 }, { token: t1 }];
    const strict = await verify(links, TRUST);
    expect([code(strict), detail(strict)]).toEqual(['bad-eku', 'link 1']);
    expect((await verify(links, TRUST, { requireCriticalEku: false })).ok).toBe(true);
    const first = [{ token: tokenAt(HASH, '2026-01-01T00:00:00Z', { ekuCritical: false }).token }];
    expect(code(await verify(first, TRUST))).toBe('bad-eku');
    expect((await verify(first, TRUST, { requireCriticalEku: false })).ok).toBe(true);
  });
  it('maxSkewMs: a link 3 minutes ahead of `now` passes the default 5 minutes, not 1 minute (link named)', async () => {
    const links = await makeChain(HASH, [
      { at: '2026-01-01T00:00:00Z' },
      { at: '2026-06-15T00:03:00Z' },
    ]);
    const now = new Date('2026-06-15T00:00:00Z');
    expect((await verify(links, TRUST, { now })).ok).toBe(true);
    const r = await verify(links, TRUST, { now, maxSkewMs: 60_000 });
    expect([code(r), detail(r)]).toEqual(['time-in-future', 'link 1']);
    expect((await verify(links, TRUST, { now, maxSkewMs: 600_000 })).ok).toBe(true);
  });
});

describe('hostile input of the chain functions', () => {
  it('a class instance is no chain object, no link and no options (never read through its prototype)', async () => {
    const links = await makeChain(HASH, [{ at: '2026-01-01T00:00:00Z' }]);
    class Input {
      hash = HASH;
      links = links;
      trust = TRUST;
    }
    class Link {
      token = links[0]!.token;
    }
    expect(code(await verifyRenewalChain(new Input() as never))).toBe('bad-options');
    expect(code(await verify([new Link() as never], TRUST))).toBe('bad-renewal');
    expect(code(await renewalImprint(new Input() as never))).toBe('bad-options');
  });
  it('the hash is exactly 32 bytes: 31, 33 and 64 are bad-hash everywhere', async () => {
    const links = await makeChain(HASH, [{ at: '2026-01-01T00:00:00Z' }]);
    for (const n of [0, 31, 33, 64]) {
      const hash = new Uint8Array(n).fill(7);
      expect(code(await verify(links, TRUST, undefined, hash))).toBe('bad-hash');
      expect(code(await renewalImprint({ hash, links }))).toBe('bad-hash');
    }
  });
});

// ---- client: the size of the evidence text, the order, the learned clock offset

const options = (origin: string, over: Partial<RelayClientOptions> = {}): RelayClientOptions => ({
  relayUrl: origin,
  audience: TEST_AUDIENCE,
  keyId: KEY_1.id,
  privateKey: KEY_1.privateKey,
  trust: HARNESS_TRUST,
  services: ['freetsa', 'sectigo'],
  minGenTimeSlackMs: 3_600_000,
  ...over,
});
function make(o: RelayClientOptions) {
  const r = createRelayClient(o);
  if (!r.ok) throw new Error(`client: ${r.reason}`);
  return r.value;
}
const evidenceOf = (r: { ok: boolean }): Evidence => {
  if (!r.ok) throw new Error(`no evidence: ${JSON.stringify(r)}`);
  return (r as unknown as { value: Evidence }).value;
};
const failure = (r: { ok: boolean }): ClientFailure => {
  expect(r.ok).toBe(false);
  return r as ClientFailure;
};
/** An evidence with `renewals` links of `padBytes` filler each, made offline with the harness signer. */
async function padded(base: Evidence, renewals: number, padBytes: number): Promise<Evidence> {
  const hash = fromBase64Url(base.hash)!;
  const links: RenewalLink[] = [{ token: fromBase64Url(base.token)! }];
  const out: NonNullable<Evidence['renewals']> = [];
  const t0 = Date.parse(base.genTime);
  for (let i = 0; i < renewals; i += 1) {
    const imprint = await renewalImprint({ hash, links });
    if (!imprint.ok) throw new Error('imprint');
    const ms = t0 + (i + 1) * 1000;
    const token = padToken(makeToken(imprint.value, ms), padBytes);
    links.push({ token });
    out.push({
      kind: 'single',
      service: 'freetsa',
      receivedAtMs: ms,
      token: toBase64Url(token),
      genTime: new Date(Math.floor(ms / 1000) * 1000).toISOString(),
    });
  }
  return { ...base, renewals: out };
}

describe('the size of the evidence text (A15-M1)', () => {
  let fake: FakeRelay | undefined;
  afterEach(async () => {
    await fake?.close();
    fake = undefined;
  });
  const slow = (extra?: (n: number) => Record<string, unknown> | null) =>
    startFake((seen, n) => {
      const special = extra?.(n);
      if (special) return special as never;
      return {
        status: 200,
        json: okBody(
          seen.path.split('/').pop()!,
          hashOf(seen),
          n === 0 ? Date.now() - 300_000 : Date.now(),
        ),
      };
    });

  it('serializeEvidence gives a code instead of a text that readEvidence would refuse; the object stays usable', async () => {
    fake = await slow();
    const client = make(options(fake.origin));
    const base = evidenceOf(await client.stamp(sha256('big')));
    const fits = await padded(base, 30, 11_000);
    const text = serializeEvidence(fits);
    expect(text.ok).toBe(true);
    if (text.ok) {
      expect(text.value.length).toBeLessThanOrEqual(500_000);
      expect(readEvidence(text.value).ok).toBe(true);
    }
    const over = await padded(base, 40, 11_000);
    const r = serializeEvidence(over);
    expect([code(r), detail(r)]).toEqual(['evidence-too-large', 'text']);
    expect(readEvidence(over).ok).toBe(true);
    expect((await verifyEvidence(over, sha256('big'), { trust: HARNESS_TRUST })).ok).toBe(true);
  }, 30_000);

  it('renew refuses BEFORE sending when the next link of that size would not fit', async () => {
    fake = await slow();
    const client = make(options(fake.origin));
    const hash = sha256('no room');
    const base = evidenceOf(await client.stamp(hash));
    const full = await padded(base, 31, 11_000); // about 480000 characters: still serializable
    const text = serializeEvidence(full);
    expect(text.ok ? text.value.length : 0).toBeGreaterThan(470_000);
    const sent = fake.seen.length;
    const r = failure(await client.renew(full));
    expect([r.reason, r.detail]).toEqual(['evidence-too-large', 'before sending']);
    expect(fake.seen).toHaveLength(sent);
  }, 30_000);

  it('a new link larger than expected: the stamp is spent, the result says so and hands over the evidence object', async () => {
    let n = 0;
    fake = await startFake((seen) => {
      const i = n;
      n += 1;
      const hash = hashOf(seen);
      const at = i === 0 ? Date.now() - 300_000 : Date.now();
      const body = okBody(seen.path.split('/').pop()!, hash, at);
      if (i === 0) return { status: 200, json: body };
      return {
        status: 200,
        json: { ...body, token: toBase64Url(padToken(makeToken(hash, at), 150_000)) },
      };
    });
    const client = make(options(fake.origin));
    const hash = sha256('huge link');
    const base = evidenceOf(await client.stamp(hash));
    const near = await padded(base, 22, 11_000); // about 330000 characters
    const r = failure(await client.renew(near));
    expect([r.reason, r.detail]).toEqual(['evidence-too-large', 'stamp spent']);
    expect(fake.seen).toHaveLength(2);
    expect(r.evidence?.renewals).toHaveLength(23);
    expect((await verifyEvidence(r.evidence, hash, { trust: HARNESS_TRUST })).ok).toBe(true);
    expect(code(serializeEvidence(r.evidence!))).toBe('evidence-too-large');
  }, 30_000);
});

describe('renew looks at the order before it spends a stamp (A15-H5)', () => {
  it('evidence whose last stamp lies after the corrected clock is refused, nothing sent', async () => {
    const fake = await startFake((seen, n) => ({
      status: 200,
      json: okBody('freetsa', hashOf(seen), n === 0 ? Date.now() + 120_000 : Date.now()),
    }));
    try {
      const client = make(options(fake.origin));
      const first = evidenceOf(await client.stamp(sha256('ahead')));
      const r = failure(await client.renew(first));
      expect([r.reason, r.detail]).toEqual(['bad-renewal', 'order']);
      expect(fake.seen).toHaveLength(1);
    } finally {
      await fake.close();
    }
  });
});

describe('renew uses the clock offset the client learned', () => {
  let relay: RealRelay;
  beforeAll(async () => {
    relay = await startRelay();
  });
  afterAll(() => relay.close());
  it('a clock 62 s behind is corrected by the stamp and then by renew (the check runs on the corrected time)', async () => {
    const client = make(
      options(relay.origin, { services: ['freetsa'], now: () => Date.now() - 62_000 }),
    );
    const first = evidenceOf(await client.stamp(sha256('offset')));
    // the stamp is about now; on the uncorrected clock it would lie 62 s in the future
    const second = await client.renew(first);
    expect(second.ok).toBe(true);
  }, 20_000);
});

describe('serializeEvidence writes the service of each renewal, not the one of the first stamp', () => {
  it('mixed services survive the text', async () => {
    const links = await makeChain(HASH, [
      { at: '2026-01-01T00:00:00Z' },
      { at: '2026-02-01T00:00:00Z' },
    ]);
    const chain = await verify(links, TRUST);
    if (!chain.ok) throw new Error('chain');
    const one = (i: number, service: string) => ({
      kind: 'single' as const,
      service,
      receivedAtMs: Date.parse(chain.value.links[i]!.genTime),
      token: toBase64Url(links[i]!.token),
      policy: chain.value.links[i]!.policy,
      genTime: chain.value.links[i]!.genTime,
      signerNotAfter: chain.value.links[i]!.signerNotAfter,
    });
    const evidence = {
      v: 1,
      ...one(0, 'freetsa'),
      hash: toBase64Url(HASH),
      hashAlg: 'sha256',
      renewals: [one(1, 'sectigo')],
    } as Evidence;
    const text = serializeEvidence(evidence);
    if (!text.ok) throw new Error('text');
    const parsed = JSON.parse(text.value) as { service: string; renewals: { service: string }[] };
    expect([parsed.service, parsed.renewals[0]!.service]).toEqual(['freetsa', 'sectigo']);
    const back = readEvidence(text.value);
    expect(back.ok && back.value.renewals![0]!.service).toBe('sectigo');
  });
});

void SIGNER;
