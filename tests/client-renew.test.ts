import {
  createRelayClient,
  readEvidence,
  serializeEvidence,
  verifyEvidence,
  type ClientFailure,
  type Evidence,
  type RelayClientOptions,
} from '../src/client/index.ts';
import { fromBase64Url, renewalImprint, toBase64Url } from '../src/index.ts';
import {
  KEY_1,
  TEST_AUDIENCE,
  TRUST,
  hashOf,
  makeToken,
  okBody,
  startFake,
  startRelay,
  type FakeRelay,
  type RealRelay,
} from './client-harness.ts';
import { sha256 } from './helpers.ts';

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
const verify = (e: unknown, hash: Uint8Array) => verifyEvidence(e, hash, { trust: TRUST });

describe('renew against a real relay (single operation)', () => {
  let relay: RealRelay;
  beforeAll(async () => {
    relay = await startRelay();
  });
  afterAll(() => relay.close());

  it('renews twice; the chain verifies, the original stamp stays as it was', async () => {
    const client = make(options(relay.origin));
    const hash = sha256('renew me');
    const first = evidenceOf(await client.stamp(hash));
    const snapshot = JSON.stringify(first);
    const second = evidenceOf(await client.renew(first));
    expect(JSON.stringify(first)).toBe(snapshot); // the input is not touched
    expect(second.renewals).toHaveLength(1);
    expect({ ...second, renewals: undefined }).toEqual({ ...first, renewals: undefined });
    const third = evidenceOf(await client.renew(second));
    expect(third.renewals).toHaveLength(2);
    expect(third.renewals![0]).toEqual(second.renewals![0]);
    const checked = await verify(third, hash);
    expect(checked).toMatchObject({ ok: true, value: { renewalLinks: 2, kind: 'single' } });
    expect(checked.ok && checked.value.genTime).toBe(first.genTime);
    expect(Date.parse(third.renewals![1]!.genTime)).toBeGreaterThanOrEqual(
      Date.parse(first.genTime),
    );
    expect(third.renewals![1]).not.toHaveProperty('hash');
    // the text form survives a trip and verifies without the relay
    const text = serializeEvidence(third);
    expect(text.ok && (await verify(text.value, hash)).ok).toBe(true);
    // and a renewal of the text form works too
    const fromText = evidenceOf(await client.renew(text.ok ? text.value : ''));
    expect(fromText.renewals).toHaveLength(3);
    // another hash does not verify
    expect((await verify(third, sha256('other'))).ok).toBe(false);
  });
});

describe('renew against a real relay (collecting operation)', () => {
  let relay: RealRelay;
  beforeAll(async () => {
    relay = await startRelay({ batch: { windowMs: 1000, max: 8 } });
  });
  afterAll(() => relay.close());

  it('a renewal stamped in a batch carries its receipt and verifies', async () => {
    const client = make(options(relay.origin));
    const hash = sha256('renew in a batch');
    const first = evidenceOf(await client.stamp(hash));
    const second = evidenceOf(await client.renew(first));
    expect(second.renewals![0]).toMatchObject({ kind: 'batch', service: 'freetsa' });
    expect(second.renewals![0]!.batch).toBeDefined();
    expect(await verify(second, hash)).toMatchObject({ ok: true, value: { renewalLinks: 1 } });
  }, 20_000);
});

describe('renew against a scripted relay', () => {
  let fake: FakeRelay | undefined;
  afterEach(async () => {
    await fake?.close();
    fake = undefined;
  });
  /** A relay that stamps what it is asked for at `time(n)`, for the n-th request. */
  async function relayAt(
    time: (n: number) => number,
    over: (n: number) => Record<string, unknown> | null = () => null,
  ) {
    fake = await startFake((seen, n) => {
      const special = over(n);
      if (special) return special as never;
      return { status: 200, json: okBody(seen.path.split('/').pop()!, hashOf(seen), time(n)) };
    });
    return fake;
  }

  it('sends exactly the renewal imprint of the evidence, and nothing else', async () => {
    const f = await relayAt(() => Date.now());
    const client = make(options(f.origin));
    const hash = sha256('what is sent');
    const first = evidenceOf(await client.stamp(hash));
    const second = evidenceOf(await client.renew(first));
    const third = evidenceOf(await client.renew(second));
    expect(f.seen).toHaveLength(3);
    expect(Buffer.from(hashOf(f.seen[0]!))).toEqual(Buffer.from(hash));
    const expectOne = await renewalImprint({
      hash,
      links: [{ token: fromBase64Url(first.token)! }],
    });
    expect(expectOne.ok && Buffer.from(hashOf(f.seen[1]!))).toEqual(
      expectOne.ok && Buffer.from(expectOne.value),
    );
    const expectTwo = await renewalImprint({
      hash,
      links: [first, ...(second.renewals ?? [])].map((x) => ({ token: fromBase64Url(x.token)! })),
    });
    expect(expectTwo.ok && Buffer.from(hashOf(f.seen[2]!))).toEqual(
      expectTwo.ok && Buffer.from(expectTwo.value),
    );
    expect(third.renewals).toHaveLength(2);
    // the renewal body carries the hash and nothing more
    expect(JSON.parse(new TextDecoder().decode(f.seen[1]!.body))).toEqual({
      hash: toBase64Url(hashOf(f.seen[1]!)),
    });
  });

  it('a form that is no evidence is bad-evidence and nothing is sent', async () => {
    const f = await relayAt(() => Date.now());
    const client = make(options(f.origin));
    for (const bad of [null, 5, 'x', {}, { v: 1 }, []]) {
      const r = failure(await client.renew(bad));
      expect(r.reason).toBe('bad-evidence');
    }
    expect(f.seen).toHaveLength(0);
  });

  it('evidence whose token was changed is refused with the library code, nothing is sent', async () => {
    const f = await relayAt(() => Date.now());
    const client = make(options(f.origin));
    const hash = sha256('tampered');
    const first = evidenceOf(await client.stamp(hash));
    const bytes = fromBase64Url(first.token)!;
    bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
    const r = failure(await client.renew({ ...first, token: toBase64Url(bytes) }));
    expect(['signature-invalid', 'malformed', 'message-digest-mismatch', 'bad-evidence']).toContain(
      r.reason,
    );
    expect(f.seen).toHaveLength(1);
  });

  it('a chain whose last signer has ended is not renewed (nothing is sent)', async () => {
    const f = await relayAt(() => Date.now());
    const hash = sha256('late');
    const first = evidenceOf(await make(options(f.origin)).stamp(hash));
    // a client whose clock stands behind the end of the harness certificates (2040)
    const late = make(options(f.origin, { now: () => Date.parse('2041-01-01T00:00:00Z') }));
    const r = failure(await late.renew(first));
    expect(r.reason).toBe('certificate-not-valid-at-time');
    expect(f.seen).toHaveLength(1);
  });

  it('a renewal token that is too old is refused: no evidence', async () => {
    const f = await relayAt((n) => (n === 0 ? Date.now() : Date.now() - 10 * 60_000));
    const client = make(options(f.origin));
    const first = evidenceOf(await client.stamp(sha256('old')));
    const r = failure(await client.renew(first));
    expect(r.reason).toBe('time-too-old');
  });

  it('a renewal token for another imprint is refused', async () => {
    const f = await relayAt(
      () => Date.now(),
      (n) =>
        n === 0
          ? null
          : { status: 200, json: { ...okBody('freetsa', sha256('not the imprint'), Date.now()) } },
    );
    const client = make(options(f.origin));
    const first = evidenceOf(await client.stamp(sha256('x')));
    expect(failure(await client.renew(first)).reason).toBe('imprint-mismatch');
  });

  it('a renewal that would lie before the stamp it covers is refused before it is sent (bad-renewal, order)', async () => {
    // the first stamp is two minutes ahead of the clock (inside the five minutes of skew), the renewal is on time
    const f = await relayAt((n) => (n === 0 ? Date.now() + 120_000 : Date.now()));
    const client = make(options(f.origin));
    const first = evidenceOf(await client.stamp(sha256('ahead')));
    const r = failure(await client.renew(first));
    expect(r.reason).toBe('bad-renewal');
    expect(r.detail).toBe('order');
    expect(f.seen).toHaveLength(1); // no stamp was spent on it
  });

  it('fails over to the next service like a stamp', async () => {
    const f = await relayAt(
      () => Date.now(),
      (n) =>
        n === 1
          ? { status: 502, json: { error: 'upstream-failed', reason: 'upstream-failed' } }
          : null,
    );
    const client = make(options(f.origin, { services: ['freetsa', 'sectigo'] }));
    const first = evidenceOf(await client.stamp(sha256('failover')));
    const second = evidenceOf(await client.renew(first));
    expect(f.seen.map((s) => s.path)).toEqual([
      '/v1/stamp/freetsa',
      '/v1/stamp/freetsa',
      '/v1/stamp/sectigo',
    ]);
    expect(second.renewals![0]!.service).toBe('sectigo');
  });

  it('a relay answer with the wrong service is bad-response', async () => {
    const f = await relayAt(
      () => Date.now(),
      (n) => (n === 1 ? { status: 200, json: okBody('sectigo', sha256('x'), Date.now()) } : null),
    );
    const client = make(options(f.origin));
    const first = evidenceOf(await client.stamp(sha256('wrong service')));
    expect(failure(await client.renew(first)).reason).toBe('bad-response');
  });

  it('options of stamp apply: a bad service, a hostile signal and an aborted signal give codes', async () => {
    const f = await relayAt(() => Date.now());
    const client = make(options(f.origin));
    const first = evidenceOf(await client.stamp(sha256('options')));
    expect(failure(await client.renew(first, { service: 'nowhere' })).reason).toBe('bad-options');
    expect(failure(await client.renew(first, { signal: 'x' as never })).reason).toBe('bad-options');
    const ctl = new AbortController();
    ctl.abort();
    expect(failure(await client.renew(first, { signal: ctl.signal })).reason).toBe('aborted');
    expect(f.seen).toHaveLength(1);
    expect(failure(await client.renew(first, 5 as never)).reason).toBe('bad-options');
  });

  it('the chain is at most 64 links: renewing evidence with 63 renewals is bad-renewal', async () => {
    const f = await relayAt((n) => (n === 0 ? Date.now() - 300_000 : Date.now()));
    const client = make(options(f.origin, { minGenTimeSlackMs: 3_600_000 }));
    const hash = sha256('full chain');
    const base0 = evidenceOf(await client.stamp(hash));
    // build 62 renewals offline with tokens of the harness signer, then one real renewal makes 63
    const links = [{ token: fromBase64Url(base0.token)! }];
    const renewals: NonNullable<Evidence['renewals']> = [];
    const t0 = Date.parse(base0.genTime);
    for (let i = 0; i < 62; i += 1) {
      const imprint = await renewalImprint({ hash, links });
      if (!imprint.ok) throw new Error('imprint');
      const token = makeToken(imprint.value, t0 + (i + 1) * 1000);
      links.push({ token });
      renewals.push({
        kind: 'single',
        service: 'freetsa',
        receivedAtMs: t0 + (i + 1) * 1000,
        token: toBase64Url(token),
        genTime: new Date(Math.floor((t0 + (i + 1) * 1000) / 1000) * 1000).toISOString(),
      });
    }
    const evidence: Evidence = { ...base0, renewals };
    // 62 renewals + the original = 63 links: one more is allowed
    const sixtyThree = evidenceOf(await client.renew(evidence));
    expect(sixtyThree.renewals).toHaveLength(63);
    const sent = f.seen.length;
    // the 64th renewal would be the 65th link
    expect(failure(await client.renew(sixtyThree)).reason).toBe('bad-renewal');
    expect(f.seen).toHaveLength(sent);
    expect(readEvidence(sixtyThree).ok).toBe(true);
  }, 60_000);
});
