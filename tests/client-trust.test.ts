import { createRelayClient } from '../src/client/index.ts';
import type { ClientFailure, Evidence, RelayClientOptions } from '../src/client/index.ts';
import { toBase64Url, readToken } from '../src/index.ts';
import { verifyEvidence } from '../src/client/index.ts';
import { sha256 } from './helpers.ts';
import { build } from './token-builder.ts';
import {
  KEY_1,
  SIGNER,
  TEST_AUDIENCE,
  hashOf,
  headParts,
  startFake,
  type FakeRelay,
  type Seen,
} from './client-harness.ts';

// Audit findings M3 (trust per service) and M4 (a relay's Date must not make an older token acceptable).

const SIGNER_B = build();
const genTimeText = (ms: number) =>
  new Date(ms)
    .toISOString()
    .replace(/[-:T]/g, '')
    .replace(/\.\d+Z$/, 'Z');

/** An answer for `service` whose token was made by `signer` (the harness's `okBody` always uses signer A). */
function bodyBy(signer: ReturnType<typeof build>, service: string, s: Seen, genTimeMs: number) {
  const made = build({
    keys: signer.keys,
    hash: hashOf(s),
    nonceBytes: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
    genTime: genTimeText(genTimeMs),
  });
  return {
    service,
    genTime: new Date(genTimeMs).toISOString(),
    accuracyMs: null,
    serial: readToken(made.token).info.serial,
    token: toBase64Url(made.token),
  };
}

const options = (origin: string, over: Partial<RelayClientOptions> = {}): RelayClientOptions => ({
  relayUrl: origin,
  audience: TEST_AUDIENCE,
  keyId: KEY_1.id,
  privateKey: KEY_1.privateKey,
  trust: [SIGNER.caPem, SIGNER_B.caPem],
  services: ['sectigo'],
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
const hash = sha256('audit trust');

describe('M3: trust per service', () => {
  let fake: FakeRelay | undefined;
  afterEach(() => fake?.close());
  const answerA = async () =>
    (fake = await startFake((s) => ({
      status: 200,
      json: bodyBy(SIGNER, 'sectigo', s, Date.now()),
    })));

  it('the array form trusts all anchors for every service (unchanged)', async () => {
    const f = await answerA();
    const r = await make(options(f.origin)).stamp(hash);
    expect(r.ok).toBe(true);
  });

  it('a token of service A under the label of service B is refused with the map', async () => {
    const f = await answerA();
    const client = make(options(f.origin, { trust: { sectigo: [SIGNER_B.caPem] } }));
    expect(failure(await client.stamp(hash)).reason).toBe('untrusted-chain');
  });

  it('with the map, the anchor of the requested service passes', async () => {
    const f = await answerA();
    const client = make(options(f.origin, { trust: { sectigo: [SIGNER.caPem] } }));
    expect((await client.stamp(hash)).ok).toBe(true);
  });

  it('a map must name every service, no unknown ones, only lists of PEM texts', () => {
    const bad = (trust: unknown, services = ['sectigo']) =>
      createRelayClient(
        options('http://127.0.0.1:1', { trust: trust as never, services }),
      ) as ClientFailure;
    expect(bad({ freetsa: [SIGNER.caPem] }).reason).toBe('bad-options'); // sectigo missing
    expect(bad({ sectigo: [] }).reason).toBe('bad-options');
    expect(bad({ sectigo: [SIGNER.caPem], other: [SIGNER.caPem] }).reason).toBe('bad-options');
    expect(bad({ sectigo: ['not pem'] }).reason).toBe('bad-pem');
    expect(bad({ sectigo: 'x' }).reason).toBe('bad-options');
  });

  it('expectedPolicy is passed to the verification (a wrong policy is refused)', async () => {
    const f = await answerA();
    const client = make(options(f.origin, { expectedPolicy: '1.2.3.4.5.6.7' }));
    expect(failure(await client.stamp(hash)).reason).toBe('policy-mismatch');
  });

  it('verifyEvidence with a map checks against the service of the evidence', async () => {
    const f = await answerA();
    const r = await make(options(f.origin)).stamp(hash);
    if (!r.ok) throw new Error('stamp');
    const evidence = r.value as Evidence;
    const wrong = await verifyEvidence(evidence, hash, {
      trust: { sectigo: [SIGNER_B.caPem] },
    });
    expect(wrong.ok).toBe(false);
    if (!wrong.ok) expect(wrong.reason).toBe('untrusted-chain');
    const right = await verifyEvidence(evidence, hash, { trust: { sectigo: [SIGNER.caPem] } });
    expect(right.ok).toBe(true);
    const unknown = await verifyEvidence(evidence, hash, { trust: { freetsa: [SIGNER.caPem] } });
    expect(unknown.ok).toBe(false);
    if (!unknown.ok) expect(unknown.reason).toBe('bad-evidence');
    // a map of several services (the app's whole list): only the evidence's entry counts
    const several = await verifyEvidence(evidence, hash, {
      trust: { freetsa: [SIGNER_B.caPem], sectigo: [SIGNER.caPem] },
    });
    expect(several.ok).toBe(true);
    const severalWrong = await verifyEvidence(evidence, hash, {
      trust: { freetsa: [SIGNER.caPem], sectigo: [SIGNER_B.caPem] },
    });
    expect(severalWrong.ok).toBe(false);
    if (!severalWrong.ok) expect(severalWrong.reason).toBe('untrusted-chain');
    const tooMany = Object.fromEntries(
      Array.from({ length: 17 }, (_, i) => [`s${i}`, [SIGNER.caPem]]),
    );
    expect((await verifyEvidence(evidence, hash, { trust: tooMany })).ok).toBe(false);
    expect((await verifyEvidence(evidence, hash, { trust: {} })).ok).toBe(false);
    // the array form is unchanged
    expect((await verifyEvidence(evidence, hash, { trust: [SIGNER.caPem] })).ok).toBe(true);
  });
});

describe('M4: the relay Date cannot make an older token acceptable', () => {
  let fake: FakeRelay | undefined;
  afterEach(() => fake?.close());
  const T0 = Math.floor(Date.now() / 1000) * 1000;

  it('401 with Date = now - 64 s, then a token 120 s old: refused (time-too-old)', async () => {
    fake = await startFake((s, n) =>
      n === 0
        ? {
            status: 401,
            headers: { Date: new Date(T0 - 64_000).toUTCString() },
            json: { error: 'unauthorized' },
          }
        : { status: 200, json: bodyBy(SIGNER, 'sectigo', s, T0 - 120_000) },
    );
    const client = make(options(fake.origin, { now: () => T0 }));
    expect(failure(await client.stamp(hash)).reason).toBe('time-too-old');
    // the head was still signed with the corrected clock
    expect(headParts(fake.seen[1]!.head).ts).toBe(T0 - 64_000);
  });

  it('a token inside the slack of the device send time still passes', async () => {
    fake = await startFake((s, n) =>
      n === 0
        ? {
            status: 401,
            headers: { Date: new Date(T0 - 64_000).toUTCString() },
            json: { error: 'unauthorized' },
          }
        : { status: 200, json: bodyBy(SIGNER, 'sectigo', s, T0 - 30_000) },
    );
    const client = make(options(fake.origin, { now: () => T0 }));
    expect((await client.stamp(hash)).ok).toBe(true);
  });
});
