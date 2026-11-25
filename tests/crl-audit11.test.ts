// Audit 11: `crls` through `verifyEvidence` and `verifyBatchedTimestamp`, the anchor cases of the CRL judge, and
// the gaps the mutation run found (each test below kills a named mutant of src/lib/crl.ts or src/lib/verify.ts).
import { createHash } from 'node:crypto';
import { verifyEvidence, type Evidence } from '../src/client/index.ts';
import { toBase64Url, verifyBatchedTimestamp, verifyTimestampToken } from '../src/index.ts';
import { batchImprint, leafHash, rootFromPath } from '../src/lib/batch.ts';
import { parseCrl } from '../src/lib/crl.ts';
import { children, parseDer, tlv } from '../src/lib/der.ts';
import { build, ext, seq } from './token-builder.ts';
import { OID_CRL, buildCrl, type CrlEntry, type CrlOpts } from './crl-builder.ts';

const BEFORE = '20251210000000Z';
const sha256 = (s: string) => new Uint8Array(createHash('sha256').update(s).digest());

// root "CA" (serial 1), intermediate "INT" (serial 2), signer (serial 7); genTime 2026-01-01
const t = build({ intermediate: {}, crlSign: true });
const rootCrl = (entries: CrlEntry[] = [], o: Partial<CrlOpts> = {}) =>
  buildCrl({ key: t.keys.ca, issuer: 'CA', entries, ...o });
const intCrl = (entries: CrlEntry[] = [], o: Partial<CrlOpts> = {}) =>
  buildCrl({ key: t.midKeys, issuer: 'INT', entries, ...o });
const revokedList = intCrl([{ serial: 7, date: BEFORE }]); // the intermediate revoked the signer

const reasonOf = (r: { ok: boolean; reason?: string }) => (r.ok ? 'ok' : r.reason);

// setups (module level: `await` is not allowed in a describe callback)
const singleHash = sha256('single');
const single = build({ intermediate: {}, crlSign: true, hash: singleHash });
const first = await verifyTimestampToken(single.token, singleHash, [single.caPem]);
if (!first.ok) throw new Error('builder token does not verify');
const evidence: Evidence = {
  v: 1,
  kind: 'single',
  service: 'stub',
  hash: toBase64Url(singleHash),
  hashAlg: 'sha256',
  receivedAtMs: Date.parse('2026-01-01T00:00:10.000Z'),
  token: toBase64Url(single.token),
  ...(first.value.policy === undefined ? {} : { policy: first.value.policy }),
  genTime: first.value.genTime,
  signerNotAfter: first.value.signerNotAfter,
};

const batchHash = sha256('batched');
const salt = new Uint8Array(32).fill(9);
// a tree of one leaf: the root is the leaf; the stamped imprint binds version, size and root
const leaf = await leafHash(salt, batchHash);
const root = await rootFromPath(leaf, 0, 1, []);
const imprint = await batchImprint(1, root);
const b = build({ intermediate: {}, crlSign: true, hash: imprint });

// ---------------------------------------------------------------------------------------------------------------
// M1: `crls` through verifyEvidence (single and batch) and through verifyBatchedTimestamp

describe('M1: crls through verifyEvidence', () => {
  const hash = singleHash;
  const trust = [single.caPem];
  const mid = (e: CrlEntry[] = [], o: Partial<CrlOpts> = {}) =>
    buildCrl({ key: single.midKeys, issuer: 'INT', entries: e, ...o });

  it('without lists nothing changes (no field, empty list)', async () => {
    expect(reasonOf(await verifyEvidence(evidence, hash, { trust }))).toBe('ok');
    expect(reasonOf(await verifyEvidence(evidence, hash, { trust, crls: [] }))).toBe('ok');
  });
  it('a clean list is ok, a list that revokes the signer is revoked', async () => {
    expect(reasonOf(await verifyEvidence(evidence, hash, { trust, crls: [mid()] }))).toBe('ok');
    const r = await verifyEvidence(evidence, hash, {
      trust,
      crls: [mid([{ serial: 7, date: BEFORE }])],
    });
    expect(reasonOf(r)).toBe('revoked');
  });
  it('an unusable list is bad-crl, never skipped', async () => {
    const strange = buildCrl({ key: build().keys.ca, issuer: 'CA' });
    expect(reasonOf(await verifyEvidence(evidence, hash, { trust, crls: [strange] }))).toBe(
      'bad-crl',
    );
    expect(
      reasonOf(await verifyEvidence(evidence, hash, { trust, crls: [Uint8Array.of(1)] })),
    ).toBe('bad-crl');
  });
  it('the same checks as verifyTimestampToken for the option itself (bad-options)', async () => {
    const good = mid();
    for (const crls of [null, 'x', 5, {}, new Set([good]), good, { length: 1, 0: good }, [null]]) {
      expect(
        reasonOf(await verifyEvidence(evidence, hash, { trust, crls } as never)),
        String(crls),
      ).toBe('bad-options');
    }
    expect(
      reasonOf(await verifyEvidence(evidence, hash, { trust, crls: Array(17).fill(good) })),
    ).toBe('bad-options');
  });
  it('a getter for crls is refused like every getter in the options', async () => {
    const options = { trust };
    Object.defineProperty(options, 'crls', { enumerable: true, get: () => [mid()] });
    expect(reasonOf(await verifyEvidence(evidence, hash, options))).toBe('bad-options');
  });
  it('the list is judged at `at`, as in verifyTimestampToken', async () => {
    const late = mid([], { thisUpdate: '20260201000000Z', nextUpdate: '20260301000000Z' });
    expect(reasonOf(await verifyEvidence(evidence, hash, { trust, crls: [late] }))).toBe('bad-crl');
    const r = await verifyEvidence(evidence, hash, {
      trust,
      crls: [late],
      at: new Date('2026-02-15T00:00:00Z'),
    });
    expect(reasonOf(r)).toBe('ok');
  });
});

describe('M1: crls through verifyEvidence of a batch and through verifyBatchedTimestamp', () => {
  const hash = batchHash;
  const trust = [b.caPem];
  const proof = { v: 1 as const, size: 1, index: 0, salt: toBase64Url(salt), path: [] as string[] };
  const mid = (e: CrlEntry[] = []) => buildCrl({ key: b.midKeys, issuer: 'INT', entries: e });
  const input = { token: b.token, hash, batch: proof };

  it('verifyBatchedTimestamp hands crls on: ok, revoked, bad-crl, bad-options', async () => {
    expect(reasonOf(await verifyBatchedTimestamp(input, trust))).toBe('ok');
    expect(reasonOf(await verifyBatchedTimestamp(input, trust, { crls: [mid()] }))).toBe('ok');
    expect(
      reasonOf(
        await verifyBatchedTimestamp(input, trust, { crls: [mid([{ serial: 7, date: BEFORE }])] }),
      ),
    ).toBe('revoked');
    expect(reasonOf(await verifyBatchedTimestamp(input, trust, { crls: [Uint8Array.of(1)] }))).toBe(
      'bad-crl',
    );
    expect(reasonOf(await verifyBatchedTimestamp(input, trust, { crls: 'x' } as never))).toBe(
      'bad-options',
    );
  });

  it('verifyEvidence of kind batch hands crls on', async () => {
    const first = await verifyBatchedTimestamp(input, trust);
    if (!first.ok) throw new Error('builder batch does not verify');
    const evidence: Evidence = {
      v: 1,
      kind: 'batch',
      service: 'stub',
      hash: toBase64Url(hash),
      hashAlg: 'sha256',
      receivedAtMs: Date.parse('2026-01-01T00:00:10.000Z'),
      token: toBase64Url(b.token),
      batch: proof,
      ...(first.value.policy === undefined ? {} : { policy: first.value.policy }),
      genTime: first.value.genTime,
      signerNotAfter: first.value.signerNotAfter,
    };
    expect(reasonOf(await verifyEvidence(evidence, hash, { trust, crls: [mid()] }))).toBe('ok');
    expect(
      reasonOf(
        await verifyEvidence(evidence, hash, { trust, crls: [mid([{ serial: 7, date: BEFORE }])] }),
      ),
    ).toBe('revoked');
    expect(
      reasonOf(await verifyEvidence(evidence, hash, { trust, crls: [Uint8Array.of(1)] })),
    ).toBe('bad-crl');
  });
});

// ---------------------------------------------------------------------------------------------------------------
// N1: anchors and lists

describe('N1: which anchors can sit under a list', () => {
  const run = async (trust: string[], crls: Uint8Array[]) =>
    reasonOf(await verifyTimestampToken(t.token, t.imprint, trust, { crls }));

  it('baselines: without lists every anchor choice that verified before still does', async () => {
    expect(await run([t.caPem], [])).toBe('ok');
    expect(await run([t.intPem], [])).toBe('ok');
    expect(await run([t.intPem, t.caPem], [])).toBe('ok');
  });
  it('the intermediate as the anchor: its own list is used, a list of the root is bad-crl', async () => {
    expect(await run([t.intPem], [intCrl()])).toBe('ok');
    expect(await run([t.intPem], [revokedList])).toBe('revoked');
    expect(await run([t.intPem], [rootCrl()])).toBe('bad-crl');
  });
  it('the intermediate and the root both as anchors: the chain ends at the first anchor reached (the intermediate)', async () => {
    expect(await run([t.intPem, t.caPem], [intCrl()])).toBe('ok');
    expect(await run([t.intPem, t.caPem], [revokedList])).toBe('revoked');
    // the root is above the end of the chain: its list is signed by no member
    expect(await run([t.intPem, t.caPem], [rootCrl()])).toBe('bad-crl');
    expect(await run([t.caPem, t.intPem], [rootCrl()])).toBe('bad-crl');
  });
  it('the signer as the anchor: every list is bad-crl (no member above it), without lists it verifies', async () => {
    const own = build({ selfSignedSigner: true });
    for (const crl of [
      buildCrl({ key: own.keys.tsa, issuer: 'TSA' }),
      buildCrl({ key: own.keys.ca, issuer: 'CA' }),
    ]) {
      const r = await verifyTimestampToken(own.token, own.imprint, [own.tsaPem], { crls: [crl] });
      expect(reasonOf(r)).toBe('bad-crl');
    }
    expect(
      reasonOf(await verifyTimestampToken(own.token, own.imprint, [own.tsaPem], { crls: [] })),
    ).toBe('ok');
  });
  it('a signer that is a CA allowed to sign lists and is its own anchor still cannot sign the list for itself (kills `k >= 0`)', async () => {
    // basicConstraints cA TRUE and digitalSignature + cRLSign: only the anchor exemption lets such a signer pass
    const bc = ext('2.5.29.19', true, seq(tlv(1, Uint8Array.of(0xff))));
    const own = build({
      selfSignedSigner: true,
      extraTsaExts: [bc],
      tsaKeyUsage: Uint8Array.of(1, 0x82),
    });
    expect(
      reasonOf(await verifyTimestampToken(own.token, own.imprint, [own.tsaPem], { crls: [] })),
    ).toBe('ok');
    const crl = buildCrl({ key: own.keys.tsa, issuer: 'TSA' });
    const r = await verifyTimestampToken(own.token, own.imprint, [own.tsaPem], { crls: [crl] });
    expect(reasonOf(r)).toBe('bad-crl');
  });
});

// ---------------------------------------------------------------------------------------------------------------
// N2: gaps found by the mutation run

describe('N2: the list reader (kills C18, C19, C25)', () => {
  const refused = (der: Uint8Array) => expect(() => parseCrl(der)).toThrow(/bad-crl/);

  it('a fourth element in the outer SEQUENCE is bad-crl (C18)', () => {
    const base = rootCrl();
    parseCrl(base);
    const outer = parseDer(base);
    const parts = children(outer).map((n) => n.raw);
    refused(tlv(0x30, ...parts, tlv(5)));
    // and a missing one
    refused(tlv(0x30, parts[0]!, parts[1]!));
  });
  it('the crlNumber of 20 bytes is read, one of 21 bytes is bad-crl (C19)', () => {
    const number = (n: number) =>
      rootCrl([], { exts: [ext(OID_CRL.number, false, tlv(2, new Uint8Array(n).fill(1)))] });
    parseCrl(number(20));
    refused(number(21));
  });
  it('a list without a version field that carries list extensions is bad-crl (C25)', () => {
    const exts = [ext(OID_CRL.number, false, tlv(2, Uint8Array.of(5)))];
    parseCrl(rootCrl([], { version: 1, exts }));
    refused(rootCrl([], { version: 'none', exts }));
    // an entry extension needs version 2 as well
    refused(rootCrl([{ serial: 7, date: BEFORE, reason: 1 }], { version: 'none' }));
  });
});

describe('N2: the judge (kills V12, V14, V15, V19)', () => {
  it('revoked wins over bad-crl when one chain is revoked and another has a list nobody on it signed (V12)', async () => {
    // chain A: signer -> INT (given as an anchor); chain B: signer -> twin of INT (serial 20) -> root (anchor)
    const twin = build({ intermediate: {}, twins: [{}], crlSign: true, keys: t.keys });
    // the list is the root's and revokes the twin: it is signed by no member of chain A (bad-crl there), and
    // it revokes the twin of chain B (revoked there)
    const list = buildCrl({
      key: twin.keys.ca,
      issuer: 'CA',
      entries: [{ serial: 20, date: BEFORE }],
    });
    const r = await verifyTimestampToken(twin.token, twin.imprint, [twin.intPem, twin.caPem], {
      crls: [list],
    });
    expect(reasonOf(r)).toBe('revoked');
  });

  it('an anchor without basicConstraints (X.509 v1) may sign lists: they are used, not refused (V14)', async () => {
    const v1 = build({ intermediate: {}, rootV1: true });
    const rootList = (entries: CrlEntry[]) => buildCrl({ key: v1.keys.ca, issuer: 'CA', entries });
    const run = async (crls: Uint8Array[]) =>
      reasonOf(await verifyTimestampToken(v1.token, v1.imprint, [v1.caPem], { crls }));
    expect(await run([])).toBe('ok');
    expect(await run([rootList([])])).toBe('ok');
    expect(await run([rootList([{ serial: 2, date: BEFORE }])])).toBe('revoked');
  });

  it('the limit of 64 signature checks: 64 are allowed, the 65th makes the list unverified (V15), and that is never ok', async () => {
    // `n` twins of the intermediate (serials 20 ...), sent before the real one, so they are tried first. The root's list
    // revokes every twin; `lists` further lists of the intermediate (empty, each signed by the key all of them share) are
    // checked once per certificate: 1 (root) + (n + 1) * lists signature checks for the whole search.
    const scenario = async (n: number, lists: number) => {
      const w = build({
        intermediate: {},
        twins: Array.from({ length: n }, () => ({})),
        crlSign: true,
        keys: t.keys,
      });
      const revokeTwins = buildCrl({
        key: w.keys.ca,
        issuer: 'CA',
        entries: Array.from({ length: n }, (_, i) => ({ serial: 20 + i, date: BEFORE })),
      });
      const empty = buildCrl({ key: w.midKeys, issuer: 'INT' });
      const r = await verifyTimestampToken(w.token, w.imprint, [w.caPem], {
        crls: [revokeTwins, ...Array.from({ length: lists }, () => empty)],
      });
      return reasonOf(r);
    };
    // 1 + 7 * 9 = 64 checks: the real intermediate is reached with all of them done
    expect(await scenario(6, 9)).toBe('ok');
    // 1 + 8 * 8 = 65 checks: the last list of the last certificate stays unchecked, the answer is not ok
    expect(await scenario(7, 8)).toBe('revoked');
  });

  it('crls as an array-like object is bad-options (V19)', async () => {
    const good = rootCrl();
    const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem], {
      crls: { length: 1, 0: good } as never,
    });
    expect(reasonOf(r)).toBe('bad-options');
    const typed = await verifyTimestampToken(t.token, t.imprint, [t.caPem], {
      crls: Object.assign(Object.create(Array.prototype) as object, {
        length: 1,
        0: good,
      }) as never,
    });
    expect(reasonOf(typed)).toBe('bad-options');
  });
});
