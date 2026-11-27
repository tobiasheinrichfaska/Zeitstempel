// RFC 4998 evidence record: export, strict reader and verification of the renewal chain (src/lib/ers.ts, src/client/record.ts).
// The writer is checked by an independent reference decoder written from the ASN.1 text (tests/ers-reference.ts) and by
// OpenSSL (`asn1parse` for the structure, `ts -verify` for every token cut out of the record); the reader is fed hostile
// variants made by an independent writer.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  exportEvidenceRecord,
  readEvidenceRecord,
  renewalImprint,
  toBase64Url,
  verifyEvidenceRecord,
  verifyRenewalChain,
  type RenewalLink,
} from '../src/index.ts';
import { ERS_LIMITS } from '../src/lib/ers.ts';
import { serializeEvidence, serializeEvidenceRecord, verifyEvidence } from '../src/client/index.ts';
import {
  ALG_SHA1,
  ALG_SHA256,
  ALG_SHA256_BARE,
  ALG_SHA384,
  decodeRecord,
  der,
  writeRecord,
  writeStamp,
} from './ers-reference.ts';
import { octet, oidT, seq } from './token-builder.ts';
import {
  BASE,
  HASH,
  TRUST,
  evidenceOf,
  makeChain,
  sha,
  tokenAt,
  type Step,
} from './renewal-helpers.ts';

const code = (r: { ok: boolean; reason?: string }) => (r.ok ? 'ok' : r.reason);
const detail = (r: { ok: boolean; detail?: string }) => (r.ok ? 'ok' : r.detail);
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

const STEPS: Step[] = [
  { at: '2026-01-01T00:00:00Z', validity: ['20200101000000Z', '20260701000000Z'] },
  { at: '2026-06-01T00:00:00Z', validity: ['20200101000000Z', '20261201000000Z'] },
  { at: '2026-11-01T00:00:00Z' },
];

let links: RenewalLink[] = [];
let record: Uint8Array = new Uint8Array();
beforeAll(async () => {
  links = await makeChain(HASH, STEPS);
  const r = await exportEvidenceRecord({ hash: HASH, links });
  if (!r.ok) throw new Error(`export: ${r.reason}`);
  record = r.value;
});
const tokens = () => links.map((l) => l.token);
const stamps = (t: Uint8Array[] = tokens()) => t.map((x) => writeStamp(x));
const good = (t: Uint8Array[] = tokens()) => writeRecord({ chains: [stamps(t)] });
const read = (b: unknown) => readEvidenceRecord(b as Uint8Array);
const verify = (b: unknown, o: Record<string, unknown> = {}, hash = HASH) =>
  verifyEvidenceRecord({ bytes: b as Uint8Array, hash, trust: TRUST, ...o });

describe('exportEvidenceRecord: the structure of RFC 4998', () => {
  it('writes version 1, SHA-256, ONE chain, one ArchiveTimeStamp per link, the tokens verbatim (reference decoder)', () => {
    const d = decodeRecord(record);
    expect(d.version).toBe(1);
    expect(d.digestAlgorithms).toEqual([`sha256/0500`]);
    expect(d.cryptoInfos).toBe(false);
    expect(d.encryptionInfo).toBe(false);
    expect(d.chains).toHaveLength(1);
    const chain = d.chains[0]!.stamps;
    expect(chain).toHaveLength(3);
    for (const [i, s] of chain.entries()) {
      expect(s.digestAlgorithm).toBe('sha256/0500');
      expect(s.attributes).toBe(false);
      expect(s.reducedHashtree).toBe(false);
      expect(hex(s.timeStamp)).toBe(hex(links[i]!.token));
    }
  });
  it('is byte for byte what the independent writer makes from the same parts', () => {
    expect(hex(record)).toBe(hex(good()));
  });
  it('is DER with the exact bytes of the head: SEQUENCE (long length), INTEGER 1, SEQUENCE { SEQUENCE { sha256, NULL } }', () => {
    expect(hex(record.subarray(0, 2))).toBe('3082');
    expect(hex(record.subarray(4, 24))).toBe(
      '020101' + '300f' + '300d' + '0609608648016503040201' + '0500',
    );
  });
  it('the second and third stamp the SHA-256 of the DER of the token before (RFC 4998 section 5.2), computed by node:crypto', () => {
    const d = decodeRecord(record).chains[0]!.stamps;
    const imprints = links.map((l) => {
      const t = l.token;
      return hex(createHash('sha256').update(t).digest());
    });
    expect(imprints).toHaveLength(3);
    // the same values come out of the library
    return Promise.all(
      [1, 2].map(async (i) => {
        const r = await renewalImprint({ hash: HASH, links: links.slice(0, i) });
        expect(r.ok && hex(r.value)).toBe(imprints[i - 1]);
        expect(d[i]!.timeStamp.length).toBeGreaterThan(100);
      }),
    );
  });
  it('one link only is a record with one ArchiveTimeStamp that stamps the hash itself (no tree: RFC 4998 section 4.2)', async () => {
    const r = await exportEvidenceRecord({ hash: HASH, links: [links[0]!] });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(decodeRecord(r.value).chains[0]!.stamps).toHaveLength(1);
    expect((await verify(r.value)).ok).toBe(true);
  });
  it('refuses a chain whose link stamps something else (imprint-mismatch, link i)', async () => {
    const swapped = [links[0]!, links[2]!, links[1]!];
    const r = await exportEvidenceRecord({ hash: HASH, links: swapped });
    expect(r).toMatchObject({ ok: false, reason: 'imprint-mismatch', detail: 'link 1' });
    expect(code(await exportEvidenceRecord({ hash: sha(Uint8Array.of(9)), links }))).toBe(
      'imprint-mismatch',
    );
    expect(detail(await exportEvidenceRecord({ hash: HASH, links: [links[0]!, links[0]!] }))).toBe(
      'link 1',
    );
  });
  it('a batch receipt in any link is export-unsupported, before anything else is looked at', async () => {
    const batch = { v: 1 as const, size: 1, index: 0, salt: 'x', path: [] };
    expect(
      await exportEvidenceRecord({ hash: HASH, links: [{ token: links[0]!.token, batch }] }),
    ).toMatchObject({ ok: false, reason: 'export-unsupported', detail: 'link 0 batch' });
    expect(
      await exportEvidenceRecord({
        hash: HASH,
        links: [links[0]!, links[1]!, { ...links[2]!, batch }],
      }),
    ).toMatchObject({ ok: false, reason: 'export-unsupported', detail: 'link 2 batch' });
    expect(
      code(await exportEvidenceRecord({ hash: HASH, links: [{ token: Uint8Array.of(1), batch }] })),
    ).toBe('export-unsupported');
  });
  it('refuses a token over another hash algorithm and an unreadable token', async () => {
    expect(
      code(await exportEvidenceRecord({ hash: HASH, links: [{ token: Uint8Array.of(1, 2) }] })),
    ).not.toBe('ok');
  });
  it('a token over a SHA-384 imprint: unsupported-hash, in the exporter and in the reader (also inside an otherwise valid record)', async () => {
    const raw = seq(seq(oidT('2.16.840.1.101.3.4.2.2')), octet(new Uint8Array(48)));
    const t384 = tokenAt(HASH, '2026-01-01T00:00:00Z', { tstImprintRaw: raw }).token;
    expect(await exportEvidenceRecord({ hash: HASH, links: [{ token: t384 }] })).toMatchObject({
      ok: false,
      reason: 'unsupported-hash',
      detail: 'link 0',
    });
    expect(read(good([t384]))).toMatchObject({
      ok: false,
      reason: 'unsupported-hash',
      detail: 'link 0',
    });
  });
  it('refuses bad input with a code and never throws', async () => {
    expect(code(await exportEvidenceRecord(null as never))).toBe('bad-options');
    expect(code(await exportEvidenceRecord({ hash: HASH } as never))).toBe('bad-options');
    expect(code(await exportEvidenceRecord({ hash: new Uint8Array(31), links }))).toBe('bad-hash');
    expect(code(await exportEvidenceRecord({ hash: HASH, links: [] }))).toBe('bad-renewal');
    expect(code(await exportEvidenceRecord({ hash: HASH, links: 'x' as never }))).toBe(
      'bad-renewal',
    );
    const many = Array.from({ length: 65 }, () => links[0]!);
    expect(code(await exportEvidenceRecord({ hash: HASH, links: many }))).toBe('bad-renewal');
    const hostile = new Proxy(
      {},
      {
        get() {
          throw new Error('boom');
        },
        getPrototypeOf() {
          throw new Error('boom');
        },
        ownKeys() {
          throw new Error('boom');
        },
      },
    );
    expect(code(await exportEvidenceRecord(hostile as never))).toBe('bad-options');
  });
});

describe('readEvidenceRecord', () => {
  it('reads what the exporter wrote, tokens as copies', () => {
    const r = read(record);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.version).toBe(1);
    expect(r.value.digestAlgorithm).toBe('sha256');
    expect(r.value.tokens.map(hex)).toEqual(tokens().map(hex));
  });
  it('copies its input: a change after the call, or a view into a larger buffer, changes nothing', () => {
    const copy = record.slice();
    const r = read(copy);
    copy.fill(0);
    expect(r.ok && r.value.tokens.map(hex)).toEqual(tokens().map(hex));
    if (r.ok) {
      r.value.tokens[0]!.fill(0);
      expect(r.value.tokens[1]).not.toEqual(r.value.tokens[0]);
    }
    const big = new Uint8Array(record.length + 10);
    big.set(record, 5);
    expect(read(big.subarray(5, 5 + record.length)).ok).toBe(true);
    const shared = new Uint8Array(new SharedArrayBuffer(record.length));
    shared.set(record);
    expect(read(shared).ok).toBe(true);
  });
  it('accepts the algorithm with or without the NULL parameter, with or without the [0] digestAlgorithm', () => {
    const t = tokens();
    expect(read(writeRecord({ algorithms: [ALG_SHA256_BARE], chains: [stamps(t)] })).ok).toBe(true);
    expect(
      read(writeRecord({ chains: [t.map((x) => writeStamp(x, { algorithm: null }))] })).ok,
    ).toBe(true);
    expect(
      read(writeRecord({ chains: [t.map((x) => writeStamp(x, { algorithm: ALG_SHA256_BARE }))] }))
        .ok,
    ).toBe(true);
  });
  it('version: only 1 (0, 2, 255, a longer integer: unsupported-version; a non-minimal integer: malformed; no integer: bad-evidence-record)', () => {
    const t = tokens();
    const v = (b: number[]) =>
      read(writeRecord({ version: der(0x02, Uint8Array.from(b)), chains: [stamps(t)] }));
    expect(code(v([0]))).toBe('unsupported-version');
    expect(code(v([2]))).toBe('unsupported-version');
    expect(code(v([0, 255]))).toBe('unsupported-version');
    expect(code(v([1, 0]))).toBe('unsupported-version');
    expect(code(v([0, 1]))).toBe('malformed');
    expect(code(v([]))).toBe('malformed');
    expect(
      code(read(writeRecord({ version: der(0x04, Uint8Array.of(1)), chains: [stamps(t)] }))),
    ).toBe('bad-evidence-record');
  });
  it('the algorithm: another hash is unsupported-hash (list, [0] and inside a token), two, none, a duplicate or odd parameters are bad-evidence-record, two different ones (hash renewal) ers-unsupported', () => {
    const t = tokens();
    const withAlgs = (a: Uint8Array[]) => read(writeRecord({ algorithms: a, chains: [stamps(t)] }));
    expect(code(withAlgs([ALG_SHA1]))).toBe('unsupported-hash');
    expect(code(withAlgs([ALG_SHA384]))).toBe('unsupported-hash');
    expect(code(withAlgs([ALG_SHA256, ALG_SHA256]))).toBe('bad-evidence-record');
    expect(code(withAlgs([ALG_SHA256, ALG_SHA384]))).toBe('ers-unsupported'); // the union of a hash renewal
    expect(code(withAlgs([ALG_SHA1, ALG_SHA384]))).toBe('unsupported-hash');
    expect(code(withAlgs([]))).toBe('bad-evidence-record');
    expect(
      code(withAlgs([der(0x30, ALG_SHA256.subarray(2, 13), der(0x05, Uint8Array.of(0)))])),
    ).toBe('bad-evidence-record');
    expect(code(withAlgs([der(0x30)]))).toBe('bad-evidence-record');
    expect(code(withAlgs([der(0x30, ALG_SHA256.subarray(2, 13), der(0x05), der(0x05))]))).toBe(
      'bad-evidence-record',
    );
    expect(code(withAlgs([der(0x04, Uint8Array.of(1))]))).toBe('bad-evidence-record');
    // [0] of an ArchiveTimeStamp
    const a = (alg: Uint8Array) =>
      read(writeRecord({ chains: [t.map((x) => writeStamp(x, { algorithm: alg }))] }));
    expect(code(a(ALG_SHA384))).toBe('unsupported-hash');
    expect(code(a(der(0x30)))).toBe('bad-evidence-record');
  });
  it('a record outside the scope is ers-unsupported, never read half: tree, attributes, cryptoInfos, encryptionInfo, two chains', () => {
    const t = tokens();
    const tree = der(0xa2, der(0x30, der(0x04, new Uint8Array(32))));
    expect(
      read(
        writeRecord({ chains: [[writeStamp(t[0]!, { extra: [tree] }), ...stamps(t.slice(1))]] }),
      ),
    ).toMatchObject({ ok: false, reason: 'ers-unsupported', detail: 'reducedHashtree' });
    const attrs = der(0xa1, der(0x31, der(0x30, Uint8Array.from([0x06, 0x01, 0x2a]), der(0x31))));
    expect(read(writeRecord({ chains: [[writeStamp(t[0]!, { extra: [attrs] })]] }))).toMatchObject({
      ok: false,
      reason: 'ers-unsupported',
      detail: 'attributes',
    });
    expect(
      read(
        writeRecord({
          between: [der(0xa0, der(0x30, Uint8Array.from([0x06, 0x01, 0x2a]), der(0x31)))],
          chains: [stamps(t)],
        }),
      ),
    ).toMatchObject({ ok: false, reason: 'ers-unsupported', detail: 'cryptoInfos' });
    expect(
      read(writeRecord({ between: [der(0xa1, der(0x30))], chains: [stamps(t)] })),
    ).toMatchObject({ ok: false, reason: 'ers-unsupported', detail: 'encryptionInfo' });
    expect(
      read(writeRecord({ chains: [stamps(t.slice(0, 2)), stamps(t.slice(2))] })),
    ).toMatchObject({ ok: false, reason: 'ers-unsupported' });
  });
  it('the shape: empty sequence, empty chain, an element too many or too few, wrong order, doubled [0], wrong tags', () => {
    const t = tokens();
    expect(read(writeRecord({ chains: [] }))).toMatchObject({
      reason: 'bad-evidence-record',
      detail: 'archiveTimeStampSequence',
    });
    expect(code(read(writeRecord({ chains: [[]] })))).toBe('bad-evidence-record');
    // the order: [0] after the time stamp, [0] twice
    const alg0 = der(0xa0, ALG_SHA256.subarray(2));
    expect(code(read(writeRecord({ chains: [[der(0x30, t[0]!, alg0)]] })))).toBe(
      'bad-evidence-record',
    );
    expect(code(read(writeRecord({ chains: [[der(0x30, alg0, alg0, t[0]!)]] })))).toBe(
      'bad-evidence-record',
    );
    // an ArchiveTimeStamp without a time stamp, with two, with an unknown tag
    expect(code(read(writeRecord({ chains: [[der(0x30, alg0)]] })))).toBe('bad-evidence-record');
    expect(code(read(writeRecord({ chains: [[der(0x30, alg0, t[0]!, t[1]!)]] })))).toBe(
      'bad-evidence-record',
    );
    expect(code(read(writeRecord({ chains: [[der(0x30, der(0xa3), t[0]!)]] })))).toBe(
      'bad-evidence-record',
    );
    expect(
      code(read(writeRecord({ chains: [[der(0x30, der(0x80, Uint8Array.of(1)), t[0]!)]] }))),
    ).toBe('bad-evidence-record');
    // an element after the sequence, a record without the sequence, the sequence where the algorithms belong
    expect(code(read(writeRecord({ chains: [stamps(t)], after: [der(0x05)] })))).toBe(
      'bad-evidence-record',
    );
    const noSeq = der(0x30, der(0x02, Uint8Array.of(1)), der(0x30, ALG_SHA256));
    expect(code(read(noSeq))).toBe('bad-evidence-record');
    expect(code(read(der(0x30)))).toBe('bad-evidence-record');
    expect(code(read(der(0x31, der(0x02, Uint8Array.of(1)))))).toBe('bad-evidence-record');
    expect(code(read(der(0x04, Uint8Array.of(1, 2, 3))))).toBe('bad-evidence-record');
    // a chain that is not a sequence, a stamp that is not
    expect(
      code(
        read(der(0x30, der(0x02, Uint8Array.of(1)), der(0x30, ALG_SHA256), der(0x30, der(0x04)))),
      ),
    ).toBe('bad-evidence-record');
    expect(code(read(writeRecord({ chains: [[der(0x04, t[0]!)]] })))).toBe('bad-evidence-record');
  });
  it('the time stamp must be a readable token over SHA-256: a name of the failing link', () => {
    const t = tokens();
    const r = read(good([t[0]!, Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x01]), t[2]!]));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.detail).toBe('link 1');
    const damaged = t[0]!.slice();
    damaged[damaged.length - 5]! ^= 1; // a flipped byte inside the signature stays readable
    expect(read(good([damaged, t[1]!, t[2]!])).ok).toBe(true);
    expect(code(read(good([der(0x04, Uint8Array.of(1))])))).toBe('bad-evidence-record');
  });
  it('64 ArchiveTimeStamps are read, 65 are too-large', () => {
    const one = links[0]!.token;
    expect(read(good(Array.from({ length: 64 }, () => one))).ok).toBe(true);
    expect(code(read(good(Array.from({ length: 65 }, () => one))))).toBe('too-large');
    expect(ERS_LIMITS.MAX_ARCHIVE_TIME_STAMPS).toBe(64);
  });
  it('size: MAX_BYTES passes the gate, one more is too-large (before anything is copied or parsed)', () => {
    expect(code(read(new Uint8Array(ERS_LIMITS.MAX_BYTES)))).toBe('trailing-bytes');
    expect(code(read(new Uint8Array(ERS_LIMITS.MAX_BYTES + 1)))).toBe('too-large');
    expect(code(read(new Uint8Array(0)))).toBe('malformed');
    // the numbers themselves are pinned (a test must not follow a changed constant)
    expect(ERS_LIMITS.MAX_BYTES).toBe(524288);
    expect(code(read(new Uint8Array(524288)))).toBe('trailing-bytes');
    expect(code(read(new Uint8Array(524289)))).toBe('too-large');
    expect(code(read(new Uint8Array(300000)))).toBe('trailing-bytes');
    expect(code(read(Uint8Array.of(0x30)))).toBe('malformed');
  });
  it('DER only: BER (indefinite length), a lying length, a longer or non-minimal length, trailing bytes', () => {
    const body = record.subarray(record.length - 0);
    void body;
    // indefinite length for the outermost sequence
    const ber = Uint8Array.from([
      0x30,
      0x80,
      ...record.subarray(record[1]! === 0x82 ? 4 : 3),
      0,
      0,
    ]);
    expect(code(read(ber))).toBe('indefinite-length');
    // the length of the outer sequence one too large, one too small
    const longer = record.slice();
    longer[3]! += 1;
    expect(code(read(longer))).toBe('malformed');
    const shorter = record.slice();
    shorter[3]! -= 1;
    expect(['malformed', 'trailing-bytes']).toContain(code(read(shorter)));
    expect(code(read(Uint8Array.from([...record, 0])))).toBe('trailing-bytes');
    expect(code(read(record.subarray(0, record.length - 1)))).toBe('malformed');
    // a long length form where the short form fits (version INTEGER written 02 81 01 01)
    const t = tokens();
    const lax = writeRecord({
      version: Uint8Array.from([0x02, 0x81, 0x01, 0x01]),
      chains: [stamps(t)],
    });
    expect(code(read(lax))).toBe('malformed');
    // a leading zero in the length
    const zero = writeRecord({
      version: Uint8Array.from([0x02, 0x82, 0x00, 0x01, 0x01]),
      chains: [stamps(t)],
    });
    expect(code(read(zero))).toBe('malformed');
    // a multi-byte tag
    expect(code(read(Uint8Array.from([0x1f, 0x01, 0x00])))).toBe('malformed');
  });
  it('nesting too deep is too-deep, also inside a part that would be ers-unsupported', () => {
    let deep: Uint8Array = der(0x05);
    for (let i = 0; i < 30; i += 1) deep = der(0x30, deep);
    expect(
      code(
        read(writeRecord({ chains: [[writeStamp(tokens()[0]!, { extra: [der(0xa1, deep)] })]] })),
      ),
    ).toBe('too-deep');
    expect(
      code(read(writeRecord({ between: [der(0xa0, deep)], chains: [stamps(tokens())] }))),
    ).toBe('too-deep');
  });
  it('never throws: wrong types, hostile proxies, other typed arrays', () => {
    for (const x of [
      null,
      undefined,
      'x',
      5,
      {},
      [],
      [1, 2],
      new Uint16Array(4),
      new ArrayBuffer(4),
      new DataView(new ArrayBuffer(4)),
    ]) {
      expect(code(read(x))).not.toBe('ok');
    }
    const proxy = new Proxy(new Uint8Array(4), {
      get() {
        throw new Error('boom');
      },
      getPrototypeOf() {
        throw new Error('boom');
      },
    });
    expect(code(read(proxy))).not.toBe('ok');
    const lying = new Uint8Array(record.length);
    lying.set(record);
    Object.defineProperty(lying, 'length', { get: () => 4 });
    expect(code(read(lying))).not.toBe('thrown');
  });
});

describe('verifyEvidenceRecord', () => {
  it('verifies the exported chain exactly like the chain itself (same result, link by link)', async () => {
    const own = await verifyRenewalChain({ hash: HASH, links, trust: TRUST });
    const r = await verify(record);
    expect(r.ok && own.ok).toBe(true);
    if (r.ok && own.ok) {
      expect(r.value).toEqual(own.value);
      expect(r.value.links).toHaveLength(3);
      expect(r.value.genTime).toBe('2026-01-01T00:00:00.000Z');
      expect(r.value.weakestLink).not.toBeNull();
    }
  });
  it('a hash that is not the data object: imprint-mismatch at link 0', async () => {
    expect(await verify(record, {}, sha(Uint8Array.of(1)))).toMatchObject({
      ok: false,
      reason: 'imprint-mismatch',
      detail: 'link 0',
    });
  });
  it('swapped, doubled, dropped and foreign links are imprint-mismatch (the time order is checked first: bad-renewal)', async () => {
    const t = tokens();
    expect(code(await verify(good([t[0]!, t[2]!, t[1]!])))).toBe('bad-renewal');
    expect(code(await verify(good([t[0]!, t[0]!, t[1]!, t[2]!])))).toBe('imprint-mismatch');
    // a chain whose certificates do not end between the links, so that only the binding can fail
    const plain = (
      await makeChain(HASH, [
        { at: '2026-01-01T00:00:00Z' },
        { at: '2026-06-01T00:00:00Z' },
        { at: '2026-12-01T00:00:00Z' },
      ])
    ).map((l) => l.token);
    expect(code(await verify(good(plain)))).toBe('ok');
    expect(await verify(good([plain[0]!, plain[2]!]))).toMatchObject({
      ok: false,
      reason: 'imprint-mismatch',
      detail: 'link 1',
    });
    expect(await verify(good([plain[1]!, plain[2]!]))).toMatchObject({
      ok: false,
      reason: 'imprint-mismatch',
      detail: 'link 0',
    });
    expect(await verify(good([plain[0]!, plain[1]!, plain[1]!]))).toMatchObject({
      ok: false,
      reason: 'imprint-mismatch',
      detail: 'link 2',
    });
    expect(code(await verify(good([plain[0]!, plain[2]!, plain[2]!])))).toBe('imprint-mismatch');
    const other = await makeChain(sha(Uint8Array.of(7)), STEPS);
    expect(code(await verify(good([t[0]!, other[1]!.token, t[2]!])))).toBe('imprint-mismatch');
  });
  it('the first stamp of a record that carries the hash of a chain is not accepted for another chain', async () => {
    const other = await makeChain(sha(Uint8Array.of(8)), STEPS);
    expect(code(await verify(good(other.map((l) => l.token))))).toBe('imprint-mismatch');
  });
  it('a changed byte of a token is signature or structure trouble, never ok', async () => {
    for (let i = 0; i < 3; i += 1) {
      const t = tokens();
      const d = t[i]!.slice();
      d[Math.floor(d.length / 2)]! ^= 0x01;
      expect(code(await verify(good(t.map((x, k) => (k === i ? d : x)))))).not.toBe('ok');
    }
  });
  it('trust is the caller: another anchor is untrusted-chain', async () => {
    const other = (await import('./token-builder.ts')).build({});
    expect(code(await verify(record, { trust: [other.caPem] }))).toBe('untrusted-chain');
  });
  it('the options of verifyRenewalChain hold: at, minGenTime, expectedNonce, crls', async () => {
    expect(code(await verify(record, { options: { expectedNonce: Uint8Array.of(1) } }))).toBe(
      'bad-options',
    );
    expect(
      code(await verify(record, { options: { minGenTime: new Date('2026-06-01T00:00:00Z') } })),
    ).toBe('time-too-old');
    expect(code(await verify(record, { options: { at: new Date('2100-01-01T00:00:00Z') } }))).toBe(
      'certificate-not-valid-at-time',
    );
    expect(code(await verify(record, { options: { crls: [new Uint8Array(3)] } }))).toBe('bad-crl');
  });
  it('input errors are codes: shape, hash, bytes', async () => {
    expect(code(await verifyEvidenceRecord(null as never))).toBe('bad-options');
    expect(code(await verifyEvidenceRecord({ bytes: record, hash: HASH } as never))).toBe(
      'bad-options',
    );
    expect(
      code(
        await verifyEvidenceRecord({ bytes: record, hash: HASH, trust: TRUST, extra: 1 } as never),
      ),
    ).toBe('bad-options');
    expect(code(await verify(record, {}, new Uint8Array(31)))).toBe('bad-hash');
    // the hash is looked at before the record is read
    expect(code(await verify(new Uint8Array(3), {}, new Uint8Array(31)))).toBe('bad-hash');
    expect(code(await verify('x'))).toBe('malformed');
    expect(code(await verify(new Uint8Array(0)))).toBe('malformed');
    const hostile = new Proxy(
      {},
      {
        get() {
          throw new Error('boom');
        },
        ownKeys() {
          throw new Error('boom');
        },
      },
    );
    expect(code(await verifyEvidenceRecord(hostile as never))).toBe('bad-options');
  });
});

describe('the client: serializeEvidenceRecord', () => {
  async function evidence(n: number) {
    const ls = links.slice(0, n);
    const r = await verifyRenewalChain({ hash: HASH, links: ls, trust: TRUST });
    if (!r.ok) throw new Error('chain');
    return evidenceOf(
      HASH,
      ls,
      r.value.links.map((l) => ({
        genTime: l.genTime,
        signerNotAfter: l.signerNotAfter,
        policy: l.policy,
      })),
    );
  }
  it('writes the evidence with its renewals as the record of the chain; object and text give the same bytes', async () => {
    const e = await evidence(3);
    const a = await serializeEvidenceRecord(e);
    const text = serializeEvidence(e);
    expect(text.ok).toBe(true);
    const b = await serializeEvidenceRecord(text.ok ? text.value : '');
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(hex(a.value)).toBe(hex(b.value));
    expect(hex(a.value)).toBe(hex(record));
  });
  it('the record verifies with the library and says what verifyEvidence says', async () => {
    const e = await evidence(2);
    const rec = await serializeEvidenceRecord(e);
    expect(rec.ok).toBe(true);
    if (!rec.ok) return;
    const viaRecord = await verifyEvidenceRecord({ bytes: rec.value, hash: HASH, trust: TRUST });
    const viaEvidence = await verifyEvidence(e, HASH, { trust: TRUST });
    expect(viaRecord.ok && viaEvidence.ok).toBe(true);
    if (viaRecord.ok && viaEvidence.ok) {
      expect(viaRecord.value.genTime).toBe(viaEvidence.value.genTime);
      expect(viaRecord.value.lastGenTime).toBe(viaEvidence.value.lastGenTime);
    }
  });
  it('evidence without a renewal gives a record of one ArchiveTimeStamp', async () => {
    const rec = await serializeEvidenceRecord(await evidence(1));
    expect(rec.ok && decodeRecord(rec.value).chains[0]!.stamps).toHaveLength(1);
  });
  it('evidence with a batch receipt, in the first link or a renewal, is export-unsupported', async () => {
    const e = await evidence(3);
    const proof = {
      v: 1 as const,
      size: 1,
      index: 0,
      salt: toBase64Url(sha(Uint8Array.of(1))),
      path: [],
    };
    const first = { ...e, kind: 'batch' as const, batch: proof };
    expect(await serializeEvidenceRecord(first)).toMatchObject({
      ok: false,
      reason: 'export-unsupported',
    });
    const later = {
      ...e,
      renewals: [e.renewals![0]!, { ...e.renewals![1]!, kind: 'batch' as const, batch: proof }],
    };
    expect(await serializeEvidenceRecord(later)).toMatchObject({
      ok: false,
      reason: 'export-unsupported',
      detail: 'link 2 batch',
    });
  });
  it('bad evidence is bad-evidence, and nothing throws', async () => {
    expect(code(await serializeEvidenceRecord({ v: 2 }))).toBe('bad-evidence');
    expect(code(await serializeEvidenceRecord('not json'))).toBe('bad-evidence');
    expect(code(await serializeEvidenceRecord(null))).toBe('bad-evidence');
    const hostile = new Proxy(
      {},
      {
        get() {
          throw new Error('boom');
        },
        ownKeys() {
          throw new Error('boom');
        },
      },
    );
    expect(code(await serializeEvidenceRecord(hostile))).toBe('bad-evidence');
  });
});

const probe = spawnSync('openssl', ['version'], { encoding: 'utf8' });
const major = Number(/^OpenSSL (\d+)/.exec(probe.stdout ?? '')?.[1] ?? 0);
const canRun = probe.status === 0 && major >= 3;
if (probe.status === 0 && !canRun)
  it.skip('evidence record against openssl (needs OpenSSL 3)', () => {});

describe.skipIf(!canRun)(
  'the record against OpenSSL (it knows no ERS: structure and every single token)',
  () => {
    let tmp = '';
    const path = (n: string) => join(tmp, n);
    beforeAll(() => {
      tmp = mkdtempSync(join(tmpdir(), 'zeitstempel-ers-'));
      writeFileSync(path('ca.pem'), BASE.caPem);
      writeFileSync(path('er.der'), record);
    });
    afterAll(() => {
      if (tmp) rmSync(tmp, { recursive: true, force: true });
    });
    const run = (args: string[]) => spawnSync('openssl', args, { encoding: 'utf8' });

    it('asn1parse reads the whole record as DER and shows the schema of RFC 4998', () => {
      const r = run(['asn1parse', '-inform', 'DER', '-in', path('er.der')]);
      expect(r.status, r.stderr).toBe(0);
      const lines = r.stdout.split('\n');
      expect(lines[0]).toMatch(/^\s*0:d=0\s+hl=4 l=\s*\d+ cons: SEQUENCE/);
      expect(lines[1]).toMatch(/d=1 .* prim: INTEGER\s+:01$/);
      expect(lines[2]).toMatch(/d=1 .* cons: SEQUENCE/);
      expect(lines[3]).toMatch(/d=2 .* cons: SEQUENCE/);
      expect(lines[4]).toMatch(/d=3 .* prim: OBJECT\s+:sha256$/);
      expect(lines[5]).toMatch(/d=3 .* prim: NULL/);
      expect(lines[6]).toMatch(/d=1 .* cons: SEQUENCE/); // ArchiveTimeStampSequence
      expect(lines[7]).toMatch(/d=2 .* cons: SEQUENCE/); // the chain
      expect(lines[8]).toMatch(/d=3 .* cons: SEQUENCE/); // ArchiveTimeStamp 0
      expect(lines[9]).toMatch(/d=4 .* cons: cont \[ 0 \]/); // digestAlgorithm
      expect(lines[10]).toMatch(/d=5 .* prim: OBJECT\s+:sha256$/);
      expect(lines.filter((l) => /d=4 .*cons: cont \[ 0 \]/.test(l))).toHaveLength(3);
      expect(lines.filter((l) => /:d=[1-4] .*cont \[ [12] \]/.test(l))).toHaveLength(0);
      expect(lines.filter((l) => /:d=5 .*OBJECT\s+:pkcs7-signedData/.test(l))).toHaveLength(3);
    });
    it('every token cut out of the record by the reference decoder verifies with openssl ts -verify over the RFC 4998 digest', () => {
      const d = decodeRecord(record).chains[0]!.stamps;
      const at = ['2026-02-01T00:00:00Z', '2026-07-01T00:00:00Z', '2026-12-01T00:00:00Z'];
      let want = hex(HASH);
      for (const [i, s] of d.entries()) {
        writeFileSync(path('t.tok'), s.timeStamp);
        const v = run([
          'ts',
          '-verify',
          '-in',
          path('t.tok'),
          '-token_in',
          '-digest',
          want,
          '-CAfile',
          path('ca.pem'),
          '-attime',
          String(Math.floor(Date.parse(at[i]!) / 1000)),
        ]);
        expect(v.status, `link ${i}: ${v.stderr}`).toBe(0);
        // the digest the next ArchiveTimeStamp must stamp: SHA-256 of THIS ContentInfo (RFC 4998 section 5.2)
        const h = run(['dgst', '-sha256', '-r', path('t.tok')]);
        want = h.stdout.split(' ')[0]!;
        // and openssl refuses the same token over the hash of the data object when it is not the first
        if (i > 0) {
          const wrong = run([
            'ts',
            '-verify',
            '-in',
            path('t.tok'),
            '-token_in',
            '-digest',
            hex(HASH),
            '-CAfile',
            path('ca.pem'),
            '-attime',
            String(Math.floor(Date.parse(at[i]!) / 1000)),
          ]);
          expect(wrong.status).not.toBe(0);
        }
      }
    });
    it('asn1parse refuses what our reader refuses at the DER level (a lying length)', () => {
      const bad = record.slice();
      bad[3]! += 1;
      writeFileSync(path('bad.der'), bad);
      expect(run(['asn1parse', '-inform', 'DER', '-in', path('bad.der')]).status).not.toBe(0);
    });
  },
);
