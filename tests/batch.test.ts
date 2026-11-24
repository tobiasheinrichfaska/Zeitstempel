import { createHash } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { BATCH_LIMITS, batchImprint, leafHash, verifyBatchedTimestamp } from '../src/lib/batch.ts';
import { verifyTimestampToken, toBase64Url, toHex, type BatchProof } from '../src/index.ts';
import { buildBatch } from '../relay/batch.ts';
import { build } from './token-builder.ts';
import { refBatch, refPath, refProof, refRoot, type RefBatch } from './batch-reference.ts';

// One signer for every token of this file: one anchor fits all.
const BASE = build();
const TRUST = [BASE.caPem];
const tokenFor = (imprint: Uint8Array, over: Parameters<typeof build>[0] = {}) =>
  build({ keys: BASE.keys, hash: new Uint8Array(imprint), ...over }).token;

const sha = (text: string) => createHash('sha256').update(text).digest();
const bytes = (b: Buffer) => new Uint8Array(b);

interface Case {
  b: RefBatch;
  token: Uint8Array;
}
const cases = new Map<number, Case>();
function caseOf(n: number): Case {
  let c = cases.get(n);
  if (!c) {
    const b = refBatch(n);
    c = { b, token: tokenFor(b.imprint) };
    cases.set(n, c);
  }
  return c;
}
const input = (c: Case, i: number, over: Partial<{ hash: Uint8Array; batch: unknown }> = {}) => ({
  token: c.token,
  hash: over.hash ?? bytes(c.b.hashes[i]!),
  batch: (over.batch ?? refProof(c.b, i)) as BatchProof,
});

describe('batched time stamps: the tree against an independent reference', () => {
  it('known answer for three leaves (computed apart, with Python hashlib)', async () => {
    const salts = [1, 2, 3].map((i) => Buffer.alloc(32, i));
    const hashes = [0, 1, 2].map((i) => sha(`h${i}`));
    const leaf0 = await leafHash(bytes(salts[0]!), bytes(hashes[0]!));
    expect(toHex(leaf0)).toBe('e253d86ae4a56983078fed8591819dbd457e066633d4217f49c71e3cbcfa1c29');
    const built = buildBatch(
      salts.map((salt, i) => ({ salt, hash: hashes[i]! })),
      [0, 1, 2],
    );
    expect(built.imprint.toString('hex')).toBe(
      'ef652db22e131c48ba0f0e7756624a397cd8e7c6ec4566dc2b56cc5dfda072ab',
    );
    const root = Buffer.from(
      '64acd9ce974182b133853f070dd0322681ded1e2099c854a148ce7694209a916',
      'hex',
    );
    expect(toHex(await batchImprint(3, root))).toBe(built.imprint.toString('hex'));
    // the third leaf's path is the inner node over the first two leaves
    expect(built.proofs[2]!.path.map((p) => p.toString('hex'))).toEqual([
      'fb594cabb351f11b56e63fef2fe67631aa9baec75984f0bdaf221bc0c63723f0',
    ]);
  });

  it.each([1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 100, 128])(
    'n = %i: every index verifies, and the relay builder agrees with the reference',
    async (n) => {
      const c = caseOf(n);
      // the relay's builder (memoised, node:crypto) against the reference: same imprint, same paths
      const entries = c.b.salts.map((salt, i) => ({ salt, hash: c.b.hashes[i]! }));
      const built = buildBatch(
        entries,
        Array.from({ length: n }, (_, i) => i),
      );
      expect(built.imprint.equals(c.b.imprint)).toBe(true);
      for (let i = 0; i < n; i += 1) {
        const p = built.proofs[i]!;
        expect(p.size).toBe(n);
        expect(p.index).toBe(i);
        expect(p.path.map((x) => x.toString('hex'))).toEqual(
          refPath(i, c.b.leaves).map((x) => x.toString('hex')),
        );
        const r = await verifyBatchedTimestamp(input(c, i), TRUST);
        expect(r.ok, `n=${n} i=${i}`).toBe(true);
        if (r.ok) expect(r.value.batch).toEqual({ size: n, index: i });
      }
    },
  );

  it('the relay builder honours a shuffled order: proofs belong to the input positions', async () => {
    const n = 9;
    const b = refBatch(n, 's');
    const order = [4, 8, 0, 2, 7, 1, 6, 3, 5]; // tree position -> input position
    const entries = b.salts.map((salt, i) => ({ salt, hash: b.hashes[i]! }));
    const built = buildBatch(entries, order);
    const token = tokenFor(built.imprint);
    const shuffledLeaves = order.map((i) => b.leaves[i]!);
    expect(built.imprint.equals(b.imprint)).toBe(false); // another tree order, another root
    for (let i = 0; i < n; i += 1) {
      const p = built.proofs[i]!;
      expect(p.index).toBe(order.indexOf(i));
      const proof: BatchProof = {
        v: 1,
        size: n,
        index: p.index,
        salt: b.salts[i]!.toString('base64url'),
        path: p.path.map((x) => x.toString('base64url')),
      };
      expect(p.path.map((x) => x.toString('hex'))).toEqual(
        refPath(p.index, shuffledLeaves).map((x) => x.toString('hex')),
      );
      const r = await verifyBatchedTimestamp(
        { token, hash: bytes(b.hashes[i]!), batch: proof },
        TRUST,
      );
      expect(r.ok, `input ${i}`).toBe(true);
    }
  });

  it('buildBatch refuses an order that is no permutation', () => {
    const e = [0, 1, 2].map((i) => ({ salt: Buffer.alloc(32, i), hash: Buffer.alloc(32, i) }));
    expect(() => buildBatch(e, [0, 1])).toThrow();
    expect(() => buildBatch(e, [0, 1, 1])).toThrow();
    expect(() => buildBatch(e, [0, 1, 3])).toThrow();
    expect(() => buildBatch([], [])).toThrow();
  });

  it('the tree has no duplicated last leaf: three leaves are not four with the third repeated', () => {
    const b = refBatch(3);
    const four = [...b.leaves, b.leaves[2]!];
    expect(refRoot(b.leaves).equals(refRoot(four))).toBe(false);
  });
});

describe('batched time stamps: every changed byte is refused (sweeps)', () => {
  const shapes: [number, number][] = [
    [1, 0],
    [2, 1],
    [5, 0],
    [7, 6],
    [9, 4],
    [13, 12],
  ];
  it.each(shapes)(
    'n = %i, index %i: salt, path, hash: each byte changed, each refused',
    async (n, i) => {
      const c = caseOf(n);
      expect((await verifyBatchedTimestamp(input(c, i), TRUST)).ok).toBe(true);
      const proof = refProof(c.b, i);
      const flip = (buf: Buffer, at: number) => {
        const copy = Buffer.from(buf);
        copy[at] = copy[at]! ^ 0x01;
        return copy;
      };
      for (let at = 0; at < 32; at += 1) {
        const salt = flip(c.b.salts[i]!, at).toString('base64url');
        const r = await verifyBatchedTimestamp(input(c, i, { batch: { ...proof, salt } }), TRUST);
        expect(r, `salt byte ${at}`).toMatchObject({ ok: false, reason: 'imprint-mismatch' });
        const hash = bytes(flip(c.b.hashes[i]!, at));
        const r2 = await verifyBatchedTimestamp(input(c, i, { hash }), TRUST);
        expect(r2, `hash byte ${at}`).toMatchObject({ ok: false, reason: 'imprint-mismatch' });
        for (let k = 0; k < proof.path.length; k += 1) {
          const path = [...proof.path];
          path[k] = flip(Buffer.from(path[k]!, 'base64url'), at).toString('base64url');
          const r3 = await verifyBatchedTimestamp(
            input(c, i, { batch: { ...proof, path } }),
            TRUST,
          );
          expect(r3, `path ${k} byte ${at}`).toMatchObject({
            ok: false,
            reason: 'imprint-mismatch',
          });
        }
      }
    },
  );

  it('size and index: every other pair is refused (never a verified wrong claim)', async () => {
    const c = caseOf(7);
    const proof = refProof(c.b, 3);
    let accepted = 0;
    for (let size = 0; size <= 40; size += 1) {
      for (let index = -1; index <= 41; index += 1) {
        if (size === 7 && index === 3) continue;
        const r = await verifyBatchedTimestamp(
          input(c, 3, { batch: { ...proof, size, index } }),
          TRUST,
        );
        if (r.ok) accepted += 1;
      }
    }
    expect(accepted).toBe(0);
  });

  it('size twist: the same path claimed for a tree of another size ends in imprint-mismatch', async () => {
    // n = 4, index 0: path [leaf1, node(leaf2, leaf3)]; for sizes 3 the procedure follows the same two steps
    // and finds the same root, so only the imprint (which binds the size) can tell
    const c = caseOf(4);
    const proof = refProof(c.b, 0);
    expect(proof.path).toHaveLength(2);
    const r = await verifyBatchedTimestamp(input(c, 0, { batch: { ...proof, size: 3 } }), TRUST);
    expect(r).toMatchObject({ ok: false, reason: 'imprint-mismatch' });
    // the same for every size that accepts a path of that length at index 0
    for (let size = 2; size <= 64; size += 1) {
      if (size === 4) continue;
      const r2 = await verifyBatchedTimestamp(input(c, 0, { batch: { ...proof, size } }), TRUST);
      expect(r2.ok, `size ${size}`).toBe(false);
    }
  });

  it('the token: every byte changed gives the same verdict as plain verification, and almost all are refused', async () => {
    const c = caseOf(5);
    const i = 2;
    let refused = 0;
    for (let at = 0; at < c.token.length; at += 1) {
      const t = Uint8Array.from(c.token);
      t[at] = t[at]! ^ 0x01;
      const batched = await verifyBatchedTimestamp(input({ ...c, token: t }, i), TRUST);
      const plain = await verifyTimestampToken(t, bytes(c.b.imprint), TRUST);
      expect(batched.ok, `token byte ${at}`).toBe(plain.ok);
      if (!batched.ok) refused += 1;
    }
    expect(refused).toBeGreaterThan(c.token.length - 6);
  });

  it('a token for another batch (another tree with the same size) is refused', async () => {
    const other = refBatch(5, 'other');
    const r = await verifyBatchedTimestamp(
      {
        token: tokenFor(other.imprint),
        hash: bytes(caseOf(5).b.hashes[1]!),
        batch: refProof(caseOf(5).b, 1),
      },
      TRUST,
    );
    expect(r).toMatchObject({ ok: false, reason: 'imprint-mismatch' });
  });

  it('a token stamped over the plain hash (no batch) is no batch receipt', async () => {
    const b = refBatch(3);
    const plain = tokenFor(b.hashes[0]!);
    const r = await verifyBatchedTimestamp(
      { token: plain, hash: bytes(b.hashes[0]!), batch: refProof(b, 0) },
      TRUST,
    );
    expect(r).toMatchObject({ ok: false, reason: 'imprint-mismatch' });
  });
});

describe('batched time stamps: second-preimage attacks', () => {
  it('an inner node submitted as a leaf is refused (leaf and node hashes are separated)', async () => {
    const c = caseOf(4);
    const [l0, l1, l2, l3] = c.b.leaves as [Buffer, Buffer, Buffer, Buffer];
    const x = refRoot([l0, l1]); // the inner node over leaf 0 and 1
    const y = refRoot([l2, l3]);
    // claim: a tree of two whose first leaf "is" x, built from salt = l0 and hash = l1 (the two halves of x)
    const forged: BatchProof = {
      v: 1,
      size: 2,
      index: 0,
      salt: l0.toString('base64url'),
      path: [y.toString('base64url')],
    };
    const r = await verifyBatchedTimestamp(
      { token: c.token, hash: bytes(l1), batch: forged },
      TRUST,
    );
    expect(r).toMatchObject({ ok: false, reason: 'imprint-mismatch' });
    // and with the real size: the path of that depth is the wrong length
    const deep: BatchProof = { ...forged, size: 4 };
    const r2 = await verifyBatchedTimestamp(
      { token: c.token, hash: bytes(l1), batch: deep },
      TRUST,
    );
    expect(r2).toMatchObject({ ok: false, reason: 'bad-batch' });
    expect(x.length).toBe(32);
  });

  it('a leaf submitted as an inner node is refused (a shorter path does not reach the root)', async () => {
    const c = caseOf(4);
    // genuine receipt of index 0 with its first path element dropped: the leaf level is skipped
    const proof = refProof(c.b, 0);
    const short: BatchProof = { ...proof, path: proof.path.slice(1) };
    expect(await verifyBatchedTimestamp(input(c, 0, { batch: short }), TRUST)).toMatchObject({
      ok: false,
      reason: 'bad-batch',
    });
    // size 2 with the one remaining element: the right depth, a root that was never stamped
    const two: BatchProof = { ...short, size: 2 };
    expect(await verifyBatchedTimestamp(input(c, 0, { batch: two }), TRUST)).toMatchObject({
      ok: false,
      reason: 'imprint-mismatch',
    });
    // the sibling leaf value used as the "salted hash" of a smaller tree
    const sibling = Buffer.from(proof.path[0]!, 'base64url');
    const swapped: BatchProof = {
      v: 1,
      size: 2,
      index: 0,
      salt: proof.path[0]!,
      path: [proof.path[1]!],
    };
    expect(
      await verifyBatchedTimestamp({ token: c.token, hash: bytes(sibling), batch: swapped }, TRUST),
    ).toMatchObject({ ok: false });
  });

  it('the path of another index does not carry a hash to the stamped root', async () => {
    const c = caseOf(8);
    for (let i = 0; i < 8; i += 1) {
      for (let j = 0; j < 8; j += 1) {
        if (i === j) continue;
        const other = refProof(c.b, j);
        const mixed: BatchProof = { ...other, salt: refProof(c.b, i).salt };
        const r = await verifyBatchedTimestamp(input(c, i, { batch: mixed }), TRUST);
        expect(r.ok, `hash ${i} with the path of ${j}`).toBe(false);
      }
    }
  });

  it('a path that is too long or too short is bad-batch for every index of every small tree', async () => {
    for (let n = 1; n <= 12; n += 1) {
      const c = caseOf(n);
      for (let i = 0; i < n; i += 1) {
        const p = refProof(c.b, i);
        const longer = { ...p, path: [...p.path, p.path[0] ?? p.salt] };
        expect(await verifyBatchedTimestamp(input(c, i, { batch: longer }), TRUST)).toMatchObject({
          ok: false,
          reason: 'bad-batch',
        });
        if (p.path.length > 0) {
          const shorter = { ...p, path: p.path.slice(0, -1) };
          expect(
            await verifyBatchedTimestamp(input(c, i, { batch: shorter }), TRUST),
          ).toMatchObject({
            ok: false,
            reason: 'bad-batch',
          });
        }
      }
    }
  });
});

describe('batched time stamps: options and trust pass through', () => {
  const c = () => caseOf(6);
  it('wrong anchors: untrusted-chain; the imprint is checked first', async () => {
    const other = build();
    const r = await verifyBatchedTimestamp(input(c(), 1), [other.caPem]);
    expect(r).toMatchObject({ ok: false, reason: 'untrusted-chain' });
  });
  it('minGenTime, now, maxSkewMs, at and requireCriticalEku reach the token check', async () => {
    const k = c();
    expect(
      await verifyBatchedTimestamp(input(k, 0), TRUST, { minGenTime: new Date('2027-01-01') }),
    ).toMatchObject({ ok: false, reason: 'time-too-old' });
    expect(
      await verifyBatchedTimestamp(input(k, 0), TRUST, { minGenTime: new Date('2025-01-01') }),
    ).toMatchObject({ ok: true });
    expect(
      await verifyBatchedTimestamp(input(k, 0), TRUST, {
        now: new Date('2025-01-01'),
        maxSkewMs: 0,
      }),
    ).toMatchObject({ ok: false, reason: 'time-in-future' });
    expect(
      await verifyBatchedTimestamp(input(k, 0), TRUST, { at: new Date('2050-01-01') }),
    ).toMatchObject({ ok: false, reason: 'certificate-not-valid-at-time' });
    expect(
      await verifyBatchedTimestamp(input(k, 0), TRUST, { requireCriticalEku: 'yes' as never }),
    ).toMatchObject({ ok: false, reason: 'bad-options' });
    expect(await verifyBatchedTimestamp(input(k, 0), TRUST, 5 as never)).toMatchObject({
      ok: false,
      reason: 'bad-options',
    });
  });
  it('expectedNonce: the nonce of the batch stamp is checked', async () => {
    const b = refBatch(3, 'nonce');
    const token = tokenFor(b.imprint, { nonceBytes: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8) });
    const ok = await verifyBatchedTimestamp(
      { token, hash: bytes(b.hashes[0]!), batch: refProof(b, 0) },
      TRUST,
      { expectedNonce: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8) },
    );
    expect(ok.ok).toBe(true);
    const bad = await verifyBatchedTimestamp(
      { token, hash: bytes(b.hashes[0]!), batch: refProof(b, 0) },
      TRUST,
      { expectedNonce: Uint8Array.of(9) },
    );
    expect(bad).toMatchObject({ ok: false, reason: 'nonce-mismatch' });
  });
  it('the result is that of verifyTimestampToken plus batch', async () => {
    const k = c();
    const batched = await verifyBatchedTimestamp(input(k, 4), TRUST);
    const plain = await verifyTimestampToken(k.token, bytes(k.b.imprint), TRUST);
    expect(batched.ok && plain.ok).toBe(true);
    if (batched.ok && plain.ok) {
      expect(batched.value).toEqual({ ...plain.value, batch: { size: 6, index: 4 } });
    }
  });
});

describe('batched time stamps: the form of the receipt', () => {
  const k = () => caseOf(5);
  const good = () => refProof(k().b, 2);
  const run = (batch: unknown, over: Record<string, unknown> = {}) =>
    verifyBatchedTimestamp(
      { token: k().token, hash: bytes(k().b.hashes[2]!), batch, ...over } as never,
      TRUST,
    );
  const bad = { ok: false, reason: 'bad-batch' };
  const holey = (path: string[]) => {
    const copy = [...path];
    delete copy[0];
    return copy;
  };

  it('refuses every wrong form with bad-batch', async () => {
    const p = good();
    const forms: [string, unknown][] = [
      ['null', null],
      ['a string', 'x'],
      ['an array', []],
      ['v 2', { ...p, v: 2 }],
      ['v as text', { ...p, v: '1' }],
      ['size 0', { ...p, size: 0 }],
      ['size over the limit', { ...p, size: BATCH_LIMITS.MAX_SIZE + 1 }],
      ['size fraction', { ...p, size: 5.5 }],
      ['size text', { ...p, size: '5' }],
      ['size NaN', { ...p, size: NaN }],
      ['index = size', { ...p, index: 5 }],
      ['index -1', { ...p, index: -1 }],
      ['index fraction', { ...p, index: 2.5 }],
      ['index text', { ...p, index: '2' }],
      ['salt 31 bytes', { ...p, salt: Buffer.alloc(31).toString('base64url') }],
      ['salt 33 bytes', { ...p, salt: Buffer.alloc(33).toString('base64url') }],
      ['salt with padding', { ...p, salt: Buffer.alloc(32).toString('base64') }],
      ['salt a number', { ...p, salt: 5 }],
      ['salt very long', { ...p, salt: 'A'.repeat(100000) }],
      ['path not an array', { ...p, path: 'x' }],
      [
        'path element 31 bytes',
        { ...p, path: [Buffer.alloc(31).toString('base64url'), ...p.path.slice(1)] },
      ],
      ['path element a number', { ...p, path: [5, ...p.path.slice(1)] }],
      ['path with a hole', { ...p, path: holey(p.path) }],
      [
        'path over the limit',
        { ...p, path: Array.from({ length: BATCH_LIMITS.MAX_PATH + 1 }, () => p.salt) },
      ],
      ['an unknown field', { ...p, extra: 1 }],
      ['a missing field', { v: 1, size: 5, index: 2, salt: p.salt }],
      ['a class instance', Object.assign(Object.create({ v: 1 }), p)],
    ];
    for (const [name, batch] of forms) expect(await run(batch), name).toMatchObject(bad);
  });

  it('fields that are only inherited do not count', async () => {
    const p = good();
    const inheriting = Object.create(null) as Record<string, unknown>;
    Object.assign(inheriting, p);
    expect((await run(inheriting)).ok).toBe(true); // a null prototype is as good as a plain object
    const proto = Object.create({ salt: p.salt });
    Object.assign(proto, { v: 1, size: 5, index: 2, path: p.path, x: 0 });
    expect(await run(proto)).toMatchObject(bad);
  });

  it('refuses a wrong hash, token or input with the matching code', async () => {
    expect(await run(good(), { hash: new Uint8Array(31) })).toMatchObject({
      ok: false,
      reason: 'bad-hash',
    });
    expect(await run(good(), { hash: new Uint8Array(33) })).toMatchObject({
      ok: false,
      reason: 'bad-hash',
    });
    expect(await run(good(), { hash: 'x' })).toMatchObject({ ok: false, reason: 'bad-hash' });
    expect(await run(good(), { hash: undefined })).toMatchObject({ ok: false, reason: 'bad-hash' });
    expect(await run(good(), { token: 'x' })).toMatchObject({ ok: false, reason: 'malformed' });
    expect(await run(good(), { token: new Uint8Array(0) })).toMatchObject({ ok: false });
    for (const v of [null, undefined, 5, 'x', [], new Map()]) {
      expect(await verifyBatchedTimestamp(v as never, TRUST), String(v)).toMatchObject({
        ok: false,
        reason: 'bad-options',
      });
    }
  });

  it('a Uint8Array of another realm is no hash (pass new Uint8Array(x))', async () => {
    const foreign = runInNewContext('new Uint8Array(32)') as Uint8Array;
    expect(await run(good(), { hash: foreign })).toMatchObject({ ok: false, reason: 'bad-hash' });
    const tok = runInNewContext('new Uint8Array(10)') as Uint8Array;
    expect(await run(good(), { token: tok })).toMatchObject({ ok: false, reason: 'malformed' });
  });

  it('never throws and never iterates: hostile proxies, throwing getters, an endless iterator', async () => {
    const trap = new Proxy(
      {},
      {
        get() {
          throw new Error('trap');
        },
        getPrototypeOf() {
          throw new Error('trap');
        },
        ownKeys() {
          throw new Error('trap');
        },
        has() {
          throw new Error('trap');
        },
        getOwnPropertyDescriptor() {
          throw new Error('trap');
        },
      },
    );
    for (const hostile of [trap, new Proxy([], trap as never)]) {
      const results = await Promise.all([
        verifyBatchedTimestamp(hostile as never, TRUST),
        run(hostile),
        run(good(), { hash: hostile }),
        run(good(), { token: hostile }),
        verifyBatchedTimestamp(
          { token: k().token, hash: bytes(k().b.hashes[2]!), batch: good() },
          hostile as never,
        ),
        verifyBatchedTimestamp(input(k(), 2), TRUST, hostile as never),
      ]);
      for (const r of results) expect(r.ok).toBe(false);
    }
    const throwing = { ...good() } as Record<string, unknown>;
    Object.defineProperty(throwing, 'size', {
      enumerable: true,
      get() {
        throw new Error('getter');
      },
    });
    expect(await run(throwing)).toMatchObject(bad);
    // an array whose iterator never ends: the path is read by index, so it still verifies
    const p = good();
    const path = [...p.path];
    Object.defineProperty(path, Symbol.iterator, {
      value: () => {
        throw new Error('iterated');
      },
    });
    expect((await run({ ...p, path })).ok).toBe(true);
    // a hash changed after the call started cannot matter: it is copied before anything else
    const hash = bytes(k().b.hashes[2]!);
    const pending = verifyBatchedTimestamp({ token: k().token, hash, batch: p }, TRUST);
    hash.fill(0);
    expect((await pending).ok).toBe(true);
  });

  it('the limits match the documented values', () => {
    expect(BATCH_LIMITS).toEqual({ MAX_SIZE: 1024, MAX_PATH: 10, NODE_BYTES: 32 });
    expect(2 ** BATCH_LIMITS.MAX_PATH).toBe(BATCH_LIMITS.MAX_SIZE);
  });

  it('a tree of the largest size verifies (path of 10)', async () => {
    const c = caseOf(1024);
    const r = await verifyBatchedTimestamp(input(c, 1023), TRUST);
    expect(r.ok).toBe(true);
    expect(refProof(c.b, 1023).path).toHaveLength(10);
  }, 60_000);
});

describe('the limits of the proof form (size, index, path length)', () => {
  const nodes = (n: number) =>
    Array.from({ length: n }, (_, i) => toBase64Url(new Uint8Array(32).fill(i + 1)));
  const salt = toBase64Url(new Uint8Array(32).fill(9));
  const reasonOf = async (batch: unknown): Promise<string> => {
    const c = caseOf(1);
    const r = await verifyBatchedTimestamp(input(c, 0, { batch }), TRUST);
    return r.ok ? 'ok' : r.reason;
  };

  it('a path of 10 elements fits a tree of 1024 leaves (the form passes, the token then says imprint-mismatch)', async () => {
    expect(
      await reasonOf({ v: 1, size: BATCH_LIMITS.MAX_SIZE, index: 0, salt, path: nodes(10) }),
    ).toBe('imprint-mismatch');
    expect(
      await reasonOf({ v: 1, size: BATCH_LIMITS.MAX_SIZE, index: 1023, salt, path: nodes(10) }),
    ).toBe('imprint-mismatch');
  });
  it('a path of 11 elements is bad-batch, and its elements are never read (the length decides first)', async () => {
    let touched = 0;
    const path = nodes(11);
    Object.defineProperty(path, 10, {
      get() {
        touched += 1;
        return toBase64Url(new Uint8Array(32));
      },
    });
    expect(await reasonOf({ v: 1, size: BATCH_LIMITS.MAX_SIZE, index: 0, salt, path })).toBe(
      'bad-batch',
    );
    expect(touched).toBe(0);
    // far over the limit: the same, without walking the array
    const huge: unknown[] = [];
    huge.length = 2 ** 31;
    expect(await reasonOf({ v: 1, size: 8, index: 0, salt, path: huge })).toBe('bad-batch');
    expect(BATCH_LIMITS.MAX_PATH).toBe(10);
  });
  it('a size above 1024 is bad-batch even where a short path would fit (the rightmost leaf of 1025)', async () => {
    // in a tree of 1025 leaves the last leaf has a path of ONE element (the root of the 1024 leaves before it)
    expect(await reasonOf({ v: 1, size: 1025, index: 1024, salt, path: nodes(1) })).toBe(
      'bad-batch',
    );
    expect(await reasonOf({ v: 1, size: 2 ** 20 + 1, index: 2 ** 20, salt, path: nodes(1) })).toBe(
      'bad-batch',
    );
    // the same shape one leaf smaller is inside the limit
    expect(await reasonOf({ v: 1, size: 1024, index: 1023, salt, path: nodes(10) })).toBe(
      'imprint-mismatch',
    );
  });
});
