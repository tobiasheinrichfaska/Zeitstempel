import { createHash } from 'node:crypto';

/**
 * An independent reference of the batch tree, written straight from RFC 6962 section 2.1 (MTH and PATH over
 * slices of the leaf list) with node:crypto. Neither the library (WebCrypto, `src/lib/batch.ts`) nor the
 * relay (`relay/batch.ts`, memoised ranges) shares code with it.
 */
const h = (...parts: Buffer[]): Buffer => {
  const x = createHash('sha256');
  for (const p of parts) x.update(p);
  return x.digest();
};

export const refLeaf = (salt: Buffer, hash: Buffer): Buffer => h(Buffer.from([0]), salt, hash);

/** MTH(D[n]) over the leaf hashes: the split is the largest power of two below n. */
export function refRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 1) return leaves[0]!;
  let k = 1;
  while (k < leaves.length) k <<= 1;
  k >>= 1; // the largest power of two strictly below n
  return h(Buffer.from([1]), refRoot(leaves.slice(0, k)), refRoot(leaves.slice(k)));
}

/** PATH(m, D[n]) of RFC 6962: the siblings from the leaf level upwards. */
export function refPath(m: number, leaves: Buffer[]): Buffer[] {
  if (leaves.length === 1) return [];
  let k = 1;
  while (k < leaves.length) k <<= 1;
  k >>= 1;
  return m < k
    ? [...refPath(m, leaves.slice(0, k)), refRoot(leaves.slice(k))]
    : [...refPath(m - k, leaves.slice(k)), refRoot(leaves.slice(0, k))];
}

export function refImprint(size: number, root: Buffer): Buffer {
  const n = Buffer.alloc(4);
  n.writeUInt32BE(size);
  return h(Buffer.from('zeitstempel-batch-v1\n'), n, root);
}

export interface RefBatch {
  salts: Buffer[];
  hashes: Buffer[];
  leaves: Buffer[];
  root: Buffer;
  imprint: Buffer;
}

/** A batch of `n` submitters with deterministic salts and hashes; tree position i holds submitter i. */
export function refBatch(n: number, tag = 'h'): RefBatch {
  const salts = Array.from({ length: n }, (_, i) => h(Buffer.from(`salt-${tag}-${i}`)));
  const hashes = Array.from({ length: n }, (_, i) => h(Buffer.from(`${tag}-${i}`)));
  const leaves = salts.map((s, i) => refLeaf(s, hashes[i]!));
  const root = refRoot(leaves);
  return { salts, hashes, leaves, root, imprint: refImprint(n, root) };
}

/** The `batch` field a relay would send for tree position `i` of `b`. */
export function refProof(b: RefBatch, i: number) {
  return {
    v: 1 as const,
    size: b.leaves.length,
    index: i,
    salt: b.salts[i]!.toString('base64url'),
    path: refPath(i, b.leaves).map((p) => p.toString('base64url')),
  };
}
