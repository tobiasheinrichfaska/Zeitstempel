import { createHash } from 'node:crypto';

/**
 * The tree of a batch (RFC 6962 shape: split at the largest power of two below n, no duplicated last leaf),
 * built with node:crypto and written apart from the library's verification (`src/lib/batch.ts`, WebCrypto):
 * a test compares both with a third reference. Leaf: SHA-256(0x00 || salt || hash); inner node:
 * SHA-256(0x01 || left || right); the stamped value: SHA-256("zeitstempel-batch-v1\n" || uint32be(n) || root).
 */
const IMPRINT_TAG = Buffer.from('zeitstempel-batch-v1\n');

const sha256 = (...parts: Uint8Array[]): Buffer => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};

export const leafHash = (salt: Uint8Array, hash: Uint8Array): Buffer =>
  sha256(Uint8Array.of(0), salt, hash);

const nodeHash = (left: Uint8Array, right: Uint8Array): Buffer =>
  sha256(Uint8Array.of(1), left, right);

/** The largest power of two strictly below n (n >= 2). */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

export interface BatchProofBytes {
  size: number;
  index: number;
  path: Buffer[];
}

export interface BuiltBatch {
  /** The value to have stamped. */
  imprint: Buffer;
  /** For each input position (not tree position): where its leaf stands and its audit path. */
  proofs: BatchProofBytes[];
}

/**
 * Builds the tree over `entries` (salt and hash of each submitter). `order` lists, for each tree position,
 * the input position that stands there (a permutation: the caller shuffles it, so the order of the leaves
 * tells nothing about the order of arrival).
 */
export function buildBatch(
  entries: readonly { salt: Uint8Array; hash: Uint8Array }[],
  order: readonly number[],
): BuiltBatch {
  const n = entries.length;
  if (n < 1 || order.length !== n) throw new Error('batch: bad order');
  if (new Set(order).size !== n || order.some((i) => !Number.isInteger(i) || i < 0 || i >= n)) {
    throw new Error('batch: order is no permutation');
  }
  const leaves = order.map((i) => leafHash(entries[i]!.salt, entries[i]!.hash));
  const memo = new Map<string, Buffer>();
  const mth = (lo: number, hi: number): Buffer => {
    if (hi - lo === 1) return leaves[lo]!;
    const key = `${lo}:${hi}`;
    const known = memo.get(key);
    if (known) return known;
    const k = split(hi - lo);
    const node = nodeHash(mth(lo, lo + k), mth(lo + k, hi));
    memo.set(key, node);
    return node;
  };
  // the audit path of RFC 6962: siblings from the leaf level upwards
  const pathOf = (m: number, lo: number, hi: number): Buffer[] => {
    if (hi - lo === 1) return [];
    const k = split(hi - lo);
    return m < lo + k
      ? [...pathOf(m, lo, lo + k), mth(lo + k, hi)]
      : [...pathOf(m, lo + k, hi), mth(lo, lo + k)];
  };
  const root = mth(0, n);
  const sizeBytes = Buffer.alloc(4);
  sizeBytes.writeUInt32BE(n);
  const proofs: BatchProofBytes[] = new Array<BatchProofBytes>(n);
  for (let position = 0; position < n; position += 1) {
    proofs[order[position]!] = { size: n, index: position, path: pathOf(position, 0, n) };
  }
  return { imprint: sha256(IMPRINT_TAG, sizeBytes, root), proofs };
}
