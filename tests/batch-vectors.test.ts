// The Merkle tree of the batch mode against published RFC 6962 values, not only against our own reference.
//
// Source of the numbers: the Merkle tree test vectors that go back to Google's Certificate Transparency
// reference implementation and are carried on in transparency-dev/merkle (Apache-2.0), the eight test leaves
// ("", 00, 10, 2021, 3031, 40414243, 5051525354555657, 606162636465666768696a6b6c6d6e6f) with the root hash of
// the first 1 to 8 leaves and the inclusion proofs of a few leaves. The numbers are hashes, no code is taken
// from there. They were written from memory of that published list, not fetched again in this session (no
// network); each one is checked here against `tests/batch-reference.ts`, an independent computation straight
// from RFC 6962 § 2.1, and a wrong number would not agree with it, so a slip would show as a failing test.
import { createHash } from 'node:crypto';
import { rootFromPath } from '../src/lib/batch.ts';
import { refPath, refRoot } from './batch-reference.ts';

const DATA = [
  '',
  '00',
  '10',
  '2021',
  '3031',
  '40414243',
  '5051525354555657',
  '606162636465666768696a6b6c6d6e6f',
];
/** The root hash after 1, 2, ... 8 leaves (RFC 6962 `MTH`, published). */
const ROOTS = [
  '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
  'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
  'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
  '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
  '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
  'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
  '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
];
/** Published inclusion proofs: [leaf index (0-based), tree size, path]. */
const PROOFS: [number, number, string[]][] = [
  [0, 1, []],
  [
    0,
    8,
    [
      '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7',
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4',
    ],
  ],
  [
    5,
    8,
    [
      'bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b',
      'ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0',
      'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
    ],
  ],
  [2, 3, ['fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125']],
  [
    1,
    6,
    [
      '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      '0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a',
    ],
  ],
  [0, 2, ['96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7']],
  [
    0,
    3,
    [
      '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7',
      '0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7',
    ],
  ],
];

const leafHash = (hex: string) =>
  createHash('sha256')
    .update(Buffer.concat([Buffer.from([0]), Buffer.from(hex, 'hex')]))
    .digest();
const LEAVES = DATA.map(leafHash);
const bytes = (hex: string) => new Uint8Array(Buffer.from(hex, 'hex'));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

describe('published RFC 6962 values: the independent reference', () => {
  it('computes the published root of the first 1 to 8 leaves', () => {
    for (let n = 1; n <= 8; n += 1) {
      expect(refRoot(LEAVES.slice(0, n)).toString('hex'), `n=${n}`).toBe(ROOTS[n - 1]);
    }
  });
  it('computes the published inclusion proofs', () => {
    for (const [index, size, path] of PROOFS) {
      expect(refPath(index, LEAVES.slice(0, size)).map((p) => p.toString('hex'))).toEqual(path);
    }
  });
});

describe('published RFC 6962 values: rootFromPath of the library', () => {
  it('rebuilds the published root from each published inclusion proof', async () => {
    for (const [index, size, path] of PROOFS) {
      const root = await rootFromPath(new Uint8Array(LEAVES[index]!), index, size, path.map(bytes));
      expect(hex(root), `leaf ${index} of ${size}`).toBe(ROOTS[size - 1]);
    }
  });
  it('rebuilds the published root of every size 1 to 8 from every leaf (path from the reference)', async () => {
    for (let size = 1; size <= 8; size += 1) {
      for (let index = 0; index < size; index += 1) {
        const path = refPath(index, LEAVES.slice(0, size)).map((p) => new Uint8Array(p));
        const root = await rootFromPath(new Uint8Array(LEAVES[index]!), index, size, path);
        expect(hex(root), `leaf ${index} of ${size}`).toBe(ROOTS[size - 1]);
      }
    }
  });
  it('does not reach the published root with another index, a shorter or a longer path', async () => {
    const [index, size, path] = PROOFS[2]!; // leaf 5 of 8
    const leaf = new Uint8Array(LEAVES[index]!);
    const nodes = path.map(bytes);
    await expect(rootFromPath(leaf, index, size, nodes.slice(1))).rejects.toMatchObject({
      reason: 'bad-batch',
    });
    await expect(rootFromPath(leaf, index, size, [...nodes, nodes[0]!])).rejects.toMatchObject({
      reason: 'bad-batch',
    });
    const other = await rootFromPath(leaf, 4, size, nodes);
    expect(hex(other)).not.toBe(ROOTS[size - 1]);
  });
});
