import { byteLength, concat, copyBytes, fromBase64Url } from './bytes.ts';
import { ReaderError, fail, ok, type Result } from './result.ts';
import {
  verifyTimestampToken,
  type TrustAnchors,
  type VerifiedTimestamp,
  type VerifyOptions,
} from './verify.ts';

/** The limits of the batch proof (docs/data-model.html and docs/relay.md name each value; a test ties them). */
export const BATCH_LIMITS = {
  /** Most leaves in one tree. */
  MAX_SIZE: 1024,
  /** Longest audit path: ceil(log2(MAX_SIZE)). */
  MAX_PATH: 10,
  /** Bytes of the salt (the random `r_i` of the relay) and of every path element. */
  NODE_BYTES: 32,
} as const;

/**
 * The receipt of one submitter in a batch (the `batch` field of the relay's answer): the tree had `size`
 * leaves, this one stood at `index`, `salt` is the relay's random value in the leaf, `path` the audit path
 * (RFC 6962/9162: siblings from the leaf level upwards). All bytes are base64url without padding.
 */
export interface BatchProof {
  v: 1;
  size: number;
  index: number;
  salt: string;
  path: string[];
}

export interface BatchedInput {
  /** The token (DER) the service issued for the batch imprint. */
  token: Uint8Array;
  /** The SHA-256 (32 bytes) the submitter sent to the relay. */
  hash: Uint8Array;
  batch: BatchProof;
}

export interface VerifiedBatchedTimestamp extends VerifiedTimestamp {
  batch: { size: number; index: number };
}

/** Domain separation of the stamped value; names the version. */
const IMPRINT_TAG = new TextEncoder().encode('zeitstempel-batch-v1\n');

const subtle = (): SubtleCrypto => {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new ReaderError('unsupported-signature');
  return s;
};

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest('SHA-256', data as BufferSource));
}

const bad = () => new ReaderError('bad-batch');

/** Reads `key` as an own property, once; `undefined` when absent. */
const own = (o: Record<string, unknown>, key: string): unknown =>
  Object.hasOwn(o, key) ? o[key] : undefined;

interface Checked {
  size: number;
  index: number;
  salt: Uint8Array;
  path: Uint8Array[];
}

/**
 * Reads the batch proof once and checks every rule: a plain object with exactly the fields `v` (1), `size`
 * (integer 1 to MAX_SIZE), `index` (integer below size), `salt` (base64url of 32 bytes) and `path` (an array
 * of at most MAX_PATH base64url strings of 32 bytes). The path is read by length and index, never through the
 * iterator. A hostile proxy whose traps throw gives `bad-batch`.
 */
function checkBatch(batch: unknown): Checked {
  try {
    if (typeof batch !== 'object' || batch === null) throw bad();
    const proto: unknown = Object.getPrototypeOf(batch);
    if (proto !== Object.prototype && proto !== null) throw bad();
    const b = batch as Record<string, unknown>;
    const keys = Object.keys(b);
    if (keys.length !== 5) throw bad();
    for (const k of keys) if (!['v', 'size', 'index', 'salt', 'path'].includes(k)) throw bad();
    const v = own(b, 'v');
    const size = own(b, 'size');
    const index = own(b, 'index');
    const salt = own(b, 'salt');
    const path = own(b, 'path');
    if (v !== 1) throw bad();
    if (typeof size !== 'number' || !Number.isInteger(size)) throw bad();
    if (size < 1 || size > BATCH_LIMITS.MAX_SIZE) throw bad();
    if (typeof index !== 'number' || !Number.isInteger(index) || index < 0 || index >= size) {
      throw bad();
    }
    if (typeof salt !== 'string' || salt.length > 64) throw bad();
    const saltBytes = fromBase64Url(salt);
    if (!saltBytes || saltBytes.length !== BATCH_LIMITS.NODE_BYTES) throw bad();
    if (!Array.isArray(path)) throw bad();
    const count: unknown = (path as unknown[]).length;
    if (typeof count !== 'number' || !Number.isInteger(count) || count < 0) throw bad();
    if (count > BATCH_LIMITS.MAX_PATH) throw bad();
    const elements: Uint8Array[] = [];
    for (let i = 0; i < count; i += 1) {
      const item: unknown = (path as unknown[])[i];
      if (typeof item !== 'string' || item.length > 64) throw bad();
      const bytes = fromBase64Url(item);
      if (!bytes || bytes.length !== BATCH_LIMITS.NODE_BYTES) throw bad();
      elements.push(bytes);
    }
    return { size, index, salt: saltBytes, path: elements };
  } catch (e) {
    throw e instanceof ReaderError ? e : bad();
  }
}

/** `SHA-256(0x00 || salt || hash)`: the leaf of one submitter. */
export const leafHash = (salt: Uint8Array, hash: Uint8Array): Promise<Uint8Array> =>
  sha256(concat(Uint8Array.of(0), salt, hash));

/** `SHA-256(0x01 || left || right)`: an inner node. */
const nodeHash = (left: Uint8Array, right: Uint8Array): Promise<Uint8Array> =>
  sha256(concat(Uint8Array.of(1), left, right));

/**
 * The root from a leaf and its audit path, by the verification procedure of RFC 9162 section 2.1.3.2 for the
 * tree shape of RFC 6962 (split at the largest power of two below n, no duplicated last leaf). The path must
 * have exactly the length that `size` and `index` call for, else `bad-batch`. Exported for the tests (published vectors); not part of the package entry.
 */
export async function rootFromPath(
  leaf: Uint8Array,
  index: number,
  size: number,
  path: readonly Uint8Array[],
): Promise<Uint8Array> {
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of path) {
    if (sn === 0) throw bad(); // more path than the tree is deep
    if ((fn & 1) === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if ((fn & 1) === 0) {
        while ((fn & 1) === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  if (sn !== 0) throw bad(); // path too short
  return r;
}

/** `SHA-256("zeitstempel-batch-v1\n" || uint32be(size) || root)`: the value the service stamped. */
export function batchImprint(size: number, root: Uint8Array): Promise<Uint8Array> {
  const n = new Uint8Array(4);
  new DataView(n.buffer).setUint32(0, size, false);
  return sha256(concat(IMPRINT_TAG, n, root));
}

/**
 * Verifies the receipt of a batched time stamp: recomputes the leaf from `hash` and the salt, follows the
 * audit path to the root, forms the imprint from the leaf count and the root and checks the token against it
 * with `verifyTimestampToken` (same trust anchors, same options, same result plus `batch`). A path that
 * leads to another root, a changed salt, hash, index or size and a token of another batch all end in the
 * token's `imprint-mismatch`; a form that cannot be a proof of that tree (size or index out of range, a path
 * of the wrong length, a field of the wrong type or size, an unknown field) is `bad-batch`. Never throws or
 * rejects, whatever it is given (a hostile proxy included). The statement is "this hash was in the set the
 * service stamped at `genTime`", not "this hash was stamped alone" (docs/grenzen.md).
 */
export async function verifyBatchedTimestamp(
  input: BatchedInput,
  trust: TrustAnchors,
  options: VerifyOptions = {},
): Promise<Result<VerifiedBatchedTimestamp>> {
  try {
    if (typeof input !== 'object' || input === null) return fail('bad-options');
    let proto: unknown;
    try {
      proto = Object.getPrototypeOf(input);
    } catch {
      return fail('bad-options'); // a proxy whose trap throws is no plain object
    }
    if (proto !== Object.prototype && proto !== null) return fail('bad-options');
    const given = input as unknown as Record<string, unknown>;
    let token: unknown;
    let hashValue: unknown;
    let batchValue: unknown;
    try {
      token = own(given, 'token');
      hashValue = own(given, 'hash');
      batchValue = own(given, 'batch');
    } catch {
      return fail('bad-options'); // a getter or proxy trap that throws
    }
    const hash = copyBytes(hashValue, 32, 32);
    if (!hash) return fail('bad-hash');
    // the token is only measured here; verifyTimestampToken copies it once, with its own rules
    if (byteLength(token) === null) return fail('malformed');
    const checked = checkBatch(batchValue);
    const leaf = await leafHash(checked.salt, hash);
    const root = await rootFromPath(leaf, checked.index, checked.size, checked.path);
    const imprint = await batchImprint(checked.size, root);
    const result = await verifyTimestampToken(token as Uint8Array, imprint, trust, options);
    if (!result.ok) return result;
    return ok({ ...result.value, batch: { size: checked.size, index: checked.index } });
  } catch (e) {
    return fail(e instanceof ReaderError ? e.reason : 'malformed');
  }
}
