import { copyBytes, equalBytes } from './bytes.ts';
import {
  TAG,
  children,
  encodeOid,
  integerBytes,
  oid,
  ownBytes,
  parseDer,
  tlv,
  type Node,
} from './der.ts';
import { SHA256_OID } from './oids.ts';
import {
  RENEWAL_LIMITS,
  expectedHashes,
  fieldsOf,
  readLinks,
  verifyRenewalChain,
  type RenewalChain,
  type VerifiedRenewalChain,
} from './renewal.ts';
import { ReaderError, fail, ok, type Reason, type Result } from './result.ts';
import { readToken } from './token.ts';
import type { TrustAnchors, VerifyOptions } from './verify.ts';

/**
 * Evidence record (RFC 4998, "ERS", ASN.1 DER) for the renewal chain: ONE ArchiveTimeStampChain, SHA-256, one
 * ArchiveTimeStamp per link, none of them with a `reducedHashtree`. The first stamps the hash of the data object
 * itself (RFC 4998 section 4.2: without a tree the time stamp is "an ordinary timestamp" over the hash), each later one
 * the SHA-256 of the DER of the `timeStamp` of the one before it (section 5.2, time stamp renewal), which is exactly
 * `renewalImprint`. Outside this scope (a hash tree, several chains = hash-tree renewal, another hash algorithm,
 * `cryptoInfos`, `encryptionInfo`, `attributes`): `ers-unsupported`; the evidence of a collecting relay (`batch`)
 * cannot be exported at all: `export-unsupported` (`docs/client.md`, "ERS-Export").
 */

/** The limits of the evidence record (`docs/data-model.html` names each value; a test ties them). */
export const ERS_LIMITS = {
  /** Largest evidence record read or written, in bytes (64 tokens of up to 8 KB; one token is at most 262144 bytes). */
  MAX_BYTES: 524_288,
  /** Most ArchiveTimeStamps in the one chain: the limit of the renewal chain. */
  MAX_ARCHIVE_TIME_STAMPS: RENEWAL_LIMITS.MAX_LINKS,
} as const;

/** What `readEvidenceRecord` returns: the version, the one algorithm and the tokens of the one chain, oldest first. */
export interface EvidenceRecordContent {
  version: 1;
  digestAlgorithm: 'sha256';
  /** The `timeStamp` of every ArchiveTimeStamp (DER of the TimeStampToken, a copy), oldest first. */
  tokens: Uint8Array[];
}

export interface EvidenceRecordInput {
  /** The evidence record (DER). */
  bytes: Uint8Array;
  /** SHA-256 of the data object (32 bytes). */
  hash: Uint8Array;
  trust: TrustAnchors;
  /** As `verifyRenewalChain`: `expectedNonce` is `bad-options`. */
  options?: VerifyOptions;
}

/** A schema violation with a place, `ReaderError` for the code. */
class Located extends ReaderError {
  readonly detail: string;
  constructor(reason: Reason, detail: string) {
    super(reason);
    this.detail = detail;
  }
}
const bad = (where: string) => new Located('bad-evidence-record', where);
const unsupported = (what: string) => new Located('ers-unsupported', what);

const SHA256_ALGORITHM = tlv(TAG.sequence, encodeOid(SHA256_OID), tlv(TAG.null));
const CTX_0 = 0xa0;
const CTX_1 = 0xa1;
const CTX_2 = 0xa2;

function toFailure(e: unknown) {
  if (e instanceof Located) return fail(e.reason, e.detail);
  return fail(e instanceof ReaderError ? e.reason : 'malformed');
}

const must = (node: Node | undefined, tag: number, where: string): Node => {
  if (node === undefined || node.tag !== tag) throw bad(where);
  return node;
};

/** The content of an AlgorithmIdentifier (`SEQUENCE { OID [, NULL] }`, also the IMPLICIT `[0]` form): SHA-256 or an error. */
function sha256Algorithm(parts: Node[], where: string): void {
  if (parts.length < 1 || parts.length > 2) throw bad(where);
  if (parts.length === 2) {
    const nul = must(parts[1], TAG.null, where);
    if (nul.value.length !== 0) throw bad(where);
  }
  if (oid(must(parts[0], TAG.oid, where)) !== SHA256_OID) {
    throw new Located('unsupported-hash', where);
  }
}

function parse(bytes: unknown): EvidenceRecordContent {
  const own = ownBytes(bytes, ERS_LIMITS.MAX_BYTES);
  const root = must(parseDer(own, ERS_LIMITS.MAX_BYTES), TAG.sequence, 'EvidenceRecord');
  const parts = children(root);
  let at = 0;
  // version INTEGER { v1(1) }
  const version = integerBytes(must(parts[at], TAG.integer, 'version'));
  at += 1;
  if (version.length !== 1 || version[0] !== 1) throw new Located('unsupported-version', 'version');
  // digestAlgorithms SEQUENCE OF AlgorithmIdentifier
  const algorithms = children(must(parts[at], TAG.sequence, 'digestAlgorithms'));
  at += 1;
  if (algorithms.length !== 1) throw bad('digestAlgorithms');
  sha256Algorithm(
    children(must(algorithms[0], TAG.sequence, 'digestAlgorithms')),
    'digestAlgorithms',
  );
  // cryptoInfos [0] and encryptionInfo [1]: valid, but not read
  if (parts[at]?.tag === CTX_0) throw unsupported('cryptoInfos');
  if (parts[at]?.tag === CTX_1) throw unsupported('encryptionInfo');
  // archiveTimeStampSequence: the last element, nothing after it
  const sequence = must(parts[at], TAG.sequence, 'archiveTimeStampSequence');
  if (parts.length !== at + 1) throw bad('EvidenceRecord');
  const chains = children(sequence);
  if (chains.length === 0) throw bad('archiveTimeStampSequence');
  if (chains.length > 1) throw unsupported('several chains (hash-tree renewal)');
  const stamps = children(must(chains[0], TAG.sequence, 'archiveTimeStampChain'));
  if (stamps.length === 0) throw bad('archiveTimeStampChain');
  if (stamps.length > ERS_LIMITS.MAX_ARCHIVE_TIME_STAMPS) throw new ReaderError('too-large');
  const tokens: Uint8Array[] = [];
  for (const [i, stamp] of stamps.entries()) {
    const where = `archiveTimeStamp ${i}`;
    const kids = children(must(stamp, TAG.sequence, where));
    let k = 0;
    if (kids[k]?.tag === CTX_0) {
      sha256Algorithm(children(kids[k]!), `${where} digestAlgorithm`);
      k += 1;
    }
    if (kids[k]?.tag === CTX_1) throw unsupported('attributes');
    if (kids[k]?.tag === CTX_2) throw unsupported('reducedHashtree');
    const info = must(kids[k], TAG.sequence, `${where} timeStamp`);
    if (kids.length !== k + 1) throw bad(where);
    let token;
    try {
      token = readToken(info.raw);
    } catch (e) {
      throw new Located(e instanceof ReaderError ? e.reason : 'malformed', `link ${i}`);
    }
    if (token.info.hashOid !== SHA256_OID) throw new Located('unsupported-hash', `link ${i}`);
    tokens.push(info.raw.slice());
  }
  return { version: 1, digestAlgorithm: 'sha256', tokens };
}

/**
 * Reads an evidence record strictly: DER only (BER, a length that lies, trailing bytes, depth and size over the
 * bounds are refused with the codes of the DER reader), the closed schema of RFC 4998 in the scope of this file:
 * version 1 (else `unsupported-version`), one algorithm, SHA-256 (else `unsupported-hash`, also inside a token),
 * one chain of 1 to `MAX_ARCHIVE_TIME_STAMPS` ArchiveTimeStamps, each with an optional `[0]` algorithm and a `timeStamp` that is a
 * readable TimeStampToken over a SHA-256 imprint; every other shape is `bad-evidence-record` (`detail` names the place),
 * every valid shape outside the scope `ers-unsupported`. The bytes are copied by length first. Never throws.
 */
export function readEvidenceRecord(bytes: Uint8Array): Result<EvidenceRecordContent> {
  try {
    return ok(parse(bytes));
  } catch (e) {
    return toFailure(e);
  }
}

/**
 * Writes the renewal chain as an evidence record (DER): `{ hash, links }` as `renewalImprint` takes them (1 to 64
 * links). Every link must carry a readable token over SHA-256 whose imprint is the hash (link 0) or the imprint of
 * the links before it (`imprint-mismatch`, `detail` `link i`); the signatures are not checked here (no trust
 * anchors): `verifyEvidenceRecord` does that. A link that carries `batch` (a stamp of a collecting relay) is
 * `export-unsupported`. Never throws.
 */
export async function exportEvidenceRecord(chain: RenewalChain): Promise<Result<Uint8Array>> {
  try {
    const f = fieldsOf(chain, ['hash', 'links'], ['hash', 'links']);
    if (f === null) return fail('bad-options');
    const hash = copyBytes(f.hash, 32, 32);
    if (hash === null) return fail('bad-hash');
    const read = readLinks(f.links, ERS_LIMITS.MAX_ARCHIVE_TIME_STAMPS);
    if (!read.ok) return read;
    for (const [i, link] of read.value.entries()) {
      if (link.batch !== undefined) return fail('export-unsupported', `link ${i} batch`);
    }
    const expected = await expectedHashes(hash, read.value);
    if (expected === null) return fail('unsupported-signature');
    const stamps: Uint8Array[] = [];
    for (const [i, link] of read.value.entries()) {
      let token;
      try {
        token = readToken(link.token);
      } catch (e) {
        return fail(e instanceof ReaderError ? e.reason : 'malformed', `link ${i}`);
      }
      if (token.info.hashOid !== SHA256_OID) return fail('unsupported-hash', `link ${i}`);
      if (!equalBytes(token.info.imprint, expected[i]!))
        return fail('imprint-mismatch', `link ${i}`);
      stamps.push(tlv(TAG.sequence, tlv(CTX_0, ...algorithmParts()), link.token));
    }
    const out = tlv(
      TAG.sequence,
      tlv(TAG.integer, Uint8Array.of(1)),
      tlv(TAG.sequence, SHA256_ALGORITHM),
      tlv(TAG.sequence, tlv(TAG.sequence, ...stamps)),
    );
    if (out.length > ERS_LIMITS.MAX_BYTES) return fail('too-large');
    return ok(out);
  } catch {
    return fail('malformed');
  }
}

/** The content of the `[0]` IMPLICIT AlgorithmIdentifier: the same two elements as the SEQUENCE has. */
function algorithmParts(): Uint8Array[] {
  return [encodeOid(SHA256_OID), tlv(TAG.null)];
}

/**
 * Verifies an evidence record against the hash of the data object: reads it (`readEvidenceRecord`), then checks the
 * chain with `verifyRenewalChain` (the first ArchiveTimeStamp stamps `hash`, every later one the SHA-256 of the
 * token before it: RFC 4998 section 5.2; each token at the time of the next one; the result and the codes are those
 * of `verifyRenewalChain`). `expectedNonce` is `bad-options`. Never throws.
 */
export async function verifyEvidenceRecord(
  input: EvidenceRecordInput,
): Promise<Result<VerifiedRenewalChain>> {
  try {
    const f = fieldsOf(input, ['bytes', 'hash', 'trust', 'options'], ['bytes', 'hash', 'trust']);
    if (f === null) return fail('bad-options');
    const hash = copyBytes(f.hash, 32, 32);
    if (hash === null) return fail('bad-hash');
    const record = readEvidenceRecord(f.bytes as Uint8Array);
    if (!record.ok) return record;
    return await verifyRenewalChain({
      hash,
      links: record.value.tokens.map((token) => ({ token })),
      trust: f.trust as TrustAnchors,
      ...(f.options === undefined ? {} : { options: f.options as VerifyOptions }),
    });
  } catch {
    return fail('malformed');
  }
}
