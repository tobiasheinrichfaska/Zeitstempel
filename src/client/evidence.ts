import { copyBytes, equalBytes, fromBase64Url, toBase64Url } from '../lib/bytes.ts';
import { BATCH_LIMITS, verifyBatchedTimestamp, type BatchProof } from '../lib/batch.ts';
import { fail, ok, type Result } from '../lib/result.ts';
import {
  verifyTimestampToken,
  type TrustAnchors,
  type VerifiedTimestamp,
  type VerifyOptions,
} from '../lib/verify.ts';
import { RENEWAL_LIMITS, verifyRenewalChain, type RenewalLink } from '../lib/renewal.ts';
import { listItems, plainFields } from './plain.ts';

/**
 * The evidence of a time stamp, format version 1: everything needed to check later, without the relay and without
 * a network, that a hash existed at the latest at `genTime`. JSON-capable (no functions, no bytes: base64url text).
 * `readEvidence` is its strict reader, `serializeEvidence` its canonical writer, `verifyEvidence` the check.
 */
export interface Evidence {
  /** Format version: exactly 1. */
  v: 1;
  /** `single`: the token covers the hash; `batch`: it covers a Merkle tree and `batch` holds the audit path. */
  kind: 'single' | 'batch';
  /** Id of the service as `services.json` names it. */
  service: string;
  /** The stamped SHA-256, base64url, 32 bytes. */
  hash: string;
  hashAlg: 'sha256';
  /** The client's clock (corrected by the relay's `Date` after a 401) when the answer came, Unix milliseconds. */
  receivedAtMs: number;
  /** The TimeStampToken (DER), base64url, exactly as the relay delivers it. */
  token: string;
  /** Only with `kind: 'batch'`: the receipt of the relay's answer, unchanged. */
  batch?: BatchProof;
  /** The policy OID of the token (from the verification at stamping time; checked again by `verifyEvidence`). */
  policy?: string;
  /** The time the token attests, ISO 8601 UTC with milliseconds (from the verification; checked again). */
  genTime: string;
  /** End of the signer certificate's validity (from the verification; checked again). */
  signerNotAfter?: string;
  /**
   * Only after a renewal: the later stamps of the chain, oldest first (1 to `MAX_RENEWALS`). Link i stamped the
   * `renewalImprint` of the hash and the tokens before it, so it carries no hash of its own. Evidence without
   * this field is a plain version 1 evidence, unchanged.
   */
  renewals?: RenewalEvidence[];
}

/** One renewal of the chain: a stamp over the imprint of everything before it (`docs/client.md`, "Erneuerungskette"). */
export interface RenewalEvidence {
  kind: 'single' | 'batch';
  service: string;
  receivedAtMs: number;
  token: string;
  batch?: BatchProof;
  policy?: string;
  genTime: string;
  signerNotAfter?: string;
}

/** The limits of the evidence reader (`docs/data-model.html` names each value; a test ties them). */
export const EVIDENCE_LIMITS = {
  /** Longest token (DER) in bytes: the limit of the library's readers. */
  MAX_TOKEN_BYTES: 262144,
  /** Longest evidence as JSON text, in characters (`serializeEvidence` refuses a longer one: `evidence-too-large`). */
  MAX_JSON_CHARS: 500000,
  /** Longest policy OID text. */
  MAX_POLICY_CHARS: 128,
  /** Most renewals in one evidence: the chain has at most `RENEWAL_LIMITS.MAX_LINKS` links, the original included. */
  MAX_RENEWALS: RENEWAL_LIMITS.MAX_LINKS - 1,
} as const;

const SERVICE_ID = /^[a-z][a-z0-9-]{0,31}$/;
const ISO_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const POLICY = /^\d{1,20}(\.\d{1,20}){1,31}$/;
const MIN_MS = 1e11;
const MAX_MS = 1e15;
const MAX_TOKEN_CHARS = Math.ceil((EVIDENCE_LIMITS.MAX_TOKEN_BYTES * 4) / 3);

const FIELDS = [
  'v',
  'kind',
  'service',
  'hash',
  'hashAlg',
  'receivedAtMs',
  'token',
  'batch',
  'policy',
  'genTime',
  'signerNotAfter',
  'renewals',
] as const;
const LINK_FIELDS = [
  'kind',
  'service',
  'receivedAtMs',
  'token',
  'batch',
  'policy',
  'genTime',
  'signerNotAfter',
] as const;
const LINK_REQUIRED = ['kind', 'service', 'receivedAtMs', 'token', 'genTime'];
const REQUIRED = ['v', 'kind', 'service', 'hash', 'hashAlg', 'receivedAtMs', 'token', 'genTime'];
const BATCH_FIELDS = ['v', 'size', 'index', 'salt', 'path'] as const;

const bad = (field: string) => fail('bad-evidence', field);

/** base64url text of exactly `bytes` bytes in its one canonical spelling, else null. */
function canonicalBytes(text: unknown, min: number, max: number, maxChars: number) {
  if (typeof text !== 'string' || text.length > maxChars) return null;
  const bytes = fromBase64Url(text);
  if (bytes === null || bytes.length < min || bytes.length > max) return null;
  return toBase64Url(bytes) === text ? bytes : null;
}

function isoTime(text: unknown): text is string {
  if (typeof text !== 'string' || !ISO_MS.test(text)) return false;
  const ms = Date.parse(text);
  return Number.isFinite(ms) && new Date(ms).toISOString() === text;
}

function readBatch(value: unknown): BatchProof | null {
  const f = plainFields(value, BATCH_FIELDS, BATCH_FIELDS);
  if (f === null) return null;
  const { v, size, index, salt } = f;
  if (v !== 1) return null;
  if (typeof size !== 'number' || !Number.isInteger(size)) return null;
  if (size < 1 || size > BATCH_LIMITS.MAX_SIZE) return null;
  if (typeof index !== 'number' || !Number.isInteger(index) || index < 0 || index >= size) {
    return null;
  }
  const n = BATCH_LIMITS.NODE_BYTES;
  if (canonicalBytes(salt, n, n, 64) === null) return null;
  const items = listItems(f.path, BATCH_LIMITS.MAX_PATH);
  if (items === null) return null;
  const path: string[] = [];
  for (const item of items) {
    if (canonicalBytes(item, n, n, 64) === null) return null;
    path.push(item as string);
  }
  return { v: 1, size, index, salt: salt as string, path };
}

/**
 * The fields the evidence and a renewal have in common (`kind`, `service`, `receivedAtMs`, `token`, `genTime`,
 * `batch`, `policy`, `signerNotAfter`) from an already read field table; `own` also checks `hash` and `hashAlg`
 * (in their old place between `service` and `receivedAtMs`). `prefix` goes in front of the field name in `detail`.
 */
function readStamp(
  f: Record<string, unknown>,
  prefix: string,
  own: boolean,
): Result<RenewalEvidence> {
  const no = (field: string) => bad(prefix + field);
  if (f.kind !== 'single' && f.kind !== 'batch') return no('kind');
  if (typeof f.service !== 'string' || !SERVICE_ID.test(f.service)) return no('service');
  if (own) {
    if (canonicalBytes(f.hash, 32, 32, 43) === null) return no('hash');
    if (f.hashAlg !== 'sha256') return no('hashAlg');
  }
  const at = f.receivedAtMs;
  if (typeof at !== 'number' || !Number.isInteger(at) || at < MIN_MS || at >= MAX_MS) {
    return no('receivedAtMs');
  }
  if (canonicalBytes(f.token, 1, EVIDENCE_LIMITS.MAX_TOKEN_BYTES, MAX_TOKEN_CHARS) === null) {
    return no('token');
  }
  if (!isoTime(f.genTime)) return no('genTime');
  const out: RenewalEvidence = {
    kind: f.kind,
    service: f.service,
    receivedAtMs: at,
    token: f.token as string,
    genTime: f.genTime,
  };
  if (f.kind === 'batch') {
    const batch = readBatch(f.batch);
    if (batch === null) return no('batch');
    out.batch = batch;
  } else if ('batch' in f) {
    return no('batch'); // a single stamp carries no receipt
  }
  if ('policy' in f) {
    const p = f.policy;
    if (typeof p !== 'string' || p.length > EVIDENCE_LIMITS.MAX_POLICY_CHARS || !POLICY.test(p)) {
      return no('policy');
    }
    out.policy = p;
  }
  if ('signerNotAfter' in f) {
    if (!isoTime(f.signerNotAfter)) return no('signerNotAfter');
    out.signerNotAfter = f.signerNotAfter;
  }
  return ok(out);
}

/**
 * Reads evidence strictly and gives a fresh, normalized copy: a plain object (or JSON text of at most
 * `MAX_JSON_CHARS`) with exactly the fields of version 1, every one of the right type and size, no unknown field,
 * `batch` exactly with `kind: 'batch'`. Reads each field once through its descriptor (a getter or a Proxy that
 * throws gives `bad-evidence`, `detail` names the field); never throws. This checks the FORM only: whether the
 * token proves anything is `verifyEvidence`.
 */
export function readEvidence(input: unknown): Result<Evidence> {
  try {
    let value = input;
    if (typeof input === 'string') {
      if (input.length > EVIDENCE_LIMITS.MAX_JSON_CHARS) return bad('size');
      try {
        value = JSON.parse(input);
      } catch {
        return bad('json');
      }
    }
    const f = plainFields(value, FIELDS, REQUIRED);
    if (f === null) return bad('object');
    if (f.v !== 1) return bad('v');
    const stamp = readStamp(f, '', true);
    if (!stamp.ok) return stamp;
    const out: Evidence = {
      v: 1,
      kind: stamp.value.kind,
      service: stamp.value.service,
      hash: f.hash as string,
      hashAlg: 'sha256',
      receivedAtMs: stamp.value.receivedAtMs,
      token: stamp.value.token,
      ...(stamp.value.batch === undefined ? {} : { batch: stamp.value.batch }),
      ...(stamp.value.policy === undefined ? {} : { policy: stamp.value.policy }),
      genTime: stamp.value.genTime,
      ...(stamp.value.signerNotAfter === undefined
        ? {}
        : { signerNotAfter: stamp.value.signerNotAfter }),
    };
    if ('renewals' in f) {
      const items = listItems(f.renewals, EVIDENCE_LIMITS.MAX_RENEWALS);
      if (items === null || items.length === 0) return bad('renewals');
      const renewals: RenewalEvidence[] = [];
      for (const [i, item] of items.entries()) {
        const lf = plainFields(item, LINK_FIELDS, LINK_REQUIRED);
        if (lf === null) return bad(`renewals[${i}]`);
        const link = readStamp(lf, `renewals[${i}].`, false);
        if (!link.ok) return link;
        renewals.push(link.value);
      }
      out.renewals = renewals;
    }
    return ok(out);
  } catch {
    return bad('unreadable'); // not reachable by design: the last net under "never throws"
  }
}

const orderedBatch = (b: BatchProof) => ({
  v: 1,
  size: b.size,
  index: b.index,
  salt: b.salt,
  path: [...b.path],
});

/**
 * The canonical JSON text of evidence: the input is read like `readEvidence` (a bad one gives `bad-evidence`) and
 * written in the fixed field order `v, kind, service, hash, hashAlg, receivedAtMs, token, batch, policy, genTime,
 * signerNotAfter` (batch: `v, size, index, salt, path`), no blanks. Equal evidence gives equal text, and
 * `readEvidence` of the text gives the same evidence back. Never throws.
 */
export function serializeEvidence(evidence: Evidence): Result<string> {
  const read = readEvidence(evidence);
  if (!read.ok) return read;
  // never write a text that `readEvidence` would refuse for its size (the object stays usable, the text does not exist)
  const e = read.value;
  const ordered: Record<string, unknown> = {
    v: e.v,
    kind: e.kind,
    service: e.service,
    hash: e.hash,
    hashAlg: e.hashAlg,
    receivedAtMs: e.receivedAtMs,
    token: e.token,
    ...(e.batch === undefined ? {} : { batch: orderedBatch(e.batch) }),
    ...(e.policy === undefined ? {} : { policy: e.policy }),
    genTime: e.genTime,
    ...(e.signerNotAfter === undefined ? {} : { signerNotAfter: e.signerNotAfter }),
    ...(e.renewals === undefined
      ? {}
      : {
          renewals: e.renewals.map((r) => ({
            kind: r.kind,
            service: r.service,
            receivedAtMs: r.receivedAtMs,
            token: r.token,
            ...(r.batch === undefined ? {} : { batch: orderedBatch(r.batch) }),
            ...(r.policy === undefined ? {} : { policy: r.policy }),
            genTime: r.genTime,
            ...(r.signerNotAfter === undefined ? {} : { signerNotAfter: r.signerNotAfter }),
          })),
        }),
  };
  const text = JSON.stringify(ordered);
  if (text.length > EVIDENCE_LIMITS.MAX_JSON_CHARS) return fail('evidence-too-large', 'text');
  return ok(text);
}

export interface VerifyEvidenceOptions {
  /** The trust anchors (PEM texts): the caller's decision, as everywhere in the library. Required. */
  trust: TrustAnchors;
  /** As in `VerifyOptions`; `expectedNonce` is not offered (the relay chooses the nonce). */
  now?: Date;
  at?: Date;
  minGenTime?: Date;
  maxSkewMs?: number;
  requireCriticalEku?: boolean;
  minRsaBits?: number;
  expectedPolicy?: string | readonly string[];
  /**
   * Revocation lists (DER) that YOU hold, as in `VerifyOptions`: the check is offline and only as good as the lists
   * given; without them nothing is checked for revocation (`docs/grenzen.md`).
   */
  crls?: readonly Uint8Array[];
}

export interface VerifiedEvidence extends VerifiedTimestamp {
  kind: 'single' | 'batch';
  service: string;
  receivedAtMs: number;
  /** Only for `kind: 'batch'`. */
  batch?: { size: number; index: number };
  /**
   * Only for evidence with `renewals`: the values above are those of the ORIGINAL stamp (the hash existed at the
   * latest then); these are the chain's: the number of renewals, the renewed link with the smallest margin, the
   * time of the latest renewal, the end of the validity of its signer and the earliest end in its whole certificate chain
   * (`lastChainNotAfter`: renew before that).
   */
  renewalLinks?: number;
  weakestLink?: { index: number; marginMs: number } | null;
  lastGenTime?: string;
  lastSignerNotAfter?: string;
  lastChainNotAfter?: string;
}

const OPTION_FIELDS = [
  'trust',
  'now',
  'at',
  'minGenTime',
  'maxSkewMs',
  'requireCriticalEku',
  'minRsaBits',
  'expectedPolicy',
  'crls',
] as const;

/** The facts a stamp of the evidence repeats against what the check found (`bad-evidence` with the field). */
function sameClaims(
  e: { genTime: string; policy?: string | undefined; signerNotAfter?: string | undefined },
  v: VerifiedTimestamp,
  prefix = '',
): Result<true> {
  if (e.genTime !== v.genTime) return bad(`${prefix}genTime`);
  if (e.policy !== undefined && e.policy !== v.policy) return bad(`${prefix}policy`);
  if (e.signerNotAfter !== undefined && e.signerNotAfter !== v.signerNotAfter) {
    return bad(`${prefix}signerNotAfter`);
  }
  return ok(true);
}

/** Evidence with `renewals`: the whole chain through `verifyRenewalChain`, then every stamp's repeated facts. */
async function verifyRenewed(
  e: Evidence,
  hash: Uint8Array,
  token: Uint8Array,
  trust: unknown,
  options: VerifyOptions,
): Promise<Result<VerifiedEvidence>> {
  const renewals = e.renewals!;
  const links: RenewalLink[] = [
    { token, ...(e.batch === undefined ? {} : { batch: e.batch }) },
    ...renewals.map((r) => ({
      token: fromBase64Url(r.token)!,
      ...(r.batch === undefined ? {} : { batch: r.batch }),
    })),
  ];
  const chain = await verifyRenewalChain({
    hash,
    links,
    trust: trust as TrustAnchors,
    options,
  });
  if (!chain.ok) return chain;
  const c = chain.value;
  const first = sameClaims(e, c.links[0]!);
  if (!first.ok) return first;
  for (const [i, r] of renewals.entries()) {
    const same = sameClaims(r, c.links[i + 1]!, `renewals[${i}].`);
    if (!same.ok) return same;
  }
  const first0 = c.links[0]!;
  const { batch: proof, ...rest0 } = first0;
  const base: VerifiedTimestamp = { ...rest0 };
  delete (base as Partial<typeof first0>).renewedAt;
  delete (base as Partial<typeof first0>).marginMs;
  return ok({
    ...base,
    kind: e.kind,
    service: e.service,
    receivedAtMs: e.receivedAtMs,
    ...(proof === undefined ? {} : { batch: proof }),
    renewalLinks: renewals.length,
    weakestLink: c.weakestLink,
    lastGenTime: c.lastGenTime,
    lastSignerNotAfter: c.lastSignerNotAfter,
    lastChainNotAfter: c.lastChainNotAfter,
  });
}

/**
 * Checks evidence against the hash it is meant for, without the relay and without a network: first the form
 * (`bad-evidence`), then the hash of the evidence against the given one (`evidence-hash-mismatch`), then the
 * token (`verifyTimestampToken`, or `verifyBatchedTimestamp` for `kind: 'batch'`: every code of those), then the
 * facts the evidence repeats (`genTime`, `policy`, `signerNotAfter`) against the verified ones (`bad-evidence`
 * when one differs). The values of the RESULT are the verified ones. Freshness is the caller's rule: pass
 * `minGenTime` if the evidence must not be older than something. Never throws or rejects.
 */
export async function verifyEvidence(
  evidence: unknown,
  hash: Uint8Array,
  options: VerifyEvidenceOptions,
): Promise<Result<VerifiedEvidence>> {
  try {
    const o = plainFields(options, OPTION_FIELDS, ['trust']);
    if (o === null) return fail('bad-options');
    const read = readEvidence(evidence);
    if (!read.ok) return read;
    const e = read.value;
    const given = copyBytes(hash, 32, 32);
    if (given === null) return fail('bad-hash');
    if (!equalBytes(given, fromBase64Url(e.hash)!)) return fail('evidence-hash-mismatch');
    const { trust, ...rest } = o;
    const verifyOptions = rest as VerifyOptions;
    const token = fromBase64Url(e.token)!;
    if (e.renewals !== undefined) return await verifyRenewed(e, given, token, trust, verifyOptions);
    const checked =
      e.batch === undefined
        ? await verifyTimestampToken(token, given, trust as TrustAnchors, verifyOptions)
        : await verifyBatchedTimestamp(
            { token, hash: given, batch: e.batch },
            trust as TrustAnchors,
            verifyOptions,
          );
    if (!checked.ok) return checked;
    const v = checked.value;
    const same = sameClaims(e, v);
    if (!same.ok) return same;
    const { batch: proof, ...base } = checked.value as VerifiedTimestamp & {
      batch?: { size: number; index: number };
    };
    return ok({
      ...base,
      kind: e.kind,
      service: e.service,
      receivedAtMs: e.receivedAtMs,
      ...(proof === undefined ? {} : { batch: proof }),
    });
  } catch {
    return fail('malformed'); // not reachable by design
  }
}
