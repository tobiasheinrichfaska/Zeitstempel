import { copyBytes, equalBytes, fromBase64Url, toBase64Url } from '../lib/bytes.ts';
import { BATCH_LIMITS, verifyBatchedTimestamp, type BatchProof } from '../lib/batch.ts';
import { fail, ok, type Result } from '../lib/result.ts';
import {
  verifyTimestampToken,
  type TrustAnchors,
  type VerifiedTimestamp,
  type VerifyOptions,
} from '../lib/verify.ts';
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
}

/** The limits of the evidence reader (`docs/data-model.html` names each value; a test ties them). */
export const EVIDENCE_LIMITS = {
  /** Longest token (DER) in bytes: the limit of the library's readers. */
  MAX_TOKEN_BYTES: 262144,
  /** Longest evidence as JSON text, in characters. */
  MAX_JSON_CHARS: 500000,
  /** Longest policy OID text. */
  MAX_POLICY_CHARS: 128,
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
] as const;
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
    if (f.kind !== 'single' && f.kind !== 'batch') return bad('kind');
    if (typeof f.service !== 'string' || !SERVICE_ID.test(f.service)) return bad('service');
    if (canonicalBytes(f.hash, 32, 32, 43) === null) return bad('hash');
    if (f.hashAlg !== 'sha256') return bad('hashAlg');
    const at = f.receivedAtMs;
    if (typeof at !== 'number' || !Number.isInteger(at) || at < MIN_MS || at >= MAX_MS) {
      return bad('receivedAtMs');
    }
    if (canonicalBytes(f.token, 1, EVIDENCE_LIMITS.MAX_TOKEN_BYTES, MAX_TOKEN_CHARS) === null) {
      return bad('token');
    }
    if (!isoTime(f.genTime)) return bad('genTime');
    const out: Evidence = {
      v: 1,
      kind: f.kind,
      service: f.service,
      hash: f.hash as string,
      hashAlg: 'sha256',
      receivedAtMs: at,
      token: f.token as string,
      genTime: f.genTime,
    };
    if (f.kind === 'batch') {
      const batch = readBatch(f.batch);
      if (batch === null) return bad('batch');
      out.batch = batch;
    } else if ('batch' in f) {
      return bad('batch'); // a single stamp carries no receipt
    }
    if ('policy' in f) {
      const p = f.policy;
      if (typeof p !== 'string' || p.length > EVIDENCE_LIMITS.MAX_POLICY_CHARS || !POLICY.test(p)) {
        return bad('policy');
      }
      out.policy = p;
    }
    if ('signerNotAfter' in f) {
      if (!isoTime(f.signerNotAfter)) return bad('signerNotAfter');
      out.signerNotAfter = f.signerNotAfter;
    }
    return ok(out);
  } catch {
    return bad('unreadable'); // not reachable by design: the last net under "never throws"
  }
}

/**
 * The canonical JSON text of evidence: the input is read like `readEvidence` (a bad one gives `bad-evidence`) and
 * written in the fixed field order `v, kind, service, hash, hashAlg, receivedAtMs, token, batch, policy, genTime,
 * signerNotAfter` (batch: `v, size, index, salt, path`), no blanks. Equal evidence gives equal text, and
 * `readEvidence` of the text gives the same evidence back. Never throws.
 */
export function serializeEvidence(evidence: Evidence): Result<string> {
  const read = readEvidence(evidence);
  if (!read.ok) return read;
  const e = read.value;
  const ordered: Record<string, unknown> = {
    v: e.v,
    kind: e.kind,
    service: e.service,
    hash: e.hash,
    hashAlg: e.hashAlg,
    receivedAtMs: e.receivedAtMs,
    token: e.token,
    ...(e.batch === undefined
      ? {}
      : {
          batch: {
            v: 1,
            size: e.batch.size,
            index: e.batch.index,
            salt: e.batch.salt,
            path: [...e.batch.path],
          },
        }),
    ...(e.policy === undefined ? {} : { policy: e.policy }),
    genTime: e.genTime,
    ...(e.signerNotAfter === undefined ? {} : { signerNotAfter: e.signerNotAfter }),
  };
  return ok(JSON.stringify(ordered));
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
}

export interface VerifiedEvidence extends VerifiedTimestamp {
  kind: 'single' | 'batch';
  service: string;
  receivedAtMs: number;
  /** Only for `kind: 'batch'`. */
  batch?: { size: number; index: number };
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
] as const;

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
    if (e.genTime !== v.genTime) return bad('genTime');
    if (e.policy !== undefined && e.policy !== v.policy) return bad('policy');
    if (e.signerNotAfter !== undefined && e.signerNotAfter !== v.signerNotAfter) {
      return bad('signerNotAfter');
    }
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
