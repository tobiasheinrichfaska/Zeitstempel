import { concat, copyBytes } from './bytes.ts';
import { verifyBatchedTimestamp, type BatchProof } from './batch.ts';
import { DER_LIMITS } from './der.ts';
import { ReaderError, fail, ok, type Result } from './result.ts';
import { readToken } from './token.ts';
import {
  checkOptions,
  verifyTimestampToken,
  type TrustAnchors,
  type VerifiedTimestamp,
  type VerifyOptions,
} from './verify.ts';

/**
 * The renewal chain: a time stamp loses weight when the signer certificate expires or its key leaks, so BEFORE that
 * the whole evidence (the hash and every token so far) is stamped again. Link 0 stamps the hash; link i > 0 stamps
 * `renewalImprint` of the chain up to link i - 1. The chain then says: "this hash existed at the latest at the
 * time of link 0, and that stamp existed at the latest at the time of link 1, ..." (docs/client.md, docs/grenzen.md).
 */

/** The limits of the renewal chain (docs/data-model.html names each value; a test ties them). */
export const RENEWAL_LIMITS = {
  /** Most links in one chain, the original stamp included. */
  MAX_LINKS: 64,
} as const;

/** One stamp of the chain: the token (DER) and, for a stamp from a collecting relay, the receipt of the tree. */
export interface RenewalLink {
  token: Uint8Array;
  batch?: BatchProof;
}

/** The chain so far: the stamped hash and the links from the original stamp on. */
export interface RenewalChain {
  hash: Uint8Array;
  links: readonly RenewalLink[];
}

export interface RenewalInput extends RenewalChain {
  trust: TrustAnchors;
  /** As `VerifyOptions`, except `expectedNonce` (the relay chooses the nonces): see `verifyRenewalChain`. */
  options?: VerifyOptions;
}

export interface VerifiedRenewalLink extends VerifiedTimestamp {
  /** Only for a link stamped through a collecting relay. */
  batch?: { size: number; index: number };
  /** The time of the next link (the moment this stamp was covered by a newer one); null for the last link. */
  renewedAt: string | null;
  /** `signerNotAfter` minus `renewedAt` in milliseconds (>= 0 when the chain is ok); null for the last link. */
  marginMs: number | null;
}

export interface VerifiedRenewalChain {
  /** The time of link 0: the hash existed at the latest then. */
  genTime: string;
  /** The time of the last link (the latest renewal). */
  lastGenTime: string;
  /** End of the signer certificate of the last link: renew before it. */
  lastSignerNotAfter: string;
  links: VerifiedRenewalLink[];
  /** The renewed link with the smallest margin (the earliest in a tie); null when there is only one link. */
  weakestLink: { index: number; marginMs: number } | null;
}

const TAG = new TextEncoder().encode('zeitstempel-renewal-v1\n');
const LINK_FIELDS = ['token', 'batch'];
const INPUT_FIELDS = ['hash', 'links', 'trust', 'options'];

const bad = (detail: string) => fail('bad-renewal', detail);

async function sha256(data: Uint8Array): Promise<Uint8Array | null> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return null;
  return new Uint8Array(await subtle.digest('SHA-256', data as BufferSource));
}

/** The own fields of a plain object through their descriptors (a getter is never run), else null. */
function fieldsOf(
  value: unknown,
  allowed: readonly string[],
  required: readonly string[],
): Record<string, unknown> | null {
  try {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
    const proto: unknown = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return null;
    const keys = Object.keys(value);
    if (keys.length > allowed.length) return null;
    const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const key of keys) {
      if (!allowed.includes(key)) return null;
      const d = Object.getOwnPropertyDescriptor(value, key);
      if (d === undefined || !('value' in d)) return null;
      out[key] = d.value;
    }
    for (const key of required) if (!(key in out)) return null;
    return out;
  } catch {
    return null;
  }
}

interface ReadLink {
  token: Uint8Array;
  batch: unknown;
}

/** The links by length and index (never the iterator), 1 to `max`, each a copy; a bad one is `bad-renewal`. */
function readLinks(value: unknown, max: number): Result<ReadLink[]> {
  let count: unknown;
  try {
    if (!Array.isArray(value)) return bad('links');
    count = (value as unknown[]).length;
  } catch {
    return bad('links');
  }
  if (typeof count !== 'number' || !Number.isInteger(count) || count < 1 || count > max) {
    return bad('links');
  }
  const out: ReadLink[] = [];
  for (let i = 0; i < count; i += 1) {
    let item: unknown;
    try {
      item = (value as unknown[])[i];
    } catch {
      return bad(`link ${i}`);
    }
    const f = fieldsOf(item, LINK_FIELDS, ['token']);
    if (f === null) return bad(`link ${i}`);
    const token = copyBytes(f.token, 1, DER_LIMITS.maxBytes);
    if (token === null) return bad(`link ${i}`);
    out.push({ token, batch: f.batch });
  }
  return ok(out);
}

/** What link j must stamp: `[hash, imprint 1, imprint 2, ...]` (one more entry than there are tokens). */
async function expectedHashes(hash: Uint8Array, links: readonly ReadLink[]) {
  const out: Uint8Array[] = [hash];
  for (const link of links) {
    const tokenHash = await sha256(link.token);
    if (tokenHash === null) return null;
    const next = await sha256(concat(TAG, tokenHash, out[out.length - 1]!));
    if (next === null) return null;
    out.push(next);
  }
  return out;
}

/**
 * The value the NEXT link of the chain must stamp: `SHA-256("zeitstempel-renewal-v1\n" || SHA-256(token of the
 * last link) || state)`, where `state` is the hash for the first link and, after that, the imprint the last link
 * stamped. Every imprint therefore binds the original hash, every token before it and its own predecessor
 * (fixed lengths, nothing to parse). `links` are the stamps so far (1 to 63: a chain has at most 64 links); the
 * receipt of a collecting relay is not part of the imprint (the token's tree root fixes it). Never throws.
 */
export async function renewalImprint(chain: RenewalChain): Promise<Result<Uint8Array>> {
  try {
    const f = fieldsOf(chain, ['hash', 'links'], ['hash', 'links']);
    if (f === null) return fail('bad-options');
    const hash = copyBytes(f.hash, 32, 32);
    if (hash === null) return fail('bad-hash');
    const links = readLinks(f.links, RENEWAL_LIMITS.MAX_LINKS - 1);
    if (!links.ok) return links;
    const all = await expectedHashes(hash, links.value);
    if (all === null) return fail('unsupported-signature');
    return ok(all[all.length - 1]!);
  } catch {
    return fail('malformed');
  }
}

/**
 * Checks a renewal chain: link 0 is a token over `hash`, link i > 0 a token over `renewalImprint` of the links
 * before it (a link that binds another predecessor, a reordered, doubled or missing link is `imprint-mismatch`).
 * Every link goes through `verifyTimestampToken` (`verifyBatchedTimestamp` when it carries `batch`) with `at` =
 * the time of the NEXT link, so the certificates count at the moment the stamp was covered by a newer one; for
 * the last link `at` is `options.at`, else `options.now`, else none. The times must not fall (`bad-renewal`); a
 * link whose certificates were no longer valid when the next link was made is `renewal-too-late`; a revoked
 * link is `revoked` (the `crls` go to every link: each list must be current at that link's check time, so one list
 * from today fits only the last link, `docs/grenzen.md`). `minGenTime` counts for link 0 only, every other
 * option for every link; `expectedNonce` is `bad-options`. The failure of a link carries `detail: "link <i>"`.
 * 1 to 64 links, each token at most 262144 bytes, inputs copied by length. Never throws.
 */
export async function verifyRenewalChain(
  input: RenewalInput,
): Promise<Result<VerifiedRenewalChain>> {
  try {
    const f = fieldsOf(input, INPUT_FIELDS, ['hash', 'links', 'trust']);
    if (f === null) return fail('bad-options');
    const hash = copyBytes(f.hash, 32, 32);
    if (hash === null) return fail('bad-hash');
    let snap: ReturnType<typeof checkOptions>;
    try {
      snap = checkOptions(f.options);
    } catch {
      return fail('bad-options');
    }
    if (snap.expectedNonce !== undefined) return fail('bad-options', 'expectedNonce');
    const read = readLinks(f.links, RENEWAL_LIMITS.MAX_LINKS);
    if (!read.ok) return read;
    const links = read.value;
    const expected = await expectedHashes(hash, links);
    if (expected === null) return fail('unsupported-signature');
    const trust = f.trust as TrustAnchors;
    const date = (ms: number | undefined) => (ms === undefined ? undefined : new Date(ms));
    const last = links.length - 1;
    // the times first (reading only, no signature): a chain must not fall in time
    const times: number[] = [];
    for (const [i, link] of links.entries()) {
      try {
        times.push(readToken(link.token).info.genTime);
      } catch (e) {
        return fail(e instanceof ReaderError ? e.reason : 'malformed', `link ${i}`);
      }
    }
    for (let i = 0; i < last; i += 1) if (times[i]! > times[i + 1]!) return bad(`order ${i}`);
    const results: VerifiedRenewalLink[] = [];
    for (const [i, link] of links.entries()) {
      const next = i < last ? times[i + 1]! : undefined;
      const at = next ?? snap.at ?? snap.now;
      const base: VerifyOptions = {
        ...(snap.now === undefined ? {} : { now: date(snap.now)! }),
        ...(i === 0 && snap.minGenTime !== undefined ? { minGenTime: date(snap.minGenTime)! } : {}),
        maxSkewMs: snap.maxSkewMs,
        requireCriticalEku: snap.requireCriticalEku,
        minRsaBits: snap.minRsaBits,
        ...(snap.expectedPolicy === undefined ? {} : { expectedPolicy: snap.expectedPolicy }),
        crls: snap.crls,
      };
      const check = (o: VerifyOptions) =>
        link.batch === undefined
          ? verifyTimestampToken(link.token, expected[i]!, trust, o)
          : verifyBatchedTimestamp(
              { token: link.token, hash: expected[i]!, batch: link.batch as BatchProof },
              trust,
              o,
            );
      const r = await check(at === undefined ? base : { ...base, at: date(at)! });
      if (!r.ok && r.reason === 'certificate-not-valid-at-time' && next !== undefined) {
        // valid when it was stamped, not when it was covered by the next link: the renewal came too late
        const plain = await check(base);
        return plain.ok ? fail('renewal-too-late', `link ${i}`) : fail(plain.reason, `link ${i}`);
      }
      if (!r.ok) return fail(r.reason, `link ${i}`);
      const v = r.value as VerifiedTimestamp & { batch?: { size: number; index: number } };
      results.push({
        ...v,
        renewedAt: next === undefined ? null : new Date(next).toISOString(),
        marginMs: next === undefined ? null : Date.parse(v.signerNotAfter) - next,
      });
    }
    let weakest: { index: number; marginMs: number } | null = null;
    for (let i = 0; i < last; i += 1) {
      const m = results[i]!.marginMs!;
      if (weakest === null || m < weakest.marginMs) weakest = { index: i, marginMs: m };
    }
    return ok({
      genTime: results[0]!.genTime,
      lastGenTime: results[last]!.genTime,
      lastSignerNotAfter: results[last]!.signerNotAfter,
      links: results,
      weakestLink: weakest,
    });
  } catch {
    return fail('malformed');
  }
}
