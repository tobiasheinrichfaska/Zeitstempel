import { byteLength, copyBytes, copyKnown, equalBytes, trimZeros } from './bytes.ts';
import {
  DER_LIMITS,
  TAG,
  children,
  ctx,
  ctxPrimitive,
  expect,
  inner,
  integerBytes,
  octets,
  oid,
  parseDer,
} from './der.ts';
import { CRL_LIMITS, parseCrl, revokedAt, type Crl } from './crl.ts';
import { checkNameConstraints } from './nameconstraints.ts';
import { CURVES, HASHES, OID, SIGNATURES, type HashName } from './oids.ts';
import { ReaderError, fail, guard, ok, type Result } from './result.ts';
import { MAX_CERTIFICATES, readToken, type ParsedToken, type TstInfo } from './token.ts';
import {
  parsePemCertificates,
  rsaModulusBits,
  sameName,
  subjectAltNames,
  type Certificate,
} from './x509.ts';

/** Trusted root (or intermediate) certificates, as PEM text. The caller decides whom to trust. */
export type TrustAnchors = readonly string[];

export interface VerifyOptions {
  /** The nonce that was sent. When given, the token must carry exactly this nonce. */
  expectedNonce?: Uint8Array;
  /**
   * An additional moment at which the signer certificate and the chain must be valid: they must be valid at the
   * token's own time (`genTime`) AND at `at` (both, `at` does not replace `genTime`). Default: only `genTime`.
   * Must be a valid Date, else `bad-options`.
   */
  at?: Date;
  /**
   * The earliest `genTime` that is accepted: an older token is refused (`time-too-old`). Without it freshness is
   * NOT checked: a token whose time lies far in the past passes as long as the signer certificate was valid
   * then (a back-dated token from a service whose key has expired or leaked; docs/grenzen.md). Pass the moment
   * the request was sent minus a small tolerance. Given but not a valid Date: `bad-options`.
   */
  minGenTime?: Date;
  /** The current time: a token from the future (beyond the skew) is refused. Default: not checked. Given but not a valid Date: `bad-options`. */
  now?: Date;
  /** Allowed difference between the token time and `now`. Default 5 minutes; a number >= 0 (Infinity allowed), else `bad-options`. */
  maxSkewMs?: number;
  /** RFC 3161 wants the extended key usage to be critical. Default true. */
  requireCriticalEku?: boolean;
  /**
   * The smallest RSA modulus (in bits) the signer certificate and every certificate of the chain may have (a
   * weaker one is `weak-key`). Default 2048; 0 switches the rule off. Trust anchors are exempt (the caller chose
   * them). A finite number >= 0, else `bad-options`.
   */
  minRsaBits?: number;
  /**
   * The policy OID(s) the caller expects, in dotted notation (a string, or a non-empty array of at most 16
   * strings): the `policy` of the TSTInfo must be one of them, else `policy-mismatch` (RFC 3161 § 2.4.1, the
   * policy of the request). Compared as exact text: `1.2.3` does not match `1.2.3.4`. Not given: not checked.
   * Anything else (another type, an empty or too long array, a text that is no OID in dotted notation):
   * `bad-options`.
   */
  expectedPolicy?: string | readonly string[];
  /**
   * Revocation lists (CRLs, DER) the caller has fetched (up to 16, each up to 262144 bytes); nothing is fetched here.
   * Every list given must be usable: readable, current (`thisUpdate` <= the check time <= `nextUpdate`; the check
   * time is `at`, else `now`, else `genTime`), signed by a certificate of the chain that was found (a CA, with
   * `cRLSign` when it has key usage), else `bad-crl`. A certificate of the chain (the signer and the intermediates,
   * not the anchor) that a list of its issuer names with a revocation time not after `genTime` (or with the reason
   * `keyCompromise` / `cACompromise`, whatever the time) gives `revoked`. No list for an issuer: as before (nothing
   * is checked). Delta and indirect CRLs are not supported (`bad-crl`). Not an array, more than 16 entries, an entry
   * that is no `Uint8Array` or too large: `bad-options`. docs/grenzen.md.
   */
  crls?: readonly Uint8Array[];
}

export interface VerifiedTimestamp {
  /** The time the service attests, ISO 8601 (UTC). */
  genTime: string;
  accuracyMs: number | null;
  policy: string;
  serial: string;
  /** The signing certificate's subject as `CN=…, O=…` (readable, not for comparisons). */
  signer: string;
  /** Number of certificates from the signer up to the trust anchor (anchor included). */
  chainLength: number;
  /**
   * Start of the validity of the signer certificate, ISO 8601 (UTC). The verification judged the certificates at
   * `genTime`; after `signerNotAfter` (or once the key leaks or is revoked) the proof loses its weight
   * (docs/grenzen.md).
   */
  signerNotBefore: string;
  /** End of the validity of the signer certificate, ISO 8601 (UTC); see `signerNotBefore`. */
  signerNotAfter: string;
}

const MAX_CHAIN = 6;
const MAX_CANDIDATES = 8; // usable, signature-valid issuer candidates tried per certificate
const MAX_SIGNATURE_CHECKS = 64; // signature verifications for the whole chain search
const MAX_REASON_CHECKS = 4; // extra verifications, after a failed search, to name the reason
const MAX_TRUST_ANCHORS = 64; // entries of `trust`; a longer list is `bad-options`, checked before any entry is read

/** The limits of the chain search (docs/grenzen.md and docs/data-model.html name each value). */
export const VERIFY_LIMITS = {
  MAX_CHAIN,
  MAX_CANDIDATES,
  MAX_SIGNATURE_CHECKS,
  MAX_REASON_CHECKS,
  MAX_TRUST_ANCHORS,
  MAX_CERTIFICATES,
} as const;

const DEFAULT_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_MIN_RSA_BITS = 2048;

const subtle = (): SubtleCrypto => {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new ReaderError('unsupported-signature');
  return s;
};

async function digest(name: HashName, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest(name, data as BufferSource));
}

/** DER `ECDSA-Sig-Value` → the fixed-size `r || s` that WebCrypto verifies. */
function ecdsaRaw(der: Uint8Array, size: number): Uint8Array {
  const parts = children(expect(parseDer(der), TAG.sequence));
  if (parts.length !== 2) throw new ReaderError('signature-invalid');
  const [r, s] = parts.map((n) => {
    const bytes = integerBytes(n);
    if ((bytes[0]! & 0x80) !== 0) throw new ReaderError('signature-invalid'); // negative
    return trimZeros(bytes);
  });
  if (!r || !s || r.length > size || s.length > size) throw new ReaderError('signature-invalid');
  const out = new Uint8Array(size * 2);
  out.set(r, size - r.length);
  out.set(s, size * 2 - s.length);
  return out;
}

/** Verifies `signature` over `data` with the key in `cert`; `hash` names the digest. */
async function verifyWithKey(
  cert: Certificate,
  algOid: string,
  fallbackHash: HashName | null,
  data: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const alg = SIGNATURES[algOid];
  const hash = alg?.hash ?? fallbackHash;
  if (!alg || !hash || hash === 'SHA-1') throw new ReaderError('unsupported-signature');
  try {
    if (alg.kind === 'rsa') {
      if (cert.keyOid !== OID.rsaEncryption) throw new ReaderError('unsupported-signature');
      const key = await subtle().importKey(
        'spki',
        cert.spki as BufferSource,
        { name: 'RSASSA-PKCS1-v1_5', hash },
        false,
        ['verify'],
      );
      return await subtle().verify(
        'RSASSA-PKCS1-v1_5',
        key,
        signature as BufferSource,
        data as BufferSource,
      );
    }
    const curve = cert.curveOid ? CURVES[cert.curveOid] : undefined;
    if (cert.keyOid !== OID.ecPublicKey || !curve) throw new ReaderError('unsupported-signature');
    const key = await subtle().importKey(
      'spki',
      cert.spki as BufferSource,
      { name: 'ECDSA', namedCurve: curve.name },
      false,
      ['verify'],
    );
    const raw = ecdsaRaw(signature, curve.size);
    return await subtle().verify(
      { name: 'ECDSA', hash },
      key,
      raw as BufferSource,
      data as BufferSource,
    );
  } catch (e) {
    if (e instanceof ReaderError) throw e;
    throw new ReaderError('unsupported-signature');
  }
}

/** Readable subject: the common name and the organisation, best effort. */
export function nameToString(name: Uint8Array): string {
  const parts: string[] = [];
  try {
    for (const rdn of children(expect(parseDer(name), TAG.sequence))) {
      for (const atv of children(rdn)) {
        const [id, value] = children(atv);
        const key = { '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C' }[
          oid(id!)
        ];
        if (key) parts.push(`${key}=${new TextDecoder().decode(value!.value)}`);
      }
    }
  } catch {
    return '?';
  }
  return parts.join(', ');
}

const same = (a: Uint8Array, b: Uint8Array) => equalBytes(a, b);

const dedupe = (certs: readonly Certificate[]): Certificate[] =>
  certs.filter((c, i) => certs.findIndex((d) => same(d.raw, c.raw)) === i);

const dateGetTime = Date.prototype.getTime;
const MAX_DATE_MS = 8.64e15;

/**
 * The milliseconds of a genuine `Date` (prototype exactly `Date.prototype`), read once with the built-in
 * `getTime` (an overridden `getTime`, a subclass or an object that only claims to be a Date count for
 * nothing); `null` when it is none or not a finite time.
 */
function dateMs(d: unknown): number | null {
  try {
    if (typeof d !== 'object' || d === null || Object.getPrototypeOf(d) !== Date.prototype) {
      return null;
    }
    const ms = dateGetTime.call(d) as unknown;
    return typeof ms === 'number' && Number.isFinite(ms) && Math.abs(ms) <= MAX_DATE_MS ? ms : null;
  } catch {
    return null; // not a real Date (no internal time slot), or a proxy that throws
  }
}

const NONCE_BYTES = { min: 1, max: 16 } as const;

/** The options as read once and checked; the rest of the verification uses only this. */
interface OptionSnapshot {
  readonly now: number | undefined;
  readonly at: number | undefined;
  readonly minGenTime: number | undefined;
  readonly maxSkewMs: number;
  readonly expectedNonce: Uint8Array | undefined;
  readonly requireCriticalEku: boolean;
  readonly minRsaBits: number;
  readonly expectedPolicy: readonly string[] | undefined;
  readonly crls: readonly Uint8Array[];
}

const MAX_EXPECTED_POLICIES = 16;
// dotted OID in canonical form: at least two arcs, no leading zeros, the first arc 0 to 2 (so the text of a
// policy read from a token and the text given here are equal exactly when they name the same OID)
const OID_TEXT = /^[012](?:\.(?:0|[1-9][0-9]{0,15})){1,31}$/;

/** `expectedPolicy` as a frozen list of OID texts; a bad value is `bad-options`. Read by length and index, once each. */
function readExpectedPolicy(value: unknown): readonly string[] | undefined {
  if (value === undefined) return undefined;
  let list: unknown[];
  if (typeof value === 'string') list = [value];
  else {
    if (!Array.isArray(value)) throw new ReaderError('bad-options');
    const count: unknown = (value as unknown[]).length;
    if (typeof count !== 'number' || !Number.isInteger(count)) throw new ReaderError('bad-options');
    if (count < 1 || count > MAX_EXPECTED_POLICIES) throw new ReaderError('bad-options');
    list = [];
    for (let i = 0; i < count; i += 1) list.push((value as unknown[])[i]);
  }
  for (const text of list) {
    if (typeof text !== 'string' || text.length > 256 || !OID_TEXT.test(text)) {
      throw new ReaderError('bad-options');
    }
    // first arcs 0 and 1 allow the second arc 0 to 39 only (X.690 § 8.19.4)
    const [a, b] = text.split('.') as [string, string];
    if (a !== '2' && Number(b) > 39) throw new ReaderError('bad-options');
  }
  return Object.freeze([...(list as string[])]);
}

/** `crls` as private copies (length checked before each copy, never iterated); a bad value is `bad-options`. */
function readCrlBytes(value: unknown): readonly Uint8Array[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new ReaderError('bad-options');
  const count: unknown = (value as unknown[]).length;
  if (typeof count !== 'number' || !Number.isInteger(count) || count < 0) {
    throw new ReaderError('bad-options');
  }
  if (count > CRL_LIMITS.MAX_CRLS) throw new ReaderError('bad-options');
  const out: Uint8Array[] = [];
  for (let i = 0; i < count; i += 1) {
    const copy = copyBytes((value as unknown[])[i], 0, CRL_LIMITS.MAX_CRL_BYTES);
    if (!copy) throw new ReaderError('bad-options');
    out.push(copy);
  }
  return Object.freeze(out);
}

/**
 * Reads every option exactly once into a frozen snapshot and checks it: a given option must be usable (no
 * silent skipping of a check because of a bad value). `options` must be a plain object (prototype
 * `Object.prototype` or `null`). Only own properties count (nothing inherited from `Object.prototype`); a
 * getter is read once and one that throws gives `bad-options`; `Date` values become milliseconds (read
 * once with the built-in `getTime`) and the nonce is copied.
 */
function checkOptions(options: unknown): OptionSnapshot {
  const bad = () => new ReaderError('bad-options');
  const snapshot = (read: (key: string) => unknown): OptionSnapshot => {
    const now = read('now');
    const at = read('at');
    const minGen = read('minGenTime');
    const skew = read('maxSkewMs');
    const nonce = read('expectedNonce');
    const critical = read('requireCriticalEku');
    const rsaBits = read('minRsaBits');
    const policy = readExpectedPolicy(read('expectedPolicy'));
    const crls = readCrlBytes(read('crls'));
    const nowMs = now === undefined ? undefined : dateMs(now);
    const atMs = at === undefined ? undefined : dateMs(at);
    const minGenMs = minGen === undefined ? undefined : dateMs(minGen);
    if (nowMs === null || atMs === null || minGenMs === null) throw bad();
    if (skew !== undefined && (typeof skew !== 'number' || Number.isNaN(skew) || skew < 0)) {
      throw bad();
    }
    // length checked before the copy, the copy never goes through the iterator (copyBytes)
    const nonceCopy =
      nonce === undefined ? undefined : copyBytes(nonce, NONCE_BYTES.min, NONCE_BYTES.max);
    if (nonceCopy === null) throw bad();
    if (critical !== undefined && typeof critical !== 'boolean') throw bad();
    if (
      rsaBits !== undefined &&
      (typeof rsaBits !== 'number' || !Number.isFinite(rsaBits) || rsaBits < 0)
    ) {
      throw bad();
    }
    return Object.freeze({
      now: nowMs,
      at: atMs,
      minGenTime: minGenMs,
      maxSkewMs: skew ?? DEFAULT_SKEW_MS,
      expectedNonce: nonceCopy,
      requireCriticalEku: critical ?? true,
      minRsaBits: rsaBits ?? DEFAULT_MIN_RSA_BITS,
      expectedPolicy: policy,
      crls,
    });
  };
  if (options === undefined) return snapshot(() => undefined);
  if (typeof options !== 'object' || options === null) throw bad();
  const o = options as Record<string, unknown>;
  try {
    const proto: unknown = Object.getPrototypeOf(o);
    if (proto !== Object.prototype && proto !== null) throw bad(); // class instance, Map, Date, array …
    return snapshot((key) => (Object.hasOwn(o, key) ? o[key] : undefined));
  } catch (e) {
    throw e instanceof ReaderError ? e : bad(); // a getter or proxy trap that throws
  }
}

async function checkSigningCertificate(token: ParsedToken, signer: Certificate): Promise<void> {
  const attrs = token.signer.attributes;
  const v2 = attrs.get(OID.signingCertificateV2);
  const v1 = attrs.get(OID.signingCertificate);
  const node = v2 ?? v1;
  if (!node) throw new ReaderError('signing-certificate-missing');
  const certs = children(expect(children(expect(node, TAG.sequence))[0], TAG.sequence));
  const first = children(expect(certs[0], TAG.sequence));
  let hash: HashName = v2 ? 'SHA-256' : 'SHA-1';
  let at = 0;
  if (v2 && first[0]?.tag === TAG.sequence) {
    // ESSCertIDv2: an unknown hash OID or SHA-1 is refused, never a silent fallback to SHA-256 (SHA-1 stays
    // accepted only in the v1 attribute)
    const named = HASHES[oid(children(first[0])[0]!)]?.name;
    if (!named || named === 'SHA-1') throw new ReaderError('unsupported-hash');
    hash = named;
    at = 1;
  }
  const expected = octets(first[at]!);
  if (!same(expected, await digest(hash, signer.raw))) {
    throw new ReaderError('signing-certificate-mismatch');
  }
}

/**
 * The signing certificate of the token. By issuer and serial number (SignerInfo version 1) the first certificate
 * of the token that matches is taken. By `subjectKeyIdentifier` (version 3) several certificates may carry the
 * same identifier (a look-alike with another key, a re-issued certificate): the one whose hash the signed
 * `signingCertificate` attribute names is taken, so a look-alike never hides the real one. At most
 * MAX_CERTIFICATES certificates are looked at, each costs one hash and no signature check; a certificate without
 * the extension never matches (the identifier is never computed from the key). The attribute binds exactly one
 * certificate, so the signature is checked against that one only. No match: `signer-certificate-missing`; matches
 * but none the attribute names: the reason of the first one (`signing-certificate-mismatch` and the like).
 */
async function findSigner(token: ParsedToken): Promise<Certificate> {
  const sid = token.signer.sid;
  if (sid.kind === 'issuerAndSerialNumber') {
    const signer = token.certificates.find(
      (c) => sameName(c.issuer, sid.issuer) && same(trimZeros(c.serial), sid.serial),
    );
    if (!signer) throw new ReaderError('signer-certificate-missing');
    await checkSigningCertificate(token, signer);
    return signer;
  }
  const named = token.certificates.filter(
    (c) => c.subjectKeyIdentifier !== null && same(c.subjectKeyIdentifier, sid.ski),
  );
  if (named.length === 0) throw new ReaderError('signer-certificate-missing');
  let firstFailure: ReaderError | null = null;
  for (const candidate of named) {
    try {
      await checkSigningCertificate(token, candidate);
      return candidate;
    } catch (e) {
      if (!(e instanceof ReaderError)) throw e;
      firstFailure ??= e;
    }
  }
  throw firstFailure ?? new ReaderError('signer-certificate-missing');
}

const lowerAscii = (bytes: Uint8Array): Uint8Array =>
  bytes.map((b) => (b >= 0x41 && b <= 0x5a ? b + 32 : b));

/**
 * RFC 3161 § 2.4.2: a `tsa` name in the TSTInfo must correspond to one of the subject names of the signer
 * certificate: its subject (a `directoryName`, by the simplified name rule) or an entry of its subjectAltName of
 * the same kind. directoryName: simplified name rule; dNSName: ASCII case ignored; every other kind (rfc822Name,
 * URI, iPAddress, registeredID, otherName ...): the same bytes (docs/grenzen.md). Nothing else is derived from the
 * certificate (no name in the subject's emailAddress counts as an rfc822Name).
 */
function checkTsaName(tsa: Uint8Array | null, signer: Certificate): void {
  if (!tsa) return;
  const name = parseDer(tsa);
  const isDirectory = name.tag === ctx(4);
  const wanted = isDirectory ? inner(name).raw : name.raw;
  if (isDirectory && sameName(wanted, signer.subject)) return;
  const entries = subjectAltNames(signer); // unreadable: bad-certificate
  for (const entry of entries) {
    if (entry.tag !== name.tag) continue;
    let match: boolean;
    try {
      match = isDirectory
        ? sameName(inner(entry).raw, wanted)
        : name.tag === ctxPrimitive(2)
          ? same(lowerAscii(entry.value), lowerAscii(name.value))
          : same(entry.raw, name.raw);
    } catch {
      throw new ReaderError('bad-certificate');
    }
    if (match) return;
  }
  throw new ReaderError('tsa-mismatch');
}

/** Valid at every one of the given moments (`genTime`, and `at` when the caller gave one). */
function validAt(cert: Certificate, times: readonly number[]): boolean {
  return times.every((t) => cert.notBefore <= t && t <= cert.notAfter);
}

/** An RSA key below the smallest allowed size (never for another kind of key; `minRsaBits` 0: never). */
function isWeakRsa(cert: Certificate, minRsaBits: number): boolean {
  if (minRsaBits === 0) return false;
  const bits = rsaModulusBits(cert);
  return bits !== null && bits < minRsaBits;
}

/** Why a candidate issuer is unusable at time `at`, or null when it is fine. */
function issuerFlaw(
  issuer: Certificate,
  anchors: readonly Certificate[],
  times: readonly number[],
  minRsaBits: number,
  below: number,
) {
  const isAnchor = anchors.some((a) => same(a.raw, issuer.raw));
  // no basicConstraints at all (an X.509 v1 root): a CA only when the caller handed it over as an anchor
  // (the caller's decision); an explicit cA=false and every intermediate without the extension stay refused
  const isCa = issuer.isCa === null && isAnchor ? true : issuer.isCa;
  if (isCa !== true || (issuer.keyUsage !== null && (issuer.keyUsage & 0x04) === 0)) {
    return 'not-a-ca' as const;
  }
  // pathLenConstraint (RFC 5280 § 4.2.1.9, § 6.1.4): at most that many non-self-issued intermediate CAs below
  // it; a trust anchor's value counts too (`openssl verify` does the same, measured: the anchor limits its chain)
  if (issuer.pathLen !== null && below > issuer.pathLen) return 'chain-too-long' as const;
  if (!validAt(issuer, times)) return 'certificate-not-valid-at-time' as const;
  if (issuer.unknownCritical && !isAnchor) {
    return 'bad-certificate' as const; // a trust anchor is the caller's decision, not checked
  }
  // EKU nesting (browser practice): a CA that names purposes must allow time stamping. No EKU: no limit.
  if (
    issuer.eku !== null &&
    !isAnchor &&
    !issuer.eku.oids.some((o) => o === OID.ekuTimeStamping || o === OID.anyExtendedKeyUsage)
  ) {
    return 'bad-eku' as const;
  }
  if (!isAnchor && isWeakRsa(issuer, minRsaBits)) return 'weak-key' as const;
  return null;
}

/**
 * Builds the chain from `signer` up to a trust anchor. Every usable, signature-valid candidate issuer is
 * tried (depth, usable candidates per step and signature checks are bounded), so a look-alike certificate
 * with the same name cannot hide the real intermediate. The cheap checks (`issuerFlaw`) come before the
 * signature check: an unusable look-alike costs no signature check and does not count against
 * MAX_CANDIDATES. The reason of a failure is worked out only after the whole search has failed, with a
 * budget of its own (MAX_REASON_CHECKS), so finding it never takes checks from a sibling branch.
 * Returns the number of certificates (anchor included) or throws the reason of the first failed branch.
 */
async function buildChain(
  signer: Certificate,
  anchors: readonly Certificate[],
  pool: readonly Certificate[],
  times: readonly number[],
  minRsaBits: number,
  accept: (path: readonly Certificate[]) => Promise<ReaderError | null> = async () => null,
): Promise<number> {
  type Flawed = { candidate: Certificate; flaw: NonNullable<ReturnType<typeof issuerFlaw>> };
  type Failure = ReaderError | { current: Certificate; flawed: Flawed[] };
  let checks = 0;
  let exhausted = false; // a usable candidate was left untried because a limit was reached
  let firstFailure: Failure | null = null;
  let revocationFailure: ReaderError | null = null; // a path that ended at an anchor but was refused by the CRLs
  const remember = (failure: Failure) => {
    firstFailure ??= failure;
  };
  const verifies = async (current: Certificate, candidate: Certificate): Promise<boolean> => {
    try {
      return await verifyWithKey(
        candidate,
        current.signatureOid,
        null,
        current.tbs,
        current.signature,
      );
    } catch {
      return false; // an unsupported key or signature: try the next candidate
    }
  };
  const walk = async (
    current: Certificate,
    length: number,
    path: readonly Certificate[],
  ): Promise<number | null> => {
    if (anchors.some((a) => same(a.raw, current.raw))) {
      const refusal = await accept(path);
      if (!refusal) return length;
      // `revoked` is the more telling answer; another path may still be fine (a twin of the revoked issuer)
      if (!revocationFailure || refusal.reason === 'revoked') revocationFailure = refusal;
      return null;
    }
    if (length > MAX_CHAIN) {
      remember(new ReaderError('chain-too-long'));
      return null;
    }
    const named = SIGNATURES[current.signatureOid]?.hash
      ? pool.filter(
          (c) => sameName(c.subject, current.issuer) && !path.some((p) => same(p.raw, c.raw)), // not self-signed, no loop
        )
      : [];
    const usable: Certificate[] = [];
    const flawed: Flawed[] = [];
    // intermediates between the signer and the candidate; a self-issued one (same name as issuer and subject:
    // a key rollover) does not count (RFC 5280 § 6.1.4 (l))
    const below = path.slice(1).filter((c) => !sameName(c.subject, c.issuer)).length;
    for (const candidate of named) {
      const flaw = issuerFlaw(candidate, anchors, times, minRsaBits, below);
      if (flaw) flawed.push({ candidate, flaw });
      else usable.push(candidate);
    }
    let found = 0;
    for (const candidate of usable) {
      if (checks >= MAX_SIGNATURE_CHECKS || found >= MAX_CANDIDATES) {
        exhausted = true;
        break;
      }
      checks += 1;
      if (!(await verifies(current, candidate))) continue;
      found += 1;
      const result = await walk(candidate, length + 1, [...path, candidate]);
      if (result !== null) return result;
    }
    if (found === 0) remember({ current, flawed }); // why is decided later, if the search fails
    return null;
  };
  const length = await walk(signer, 1, [signer]);
  if (length !== null) return length;
  if (revocationFailure) throw revocationFailure;
  if (exhausted) throw new ReaderError('untrusted-chain'); // the search was cut short: no more exact reason
  const failure = firstFailure as Failure | null;
  if (failure instanceof ReaderError) throw failure;
  if (failure) {
    // nothing usable signed it: report why the first look-alike that did sign it is unusable
    let spent = 0;
    for (const { candidate, flaw } of failure.flawed) {
      if (spent >= MAX_REASON_CHECKS) break;
      spent += 1;
      if (await verifies(failure.current, candidate)) throw new ReaderError(flaw);
    }
  }
  throw new ReaderError('untrusted-chain');
}

/**
 * The judge of the CRLs for one verification: the lists are read and checked for currency once, `accept(path)`
 * then decides for a finished chain (signer first, anchor last). Every list must be signed by a certificate of
 * that chain (a CA that may sign lists), else `bad-crl`; a certificate whose issuer's list names it is `revoked`.
 * Signature checks are cached per (list, certificate) and bounded (`CRL_LIMITS.MAX_CRL_SIGNATURE_CHECKS`, more: the
 * list counts as unverified, so `bad-crl`).
 */
function crlJudge(
  crls: readonly Crl[],
  genTime: number,
  anchors: readonly Certificate[],
): (path: readonly Certificate[]) => Promise<ReaderError | null> {
  const cache = new Map<Certificate, Map<number, boolean>>();
  let checks = 0;
  const signedBy = async (j: number, cert: Certificate): Promise<boolean> => {
    const crl = crls[j]!;
    let known = cache.get(cert);
    if (!known) cache.set(cert, (known = new Map()));
    const hit = known.get(j);
    if (hit !== undefined) return hit;
    let good = false;
    // a CRL issuer is a CA (an anchor without basicConstraints counts, as for certificates) that may sign lists
    const isAnchor = anchors.some((a) => same(a.raw, cert.raw));
    const isCa = cert.isCa === null && isAnchor ? true : cert.isCa;
    if (
      isCa === true &&
      (cert.keyUsage === null || (cert.keyUsage & 0x02) !== 0) &&
      sameName(cert.subject, crl.issuer) &&
      checks < CRL_LIMITS.MAX_CRL_SIGNATURE_CHECKS
    ) {
      checks += 1;
      try {
        good = await verifyWithKey(cert, crl.signatureOid, null, crl.tbs, crl.signature);
      } catch {
        good = false;
      }
    }
    known.set(j, good);
    return good;
  };
  return async (path) => {
    if (crls.length === 0) return null;
    const signers: boolean[][] = [];
    for (let j = 0; j < crls.length; j += 1) {
      const row: boolean[] = [];
      for (let k = 0; k < path.length; k += 1) row.push(k >= 1 && (await signedBy(j, path[k]!)));
      if (!row.some(Boolean)) return new ReaderError('bad-crl'); // signed by no member of this chain
      signers.push(row);
    }
    for (let i = 0; i + 1 < path.length; i += 1) {
      for (let j = 0; j < crls.length; j += 1) {
        if (signers[j]![i + 1] && revokedAt(crls[j]!, path[i]!.serial, genTime)) {
          return new ReaderError('revoked');
        }
      }
    }
    return null;
  };
}

/**
 * Verifies a time stamp token against the SHA-256 hash it must cover:
 * imprint, nonce (when given), the CMS signature, the signing-certificate attribute, the key usage of
 * the signer, the validity of every certificate at the stamped time (and at `at`, when given), and a chain
 * that ends in one of the given trust anchors. The age of the token is checked only with `minGenTime`.
 * Revocation: only offline lists the caller gives (`crls`), no OCSP, nothing is downloaded; name constraints (`nameConstraints`) and `pathLenConstraint` are evaluated (see docs/grenzen.md). Never throws or rejects, whatever it is given (a hostile proxy included).
 */
export async function verifyTimestampToken(
  tokenBytes: Uint8Array,
  expectedSha256: Uint8Array,
  trust: TrustAnchors,
  options: VerifyOptions = {},
): Promise<Result<VerifiedTimestamp>> {
  try {
    return await verifyChecked(tokenBytes, expectedSha256, trust, options);
  } catch {
    return fail('malformed'); // not reachable by design: the last net under the promise "never throws"
  }
}

async function verifyChecked(
  tokenBytes: unknown,
  expectedSha256: unknown,
  trust: unknown,
  options: unknown,
): Promise<Result<VerifiedTimestamp>> {
  const wanted = copyBytes(expectedSha256, 32, 32);
  if (!wanted) return fail('bad-hash');
  // the token is copied once, into an ArrayBuffer of its own (length checked before the copy); the rest
  // works with the copy only, so a buffer changed or emptied meanwhile, or one living in a
  // SharedArrayBuffer, changes nothing
  const tokenLength = byteLength(tokenBytes);
  if (tokenLength === null) return fail('malformed');
  if (tokenLength > DER_LIMITS.maxBytes) return fail('too-large');
  const tokenCopy = copyKnown(tokenBytes as Uint8Array, tokenLength); // the value is asked once, not twice
  if (!tokenCopy) return fail('malformed');
  // the list is read by length and index (once each), never through the iterator, and bounded first
  let trustList: unknown[];
  try {
    if (!Array.isArray(trust)) return fail('bad-options');
    const count: unknown = (trust as unknown[]).length;
    if (typeof count !== 'number' || !Number.isInteger(count) || count < 0) {
      return fail('bad-options');
    }
    if (count > MAX_TRUST_ANCHORS) return fail('bad-options');
    trustList = [];
    for (let i = 0; i < count; i += 1) trustList.push((trust as unknown[])[i]);
  } catch {
    return fail('bad-options'); // a proxy whose traps throw is no list
  }
  const anchorsRead = guard(() => trustList.flatMap((pem) => parsePemCertificates(pem as string)));
  if (!anchorsRead.ok) return anchorsRead;
  const anchors = anchorsRead.value;
  try {
    const opts = checkOptions(options);
    const token = readToken(tokenCopy);
    const info: TstInfo = token.info;
    if (info.hashName !== 'SHA-256') throw new ReaderError('unsupported-hash');
    if (!same(info.imprint, wanted)) throw new ReaderError('imprint-mismatch');
    if (opts.expectedNonce !== undefined) {
      const want = trimZeros(opts.expectedNonce);
      if (!info.nonce || !same(info.nonce, want)) throw new ReaderError('nonce-mismatch');
    }
    if (opts.expectedPolicy !== undefined && !opts.expectedPolicy.includes(info.policy)) {
      throw new ReaderError('policy-mismatch');
    }
    if (opts.now !== undefined && info.genTime > opts.now + opts.maxSkewMs) {
      throw new ReaderError('time-in-future');
    }
    if (opts.minGenTime !== undefined && info.genTime < opts.minGenTime) {
      throw new ReaderError('time-too-old');
    }
    // the certificates must be valid at the stamped time and, when given, at `at` as well
    const times = opts.at === undefined ? [info.genTime] : [info.genTime, opts.at];

    // signed attributes: content type, message digest, signing certificate
    const attrs = token.signer.attributes;
    const contentType = attrs.get(OID.contentType);
    if (!contentType || oid(contentType) !== OID.tstInfo) throw new ReaderError('bad-content-type');
    const digestHash = HASHES[token.signer.digestOid]?.name;
    if (!digestHash || digestHash === 'SHA-1') throw new ReaderError('unsupported-hash');
    const md = attrs.get(OID.messageDigest);
    if (!md || !same(octets(md), await digest(digestHash, token.content))) {
      throw new ReaderError('message-digest-mismatch');
    }

    // signer certificate, found as the SignerInfo names it
    const signer = await findSigner(token);
    // an RSA key below the smallest size is refused before it is used (a platform may or may not import it); a
    // signer the caller trusts as an anchor is exempt
    if (!anchors.some((a) => same(a.raw, signer.raw)) && isWeakRsa(signer, opts.minRsaBits)) {
      throw new ReaderError('weak-key');
    }
    // A signature OID that names its hash (ecdsa-with-SHA384 ...) must agree with the digestAlgorithm of the
    // SignerInfo (RFC 5652 § 5.3, openssl: "signature failure"); a bare OID takes the digestAlgorithm's hash.
    // SHA-1 stays `unsupported-signature` (refused in verifyWithKey).
    const namedHash = SIGNATURES[token.signer.signatureOid]?.hash;
    if (namedHash && namedHash !== 'SHA-1' && namedHash !== digestHash) {
      throw new ReaderError('signature-invalid');
    }
    if (
      !(await verifyWithKey(
        signer,
        token.signer.signatureOid,
        digestHash,
        token.signer.signedAttributesDer,
        token.signer.signature,
      ))
    ) {
      throw new ReaderError('signature-invalid');
    }
    checkTsaName(info.tsa, signer); // RFC 3161 § 2.4.2: the tsa name must be one of the signer's names
    const eku = signer.eku;
    if (
      !eku ||
      eku.oids.length !== 1 || // RFC 3161 § 2.3: exactly one purpose, id-kp-timeStamping
      eku.oids[0] !== OID.ekuTimeStamping ||
      (opts.requireCriticalEku && !eku.critical)
    ) {
      throw new ReaderError('bad-eku');
    }
    const signerIsAnchor = anchors.some((a) => same(a.raw, signer.raw));
    if (signer.unknownCritical && !signerIsAnchor) {
      throw new ReaderError('bad-certificate');
    }
    if (signer.keyUsage !== null && (signer.keyUsage & 0xc0) === 0)
      throw new ReaderError('bad-eku');
    // the signer is an end entity: a certificate that is a CA (cA TRUE) or may sign certificates (keyCertSign)
    // is refused, unless the caller handed it over as the trust anchor itself
    if (
      !signerIsAnchor &&
      (signer.isCa === true || (signer.keyUsage !== null && (signer.keyUsage & 0x04) !== 0))
    ) {
      throw new ReaderError('bad-certificate');
    }
    if (!validAt(signer, times)) throw new ReaderError('certificate-not-valid-at-time');

    // chain to a trust anchor
    const pool = dedupe([...anchors, ...token.certificates]); // anchors first: a cross-signed twin of an anchor must not win
    // CRLs: read and checked for currency before the chain search (the chain decides who signed them)
    const crlTime = opts.at ?? opts.now ?? info.genTime;
    const crls = opts.crls.map((bytes) => parseCrl(bytes));
    for (const crl of crls) {
      if (crl.thisUpdate > crlTime || crlTime > crl.nextUpdate) throw new ReaderError('bad-crl');
    }
    const judgeCrls = crlJudge(crls, info.genTime, anchors);
    const length = await buildChain(
      signer,
      anchors,
      pool,
      times,
      opts.minRsaBits,
      async (path) => checkNameConstraints(path) ?? (await judgeCrls(path)),
    );
    return ok({
      genTime: new Date(info.genTime).toISOString(),
      accuracyMs: info.accuracyMs,
      policy: info.policy,
      serial: info.serial,
      signer: nameToString(signer.subject),
      chainLength: length,
      signerNotBefore: new Date(signer.notBefore).toISOString(),
      signerNotAfter: new Date(signer.notAfter).toISOString(),
    });
  } catch (e) {
    return fail(e instanceof ReaderError ? e.reason : 'malformed');
  }
}
